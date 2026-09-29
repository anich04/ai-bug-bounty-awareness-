"""Fixed offline runtime with persisted inputs, runs and approval-gated handoffs."""

import json

from .agent_contracts import ContractError, charter, digest, ensure, load_input, validate_output
from .agents import AgentContext, HANDLERS
from .jobs import JobError, JobQueue
from .policy import PolicyError


class AgentRuntime:
    def __init__(self, queue: JobQueue):
        self.queue = queue
        self.database = queue.database

    def enqueue(self, agent: str, program_id: str, target: str, payload: dict,
                *, idempotency_key: str | None = None) -> dict:
        definition = charter(agent)
        return self.queue.create(program_id, target, definition.action, method=definition.method,
                                 agent_input=payload, idempotency_key=idempotency_key)

    def handoff(self, parent_job_id: str, destination: str, payload: dict) -> dict:
        definition = charter(destination)
        parent = self.queue.show(parent_job_id)
        return self.queue.create(parent["program_id"], parent["target"], definition.action,
                                 method=definition.method, source_agent=parent["owner"],
                                 agent_input=payload, parent_job_id=parent_job_id)

    def _input(self, connection, row):
        item = connection.execute("SELECT * FROM agent_inputs WHERE job_id=?", (row["id"],)).fetchone()
        ensure(item is not None and item["agent"] == row["owner"] and item["contract_version"] == 1,
               "Missing or mismatched agent input")
        ensure(digest(item["document_json"]) == item["input_sha"], "Agent input hash mismatch")
        definition = charter(item["agent"])
        ensure(row["type"] == definition.action and row["method"] == definition.method, "Agent job contract mismatch")
        payload = load_input(item["agent"], item["document_json"])
        return item, payload

    def run_next(self, agent: str, worker: str = "local-agent-worker") -> dict | None:
        charter(agent)
        claimed = self.queue.claim(agent, worker, agent_mode=True)
        if claimed is None:
            return None
        output = None
        error = None
        try:
            with self.database.transaction(write=True) as connection:
                now = self.queue._now(connection)
                self.queue._enabled(connection)
                row = self.queue._row(connection, claimed["id"])
                self.queue._owned(row, worker, claimed["lease_token"], now)
                program, reason = self.queue._current(connection, row, now)
                if reason:
                    return self.queue._public(self.queue._move(connection, row, "blocked", reason, now, worker))
                item, payload = self._input(connection, row)
                context = AgentContext(row["id"], row["target"], program, now, item["input_sha"])
            # Only the fixed built-in handler is invoked; no import strings or shell callbacks.
            output = HANDLERS[agent].run(context, payload)
            validate_output(output, agent=agent, job_id=context.job_id,
                            revision=program.revision, input_sha=context.input_sha)
        except (ContractError, PolicyError):
            error = "invalid_agent_contract"
        except JobError:
            # A stop/cancellation or lease loss must not be transformed into a success.
            raise
        except Exception:
            # Never log or persist raw exception text that could contain input data.
            error = "agent_handler_failed"
        return self._publish(claimed, output, error)

    def _publish(self, claimed: dict, output: dict | None, error: str | None) -> dict:
        with self.database.transaction(write=True) as connection:
            now = self.queue._now(connection)
            self.queue._enabled(connection)
            row = self.queue._row(connection, claimed["id"])
            self.queue._owned(row, claimed["worker"], claimed["lease_token"], now)
            _, reason = self.queue._current(connection, row, now)
            if reason:
                return self.queue._public(self.queue._move(connection, row, "blocked", reason, now, claimed["worker"]))
            run = connection.execute("SELECT * FROM agent_runs WHERE job_id=? AND attempt=? AND status='running'", (row["id"], row["attempts"])).fetchone()
            ensure(run is not None, "Missing active agent run")
            document = None
            if error is None:
                try:
                    item, payload = self._input(connection, row)
                    ensure(item["input_sha"] == run["input_sha"], "Agent input changed during execution")
                    document = validate_output(output, agent=row["owner"], job_id=row["id"],
                                               revision=row["policy_revision"], input_sha=item["input_sha"])
                    if row["owner"] == "reporter":
                        ensure([{k: q[k] for k in ("id", "label", "required")} for q in output["data"]["questions"]] == payload["data"]["questions"], "Report question text changed")
                    if row["owner"] == "validator":
                        ensure(output["data"]["supplied_facts"] == payload["data"]["observations"] and
                               output["data"]["hypothesis"] == payload["data"]["hypothesis"], "Validator changed supplied data")
                except (ContractError, PolicyError):
                    error = "invalid_agent_contract"
            if error:
                return self.queue._public(self.queue._retry_or_fail(connection, row, now, claimed["worker"], error,
                                                                    retryable=error == "agent_handler_failed"))
            updated = self.queue._move(connection, row, "succeeded", "offline_agent_completed", now,
                                       claimed["worker"], result_json=document)
            connection.execute("UPDATE agent_runs SET output_json=?,output_sha=? WHERE id=?", (document, digest(document), run["id"]))
            return self.queue._public(updated)

    def runs(self, *, job_id: str | None = None) -> list[dict]:
        with self.database.transaction() as connection:
            return [dict(row) for row in connection.execute("SELECT id,job_id,attempt,agent,worker,input_sha,status,reason,started_at,ended_at,output_sha FROM agent_runs WHERE (? IS NULL OR job_id=?) ORDER BY started_at,id", (job_id, job_id))]

    def show_run(self, run_id: str) -> dict:
        with self.database.transaction() as connection:
            row = connection.execute("SELECT * FROM agent_runs WHERE id=?", (run_id,)).fetchone()
            ensure(row is not None, "Unknown agent run")
            result = dict(row)
            document = result.pop("output_json")
            if document is not None:
                ensure(digest(document) == row["output_sha"], "Agent output hash mismatch")
            result["output"] = json.loads(document) if document else None
            result["handoffs"] = [dict(item) for item in connection.execute("SELECT * FROM agent_handoffs WHERE parent_job_id=? OR child_job_id=? ORDER BY created_at", (row["job_id"], row["job_id"]))]
            return result
