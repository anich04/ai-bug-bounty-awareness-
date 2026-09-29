"""Persistent dry-run orchestration. No arbitrary callbacks, tools or network I/O."""

import hashlib
import json
import math
import time
from uuid import uuid4

from .database import Database, DatabaseError
from .policy import HTTP_ACTIONS, PolicyError, identifier, normalize_target
from .programs import ProgramStore
from .scope import action_is_allowed, rate_limit_allows, target_is_in_scope


ROUTES = {
    "review_policy": "scout", "draft_report": "reporter",
    "discover_assets": "mapper", "resolve_dns": "mapper", "probe_http": "mapper",
    "collect_urls": "crawler", "parse_javascript": "crawler", "analyze_http": "tester",
    "compare_responses": "validator", "validate_candidate": "validator",
    "save_artifact": "evidence", "report_submission": "reporter",
    "state_change": "tester", "high_volume": "tester", "sensitive_account": "tester",
}
AGENTS = frozenset({"human", "orchestrator", "scout", "mapper", "crawler", "tester",
                    "validator", "evidence", "reporter", "monitor"})
TRANSITIONS = {
    "waiting_human": {"queued", "rejected", "blocked", "cancelled"},
    "queued": {"running", "blocked", "cancelled"},
    "running": {"succeeded", "retry_wait", "failed", "blocked", "cancelled"},
    "retry_wait": {"running", "blocked", "cancelled"},
    "succeeded": set(), "failed": set(), "cancelled": set(), "blocked": set(), "rejected": set(),
}
TERMINAL = frozenset(status for status, transitions in TRANSITIONS.items() if not transitions)


class JobError(ValueError):
    pass


def check(condition: bool, message: str) -> None:
    if not condition:
        raise JobError(message)


class JobQueue:
    def __init__(self, database: Database, *, clock=time.time):
        self.database = database
        self.clock = clock

    def _now(self, connection, *, allow_rollback: bool = False) -> float:
        now = self.clock()
        check(type(now) in (int, float) and math.isfinite(now) and now >= 0, "Invalid queue clock")
        row = connection.execute("SELECT * FROM engine_control WHERE id=1").fetchone()
        if row is None:
            raise DatabaseError("Missing engine control; queue is blocked")
        check(allow_rollback or now >= row["last_seen"], "Queue clock moved backwards")
        # Emergency stop and cancellation must remain possible during a clock rollback.
        now = max(now, row["last_seen"])
        connection.execute("UPDATE engine_control SET last_seen=? WHERE id=1", (now,))
        return now

    @staticmethod
    def _enabled(connection) -> None:
        row = connection.execute("SELECT stopped FROM engine_control WHERE id=1").fetchone()
        check(row is not None and not row[0], "Emergency stop is active; resume explicitly before new work")

    @staticmethod
    def _row(connection, job_id: str):
        row = connection.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        check(row is not None, "Unknown job")
        return row

    @staticmethod
    def _public(row, *, include_token: bool = False) -> dict:
        result = dict(row)
        if not include_token:
            result.pop("lease_token", None)
        raw = result.pop("result_json")
        result["result"] = json.loads(raw) if raw else None
        result["dry_run"] = True
        result["execution_enabled"] = False
        return result

    @staticmethod
    def _event(connection, row, now: float, actor: str, event: str,
               from_status: str | None, reason: str) -> None:
        connection.execute("INSERT INTO job_events(job_id,at,actor,event,from_status,to_status,reason,attempt,correlation_id) VALUES (?,?,?,?,?,?,?,?,?)",
                           (row["id"], now, actor, event, from_status, row["status"], reason,
                            row["attempts"], row["correlation_id"]))

    def _move(self, connection, row, status: str, reason: str, now: float, actor: str, **updates):
        check(status in TRANSITIONS[row["status"]], "Invalid job state transition")
        allowed_columns = {"available_at", "attempts", "worker", "lease_token", "lease_until", "approval_revision", "result_json"}
        check(updates.keys() <= allowed_columns, "Invalid job update")
        if status != "running":
            updates.update(worker=None, lease_token=None, lease_until=None)
        updates.update(status=status, reason=reason, updated_at=now)
        # Column names are internal and allowlisted above; values are always bound.
        connection.execute("UPDATE jobs SET " + ",".join(key + "=?" for key in updates) + " WHERE id=?",
                           (*updates.values(), row["id"]))
        updated = self._row(connection, row["id"])
        self._event(connection, updated, now, actor, "transition", row["status"], reason)
        if row["status"] == "running" and status != "running":
            connection.execute("UPDATE agent_runs SET status=?,reason=?,ended_at=? WHERE job_id=? AND attempt=? AND status='running'",
                               (status, reason, now, row["id"], row["attempts"]))
        return updated

    @staticmethod
    def _policy_reason(program, target: str, action: str, method: str | None, now: float) -> str | None:
        scope = target_is_in_scope(program, target, now=now)
        if not scope.allowed:
            return scope.reason
        policy = action_is_allowed(program, action, method)
        if not policy.allowed:
            return policy.reason
        if action in HTTP_ACTIONS and normalize_target(target).scheme is None:
            return "http_action_requires_url"
        return None

    def _current(self, connection, row, now: float):
        try:
            program = ProgramStore.read(connection, row["program_id"])
        except PolicyError:
            return None, "policy_unavailable_or_invalid"
        if program.revision != row["policy_revision"]:
            return program, "policy_changed_create_new_job"
        reason = self._policy_reason(program, row["target"], row["type"], row["method"], now)
        return program, reason

    def create(self, program_id: str, target: str, action: str, *, method: str | None = None,
               source_agent: str = "human", max_attempts: int = 3,
               idempotency_key: str | None = None, agent_input: dict | None = None,
               parent_job_id: str | None = None) -> dict:
        check(action in ROUTES, "Unknown job type; no route exists")
        check(source_agent in AGENTS, "Unknown source agent")
        check(type(max_attempts) is int and 1 <= max_attempts <= 5, "max_attempts must be between 1 and 5")
        if idempotency_key is not None:
            identifier(idempotency_key)
        # Phase 1 display strips queries. Do not silently turn a requested job into a different request.
        check("?" not in target, "Query-bearing jobs are not supported in this phase")
        normalized = normalize_target(target).display
        input_document = None
        if agent_input is not None:
            from .agent_contracts import charter, validate_input
            definition = charter(ROUTES[action])
            check(definition.action == action and definition.method == method, "Job does not match the agent action/method contract")
            input_document = validate_input(definition.name, agent_input)
        check(parent_job_id is None or agent_input is not None, "Handoffs require an agent input contract")
        if parent_job_id is not None:
            idempotency_key = "H-" + hashlib.sha256((parent_job_id + ":" + ROUTES[action]).encode()).hexdigest()[:40]
        fingerprint_fields = [program_id, normalized, action, method, source_agent, max_attempts]
        if input_document is not None:
            fingerprint_fields.append(input_document)
        fingerprint = hashlib.sha256(json.dumps(fingerprint_fields, separators=(",", ":")).encode()).hexdigest()
        with self.database.transaction(write=True) as connection:
            now = self._now(connection)
            self._enabled(connection)
            parent = None
            if parent_job_id is not None:
                from .agent_contracts import charter
                parent = self._row(connection, parent_job_id)
                check(parent["status"] == "succeeded" and connection.execute("SELECT 1 FROM agent_runs WHERE job_id=? AND status='succeeded' AND output_json IS NOT NULL", (parent_job_id,)).fetchone() is not None,
                      "Handoff source must be a completed agent run")
                check(parent["program_id"] == program_id and parent["target"] == normalized and source_agent == parent["owner"], "Handoff cannot change program, target or source identity")
                check(ROUTES[action] in charter(parent["owner"]).next_agents, "Agent handoff route is not allowed")
                _, reason = self._current(connection, parent, now)
                check(reason is None, "Handoff source policy is stale or invalid")
            if idempotency_key is not None:
                existing = connection.execute("SELECT * FROM jobs WHERE program_id=? AND idempotency_key=?", (program_id, idempotency_key)).fetchone()
                if existing is not None:
                    check(existing["fingerprint"] == fingerprint, "Idempotency key already refers to different job inputs")
                    return self._public(existing)
            program = ProgramStore.read(connection, program_id)
            reason = self._policy_reason(program, normalized, action, method, now)
            status = "blocked" if reason else "waiting_human"
            reason = reason or "human_approval_required_for_dry_run"
            job_id = "J-" + uuid4().hex
            connection.execute("""INSERT INTO jobs(id,program_id,source_agent,owner,type,target,method,policy_revision,
                               status,reason,created_at,updated_at,available_at,max_attempts,idempotency_key,fingerprint,correlation_id)
                               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                               (job_id, program_id, source_agent, ROUTES[action], action, normalized, method,
                                program.revision, status, reason, now, now, now, max_attempts,
                                idempotency_key, fingerprint, str(uuid4())))
            row = self._row(connection, job_id)
            if input_document is not None:
                input_sha = hashlib.sha256(input_document.encode()).hexdigest()
                connection.execute("INSERT INTO agent_inputs VALUES (?,?,?,?,?)", (job_id, ROUTES[action], 1, input_document, input_sha))
            if parent is not None:
                connection.execute("UPDATE jobs SET correlation_id=? WHERE id=?", (parent["correlation_id"], job_id))
                connection.execute("INSERT INTO agent_handoffs VALUES (?,?,?,?,?,?)", (parent_job_id, job_id, source_agent, ROUTES[action], now, parent["correlation_id"]))
                row = self._row(connection, job_id)
            self._event(connection, row, now, source_agent, "created", None, reason)
            return self._public(row)

    def review(self, job_id: str, *, approve: bool, actor: str = "local-human") -> dict:
        identifier(actor)
        check(type(approve) is bool, "Review decision must be boolean")
        with self.database.transaction(write=True) as connection:
            now = self._now(connection)
            self._enabled(connection)
            row = self._row(connection, job_id)
            check(row["status"] == "waiting_human", "Only waiting jobs can be reviewed")
            if approve:
                _, reason = self._current(connection, row, now)
                if reason:
                    return self._public(self._move(connection, row, "blocked", reason, now, actor))
            connection.execute("INSERT INTO approvals(job_id,policy_revision,decision,actor,at,correlation_id) VALUES (?,?,?,?,?,?)",
                               (job_id, row["policy_revision"], "approved" if approve else "rejected", actor, now, row["correlation_id"]))
            return self._public(self._move(connection, row, "queued" if approve else "rejected",
                                           "human_approved_dry_run" if approve else "human_rejected", now, actor,
                                           approval_revision=row["policy_revision"] if approve else None))

    def _retry_or_fail(self, connection, row, now: float, actor: str, reason: str, *, retryable: bool):
        if retryable and row["attempts"] < row["max_attempts"]:
            delay = min(300, 5 * 2 ** (row["attempts"] - 1))
            return self._move(connection, row, "retry_wait", reason, now, actor, available_at=now + delay)
        return self._move(connection, row, "failed", reason, now, actor)

    def _recover(self, connection, now: float) -> list[str]:
        expired = connection.execute("SELECT * FROM jobs WHERE status='running' AND lease_until<=? ORDER BY id", (now,)).fetchall()
        for row in expired:
            self._retry_or_fail(connection, row, now, "orchestrator", "worker_lease_expired", retryable=True)
        return [row["id"] for row in expired]

    def recover(self) -> list[str]:
        with self.database.transaction(write=True) as connection:
            now = self._now(connection)
            return self._recover(connection, now)

    def claim(self, owner: str, worker: str, *, lease_seconds: int = 30, agent_mode: bool = False) -> dict | None:
        check(owner in set(ROUTES.values()), "No worker route exists for that owner")
        identifier(worker)
        check(type(lease_seconds) is int and 5 <= lease_seconds <= 3600, "Lease must be between 5 and 3600 seconds")
        with self.database.transaction(write=True) as connection:
            now = self._now(connection)
            self._enabled(connection)
            self._recover(connection, now)
            running = connection.execute("SELECT COUNT(*) FROM jobs WHERE status='running'").fetchone()[0]
            limit = connection.execute("SELECT concurrency_limit FROM engine_control WHERE id=1").fetchone()[0]
            if running >= limit:
                return None
            candidates = connection.execute("SELECT * FROM jobs WHERE owner=? AND status IN ('queued','retry_wait') AND available_at<=? AND EXISTS(SELECT 1 FROM agent_inputs WHERE job_id=jobs.id)=? ORDER BY created_at,id", (owner, now, int(agent_mode))).fetchall()
            for row in candidates:
                program, reason = self._current(connection, row, now)
                if reason is None and row["approval_revision"] != row["policy_revision"]:
                    reason = "missing_bound_approval"
                if reason is None and connection.execute("SELECT 1 FROM approvals WHERE job_id=? AND policy_revision=? AND decision='approved'", (row["id"], row["policy_revision"])).fetchone() is None:
                    reason = "missing_bound_approval"
                if reason:
                    self._move(connection, row, "blocked", reason, now, "orchestrator")
                    continue
                budget = rate_limit_allows(connection, program, now=now, consume=True)
                if not budget.allowed:
                    if budget.reason == "rate_limit_exceeded":
                        if row["reason"] != budget.reason:
                            connection.execute("UPDATE jobs SET reason=?,updated_at=? WHERE id=?", (budget.reason, now, row["id"]))
                            self._event(connection, self._row(connection, row["id"]), now, "orchestrator", "rate_deferred", row["status"], budget.reason)
                        continue
                    self._move(connection, row, "blocked", budget.reason, now, "orchestrator")
                    continue
                claimed = self._move(connection, row, "running", "dry_run_claimed", now, worker,
                                     attempts=row["attempts"] + 1, worker=worker, lease_token=uuid4().hex,
                                     lease_until=now + lease_seconds)
                if agent_mode:
                    item = connection.execute("SELECT * FROM agent_inputs WHERE job_id=?", (row["id"],)).fetchone()
                    connection.execute("INSERT INTO agent_runs(id,job_id,attempt,agent,worker,input_sha,status,reason,started_at) VALUES (?,?,?,?,?,?,?,?,?)",
                                       ("R-" + uuid4().hex, row["id"], claimed["attempts"], owner, worker, item["input_sha"], "running", "agent_claimed", now))
                return self._public(claimed, include_token=True)
            return None

    @staticmethod
    def _owned(row, worker: str, token: str, now: float) -> None:
        check(row["status"] == "running" and row["worker"] == worker and
              row["lease_token"] == token and row["lease_until"] > now,
              "Worker does not hold a current job lease")

    def heartbeat(self, job_id: str, worker: str, token: str, *, lease_seconds: int = 30) -> dict:
        check(type(lease_seconds) is int and 5 <= lease_seconds <= 3600, "Invalid lease duration")
        with self.database.transaction(write=True) as connection:
            now = self._now(connection)
            self._enabled(connection)
            row = self._row(connection, job_id)
            self._owned(row, worker, token, now)
            _, reason = self._current(connection, row, now)
            if reason:
                return self._public(self._move(connection, row, "blocked", reason, now, worker))
            connection.execute("UPDATE jobs SET lease_until=?,updated_at=? WHERE id=?", (max(row["lease_until"], now + lease_seconds), now, job_id))
            updated = self._row(connection, job_id)
            self._event(connection, updated, now, worker, "heartbeat", "running", "lease_extended")
            return self._public(updated)

    def finish(self, job_id: str, worker: str, token: str, *, outcome: str = "success") -> dict:
        check(outcome in {"success", "transient_failure", "permanent_failure"}, "Unknown dry-run outcome")
        with self.database.transaction(write=True) as connection:
            now = self._now(connection)
            self._enabled(connection)
            row = self._row(connection, job_id)
            self._owned(row, worker, token, now)
            check(connection.execute("SELECT 1 FROM agent_inputs WHERE job_id=?", (job_id,)).fetchone() is None,
                  "Agent jobs must publish through AgentRuntime")
            _, reason = self._current(connection, row, now)
            if reason:
                return self._public(self._move(connection, row, "blocked", reason, now, worker))
            if outcome != "success":
                return self._public(self._retry_or_fail(connection, row, now, worker, outcome,
                                                        retryable=outcome == "transient_failure"))
            result = {"kind": "dry_run_simulation", "tool_executed": False,
                      "network_requests": 0, "finding_created": False, "report_submitted": False}
            return self._public(self._move(connection, row, "succeeded", "dry_run_completed", now, worker,
                                           result_json=json.dumps(result)))

    def run_next(self, owner: str, worker: str, *, outcome: str = "success") -> dict | None:
        check(outcome in {"success", "transient_failure", "permanent_failure"}, "Unknown dry-run outcome")
        job = self.claim(owner, worker)
        if job is None:
            return None
        return self.finish(job["id"], worker, job["lease_token"], outcome=outcome)

    def cancel(self, job_id: str, *, actor: str = "local-human") -> dict:
        identifier(actor)
        with self.database.transaction(write=True) as connection:
            now = self._now(connection, allow_rollback=True)
            row = self._row(connection, job_id)
            check(row["status"] not in TERMINAL, "Terminal jobs cannot be cancelled")
            return self._public(self._move(connection, row, "cancelled", "human_cancelled", now, actor))

    def emergency_stop(self, *, actor: str = "local-human") -> dict:
        identifier(actor)
        with self.database.transaction(write=True) as connection:
            now = self._now(connection, allow_rollback=True)
            connection.execute("UPDATE engine_control SET stopped=1 WHERE id=1")
            rows = connection.execute("SELECT * FROM jobs WHERE status IN ('waiting_human','queued','retry_wait','running')").fetchall()
            for row in rows:
                self._move(connection, row, "cancelled", "emergency_stop", now, actor)
            connection.execute("INSERT INTO engine_events(at,actor,event,correlation_id) VALUES (?,?,?,?)", (now, actor, "emergency_stop", str(uuid4())))
            return {"stopped": True, "cancelled_jobs": len(rows), "execution_enabled": False}

    def resume(self, *, actor: str = "local-human") -> dict:
        identifier(actor)
        with self.database.transaction(write=True) as connection:
            now = self._now(connection)
            connection.execute("UPDATE engine_control SET stopped=0 WHERE id=1")
            connection.execute("INSERT INTO engine_events(at,actor,event,correlation_id) VALUES (?,?,?,?)", (now, actor, "resume", str(uuid4())))
            return {"stopped": False, "execution_enabled": False}

    def status(self) -> dict:
        with self.database.transaction() as connection:
            row = connection.execute("SELECT stopped,concurrency_limit FROM engine_control WHERE id=1").fetchone()
            if row is None:
                raise DatabaseError("Missing engine control; queue is blocked")
            counts = {item[0]: item[1] for item in connection.execute("SELECT status,COUNT(*) FROM jobs GROUP BY status")}
            return {"stopped": bool(row[0]), "concurrency_limit": row[1], "jobs": counts, "execution_enabled": False}

    def list(self, *, status: str | None = None, owner: str | None = None) -> list[dict]:
        check(status is None or status in TRANSITIONS, "Unknown job status")
        check(owner is None or owner in set(ROUTES.values()), "Unknown job owner")
        with self.database.transaction() as connection:
            rows = connection.execute("SELECT * FROM jobs WHERE (? IS NULL OR status=?) AND (? IS NULL OR owner=?) ORDER BY created_at,id", (status, status, owner, owner)).fetchall()
            return [self._public(row) for row in rows]

    def show(self, job_id: str) -> dict:
        with self.database.transaction() as connection:
            result = self._public(self._row(connection, job_id))
            agent_input = connection.execute("SELECT * FROM agent_inputs WHERE job_id=?", (job_id,)).fetchone()
            if agent_input is not None:
                check(hashlib.sha256(agent_input["document_json"].encode()).hexdigest() == agent_input["input_sha"], "Agent input hash mismatch")
                result["agent_input"] = {"agent": agent_input["agent"], "input_sha": agent_input["input_sha"],
                                         "payload": json.loads(agent_input["document_json"])}
            result["events"] = [dict(row) for row in connection.execute("SELECT * FROM job_events WHERE job_id=? ORDER BY id", (job_id,))]
            result["approvals"] = [dict(row) for row in connection.execute("SELECT * FROM approvals WHERE job_id=? ORDER BY id", (job_id,))]
            return result
