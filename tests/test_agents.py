import copy
import contextlib
from concurrent.futures import ThreadPoolExecutor
import io
import json
import logging
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from abh.agent_contracts import ContractError, REGISTRY, charter, load_input, validate_input
from abh.agent_runtime import AgentRuntime
from abh.agents import HANDLERS
from abh.cli import main
from abh.config import Settings
from abh.database import create_database
from abh.jobs import JobError, JobQueue
from abh.policy import Program
from abh.programs import ProgramStore
from test_scope import NOW, policy


INPUTS = {
    "scout": {"version": 1, "data": {}},
    "mapper": {"version": 1, "data": {"assets": ["https://example.test/app", "unknown.test", "vendor.lab.test"]}},
    "crawler": {"version": 1, "data": {"urls": ["https://example.test/app/item", "https://example.test/app/private", "node.lab.test"]}},
    "validator": {"version": 1, "data": {"observations": [{"id": "o1", "fact": "A user-supplied response differed", "evidence_refs": ["e1"]}], "hypothesis": "Possible authorization inconsistency"}},
    "reporter": {"version": 1, "data": {"questions": [{"id": "q1", "label": "What are the EXACT steps to reproduce?", "required": True}]}},
}


class AgentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.database = create_database(Settings.load(self.root, {}))
        self.database.initialize()
        self.store = ProgramStore(self.database)
        data = policy()
        data["rate_limit"]["requests"] = 100
        existing = {item["action"] for item in data["actions"]}
        for definition in REGISTRY.values():
            if definition.action not in existing:
                entry = {"action": definition.action, "allowed": True, "requires_approval": True}
                if definition.method:
                    entry["methods"] = [definition.method]
                data["actions"].append(entry)
        self.program = Program.from_dict(data)
        self.store.save(self.program)
        self.now = NOW
        self.queue = JobQueue(self.database, clock=lambda: self.now)
        self.runtime = AgentRuntime(self.queue)

    def tearDown(self):
        for handler in logging.getLogger("abh").handlers[:]:
            handler.close()
            logging.getLogger("abh").removeHandler(handler)
        self.temp.cleanup()

    def enqueue(self, agent="scout", *, ready=False, payload=None):
        job = self.runtime.enqueue(agent, self.program.id, "https://example.test/app", copy.deepcopy(INPUTS[agent]) if payload is None else payload)
        if ready:
            self.queue.review(job["id"], approve=True)
        return job

    def complete(self, agent="scout"):
        self.enqueue(agent, ready=True)
        result = self.runtime.run_next(agent)
        self.assertEqual(result["status"], "succeeded")
        return result

    def cli(self, arguments):
        output, errors = io.StringIO(), io.StringIO()
        with patch.dict("os.environ", {}, clear=True), contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            code = main(["--root", str(self.root)] + arguments)
        return code, json.loads(output.getvalue() or errors.getvalue())

    def test_registry_contains_five_fixed_agents(self):
        self.assertEqual(set(REGISTRY), {"scout", "mapper", "crawler", "validator", "reporter"})
        for name in ("tester", "evidence", "monitor", "arbitrary_module"):
            with self.assertRaises(ContractError):
                charter(name)

    def test_strict_input_contract_versions_fields_and_bounds(self):
        cases = [{"version": True, "data": {}}, {"version": 2, "data": {}},
                 {"version": 1, "data": {}, "command": "run shell"},
                 {"version": 1, "data": {"policy_override": True}}]
        for value in cases:
            with self.assertRaises(ContractError):
                validate_input("scout", value)
        with self.assertRaises(ContractError):
            validate_input("mapper", {"version": 1, "data": {"assets": ["example.test"] * 101}})
        with self.assertRaises(ContractError):
            load_input("scout", '{"version":1,"version":1,"data":{}}')
        with self.assertRaises(ContractError):
            load_input("scout", "x" * 131073)

    def test_agent_job_requires_separate_approval(self):
        job = self.enqueue()
        self.assertIsNone(self.runtime.run_next("scout"))
        self.assertEqual(self.runtime.runs(), [])
        self.assertEqual(self.queue.show(job["id"])["status"], "waiting_human")
        self.assertEqual(self.queue.show(job["id"])["agent_input"]["payload"], INPUTS["scout"])

    def test_legacy_simulator_cannot_consume_agent_job(self):
        job = self.enqueue(ready=True)
        self.assertIsNone(self.queue.run_next("scout", "legacy-worker"))
        claimed = self.queue.claim("scout", "agent-worker", agent_mode=True)
        with self.assertRaises(JobError):
            self.queue.finish(job["id"], "agent-worker", claimed["lease_token"])
        self.queue.heartbeat(job["id"], "agent-worker", claimed["lease_token"])

    def test_runtime_does_not_claim_legacy_job(self):
        job = self.queue.create(self.program.id, "https://example.test/app", "discover_assets")
        self.queue.review(job["id"], approve=True)
        self.assertIsNone(self.runtime.run_next("mapper"))
        self.assertIsNotNone(self.queue.run_next("mapper", "legacy-worker"))

    def test_scout_summarizes_stored_rules_without_expansion(self):
        result = self.complete()["result"]
        source = json.loads(self.program.document)
        self.assertEqual(result["data"]["includes"], [r for r in source["scope"] if r["effect"] == "include"])
        self.assertEqual(result["data"]["exclusions"], [r for r in source["scope"] if r["effect"] == "exclude"])
        self.assertFalse(result["tool_executed"])
        self.assertTrue(result["uncertainty"])

    def test_mapper_rejects_unknown_and_excluded_assets(self):
        result = self.complete("mapper")["result"]["data"]["items"]
        self.assertEqual([item["in_scope"] for item in result], [True, False, False])
        self.assertEqual(result[2]["reason"], "explicit_exclusion")

    def test_crawler_filters_urls_without_fetching(self):
        result = self.complete("crawler")["result"]
        self.assertEqual([item["in_scope"] for item in result["data"]["items"]], [True, False, False])
        self.assertEqual(result["network_requests"], 0)
        self.assertIsNone(result["data"]["items"][2]["target"])

    def test_validator_distinguishes_supplied_facts_and_uncertainty(self):
        result = self.complete("validator")["result"]
        self.assertEqual(result["data"]["status"], "needs_evidence")
        self.assertEqual(result["data"]["supplied_facts"], INPUTS["validator"]["data"]["observations"])
        self.assertEqual(result["data"]["checks"]["reproducible"], "unknown")
        self.assertFalse(result["finding_created"])
        self.assertFalse(result["data"]["checks"]["evidence_sufficient"])

    def test_reporter_preserves_questions_and_leaves_answers_empty(self):
        result = self.complete("reporter")["result"]
        question = result["data"]["questions"][0]
        self.assertEqual(question["label"], INPUTS["reporter"]["data"]["questions"][0]["label"])
        self.assertIsNone(question["answer"])
        self.assertFalse(result["report_submitted"])

    def test_run_history_and_output_hash_persist(self):
        job = self.complete()
        runs = AgentRuntime(JobQueue(self.database)).runs(job_id=job["id"])
        self.assertEqual(len(runs), 1)
        details = self.runtime.show_run(runs[0]["id"])
        self.assertEqual(details["output"], job["result"])
        self.assertEqual(details["status"], "succeeded")
        self.assertEqual(len(details["output_sha"]), 64)

    def test_input_corruption_fails_without_publishing_output(self):
        job = self.enqueue(ready=True)
        with self.database.transaction(write=True) as connection:
            connection.execute("UPDATE agent_inputs SET document_json='{}' WHERE job_id=?", (job["id"],))
        result = self.runtime.run_next("scout")
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["reason"], "invalid_agent_contract")
        self.assertIsNone(self.runtime.show_run(self.runtime.runs()[0]["id"])["output"])

    def test_invalid_output_cannot_claim_execution(self):
        self.enqueue(ready=True)
        original = HANDLERS["scout"].run
        def dishonest(context, payload):
            output = original(context, payload)
            output["tool_executed"] = True
            return output
        with patch.object(HANDLERS["scout"], "run", side_effect=dishonest):
            result = self.runtime.run_next("scout")
        self.assertEqual(result["status"], "failed")
        self.assertIsNone(result["result"])

    def test_reporter_cannot_change_exact_question(self):
        self.enqueue("reporter", ready=True)
        original = HANDLERS["reporter"].run
        def altered(context, payload):
            output = original(context, payload)
            output["data"]["questions"][0]["label"] = "Different question"
            return output
        with patch.object(HANDLERS["reporter"], "run", side_effect=altered):
            self.assertEqual(self.runtime.run_next("reporter")["status"], "failed")

    def test_handler_exception_is_sanitized_and_retryable(self):
        self.enqueue(ready=True)
        with patch.object(HANDLERS["scout"], "run", side_effect=RuntimeError("SECRET-input")):
            result = self.runtime.run_next("scout")
        self.assertEqual(result["status"], "retry_wait")
        self.assertNotIn("SECRET-input", json.dumps(self.runtime.runs()))
        self.now += 5
        result = self.runtime.run_next("scout")
        self.assertEqual(result["status"], "succeeded")
        self.assertEqual([run["attempt"] for run in self.runtime.runs()], [1, 2])

    def test_policy_change_during_handler_discards_output(self):
        self.enqueue(ready=True)
        original = HANDLERS["scout"].run
        def changed(context, payload):
            data = json.loads(self.program.document)
            data["name"] = "Updated"
            self.store.save(Program.from_dict(data), replace=True)
            return original(context, payload)
        with patch.object(HANDLERS["scout"], "run", side_effect=changed):
            result = self.runtime.run_next("scout")
        self.assertEqual(result["status"], "blocked")
        self.assertIsNone(self.runtime.show_run(self.runtime.runs()[0]["id"])["output"])

    def test_emergency_stop_during_handler_discards_output(self):
        self.enqueue(ready=True)
        original = HANDLERS["scout"].run
        def stopped(context, payload):
            self.queue.emergency_stop()
            return original(context, payload)
        with patch.object(HANDLERS["scout"], "run", side_effect=stopped):
            with self.assertRaises(JobError):
                self.runtime.run_next("scout")
        self.assertEqual(self.runtime.runs()[0]["status"], "cancelled")
        self.assertIsNone(self.runtime.show_run(self.runtime.runs()[0]["id"])["output"])

    def test_expired_agent_run_is_closed_on_recovery(self):
        self.enqueue(ready=True)
        self.queue.claim("scout", "worker-1", agent_mode=True)
        self.now += 30
        self.queue.recover()
        self.assertEqual(self.runtime.runs()[0]["status"], "retry_wait")
        self.assertEqual(self.runtime.runs()[0]["ended_at"], self.now)

    def test_handoff_preserves_lineage_and_requires_new_approval(self):
        parent = self.complete()
        child = self.runtime.handoff(parent["id"], "mapper", INPUTS["mapper"])
        duplicate = self.runtime.handoff(parent["id"], "mapper", INPUTS["mapper"])
        self.assertEqual(child["id"], duplicate["id"])
        self.assertEqual(child["source_agent"], "scout")
        self.assertEqual(child["correlation_id"], parent["correlation_id"])
        self.assertEqual(child["status"], "waiting_human")
        self.assertIsNone(self.runtime.run_next("mapper"))
        self.queue.review(child["id"], approve=True)
        self.assertEqual(self.runtime.run_next("mapper")["status"], "succeeded")
        self.assertEqual(len(self.runtime.show_run(self.runtime.runs(job_id=parent["id"])[0]["id"])["handoffs"]), 1)

    def test_complete_five_agent_chain_stays_offline_and_approval_gated(self):
        parent = self.complete("scout")
        correlation = parent["correlation_id"]
        for destination in ("mapper", "crawler", "validator", "reporter"):
            child = self.runtime.handoff(parent["id"], destination, INPUTS[destination])
            self.assertEqual(child["status"], "waiting_human")
            self.assertIsNone(self.runtime.run_next(destination))
            self.queue.review(child["id"], approve=True)
            parent = self.runtime.run_next(destination)
            self.assertEqual(parent["status"], "succeeded")
            self.assertEqual(parent["correlation_id"], correlation)
            self.assertFalse(parent["result"]["tool_executed"])
        self.assertEqual(parent["result"]["data"]["status"], "needs_validated_evidence")
        self.assertEqual(len(self.runtime.runs()), 5)
        with self.database.transaction() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM agent_handoffs").fetchone()[0], 4)

    def test_handoff_blocks_wrong_route_stale_policy_and_changed_input(self):
        parent = self.complete()
        with self.assertRaises(JobError):
            self.runtime.handoff(parent["id"], "reporter", INPUTS["reporter"])
        self.runtime.handoff(parent["id"], "mapper", INPUTS["mapper"])
        with self.assertRaises(JobError):
            self.runtime.handoff(parent["id"], "mapper", {"version": 1, "data": {"assets": []}})
        data = json.loads(self.program.document)
        data["name"] = "Changed"
        self.store.save(Program.from_dict(data), replace=True)
        with self.assertRaises(JobError):
            self.runtime.handoff(parent["id"], "mapper", INPUTS["mapper"])

    def test_incomplete_or_legacy_job_cannot_be_handoff_source(self):
        pending = self.enqueue()
        with self.assertRaises(JobError):
            self.runtime.handoff(pending["id"], "mapper", INPUTS["mapper"])
        old = self.queue.create(self.program.id, "https://example.test/app", "review_policy")
        self.queue.review(old["id"], approve=True)
        self.queue.run_next("scout", "legacy")
        with self.assertRaises(JobError):
            self.runtime.handoff(old["id"], "mapper", INPUTS["mapper"])

    def test_concurrent_handoffs_create_one_child(self):
        parent = self.complete()
        with ThreadPoolExecutor(max_workers=4) as pool:
            ids = list(pool.map(lambda _: self.runtime.handoff(parent["id"], "mapper", INPUTS["mapper"])["id"], range(8)))
        self.assertEqual(len(set(ids)), 1)

    def test_failed_handoff_rolls_back_child_and_contract(self):
        parent = self.complete()
        with patch.object(self.queue, "_event", side_effect=RuntimeError("failed event")):
            with self.assertRaises(RuntimeError):
                self.runtime.handoff(parent["id"], "mapper", INPUTS["mapper"])
        self.assertEqual(len(self.queue.list()), 1)
        with self.database.transaction() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM agent_handoffs").fetchone()[0], 0)

    def test_v3_migration_keeps_legacy_job_and_idempotency(self):
        legacy = self.queue.create(self.program.id, "https://example.test/app", "discover_assets", idempotency_key="legacy")
        with self.database.transaction(write=True) as connection:
            for table in ("tool_artifacts", "tool_runs", "tool_inputs", "report_evidence", "evidence_artifacts", "artifacts", "data_objects", "agent_handoffs", "agent_runs", "agent_inputs"):
                connection.execute("DROP TABLE " + table)
            connection.execute("DELETE FROM schema_migrations WHERE version>=4")
            connection.execute("PRAGMA user_version=3")
        self.database.initialize()
        duplicate = self.queue.create(self.program.id, "https://example.test/app", "discover_assets", idempotency_key="legacy")
        self.assertEqual(duplicate["id"], legacy["id"])
        self.assertEqual(self.database.health()["schema_version"], 6)

    def test_cli_registry_enqueue_run_and_handoff(self):
        source = self.root / "input.json"
        source.write_text(json.dumps(INPUTS["scout"]), encoding="utf-8")
        self.assertEqual(self.cli(["agents", "list"])[0], 0)
        self.assertEqual(self.cli(["agents", "show", "scout"])[0], 0)
        code, result = self.cli(["agents", "enqueue", "scout", "https://example.test/app", "--program", self.program.id, "--input", str(source)])
        self.assertEqual(code, 3)
        job_id = result["job"]["id"]
        self.assertEqual(self.cli(["jobs", "approve", job_id])[0], 0)
        self.assertEqual(self.cli(["agents", "run-next", "scout"])[0], 0)
        code, result = self.cli(["agents", "runs", "--job", job_id])
        self.assertEqual(code, 0)
        self.assertEqual(self.cli(["agents", "run-show", result["runs"][0]["id"]])[0], 0)
        source.write_text(json.dumps(INPUTS["mapper"]), encoding="utf-8")
        self.assertEqual(self.cli(["agents", "handoff", job_id, "--to", "mapper", "--input", str(source)])[0], 3)


if __name__ == "__main__":
    unittest.main()
