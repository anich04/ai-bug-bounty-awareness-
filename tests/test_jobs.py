import contextlib
from concurrent.futures import ThreadPoolExecutor
import io
import json
import logging
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from abh.cli import main
from abh.config import Settings
from abh.database import create_database
from abh.jobs import JobError, JobQueue
from abh.policy import PolicyError, Program
from abh.programs import ProgramStore
from test_scope import NOW, policy


class JobTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.database = create_database(Settings.load(self.root, {}))
        self.database.initialize()
        self.store = ProgramStore(self.database)
        data = policy()
        data["rate_limit"]["requests"] = 100
        self.program = Program.from_dict(data)
        self.store.save(self.program)
        self.now = NOW
        self.queue = JobQueue(self.database, clock=lambda: self.now)

    def tearDown(self):
        for handler in logging.getLogger("abh").handlers[:]:
            handler.close()
            logging.getLogger("abh").removeHandler(handler)
        self.temp.cleanup()

    def create(self, **kwargs):
        return self.queue.create(self.program.id, "https://example.test/app", "probe_http", method="HEAD", **kwargs)

    def ready(self, **kwargs):
        row = self.create(**kwargs)
        return self.queue.review(row["id"], approve=True)

    def claim(self, worker="test-worker"):
        return self.queue.claim("mapper", worker)

    def finish(self, row, outcome="success"):
        return self.queue.finish(row["id"], row["worker"], row["lease_token"], outcome=outcome)

    def replace_policy(self, **values):
        data = json.loads(self.program.document)
        data.update(values)
        self.store.save(Program.from_dict(data), replace=True)

    def cli(self, arguments):
        output, errors = io.StringIO(), io.StringIO()
        with patch.dict("os.environ", {}, clear=True), contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            status = main(["--root", str(self.root)] + arguments)
        return status, json.loads(output.getvalue() or errors.getvalue())

    def test_creation_routing_and_persistence(self):
        job = self.create(source_agent="scout")
        self.assertEqual(job["owner"], "mapper")
        self.assertEqual(job["status"], "waiting_human")
        self.assertIsNone(self.claim())
        again = JobQueue(self.database).show(job["id"])
        self.assertEqual(again["source_agent"], "scout")
        self.assertEqual(again["events"][0]["event"], "created")
        self.assertEqual(again["policy_revision"], self.program.revision)

    def test_blocked_scope_cannot_be_reviewed_into_permission(self):
        job = self.queue.create(self.program.id, "https://example.test/app/private", "probe_http", method="HEAD")
        self.assertEqual(job["status"], "blocked")
        self.assertEqual(job["reason"], "explicit_exclusion")
        with self.assertRaises(JobError):
            self.queue.review(job["id"], approve=True)
        self.assertIsNone(self.claim())

    def test_invalid_job_inputs(self):
        for kwargs in ({"source_agent": "unknown"}, {"max_attempts": 0}, {"max_attempts": True}, {"idempotency_key": "../x"}):
            with self.subTest(kwargs=kwargs), self.assertRaises((JobError, PolicyError)):
                self.create(**kwargs)
        with self.assertRaises(JobError):
            self.queue.create(self.program.id, "https://example.test/app?key=SECRET", "probe_http", method="HEAD")
        with self.assertRaises(JobError):
            self.queue.create(self.program.id, "https://example.test/app", "arbitrary_shell")
        with self.assertRaises(PolicyError):
            self.queue.create("unknown", "https://example.test/app", "probe_http", method="HEAD")
        self.assertEqual(self.queue.list(), [])

    def test_idempotency_key_reuses_exact_request_only(self):
        first = self.create(idempotency_key="request-1")
        second = self.create(idempotency_key="request-1")
        self.assertEqual(first["id"], second["id"])
        with self.assertRaises(JobError):
            self.create(idempotency_key="request-1", max_attempts=4)
        self.assertEqual(len(self.queue.show(first["id"])["events"]), 1)

    def test_concurrent_idempotent_enqueue(self):
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda _: self.create(idempotency_key="same-request")["id"], range(12)))
        self.assertEqual(len(set(results)), 1)

    def test_approval_bound_to_job_and_policy_then_dry_run(self):
        job = self.ready()
        self.assertEqual(job["status"], "queued")
        completed = self.queue.run_next("mapper", "worker-1")
        self.assertEqual(completed["id"], job["id"])
        self.assertEqual(completed["status"], "succeeded")
        self.assertEqual(completed["result"]["kind"], "dry_run_simulation")
        self.assertFalse(completed["result"]["tool_executed"])
        self.assertFalse(completed["result"]["report_submitted"])
        details = self.queue.show(job["id"])
        self.assertEqual([event["to_status"] for event in details["events"]], ["waiting_human", "queued", "running", "succeeded"])
        self.assertEqual(details["approvals"][0]["policy_revision"], job["policy_revision"])
        self.assertEqual(len({event["correlation_id"] for event in details["events"]}), 1)

    def test_human_rejection_is_terminal(self):
        job = self.create()
        self.assertEqual(self.queue.review(job["id"], approve=False)["status"], "rejected")
        with self.assertRaises(JobError):
            self.queue.review(job["id"], approve=True)
        self.assertIsNone(self.claim())

    def test_owner_routing_and_worker_fencing(self):
        self.ready()
        self.assertIsNone(self.queue.claim("crawler", "wrong-owner"))
        job = self.claim()
        with self.assertRaises(JobError):
            self.queue.finish(job["id"], "another-worker", job["lease_token"])
        with self.assertRaises(JobError):
            self.queue.finish(job["id"], job["worker"], "wrong-token")
        self.assertNotIn("lease_token", self.queue.show(job["id"]))
        self.assertEqual(self.finish(job)["status"], "succeeded")
        with self.assertRaises(JobError):
            self.finish(job)

    def test_concurrent_workers_claim_a_job_once(self):
        self.ready()
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda i: self.claim(f"worker-{i}"), range(16)))
        self.assertEqual(sum(row is not None for row in results), 1)

    def test_global_concurrency_limit_is_persistent(self):
        for _ in range(5):
            self.ready()
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda i: JobQueue(self.database, clock=lambda: self.now).claim("mapper", f"worker-{i}"), range(8)))
        claimed = [row for row in results if row]
        self.assertEqual(len(claimed), 2)
        self.assertEqual(len({row["id"] for row in claimed}), 2)
        self.finish(claimed[0])
        self.assertIsNotNone(self.claim("next-worker"))

    def test_retry_backoff_and_bounded_attempts(self):
        self.ready(max_attempts=2)
        first = self.claim()
        failed = self.finish(first, "transient_failure")
        self.assertEqual(failed["status"], "retry_wait")
        self.assertEqual(failed["available_at"], NOW + 5)
        self.assertIsNone(self.claim())
        self.now += 5
        second = self.claim()
        self.assertEqual(second["attempts"], 2)
        self.assertEqual(self.finish(second, "transient_failure")["status"], "failed")
        self.now += 100
        self.assertIsNone(self.claim())

    def test_permanent_failure_does_not_retry(self):
        self.ready(max_attempts=5)
        job = self.claim()
        result = self.finish(job, "permanent_failure")
        self.assertEqual(result["status"], "failed")
        self.assertIsNone(self.claim())

    def test_worker_restart_lease_expiry_and_late_result(self):
        self.ready()
        first = self.claim()
        self.now += 30
        restarted = JobQueue(self.database, clock=lambda: self.now)
        self.assertEqual(restarted.recover(), [first["id"]])
        self.assertEqual(restarted.show(first["id"])["status"], "retry_wait")
        with self.assertRaises(JobError):
            self.finish(first)
        self.now += 5
        next_attempt = self.claim()
        self.assertNotEqual(first["lease_token"], next_attempt["lease_token"])
        with self.assertRaises(JobError):
            self.finish(first)
        self.assertEqual(self.finish(next_attempt)["status"], "succeeded")

    def test_heartbeat_extends_lease(self):
        self.ready()
        job = self.claim()
        self.now += 20
        beat = self.queue.heartbeat(job["id"], job["worker"], job["lease_token"])
        self.assertEqual(beat["lease_until"], NOW + 50)
        self.now += 15
        self.assertEqual(self.queue.recover(), [])
        self.assertEqual(self.finish(job)["status"], "succeeded")

    def test_expired_lease_cannot_heartbeat(self):
        self.ready(max_attempts=1)
        job = self.claim()
        self.now += 30
        with self.assertRaises(JobError):
            self.queue.heartbeat(job["id"], job["worker"], job["lease_token"])
        self.queue.recover()
        self.assertEqual(self.queue.show(job["id"])["status"], "failed")

    def test_cancel_running_job_rejects_late_completion(self):
        self.ready()
        job = self.claim()
        self.assertEqual(self.queue.cancel(job["id"])["status"], "cancelled")
        with self.assertRaises(JobError):
            self.finish(job)
        self.assertIsNone(self.claim())

    def test_policy_change_invalidates_waiting_approval(self):
        job = self.create()
        self.replace_policy(name="Updated policy")
        result = self.queue.review(job["id"], approve=True)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["reason"], "policy_changed_create_new_job")

    def test_policy_change_before_dispatch_revokes_job(self):
        job = self.ready()
        self.replace_policy(authorization_status="ambiguous")
        self.assertIsNone(self.claim())
        self.assertEqual(self.queue.show(job["id"])["status"], "blocked")
        with self.database.transaction() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM rate_events").fetchone()[0], 0)

    def test_policy_change_before_completion_does_not_publish_success(self):
        self.ready()
        job = self.claim()
        self.replace_policy(name="Revised")
        result = self.finish(job)
        self.assertEqual(result["status"], "blocked")
        self.assertIsNone(result["result"])

    def test_expired_policy_blocks_dispatch(self):
        job = self.ready()
        self.now = self.program.valid_until
        self.assertIsNone(self.claim())
        self.assertEqual(self.queue.show(job["id"])["reason"], "expired_policy")

    def test_missing_approval_record_fails_closed(self):
        job = self.ready()
        with self.database.transaction(write=True) as connection:
            connection.execute("DELETE FROM approvals WHERE job_id=?", (job["id"],))
        self.assertIsNone(self.claim())
        self.assertEqual(self.queue.show(job["id"])["reason"], "missing_bound_approval")

    def test_rate_deferral_does_not_spend_attempts(self):
        self.replace_policy(rate_limit={"requests": 1, "window_seconds": 60})
        self.ready()
        self.queue.run_next("mapper", "worker-1")
        second = self.ready()
        self.assertIsNone(self.claim())
        details = self.queue.show(second["id"])
        self.assertEqual(details["status"], "queued")
        self.assertEqual(details["reason"], "rate_limit_exceeded")
        self.assertEqual(details["attempts"], 0)
        self.now += 60
        self.assertEqual(self.queue.run_next("mapper", "worker-2")["id"], second["id"])

    def test_claim_failure_rolls_back_budget_state_and_event(self):
        job = self.ready()
        with patch.object(self.queue, "_event", side_effect=RuntimeError("audit failure")):
            with self.assertRaises(RuntimeError):
                self.claim()
        self.assertEqual(self.queue.show(job["id"])["status"], "queued")
        with self.database.transaction() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM rate_events").fetchone()[0], 0)
        self.assertIsNotNone(self.claim())

    def test_emergency_stop_cancels_active_jobs_and_persists(self):
        self.create()
        self.ready()
        first = self.claim()
        self.ready()
        second = self.claim("worker-2")
        self.finish(second, "transient_failure")
        self.ready()
        stopped = self.queue.emergency_stop()
        self.assertEqual(stopped["cancelled_jobs"], 4)
        self.assertTrue(JobQueue(self.database).status()["stopped"])
        self.assertTrue(all(row["status"] == "cancelled" for row in self.queue.list()))
        for operation in (self.create, self.claim, lambda: self.finish(first)):
            with self.assertRaises(JobError):
                operation()
        self.queue.resume()
        self.assertFalse(self.queue.status()["stopped"])
        self.assertIsNone(self.claim())
        self.ready()
        self.assertIsNotNone(self.claim())

    def test_clock_rollback_blocks_work_but_not_stop_or_cancel(self):
        job = self.ready()
        self.now -= 10
        with self.assertRaises(JobError):
            self.claim()
        self.assertEqual(self.queue.cancel(job["id"])["status"], "cancelled")
        self.assertTrue(self.queue.emergency_stop()["stopped"])
        with self.assertRaises(JobError):
            self.queue.resume()

    def test_cli_job_lifecycle_and_engine_status(self):
        code, result = self.cli(["jobs", "create", "https://example.test/app", "--program", self.program.id, "--action", "probe_http", "--method", "HEAD"])
        self.assertEqual(code, 3)
        job_id = result["job"]["id"]
        self.assertEqual(self.cli(["jobs", "approve", job_id])[0], 0)
        code, result = self.cli(["jobs", "run-next", "--owner", "mapper"])
        self.assertEqual(code, 0)
        self.assertEqual(result["job"]["status"], "succeeded")
        self.assertEqual(self.cli(["jobs", "show", job_id])[0], 0)
        self.assertEqual(self.cli(["jobs", "list", "--status", "succeeded"])[0], 0)
        self.assertEqual(self.cli(["jobs", "routes"])[0], 0)
        self.assertEqual(self.cli(["jobs", "recover"])[0], 0)
        self.assertEqual(self.cli(["emergency-stop"])[0], 0)
        self.assertTrue(self.cli(["orchestrator", "status"])[1]["stopped"])
        self.assertEqual(self.cli(["orchestrator", "resume"])[0], 0)

    def test_v2_to_v3_migration_preserves_policies_and_usage(self):
        with self.database.transaction(write=True) as connection:
            connection.execute("INSERT INTO rate_events(program_id,at) VALUES (?,?)", (self.program.id, NOW))
            for table in ("tool_artifacts", "tool_runs", "tool_inputs", "report_evidence", "evidence_artifacts", "artifacts", "data_objects", "agent_handoffs", "agent_runs", "agent_inputs", "approvals", "job_events", "jobs", "engine_control", "engine_events"):
                connection.execute("DROP TABLE " + table)
            connection.execute("DELETE FROM schema_migrations WHERE version>=3")
            connection.execute("PRAGMA user_version=2")
        self.database.initialize()
        self.assertEqual(self.store.get(self.program.id), self.program)
        self.assertFalse(self.queue.status()["stopped"])
        with self.database.transaction() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM rate_events").fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
