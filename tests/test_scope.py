import contextlib
from concurrent.futures import ThreadPoolExecutor
import io
import json
import logging
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from abh.cli import main
from abh.config import Settings
from abh.database import create_database
from abh.policy import PolicyError, Program, load_program, normalize_target
from abh.programs import ProgramStore
from abh.scope import (RateLimiter, ScopeGuard, action_is_allowed, rate_limit_allows,
                       requires_human_approval, target_is_in_scope)

NOW = 1_790_000_000.0


def policy():
    return {
        "id": "test-lab", "name": "Synthetic policy",
        "authorization_status": "confirmed", "authorization_source": "Unit test fixture only",
        "valid_until": "2099-01-01T00:00:00Z",
        "scope": [
            {"id": "web", "effect": "include", "host": "example.test", "schemes": ["https"], "ports": [443], "path_prefix": "/app"},
            {"id": "subdomains", "effect": "include", "host": "*.lab.test"},
            {"id": "private", "effect": "exclude", "host": "example.test", "path_prefix": "/app/private"},
            {"id": "third-party", "effect": "exclude", "host": "vendor.lab.test"}
        ],
        "actions": [
            {"action": "probe_http", "allowed": True, "requires_approval": False, "methods": ["HEAD", "GET"]},
            {"action": "resolve_dns", "allowed": True, "requires_approval": False},
            {"action": "state_change", "allowed": True, "requires_approval": False, "methods": ["POST"]},
            {"action": "report_submission", "allowed": False, "requires_approval": True}
        ],
        "rate_limit": {"requests": 3, "window_seconds": 60}
    }


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.program = Program.from_dict(policy())

    def test_case_terminal_dot_and_default_port(self):
        target = normalize_target("HTTPS://EXAMPLE.TEST./app?a=SECRET")
        self.assertEqual(target.display, "https://example.test:443/app")
        self.assertTrue(target_is_in_scope(self.program, target, now=NOW).allowed)

    def test_url_constraints_and_path_boundaries(self):
        for target, expected in (("https://example.test/app", True), ("https://example.test/app/item", True),
                                 ("https://example.test/apple", False), ("https://example.test/APP", False),
                                 ("http://example.test/app", False), ("https://example.test:8443/app", False),
                                 ("example.test", False), ("example.test:443", False)):
            with self.subTest(target=target):
                self.assertEqual(target_is_in_scope(self.program, target, now=NOW).allowed, expected)

    def test_exclusions_override_all_inclusions(self):
        for target in ("https://example.test/app/private", "https://example.test/app/private/child",
                       "https://example.test/app/PRIVATE", "vendor.lab.test", "https://vendor.lab.test/"):
            with self.subTest(target=target):
                result = target_is_in_scope(self.program, target, now=NOW)
                self.assertFalse(result.allowed)
                self.assertEqual(result.reason, "explicit_exclusion")

    def test_wildcard_label_boundaries_and_apex(self):
        for target, expected in (("one.lab.test", True), ("one.two.lab.test", True), ("lab.test", False),
                                 ("evillab.test", False), ("one.lab.test.evil.test", False)):
            with self.subTest(target=target):
                self.assertEqual(target_is_in_scope(self.program, target, now=NOW).allowed, expected)

    def test_ip_never_inherits_hostname_authorization(self):
        for target in ("127.0.0.1", "https://127.0.0.1/app", "[::1]", "https://[::1]/app"):
            self.assertFalse(target_is_in_scope(self.program, target, now=NOW).allowed)

    def test_explicit_ipv4_ipv6_and_punycode(self):
        data = policy()
        data["scope"] = [{"id": "ip4", "effect": "include", "host": "127.0.0.1"},
                         {"id": "ip6", "effect": "include", "host": "::1"},
                         {"id": "idn", "effect": "include", "host": "xn--bcher-kva.test"}]
        program = Program.from_dict(data)
        for target in ("https://127.0.0.1:8443/", "http://[0:0:0:0:0:0:0:1]/", "xn--bcher-kva.test"):
            self.assertTrue(target_is_in_scope(program, target, now=NOW).allowed)

    def test_malformed_and_ambiguous_targets_fail_closed(self):
        targets = ("", " example.test", "https://example.test\n/app", "https://user:secret@example.test/app",
                   "https://example.test\\@evil.test/app", "https://example.test/app/../app/private",
                   "https://example.test/app/%70rivate", "https://example.test/app/%252e%252e",
                   "https://example.test/app//private", "https://example.test/app/private.",
                   "https://example.test/app/private;x", "https://example.test/app#x",
                   "https://example.test:0/app", "https://example.test:65536/app", "https://example.test:/app",
                   "https://example.test:abc/app", "file://example.test/app", "//example.test/app",
                   "https://exämple.test/app", "https://example.test../app", "https://%65xample.test/app",
                   "https://[fe80::1%25eth0]/", "https://[::1]evil/app", "https://[::1].evil/app",
                   "2130706433", "0177.0.0.1", "127.1", "0x7f000001")
        for target in targets:
            with self.subTest(target=target):
                self.assertFalse(target_is_in_scope(self.program, target, now=NOW).allowed)

    def test_missing_components_cannot_evade_constrained_exclusion(self):
        data = policy()
        data["scope"].append({"id": "sensitive-path", "effect": "exclude", "host": "node.lab.test", "schemes": ["https"], "ports": [443], "path_prefix": "/secret"})
        program = Program.from_dict(data)
        self.assertFalse(target_is_in_scope(program, "node.lab.test", now=NOW).allowed)
        self.assertTrue(target_is_in_scope(program, "http://node.lab.test/public", now=NOW).allowed)

    def test_ambiguous_and_expired_authorization(self):
        data = policy()
        data["authorization_status"] = "ambiguous"
        self.assertEqual(target_is_in_scope(Program.from_dict(data), "one.lab.test", now=NOW).reason, "ambiguous_authorization")
        self.assertEqual(target_is_in_scope(self.program, "one.lab.test", now=self.program.valid_until).reason, "expired_policy")
        self.assertFalse(target_is_in_scope(self.program, "one.lab.test", now=float("nan")).allowed)

    def test_actions_and_methods_are_explicit(self):
        for action, method in (("shell", None), ("collect_urls", "GET"), ("report_submission", None),
                               ("probe_http", "POST"), ("probe_http", None), ("probe_http", "get"), ("resolve_dns", "FOO")):
            with self.subTest(action=action, method=method):
                self.assertFalse(action_is_allowed(self.program, action, method).allowed)
        self.assertTrue(action_is_allowed(self.program, "probe_http", "HEAD").allowed)

    def test_sensitive_actions_always_need_approval(self):
        self.assertTrue(requires_human_approval(self.program, "probe_http", "HEAD"))
        self.assertFalse(requires_human_approval(self.program, "probe_http", "HEAD", require_all=False))
        for action, method in (("state_change", "POST"), ("high_volume", None), ("report_submission", None),
                               ("sensitive_account", None), ("probe_http", "DELETE"), ("unknown", None)):
            self.assertTrue(requires_human_approval(self.program, action, method, require_all=False))

    def test_invalid_policy_fields_and_types(self):
        mutations = [lambda p: p.update(unrecognized=True), lambda p: p.update(id="../bad"),
                     lambda p: p.update(authorization_source=""), lambda p: p.update(valid_until="2099-01-01"),
                     lambda p: p["rate_limit"].update(requests=True), lambda p: p["rate_limit"].update(window_seconds=0),
                     lambda p: p["scope"][0].update(ports=[True]), lambda p: p["scope"][0].update(schemes=[]),
                     lambda p: p["scope"][0].update(host="*example.test"), lambda p: p["scope"][0].update(host="*.127.0.0.1"),
                     lambda p: p["scope"][0].update(path_prefix="/app/.."), lambda p: p["scope"][0].update(ports=None),
                     lambda p: p["actions"][0].update(allowed="true"), lambda p: p["actions"][0].update(action="bash"),
                     lambda p: p["actions"].append(p["actions"][0]), lambda p: p["scope"].append(p["scope"][0])]
        for index, mutate in enumerate(mutations):
            data = policy()
            mutate(data)
            with self.subTest(case=index), self.assertRaises(PolicyError):
                Program.from_dict(data)

    def test_duplicate_json_and_malformed_documents(self):
        for text in ('{"id":"a","id":"b"}', "{", "null", "[]", "x" * 1_000_001):
            with self.assertRaises(PolicyError):
                load_program(text)


class StoredPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.database = create_database(Settings.load(self.root, {}))
        self.database.initialize()
        self.store = ProgramStore(self.database)
        self.program = Program.from_dict(policy())
        self.store.save(self.program)
        self.guard = ScopeGuard(self.store)

    def tearDown(self):
        for handler in logging.getLogger("abh").handlers[:]:
            handler.close()
            logging.getLogger("abh").removeHandler(handler)
        self.temp.cleanup()

    def reserve(self, now=NOW, consume=True):
        return RateLimiter(self.store).reserve(self.program.id, now=now, consume=consume)

    def check(self, target="https://example.test/app", **kwargs):
        return self.guard.check(self.program.id, target, "probe_http", method="HEAD", now=NOW, **kwargs)

    def cli(self, args):
        output, error = io.StringIO(), io.StringIO()
        with patch.dict("os.environ", {}, clear=True), contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            status = main(["--root", str(self.root)] + args)
        return status, json.loads(output.getvalue() or error.getvalue())

    def test_persistence_requires_explicit_replacement(self):
        self.assertEqual(self.store.get(self.program.id), self.program)
        with self.assertRaises(PolicyError):
            self.store.save(self.program)
        data = policy()
        data["scope"][0]["ports"] = [8443]
        new = Program.from_dict(data)
        self.store.save(new, replace=True)
        self.assertNotEqual(self.store.get(new.id).revision, self.program.revision)
        self.assertEqual(self.store.get(new.id, revision=self.program.revision), self.program)
        self.assertEqual(self.check()["status"], "BLOCKED")

    def test_waiting_approval_never_means_execution(self):
        result = self.check()
        self.assertEqual(result["status"], "WAITING_FOR_HUMAN_APPROVAL")
        self.assertFalse(result["execution_enabled"])
        self.assertEqual(result["policy_revision"], self.program.revision)
        with self.database.transaction() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM rate_events").fetchone()[0], 0)

    def test_denied_action_or_scope_cannot_be_approved(self):
        for target in ("https://example.test/app/private", "https://unknown.test/"):
            result = self.check(target)
            self.assertEqual(result["status"], "BLOCKED")
            self.assertEqual(result["rate_limit"]["reason"], "not_evaluated")
        result = self.guard.check(self.program.id, "https://example.test/app", "report_submission", now=NOW)
        self.assertEqual(result["status"], "BLOCKED")

    def test_unknown_program_and_tampered_policy_fail_closed(self):
        with self.assertRaises(PolicyError):
            self.guard.check("unknown", "example.test", "resolve_dns", now=NOW)
        with self.database.transaction(write=True) as connection:
            connection.execute("UPDATE programs SET authorization_source='modified'")
        with self.assertRaises(PolicyError):
            self.check()

    def test_http_actions_require_url(self):
        self.assertEqual(self.check("node.lab.test")["reason"], "http_action_requires_url")

    def test_redirects_are_independently_checked(self):
        for location, expected in (("/app/other", "WAITING_FOR_HUMAN_APPROVAL"),
                                   ("https://evil.test/", "BLOCKED"), ("//vendor.lab.test/", "BLOCKED"),
                                   ("/app/private", "BLOCKED"), ("http://example.test/app", "BLOCKED"),
                                   ("../app/other", "BLOCKED"), ("/app/%70rivate", "BLOCKED"),
                                   (" https://example.test/app", "BLOCKED"), ("javascript:alert(1)", "BLOCKED")):
            with self.subTest(location=location):
                result = self.guard.check_redirect(self.program.id, "https://example.test/app", location,
                                                   "probe_http", method="HEAD", now=NOW)
                self.assertEqual(result["status"], expected)
        self.assertEqual(self.guard.check_redirect(self.program.id, "https://unknown.test/", "/app", "probe_http", method="HEAD", now=NOW)["status"], "BLOCKED")

    def test_sliding_window_boundary_and_persistence(self):
        for instant in (NOW, NOW + 10, NOW + 20):
            self.assertTrue(self.reserve(instant).allowed)
        self.assertFalse(self.reserve(NOW + 59).allowed)
        self.assertTrue(self.reserve(NOW + 60).allowed)
        recreated = ProgramStore(create_database(Settings.load(self.root, {})))
        with recreated.database.transaction(write=True) as connection:
            self.assertFalse(rate_limit_allows(connection, recreated.get(self.program.id), now=NOW + 60, consume=True).allowed)

    def test_budget_is_program_wide_and_edits_do_not_reset_it(self):
        for _ in range(3):
            self.reserve()
        data = policy()
        data["name"] = "Renamed"
        self.store.save(Program.from_dict(data), replace=True)
        self.assertFalse(self.reserve().allowed)
        result = self.guard.check(self.program.id, "node.lab.test", "resolve_dns", now=NOW)
        self.assertEqual(result["reason"], "rate_limit_exceeded")

    def test_peek_and_clock_rollback(self):
        for _ in range(5):
            self.assertTrue(self.reserve(consume=False).allowed)
        self.assertEqual(self.reserve(NOW - 1).reason, "clock_moved_backwards")
        self.assertFalse(self.reserve(float("inf")).allowed)

    def test_concurrent_reservations_do_not_overrun_budget(self):
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: self.reserve().allowed, range(20)))
        self.assertEqual(sum(results), 3)

    def test_transaction_rollback_does_not_consume_budget(self):
        with self.assertRaises(RuntimeError):
            with self.database.transaction(write=True) as connection:
                rate_limit_allows(connection, self.program, now=NOW, consume=True)
                raise RuntimeError("simulate failed operation")
        for _ in range(3):
            self.assertTrue(self.reserve().allowed)

    def test_audit_contains_decision_but_no_query_secret(self):
        result = self.check("https://example.test/app?token=VERY_SECRET", correlation_id="test-correlation")
        self.assertNotIn("VERY_SECRET", json.dumps(result))
        with self.database.transaction() as connection:
            rows = [dict(row) for row in connection.execute("SELECT * FROM audit_logs")]
        self.assertNotIn("VERY_SECRET", json.dumps(rows))
        self.assertEqual(rows[-1]["target_host"], "example.test")
        self.assertEqual(rows[-1]["correlation_id"], "test-correlation")
        self.assertEqual(rows[-1]["decision"], "WAITING_FOR_HUMAN_APPROVAL")

    def test_cli_exit_codes_and_import(self):
        source = self.root / "policy.json"
        source.write_text(json.dumps(policy()), encoding="utf-8")
        self.assertEqual(self.cli(["programs", "import", str(source)])[0], 1)
        self.assertEqual(self.cli(["programs", "import", str(source), "--replace"])[0], 0)
        self.assertEqual(self.cli(["programs", "list"])[0], 0)
        self.assertEqual(self.cli(["programs", "show", self.program.id])[0], 0)
        base = ["scope", "check", "https://example.test/app", "--program", self.program.id, "--action", "probe_http", "--method", "HEAD"]
        self.assertEqual(self.cli(base)[0], 3)
        self.assertEqual(self.cli(base + ["--redirect", "https://evil.test/"])[0], 1)
        self.assertEqual(self.cli(["scope", "check", "https://unknown.test/", "--program", self.program.id, "--action", "probe_http", "--method", "HEAD"])[0], 1)

    def test_cli_invalid_document_is_clean_error(self):
        source = self.root / "bad.json"
        source.write_text('{"id":"SECRET", "id":"SECRET"}', encoding="utf-8")
        status, result = self.cli(["programs", "import", str(source)])
        self.assertEqual(status, 1)
        self.assertNotIn("SECRET", json.dumps(result))


class MigrationTests(unittest.TestCase):
    def test_phase_zero_migration_preserves_existing_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            database = create_database(Settings.load(Path(temporary), {}))
            database.path.parent.mkdir(parents=True)
            with contextlib.closing(sqlite3.connect(database.path)) as connection:
                connection.execute("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
                connection.execute("INSERT INTO schema_migrations VALUES (1, 'original-timestamp')")
                connection.execute("PRAGMA user_version=1")
                connection.commit()
            database.initialize()
            database.initialize()
            self.assertEqual(database.health()["schema_version"], 3)
            with database.transaction() as connection:
                self.assertEqual(connection.execute("SELECT applied_at FROM schema_migrations WHERE version=1").fetchone()[0], "original-timestamp")

    def test_failed_migration_rolls_back_all_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            database = create_database(Settings.load(Path(temporary), {}))
            database.path.parent.mkdir(parents=True)
            with contextlib.closing(sqlite3.connect(database.path)) as connection:
                connection.executescript("CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT); INSERT INTO schema_migrations VALUES(1, 'original'); PRAGMA user_version=1; CREATE TABLE scope_rules(original TEXT);")
            with self.assertRaises(sqlite3.Error):
                database.initialize()
            with contextlib.closing(sqlite3.connect(database.path)) as connection:
                self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 1)
                self.assertIsNone(connection.execute("SELECT name FROM sqlite_master WHERE name='programs'").fetchone())


if __name__ == "__main__":
    unittest.main()
