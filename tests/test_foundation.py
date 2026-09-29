import contextlib
import io
import json
import logging
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from abh.cli import main
from abh.config import ConfigError, Settings
from abh.database import DatabaseError, create_database
from abh.logging import JsonFormatter


class FoundationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        for handler in logging.getLogger("abh").handlers[:]:
            handler.close()
            logging.getLogger("abh").removeHandler(handler)
        self.temporary.cleanup()

    def settings(self, **values):
        return Settings.load(self.root, values)

    def cli(self, command, env=None):
        output, errors = io.StringIO(), io.StringIO()
        with patch.dict("os.environ", env or {}, clear=True), contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            status = main(["--root", str(self.root), command])
        return status, json.loads(output.getvalue() or errors.getvalue())

    def test_safe_defaults(self):
        settings = self.settings()
        self.assertTrue(settings.dry_run)
        self.assertTrue(settings.require_human_approval)
        self.assertEqual(settings.environment, "development")

    def test_env_precedence_and_quotes(self):
        (self.root / ".env").write_text('ABH_ENV="test"\nLOG_LEVEL=DEBUG\n', encoding="utf-8")
        settings = self.settings(LOG_LEVEL="WARNING")
        self.assertEqual(settings.log_level, "WARNING")
        self.assertEqual(settings.environment, "test")

    def test_invalid_env_reports_line_not_value(self):
        (self.root / ".env").write_text("SECRET confidential\n", encoding="utf-8")
        with self.assertRaisesRegex(ConfigError, "line 1"):
            self.settings()

    def test_unsafe_or_invalid_settings_rejected(self):
        for values in ({"DRY_RUN": "false"}, {"REQUIRE_HUMAN_APPROVAL": "false"},
                       {"DRY_RUN": "yes"}, {"LOG_LEVEL": "oops"}, {"ABH_ENV": "production"}):
            with self.subTest(values=values), self.assertRaises(ConfigError):
                self.settings(**values)

    def test_unsupported_database_rejected_without_credentials(self):
        status, result = self.cli("init", {"DATABASE_URL": "postgresql://user:SECRET@example/db"})
        self.assertEqual(status, 1)
        self.assertNotIn("SECRET", json.dumps(result))

    def test_database_requires_persistent_file(self):
        for value in ("sqlite:///", "sqlite:///:memory:", "sqlite:///db?mode=rw"):
            with self.subTest(value=value), self.assertRaises(ConfigError):
                create_database(self.settings(DATABASE_URL=value))

    def test_doctor_does_not_create_missing_database(self):
        status, result = self.cli("doctor")
        self.assertEqual(status, 1)
        self.assertFalse(result["checks"]["database"]["ok"])
        self.assertFalse((self.root / "data/abh.db").exists())

    def test_init_idempotent_persistent_and_doctor(self):
        for _ in range(2):
            self.assertEqual(self.cli("init")[0], 0)
        database = create_database(self.settings())
        self.assertTrue(database.health()["ok"])
        connection = sqlite3.connect(self.root / "data/abh.db")
        try:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0], 6)
        finally:
            connection.close()
        status, result = self.cli("doctor")
        self.assertEqual(status, 0)
        self.assertFalse(result["execution_enabled"])

    def test_unknown_schema_is_preserved(self):
        database = create_database(self.settings())
        database.initialize()
        connection = sqlite3.connect(database.path)
        connection.execute("PRAGMA user_version = 99")
        connection.close()
        with self.assertRaises(DatabaseError):
            database.initialize()
        self.assertFalse(database.health()["ok"])

    def test_foreign_database_not_modified(self):
        database = create_database(self.settings())
        database.path.parent.mkdir(parents=True)
        connection = sqlite3.connect(database.path)
        connection.execute("CREATE TABLE existing (value TEXT)")
        connection.commit()
        connection.close()
        with self.assertRaises(DatabaseError):
            database.initialize()

    def test_corrupt_database_fails_cleanly(self):
        path = self.root / "data/abh.db"
        path.parent.mkdir(parents=True)
        path.write_bytes(b"invalid database" * 20)
        status, result = self.cli("doctor")
        self.assertEqual(status, 1)
        self.assertFalse(result["ok"])

    def test_config_and_logs_do_not_expose_secrets(self):
        status, result = self.cli("config", {"KIMI_API_KEY": "SECRET-123"})
        self.assertEqual(status, 0)
        logs = (self.root / "data/abh.jsonl").read_text()
        self.assertNotIn("SECRET-123", logs + json.dumps(result))
        event = json.loads(logs.splitlines()[-1])
        self.assertEqual(event["correlation_id"], result["correlation_id"])
        for key in ("actor", "event", "timestamp", "reason", "target", "scope_decision", "action", "result"):
            self.assertIn(key, event)

    def test_formatter_ignores_arbitrary_message_and_extra(self):
        record = logging.LogRecord("test", logging.INFO, "", 1, "SECRET", (), None)
        record.api_key = "SECRET"
        self.assertNotIn("SECRET", JsonFormatter().format(record))

    def test_logging_path_failure_returns_failure(self):
        (self.root / "blocked").write_text("file")
        status, result = self.cli("init", {"LOG_FILE": "blocked/log.jsonl"})
        self.assertEqual(status, 1)
        self.assertFalse(result["ok"])


if __name__ == "__main__":
    unittest.main()
