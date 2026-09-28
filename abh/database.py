"""Storage boundary and transactional migrations. SQLite development backend."""

from pathlib import Path
from typing import Protocol
from contextlib import contextmanager
import sqlite3

from .config import ConfigError, Settings

SCHEMA_VERSION = 2

PHASE_ONE_SCHEMA = (
    "CREATE TABLE programs (id TEXT PRIMARY KEY, name TEXT NOT NULL, authorization_status TEXT NOT NULL, authorization_source TEXT NOT NULL, valid_until TEXT NOT NULL, revision TEXT NOT NULL)",
    "CREATE TABLE policy_revisions (program_id TEXT NOT NULL REFERENCES programs(id), revision TEXT NOT NULL, document_json TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(program_id, revision))",
    "CREATE TABLE scope_rules (program_id TEXT NOT NULL REFERENCES programs(id), id TEXT NOT NULL, rule_json TEXT NOT NULL, ordinal INTEGER NOT NULL, PRIMARY KEY(program_id, id))",
    "CREATE TABLE action_policies (program_id TEXT NOT NULL REFERENCES programs(id), action TEXT NOT NULL, policy_json TEXT NOT NULL, ordinal INTEGER NOT NULL, PRIMARY KEY(program_id, action))",
    "CREATE TABLE rate_limits (program_id TEXT PRIMARY KEY REFERENCES programs(id), requests INTEGER NOT NULL CHECK(requests > 0), window_seconds INTEGER NOT NULL CHECK(window_seconds > 0))",
    "CREATE TABLE rate_state (program_id TEXT PRIMARY KEY REFERENCES programs(id), last_seen REAL NOT NULL)",
    "CREATE TABLE rate_events (id INTEGER PRIMARY KEY, program_id TEXT NOT NULL REFERENCES programs(id), at REAL NOT NULL)",
    "CREATE INDEX rate_events_program_time ON rate_events(program_id, at)",
    "CREATE TABLE audit_logs (id INTEGER PRIMARY KEY, at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, actor TEXT NOT NULL, event TEXT NOT NULL, program_id TEXT NOT NULL, revision TEXT NOT NULL, target_host TEXT, action TEXT, decision TEXT NOT NULL, reason TEXT NOT NULL, correlation_id TEXT NOT NULL)",
)


class DatabaseError(RuntimeError):
    pass


class Database(Protocol):
    def initialize(self) -> None: ...
    def health(self) -> dict: ...
    def transaction(self, *, write: bool = False): ...


class SQLiteDatabase:
    def __init__(self, path: Path):
        self.path = path.resolve()

    @contextmanager
    def transaction(self, *, write: bool = False):
        if not self.path.is_file():
            raise DatabaseError("Database missing; run init")
        connection = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True, timeout=5)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            self._check_schema(connection)
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=5)
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("BEGIN IMMEDIATE")
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version not in {0, 1, SCHEMA_VERSION}:
                raise DatabaseError("Unsupported database schema version")
            if version == 0:
                tables = connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall()
                if tables:
                    raise DatabaseError("Refusing to initialize an unrecognized database")
                connection.execute("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)")
                connection.execute("INSERT INTO schema_migrations(version) VALUES (1)")
                connection.execute("PRAGMA user_version = 1")
                version = 1
            else:
                self._check_schema(connection, version)
            if version == 1:
                for statement in PHASE_ONE_SCHEMA:
                    connection.execute(statement)
                connection.execute("INSERT INTO schema_migrations(version, applied_at) VALUES (2, CURRENT_TIMESTAMP)")
                connection.execute("PRAGMA user_version = 2")
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _check_schema(connection: sqlite3.Connection, expected: int = SCHEMA_VERSION) -> None:
        versions = connection.execute("SELECT version FROM schema_migrations ORDER BY version").fetchall()
        if [row[0] for row in versions] != list(range(1, expected + 1)) or connection.execute("PRAGMA user_version").fetchone()[0] != expected:
            raise DatabaseError("Database migration history is inconsistent")
        if expected == 2:
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if not {"programs", "policy_revisions", "scope_rules", "action_policies", "rate_limits", "rate_state", "rate_events", "audit_logs"} <= tables:
                raise DatabaseError("Database schema is incomplete")

    def health(self) -> dict:
        if not self.path.is_file():
            return {"ok": False, "reason": "Database missing; run init"}
        connection = sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True, timeout=5)
        try:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version != SCHEMA_VERSION:
                return {"ok": False, "reason": "Unsupported database schema version"}
            self._check_schema(connection)
            if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                return {"ok": False, "reason": "Database integrity check failed"}
            return {"ok": True, "backend": "sqlite", "schema_version": version}
        finally:
            connection.close()


def create_database(settings: Settings) -> Database:
    prefix = "sqlite:///"
    if not settings.database_url.startswith(prefix):
        raise ConfigError("Unsupported database backend; development implements SQLite only")
    value = settings.database_url[len(prefix):]
    if not value or value == ":memory:" or "?" in value or "#" in value:
        raise ConfigError("DATABASE_URL must reference a persistent SQLite file")
    path = Path(value)
    return SQLiteDatabase(path if path.is_absolute() else settings.root / path)
