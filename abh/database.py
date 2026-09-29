"""Storage boundary and transactional migrations. SQLite development backend."""

from pathlib import Path
from typing import Protocol
from contextlib import contextmanager
import sqlite3

from .config import ConfigError, Settings

SCHEMA_VERSION = 5

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

PHASE_TWO_SCHEMA = (
    """CREATE TABLE jobs (
        id TEXT PRIMARY KEY, program_id TEXT NOT NULL REFERENCES programs(id),
        source_agent TEXT NOT NULL, owner TEXT NOT NULL, type TEXT NOT NULL,
        target TEXT NOT NULL, method TEXT, policy_revision TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('waiting_human','queued','running','retry_wait','succeeded','failed','cancelled','blocked','rejected')),
        reason TEXT NOT NULL, created_at REAL NOT NULL, updated_at REAL NOT NULL,
        available_at REAL NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
        max_attempts INTEGER NOT NULL CHECK(max_attempts BETWEEN 1 AND 5),
        worker TEXT, lease_token TEXT, lease_until REAL, approval_revision TEXT,
        idempotency_key TEXT, fingerprint TEXT NOT NULL, correlation_id TEXT NOT NULL,
        result_json TEXT, UNIQUE(program_id, idempotency_key))""",
    "CREATE INDEX jobs_dispatch ON jobs(owner,status,available_at,created_at)",
    """CREATE TABLE job_events (
        id INTEGER PRIMARY KEY, job_id TEXT NOT NULL REFERENCES jobs(id),
        at REAL NOT NULL, actor TEXT NOT NULL, event TEXT NOT NULL,
        from_status TEXT, to_status TEXT NOT NULL, reason TEXT NOT NULL,
        attempt INTEGER NOT NULL, correlation_id TEXT NOT NULL)""",
    """CREATE TABLE approvals (
        id INTEGER PRIMARY KEY, job_id TEXT NOT NULL REFERENCES jobs(id),
        policy_revision TEXT NOT NULL, decision TEXT NOT NULL CHECK(decision IN ('approved','rejected')),
        actor TEXT NOT NULL, at REAL NOT NULL, correlation_id TEXT NOT NULL)""",
    """CREATE TABLE engine_control (
        id INTEGER PRIMARY KEY CHECK(id=1), stopped INTEGER NOT NULL CHECK(stopped IN (0,1)),
        concurrency_limit INTEGER NOT NULL CHECK(concurrency_limit > 0), last_seen REAL NOT NULL)""",
    "INSERT INTO engine_control VALUES (1,0,2,0)",
    """CREATE TABLE engine_events (
        id INTEGER PRIMARY KEY, at REAL NOT NULL, actor TEXT NOT NULL,
        event TEXT NOT NULL, correlation_id TEXT NOT NULL)""",
)

PHASE_THREE_SCHEMA = (
    """CREATE TABLE agent_inputs (
        job_id TEXT PRIMARY KEY REFERENCES jobs(id), agent TEXT NOT NULL,
        contract_version INTEGER NOT NULL CHECK(contract_version=1),
        document_json TEXT NOT NULL, input_sha TEXT NOT NULL)""",
    """CREATE TABLE agent_runs (
        id TEXT PRIMARY KEY, job_id TEXT NOT NULL REFERENCES jobs(id), attempt INTEGER NOT NULL,
        agent TEXT NOT NULL, worker TEXT NOT NULL, input_sha TEXT NOT NULL,
        status TEXT NOT NULL, reason TEXT NOT NULL, started_at REAL NOT NULL, ended_at REAL,
        output_json TEXT, output_sha TEXT, UNIQUE(job_id,attempt))""",
    """CREATE TABLE agent_handoffs (
        parent_job_id TEXT NOT NULL REFERENCES jobs(id), child_job_id TEXT NOT NULL UNIQUE REFERENCES jobs(id),
        source_agent TEXT NOT NULL, destination_agent TEXT NOT NULL,
        created_at REAL NOT NULL, correlation_id TEXT NOT NULL,
        PRIMARY KEY(parent_job_id,destination_agent))""",
)


PHASE_FOUR_SCHEMA = (
    """CREATE TABLE data_objects (
        id TEXT PRIMARY KEY, program_id TEXT NOT NULL REFERENCES programs(id),
        kind TEXT NOT NULL CHECK(kind IN ('asset','endpoint','observation','finding','evidence','report')),
        parent_id TEXT REFERENCES data_objects(id), policy_revision TEXT NOT NULL,
        document_json TEXT NOT NULL, document_sha TEXT NOT NULL,
        created_at TEXT NOT NULL, FOREIGN KEY(program_id,policy_revision) REFERENCES policy_revisions(program_id,revision))""",
    "CREATE INDEX data_objects_program_kind ON data_objects(program_id,kind)",
    """CREATE TABLE artifacts (
        sha256 TEXT PRIMARY KEY, content BLOB NOT NULL, size INTEGER NOT NULL CHECK(size >= 0))""",
    """CREATE TABLE evidence_artifacts (
        evidence_id TEXT PRIMARY KEY REFERENCES data_objects(id),
        sha256 TEXT NOT NULL REFERENCES artifacts(sha256))""",
    """CREATE TABLE report_evidence (
        report_id TEXT NOT NULL REFERENCES data_objects(id),
        evidence_id TEXT NOT NULL REFERENCES data_objects(id), PRIMARY KEY(report_id,evidence_id))""",
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
            if version not in {0, 1, 2, 3, 4, SCHEMA_VERSION}:
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
                version = 2
            if version == 2:
                for statement in PHASE_TWO_SCHEMA:
                    connection.execute(statement)
                connection.execute("INSERT INTO schema_migrations(version, applied_at) VALUES (3, CURRENT_TIMESTAMP)")
                connection.execute("PRAGMA user_version = 3")
                version = 3
            if version == 3:
                for statement in PHASE_THREE_SCHEMA:
                    connection.execute(statement)
                connection.execute("INSERT INTO schema_migrations(version, applied_at) VALUES (4, CURRENT_TIMESTAMP)")
                connection.execute("PRAGMA user_version = 4")
                version = 4
            if version == 4:
                for statement in PHASE_FOUR_SCHEMA:
                    connection.execute(statement)
                connection.execute("INSERT INTO schema_migrations(version, applied_at) VALUES (5, CURRENT_TIMESTAMP)")
                connection.execute("PRAGMA user_version = 5")
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
        if expected >= 2:
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if not {"programs", "policy_revisions", "scope_rules", "action_policies", "rate_limits", "rate_state", "rate_events", "audit_logs"} <= tables:
                raise DatabaseError("Database schema is incomplete")
            if expected >= 3 and not {"jobs", "job_events", "approvals", "engine_control", "engine_events"} <= tables:
                raise DatabaseError("Database job schema is incomplete")
            if expected >= 4 and not {"agent_inputs", "agent_runs", "agent_handoffs"} <= tables:
                raise DatabaseError("Database agent schema is incomplete")
            if expected >= 5 and not {"data_objects", "artifacts", "evidence_artifacts", "report_evidence"} <= tables:
                raise DatabaseError("Database evidence schema is incomplete")

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
