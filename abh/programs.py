"""Transactional policy storage and traceable local policy decisions."""

import json
from uuid import uuid4

from .database import Database
from .policy import PolicyError, Program, require


class ProgramStore:
    def __init__(self, database: Database):
        self.database = database

    def save(self, program: Program, *, replace: bool = False, correlation_id: str | None = None) -> None:
        # Validate even if a caller manually constructed the dataclass.
        program = Program.from_dict(json.loads(program.document))
        document = json.loads(program.document)
        with self.database.transaction(write=True) as connection:
            existing = connection.execute("SELECT revision FROM programs WHERE id=?", (program.id,)).fetchone()
            require(existing is None or replace, "Program exists; explicit --replace is required")
            connection.execute("INSERT INTO programs VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET name=excluded.name, authorization_status=excluded.authorization_status, authorization_source=excluded.authorization_source, valid_until=excluded.valid_until, revision=excluded.revision",
                               (program.id, program.name, program.authorization_status, program.authorization_source, document["valid_until"], program.revision))
            connection.execute("INSERT OR IGNORE INTO policy_revisions(program_id,revision,document_json) VALUES (?,?,?)",
                               (program.id, program.revision, program.document))
            connection.execute("DELETE FROM scope_rules WHERE program_id=?", (program.id,))
            connection.execute("DELETE FROM action_policies WHERE program_id=?", (program.id,))
            for index, rule in enumerate(document["scope"]):
                connection.execute("INSERT INTO scope_rules VALUES (?, ?, ?, ?)", (program.id, rule["id"], json.dumps(rule), index))
            for index, action in enumerate(document["actions"]):
                connection.execute("INSERT INTO action_policies VALUES (?, ?, ?, ?)", (program.id, action["action"], json.dumps(action), index))
            connection.execute("INSERT INTO rate_limits VALUES (?, ?, ?) ON CONFLICT(program_id) DO UPDATE SET requests=excluded.requests, window_seconds=excluded.window_seconds", (program.id, program.requests, program.window_seconds))
            self.audit(connection, program, "policy_import", "stored", "explicit_local_policy_import", correlation_id or str(uuid4()))

    @staticmethod
    def read(connection, program_id: str) -> Program:
        row = connection.execute("SELECT * FROM programs WHERE id=?", (program_id,)).fetchone()
        require(row is not None, "Unknown program; authorization is blocked")
        rate = connection.execute("SELECT requests, window_seconds FROM rate_limits WHERE program_id=?", (program_id,)).fetchone()
        require(rate is not None, "Missing rate policy; authorization is blocked")
        try:
            document = {key: row[key] for key in ("id", "name", "authorization_status", "authorization_source", "valid_until")}
            document["scope"] = [json.loads(item[0]) for item in connection.execute("SELECT rule_json FROM scope_rules WHERE program_id=? ORDER BY ordinal", (program_id,))]
            document["actions"] = [json.loads(item[0]) for item in connection.execute("SELECT policy_json FROM action_policies WHERE program_id=? ORDER BY ordinal", (program_id,))]
            document["rate_limit"] = dict(rate)
            program = Program.from_dict(document)
        except (ValueError, TypeError, RecursionError):
            raise PolicyError("Stored policy is invalid; authorization is blocked") from None
        require(program.revision == row["revision"], "Stored policy revision mismatch; authorization is blocked")
        return program

    def get(self, program_id: str, *, revision: str | None = None) -> Program:
        with self.database.transaction() as connection:
            if revision is not None:
                row = connection.execute("SELECT document_json FROM policy_revisions WHERE program_id=? AND revision=?", (program_id, revision)).fetchone()
                require(row is not None, "Unknown policy revision")
                from .policy import load_program
                program = load_program(row[0])
                require(program.id == program_id and program.revision == revision, "Stored policy revision mismatch")
                return program
            return self.read(connection, program_id)

    def list(self) -> list[dict]:
        with self.database.transaction() as connection:
            return [dict(row) for row in connection.execute("SELECT id, name, authorization_status, valid_until, revision FROM programs ORDER BY id")]

    @staticmethod
    def audit(connection, program: Program, event: str, decision: str, reason: str,
              correlation_id: str, target_host: str | None = None, action: str | None = None) -> None:
        connection.execute("INSERT INTO audit_logs(actor,event,program_id,revision,target_host,action,decision,reason,correlation_id) VALUES (?,?,?,?,?,?,?,?,?)",
                           ("local_cli", event, program.id, program.revision, target_host, action,
                            decision, reason, correlation_id))
