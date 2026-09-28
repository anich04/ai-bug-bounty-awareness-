"""Local-only configuration, storage and policy checks; no execution tools."""

import argparse
import json
from pathlib import Path
import sqlite3
import sys
from uuid import uuid4

from . import __version__
from .config import ConfigError, Settings
from .database import DatabaseError, create_database
from .logging import configure_logging, record_event
from .policy import PolicyError, load_program
from .programs import ProgramStore
from .scope import ScopeGuard


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="abh", description="AI Bug Bounty Awareness - Phase 1")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="Workspace containing .env and local data")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="Initialize local database safely and idempotently")
    commands.add_parser("doctor", help="Check configuration, log output and initialized database")
    commands.add_parser("config", help="Show non-secret effective configuration")
    programs = commands.add_parser("programs", help="Manage explicit local authorization policies")
    program_commands = programs.add_subparsers(dest="program_command", required=True)
    importer = program_commands.add_parser("import", help="Import a JSON policy; does not verify external authorization")
    importer.add_argument("file", type=Path)
    importer.add_argument("--replace", action="store_true")
    program_commands.add_parser("list")
    show = program_commands.add_parser("show")
    show.add_argument("program_id")
    show.add_argument("--revision", help="Inspect a historical revision; scope checks always use the current policy")
    scope = commands.add_parser("scope", help="Evaluate policy without executing or reserving requests")
    scope_commands = scope.add_subparsers(dest="scope_command", required=True)
    check = scope_commands.add_parser("check")
    check.add_argument("target")
    check.add_argument("--program", required=True)
    check.add_argument("--action", required=True)
    check.add_argument("--method", help="Explicit uppercase HTTP method when applicable")
    check.add_argument("--redirect", help="Evaluate an observed redirect Location after checking the source")
    args = parser.parse_args(argv)
    logger = None
    correlation_id = str(uuid4())
    try:
        settings = Settings.load(args.root)
        database = create_database(settings)
        logger = configure_logging(settings)
        if args.command == "init":
            database.initialize()
            result = {"ok": True, "message": "Local database initialized", "phase": 1}
        elif args.command == "doctor":
            health = database.health()
            result = {"ok": health["ok"], "checks": {
                "configuration": True, "log_file": True, "database": health,
                "dry_run": settings.dry_run, "require_human_approval": settings.require_human_approval},
                "execution_enabled": False}
        elif args.command == "programs":
            store = ProgramStore(database)
            if args.program_command == "import":
                # Read at most the policy limit, never an unbounded attachment.
                with args.file.open(encoding="utf-8-sig") as source:
                    program = load_program(source.read(1_000_001))
                store.save(program, replace=args.replace, correlation_id=correlation_id)
                result = {"ok": True, "program_id": program.id, "policy_revision": program.revision}
            elif args.program_command == "list":
                result = {"ok": True, "programs": store.list()}
            else:
                program = store.get(args.program_id, revision=args.revision)
                result = {"ok": True, "program": json.loads(program.document), "policy_revision": program.revision}
        elif args.command == "scope":
            guard = ScopeGuard(ProgramStore(database), require_all_approvals=settings.require_human_approval)
            if args.redirect is not None:
                result = guard.check_redirect(args.program, args.target, args.redirect, args.action, method=args.method, correlation_id=correlation_id)
            else:
                result = guard.check(args.program, args.target, args.action, method=args.method, correlation_id=correlation_id)
        else:
            result = {"ok": True, "environment": settings.environment,
                      "dry_run": settings.dry_run, "require_human_approval": settings.require_human_approval,
                      "database_backend": "sqlite", "log_level": settings.log_level, "phase": 1}
        result["correlation_id"] = correlation_id
        record_event(logger, args.command, "ok" if result["ok"] else "failed", correlation_id)
        print(json.dumps(result, indent=2))
        return 3 if result.get("status") == "WAITING_FOR_HUMAN_APPROVAL" else (0 if result["ok"] else 1)
    except (ConfigError, DatabaseError, PolicyError, UnicodeError, OSError, sqlite3.Error) as error:
        if logger:
            record_event(logger, args.command, "failed", correlation_id)
        # Raw exception strings may contain credentials or private paths.
        reason = str(error) if isinstance(error, (ConfigError, DatabaseError, PolicyError)) else "Local storage or policy text unavailable; check paths, permissions, encoding and database integrity"
        print(json.dumps({"ok": False, "error": reason, "correlation_id": correlation_id}), file=sys.stderr)
        return 1
