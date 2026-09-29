"""Local-only configuration, storage and policy checks; no execution tools."""

import argparse
import json
from pathlib import Path
import sqlite3
import sys
from uuid import uuid4

from . import __version__
from .data import DataError
from .data_cli import register as register_data, dispatch as dispatch_data
from .config import ConfigError, Settings
from .database import DatabaseError, create_database
from .logging import configure_logging, record_event
from .policy import PolicyError, load_program
from .programs import ProgramStore
from .scope import ScopeGuard
from .jobs import JobError, JobQueue, ROUTES, TRANSITIONS
from .agent_contracts import ContractError, REGISTRY, charter, load_input
from .agent_runtime import AgentRuntime


def job_result(job: dict | None) -> dict:
    if job is None:
        return {"ok": True, "status": "idle", "job": None, "execution_enabled": False}
    return {"ok": job["status"] not in {"blocked", "failed", "rejected"},
            "status": job["status"], "job": job, "execution_enabled": False}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="abh", description="AI Bug Bounty Awareness - Phase 4")
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
    jobs = commands.add_parser("jobs", help="Persistent dry-run job orchestration")
    job_commands = jobs.add_subparsers(dest="job_command", required=True)
    create = job_commands.add_parser("create")
    create.add_argument("target")
    create.add_argument("--program", required=True)
    create.add_argument("--action", required=True, choices=sorted(ROUTES))
    create.add_argument("--method")
    create.add_argument("--source", default="human")
    create.add_argument("--max-attempts", type=int, default=3)
    create.add_argument("--key", help="Optional idempotency key scoped to this program")
    listing = job_commands.add_parser("list")
    listing.add_argument("--status", choices=sorted(TRANSITIONS))
    listing.add_argument("--owner", choices=sorted(set(ROUTES.values())))
    for verb in ("show", "approve", "reject", "cancel"):
        command = job_commands.add_parser(verb)
        command.add_argument("job_id")
        if verb != "show":
            command.add_argument("--actor", default="local-human")
    run = job_commands.add_parser("run-next", help="Simulate a routed job; never invokes tools or network")
    run.add_argument("--owner", required=True, choices=sorted(set(ROUTES.values())))
    run.add_argument("--worker", default="local-worker")
    run.add_argument("--outcome", choices=("success", "transient_failure", "permanent_failure"), default="success")
    job_commands.add_parser("recover", help="Recover expired worker leases")
    job_commands.add_parser("routes", help="Show job routing metadata")
    agents = commands.add_parser("agents", help="Built-in offline agent framework")
    agent_commands = agents.add_subparsers(dest="agent_command", required=True)
    agent_commands.add_parser("list")
    describe = agent_commands.add_parser("show")
    describe.add_argument("agent", choices=sorted(REGISTRY))
    enqueue = agent_commands.add_parser("enqueue")
    enqueue.add_argument("agent", choices=sorted(REGISTRY))
    enqueue.add_argument("target")
    enqueue.add_argument("--program", required=True)
    enqueue.add_argument("--input", type=Path, required=True)
    enqueue.add_argument("--key")
    execute = agent_commands.add_parser("run-next")
    execute.add_argument("agent", choices=sorted(REGISTRY))
    execute.add_argument("--worker", default="local-agent-worker")
    handoff = agent_commands.add_parser("handoff")
    handoff.add_argument("job_id")
    handoff.add_argument("--to", required=True, choices=sorted(REGISTRY))
    handoff.add_argument("--input", type=Path, required=True)
    runs = agent_commands.add_parser("runs")
    runs.add_argument("--job")
    run_details = agent_commands.add_parser("run-show")
    run_details.add_argument("run_id")
    stop = commands.add_parser("emergency-stop", help="Persistently stop new work and cancel active dry-run jobs")
    stop.add_argument("--actor", default="local-human")
    engine = commands.add_parser("orchestrator")
    engine_commands = engine.add_subparsers(dest="engine_command", required=True)
    engine_commands.add_parser("status")
    resume = engine_commands.add_parser("resume", help="Explicitly resume admission; cancelled jobs remain cancelled")
    resume.add_argument("--actor", default="local-human")
    register_data(commands)
    args = parser.parse_args(argv)
    logger = None
    correlation_id = str(uuid4())
    try:
        settings = Settings.load(args.root)
        database = create_database(settings)
        logger = configure_logging(settings)
        if args.command == "init":
            database.initialize()
            result = {"ok": True, "message": "Local database initialized", "phase": 4}
        elif args.command == "doctor":
            health = database.health()
            result = {"ok": health["ok"], "checks": {
                "configuration": True, "log_file": True, "database": health,
                "dry_run": settings.dry_run, "require_human_approval": settings.require_human_approval},
                "execution_enabled": False}
            if health["ok"]:
                result["checks"]["orchestrator"] = JobQueue(database).status()
        elif args.command == "data":
            result = dispatch_data(args, database)
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
        elif args.command == "jobs":
            queue = JobQueue(database)
            if args.job_command == "create":
                result = job_result(queue.create(args.program, args.target, args.action, method=args.method,
                                    source_agent=args.source, max_attempts=args.max_attempts, idempotency_key=args.key))
            elif args.job_command == "list":
                result = {"ok": True, "jobs": queue.list(status=args.status, owner=args.owner)}
            elif args.job_command == "show":
                result = job_result(queue.show(args.job_id))
            elif args.job_command in {"approve", "reject"}:
                result = job_result(queue.review(args.job_id, approve=args.job_command == "approve", actor=args.actor))
            elif args.job_command == "cancel":
                result = job_result(queue.cancel(args.job_id, actor=args.actor))
            elif args.job_command == "run-next":
                result = job_result(queue.run_next(args.owner, args.worker, outcome=args.outcome))
            elif args.job_command == "recover":
                result = {"ok": True, "recovered_jobs": queue.recover()}
            else:
                result = {"ok": True, "routes": ROUTES, "implemented_offline_agents": sorted(REGISTRY)}
        elif args.command == "agents":
            runtime = AgentRuntime(JobQueue(database))
            if args.agent_command == "list":
                result = {"ok": True, "agents": [definition.describe() for definition in REGISTRY.values()],
                          "deferred_agents": ["tester", "evidence", "monitor"], "execution_enabled": False}
            elif args.agent_command == "show":
                result = {"ok": True, "agent": charter(args.agent).describe()}
            elif args.agent_command in {"enqueue", "handoff"}:
                owner = args.agent if args.agent_command == "enqueue" else args.to
                with args.input.open(encoding="utf-8-sig") as source:
                    payload = load_input(owner, source.read(131073))
                result = job_result(runtime.enqueue(owner, args.program, args.target, payload, idempotency_key=args.key)
                                    if args.agent_command == "enqueue" else runtime.handoff(args.job_id, owner, payload))
            elif args.agent_command == "run-next":
                result = job_result(runtime.run_next(args.agent, args.worker))
            elif args.agent_command == "runs":
                result = {"ok": True, "runs": runtime.runs(job_id=args.job)}
            else:
                result = {"ok": True, "run": runtime.show_run(args.run_id)}
        elif args.command == "emergency-stop":
            result = {"ok": True, **JobQueue(database).emergency_stop(actor=args.actor)}
        elif args.command == "orchestrator":
            queue = JobQueue(database)
            result = {"ok": True, **(queue.resume(actor=args.actor) if args.engine_command == "resume" else queue.status())}
        else:
            result = {"ok": True, "environment": settings.environment,
                      "dry_run": settings.dry_run, "require_human_approval": settings.require_human_approval,
                      "database_backend": "sqlite", "log_level": settings.log_level, "phase": 4}
        result["correlation_id"] = correlation_id
        record_event(logger, args.command, "ok" if result["ok"] else "failed", correlation_id)
        print(json.dumps(result, indent=2))
        return 3 if result.get("status") in {"WAITING_FOR_HUMAN_APPROVAL", "waiting_human"} else (0 if result["ok"] else 1)
    except (ConfigError, DatabaseError, PolicyError, JobError, ContractError, DataError, UnicodeError, OSError, sqlite3.Error) as error:
        if logger:
            record_event(logger, args.command, "failed", correlation_id)
        # Raw exception strings may contain credentials or private paths.
        reason = str(error) if isinstance(error, (ConfigError, DatabaseError, PolicyError, JobError, ContractError, DataError)) else "Local storage or policy text unavailable; check paths, permissions, encoding and database integrity"
        print(json.dumps({"ok": False, "error": reason, "correlation_id": correlation_id}), file=sys.stderr)
        return 1
