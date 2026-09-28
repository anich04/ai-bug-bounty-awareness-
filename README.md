# AI Bug Bounty Awareness

Phase 1 of an authorized security workflow engine. This release adds deterministic scope and action checks, persistent program policies, policy history, rate budgets, and approval requirements to the local foundation. It does not test targets or run tools.

## Run locally

Requires Python 3.11 or newer. From this project directory on Windows or Kali:

```text
python -m abh init
python -m abh doctor
python -m abh config
python -m unittest discover -s tests -v
```

No packages or API keys are required for these commands. Optional installation in a virtual environment provides the `abh` command:

```text
python -m venv .venv
```

Windows:

```text
.venv\Scripts\python -m pip install --no-build-isolation -e .
.venv\Scripts\abh doctor
```

Kali:

```text
.venv/bin/python -m pip install --no-build-isolation -e .
.venv/bin/abh doctor
```

Editable installation requires setuptools 68+ in that environment; use the dependency-free module commands if unavailable. Installation may require obtaining setuptools separately.

Copy `.env.example` to `.env` to customize local paths. Defaults work without that file. Environment variables override `.env`. Relative paths resolve against the current directory, or the explicit workspace:

```text
python -m abh --root /path/to/workspace init
python -m abh --root /path/to/workspace doctor
```

`init` preserves an existing recognized database and upgrades Phase 0 schema version 1 to version 2 transactionally. Unknown schemas are rejected. `doctor` returns exit status 1 for failed checks and never initializes a missing database. It writes a health event to the local log. CLI output is JSON; errors go to stderr. Exit status 0 means success, 1 means blocked/error, 2 means malformed CLI usage, and 3 means waiting for human approval.

## Check a local policy

```text
python -m abh init
python -m abh programs import configs/lab-program.example.json
python -m abh programs list
python -m abh programs show local-lab
python -m abh scope check http://localhost:8080/ --program local-lab --action probe_http --method HEAD
```

The example deliberately has ambiguous authorization, so its check returns `BLOCKED`. Make a separate policy file reflecting your actual lab authorization before changing its status to `confirmed`; confirmed policies still return `WAITING_FOR_HUMAN_APPROVAL` for otherwise permitted actions. Neither result runs a request. Policy changes require an explicit `programs import FILE --replace` and retain prior revisions.

See [scope and policy rules](docs/scope-policy.md) for matching rules, redirect checks, rate-budget semantics and JSON fields.

## Safety and status

`DRY_RUN=true` and `REQUIRE_HUMAN_APPROVAL=true` remain mandatory. Production mode and non-SQLite backends are rejected. No agents, networking, shell execution, target testing or external integrations exist yet. Scope decisions are advisory checks of your supplied policy, not reusable execution permits. Future execution adapters must recheck current policy and consume rate budget atomically at dispatch. No real API keys belong in source or logs.

See [architecture](docs/architecture.md), [configuration](docs/configuration.md), [development](docs/development.md) and [Phase 1 status](docs/phase-1.md). The [Phase 0 record](docs/phase-0.md) is retained as historical documentation.
