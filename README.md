# AI Bug Bounty Awareness

Phase 2 of an authorized security workflow engine. This release includes persistent jobs, fixed agent routing, human approval, worker leases, retries, cancellation and emergency stop, built on the scope/policy engine. Job execution is a dry-run simulation: no targets are tested and no security tools run.

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

`init` preserves an existing recognized database and upgrades schema versions 1 or 2 to version 3 transactionally. Unknown schemas are rejected. `doctor` returns exit status 1 for failed checks and never initializes a missing database. It writes a health event to the local log. CLI output is JSON; errors go to stderr. Exit status 0 means success, 1 means blocked/error, 2 means malformed CLI usage, and 3 means waiting for human approval.

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

## Manage dry-run jobs

After importing a policy reflecting your actual authorized lab:

```text
python -m abh jobs create http://localhost:8080/ --program local-lab --action probe_http --method HEAD --key first-check
python -m abh jobs list
python -m abh jobs show JOB_ID
python -m abh jobs approve JOB_ID
python -m abh jobs run-next --owner mapper
python -m abh orchestrator status
python -m abh emergency-stop
python -m abh orchestrator resume
```

Replace `JOB_ID` with the ID from `jobs create`. An ambiguous or excluded policy produces a terminal blocked job that cannot be approved. A permitted job waits for explicit approval, then `run-next` simulates its outcome. `succeeded` means the simulation completed; it does not mean a vulnerability was found or a request was sent. Resume does not restart cancelled jobs.

See [jobs and orchestration](docs/jobs.md) for routing, retries, cancellation, leases, audit history and current limits.

## Safety and status

`DRY_RUN=true` and `REQUIRE_HUMAN_APPROVAL=true` remain mandatory. Production mode and non-SQLite backends are rejected. No agent runtimes, networking, shell execution, target testing or external integrations exist yet. Dry-run dispatch rechecks the current policy and approval and reserves budget atomically. These checks are not reusable live-execution permits. Future tool adapters must bind them to the actual request and enforce transport/DNS safeguards. No real API keys belong in source or logs.

See [architecture](docs/architecture.md), [configuration](docs/configuration.md), [development](docs/development.md) and [Phase 2 status](docs/phase-2.md). The [Phase 0](docs/phase-0.md) and [Phase 1](docs/phase-1.md) records are retained as historical documentation.
