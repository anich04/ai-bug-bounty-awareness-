# AI Bug Bounty Awareness

Phase 3 of an authorized security workflow engine. Five built-in offline agents now run through the persistent job system: Scout, Mapper, Crawler, Validator and Reporter. They process supplied data under versioned contracts with recorded runs and approval-gated handoffs. No targets are contacted, no security tools run and no AI provider is called yet.

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

`init` preserves an existing recognized database and upgrades schema versions 1, 2 or 3 to version 4 transactionally. Unknown schemas are rejected. `doctor` returns exit status 1 for failed checks and never initializes a missing database. It writes a health event to the local log. CLI output is JSON; errors go to stderr. Exit status 0 means success, 1 means blocked/error, 2 means malformed CLI usage, and 3 means waiting for human approval.

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

## Run offline agents

```text
python -m abh agents list
python -m abh agents show scout
python -m abh agents enqueue scout http://localhost:8080/ --program local-lab --input configs/agents/scout.example.json
python -m abh jobs show JOB_ID
python -m abh jobs approve JOB_ID
python -m abh agents run-next scout
python -m abh agents runs --job JOB_ID
python -m abh agents handoff JOB_ID --to mapper --input configs/agents/mapper.example.json
```

Replace `JOB_ID` with the actual job ID. The policy must explicitly allow the agent's action (`review_policy` for Scout); the ambiguous lab template is deliberately blocked. `jobs show` displays the stored agent input before approval. Handoffs also wait for new approval. See [agent contracts and charters](docs/agents.md) for all five input formats, required actions and current capabilities.

## Safety and status

`DRY_RUN=true` and `REQUIRE_HUMAN_APPROVAL=true` remain mandatory. Production mode and non-SQLite backends are rejected. Built-in agents perform deterministic offline processing; networking, shell execution, target testing and external integrations do not exist yet. Dispatch rechecks the current policy and approval and reserves budget atomically. These checks are not reusable live-execution permits. Future tool adapters must bind them to the actual request and enforce transport/DNS safeguards. No real API keys belong in source or logs.

See [architecture](docs/architecture.md), [configuration](docs/configuration.md), [development](docs/development.md) and [Phase 3 status](docs/phase-3.md). Earlier phase records remain historical documentation.
