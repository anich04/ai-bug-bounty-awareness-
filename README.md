# AI Bug Bounty Awareness

An authorized security workflow engine with passive traffic analysis (version 0.11). Import Burp captures and detect evidence-backed candidates for credentialed CORS, session-cookie weaknesses, exposed configuration, external redirects and server traces. Candidates include reasoning, original request/response evidence and validation steps. The project also includes strict local scope policy, approval-gated jobs, offline agent contracts, immutable evidence storage and a loopback-only dashboard. Target execution remains disabled: the analyzer inspects existing captures without contacting targets or AI providers.

## Detect candidates from traffic

Open **Analyze traffic** in the dashboard to import and analyze Burp XML. The program policy must explicitly allow `analyze_http`; findings remain unvalidated until human review. From the CLI:

```text
python -m abh burp import traffic.xml --program YOUR_PROGRAM
python -m abh analysis run IMPORT_RECORD_ID
python -m abh analysis report ANALYSIS_RECORD_ID assessment.md
```

For a separate synthetic learning workspace:

```text
python -m abh --root /path/to/training-workspace init
python -m abh --root /path/to/training-workspace analysis demo
python -m abh --root /path/to/training-workspace dashboard --port 8767
```

The demo detects five patterns in synthetic fixtures and rejects three controls. It makes no network requests and represents no live-target findings. See [traffic analysis and limitations](docs/traffic-analysis.md).

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

`init` preserves an existing recognized database and upgrades schema versions 1 through 6 to version 7 transactionally. Unknown schemas are rejected. `doctor` returns exit status 1 for failed checks and never initializes a missing database. It writes a health event to the local log. CLI output is JSON; errors go to stderr. Exit status 0 means success, 1 means blocked/error, 2 means malformed CLI usage, and 3 means waiting for human approval.

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

See [architecture](docs/architecture.md), [configuration](docs/configuration.md), [development](docs/development.md) and [the Phase 9 dashboard record](docs/phase-9.md). Earlier phase records remain historical documentation.


## Data and evidence

Use `python -m abh data --help` to import, list, inspect, trace and export local objects. See [the data and evidence guide](docs/data-evidence.md) for payload examples and the workflow. Original evidence bytes are stored atomically in the ignored local SQLite database, with a 10 MiB limit per artifact. Findings remain unvalidated candidates and reports remain drafts.

## Controlled Kali adapters

Use `python -m abh tools list` to inspect the initial adapters and [the tool-layer guide](docs/kali-tools.md) for enqueue, approval, dry-run processing and artifact export. This phase supports DNS A lookup plans and HTTP HEAD plans. Optional supplied captures are parsed offline and explicitly marked unverified.

Actual execution inside the Kali VM is NOT VERIFIED and is disabled. Burp Community XML import and passive local traffic analysis are available.


## Burp Community

Phase 6 adds supported XML traffic import, existing issue import and byte-preserving evidence exports. See [the Burp guide](docs/phase-6.md). No live Burp connection or scanner execution is claimed.


## Model providers

Phase 7 adds configurable provider contracts and offline response/usage ingestion. All providers default to disabled; no paid or live calls are made. See [model setup and limitations](docs/phase-7.md).


## Finding review

Phase 8 adds human validation, duplicate-candidate checks, snapshot-bound report preparation and approval without submission. See [the finding workflow](docs/phase-8.md).


## Local dashboard

Phase 9 adds a private loopback dashboard for reviewing the local workspace:

```text
python -m abh dashboard
```

Open the printed `127.0.0.1` URL. The dashboard displays programs, scope, data objects, evidence, jobs, integrations, model status, findings and reports. It can approve or reject local jobs, trigger emergency stop/resume, review candidate findings, preview original evidence and approve reports locally. It never submits a report or makes live target/model/tool requests. See [the dashboard record](docs/phase-9.md).
