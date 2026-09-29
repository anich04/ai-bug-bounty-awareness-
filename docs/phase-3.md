# Phase 3 — Agent Framework

Implemented a fixed registry, explicit charters, bounded versioned input/output contracts, a base agent protocol/runtime, and five deterministic offline handlers: Scout, Mapper, Crawler, Validator and Reporter. Added persistent inputs and per-attempt runs, output hashing, and structured approval-gated handoffs with preserved lineage. Tester, Evidence and Monitor remain deferred.

## Files created and changed

Created `abh/agent_contracts.py`, `abh/agents.py`, `abh/agent_runtime.py`, `tests/test_agents.py`, five `configs/agents/*.example.json` inputs, `docs/agents.md` and this record.

Updated the database migration to schema 4; job claims, completion boundaries, handoff creation and input inspection; policy action vocabulary for policy review/report drafting; CLI agent commands; package version to 0.4.0; existing migration tests; and current documentation. Historical phase records are preserved. No runtime dependencies were added.

## Verification

Full automated suite: **96 passed, 0 failed** (70 prior tests plus 26 agent tests). Coverage includes each handler, input contract rejection, approval gating, dispatcher separation, persisted outputs, corrupted input rejection, unsupported output rejection, exact report questions, sanitized failures and retries, stale policy/cancellation during processing, lease recovery, idempotent and concurrent handoffs, rollback, migration preservation and CLI agent lifecycle. An end-to-end test runs all five agents through four persisted handoffs, with separate approval at every step, and finishes with an explicitly incomplete report scaffold.

Local `init` successfully upgraded the existing database to schema 4; `doctor` confirmed healthy storage, dry-run and human approval enabled, and live execution disabled. The whitespace check passed. GitHub synchronization is verified against the published commit during delivery. All tests use synthetic inputs and temporary local databases; none contact security-testing targets.

## Remaining work and risks

Next: **Phase 4 — Data + Evidence**. Asset/endpoint/finding/evidence/report objects and durable evidence artifacts have not been built yet. Current agents process only supplied data: there are no actual discovery/crawling requests, AI model calls, verified vulnerability findings or report submissions. The full platform is not complete.

Contracts and local hashes are not a security sandbox or signed audit trail. Actor labels remain local, and there is no remote authentication, background daemon or provider timeout layer. Linux/Kali, PostgreSQL and live integrations are **NOT VERIFIED**. The fixed handlers are intentionally conservative until the later evidence, tooling and model layers exist.
