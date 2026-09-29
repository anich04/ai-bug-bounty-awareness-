# Phase 2 — job system and orchestrator

Built persistent structured jobs with fixed ownership/routing, a guarded state machine, job-scoped dry-run approval, idempotent enqueue, atomic claims, worker leases and stale-token protection, bounded retries/backoff, cancellation, decision history and persistent emergency stop/resume.

There is one outcome, one owner and one job. No agent runtime, unrestricted callback, shell or network execution was introduced. Completed jobs explicitly report a simulated result with no tool execution, findings or submissions.

## Files created and changed

Created `abh/jobs.py`, `tests/test_jobs.py`, `docs/jobs.md` and this record.

Updated `abh/database.py` for transactional schema version 3, `abh/cli.py` for job/control commands, `abh/__init__.py` and `pyproject.toml` to 0.3.0, existing migration expectations in the foundation/scope tests, and README, architecture and development documentation. Existing policy logic, policy history and prior phase records remain intact.

## Verification

The full automated suite passed **70 tests, 0 failed**: 43 existing tests plus 27 Phase 2 tests. Coverage includes policy-bound approval, out-of-scope blocking, concurrent idempotency, ownership routing, duplicate claims, a shared concurrency cap, retries and attempt limits, lease expiry and recovery, stale results, heartbeat, cancellation, policy changes and expiry, missing approval records, rate deferral, transactional rollback, emergency stop/resume, clock rollback, CLI lifecycle and migration preservation.

The concurrency test admitted a single worker to one job; another test admitted exactly two workers under the global cap. The rollback test left both the job and rate budget unchanged after simulated audit failure. The CLI lifecycle test exercised create, approve, simulate, inspect, recover, stop and resume. Tests contact no external targets.

On 2026-09-29, `python -m abh init` upgraded the existing local database to schema 3. `doctor` confirmed a healthy database, dry-run and human approval enabled, and external execution disabled. `orchestrator status` reported the persistent concurrency limit of two with no jobs queued. `git diff --check` found no whitespace errors. GitHub publication is verified against the remote commit during delivery.

## Remaining work and risks

Next: **Phase 3 — Agent Framework**. It has not been implemented in this phase. The dashboard, actual security tooling, AI model integrations and end-to-end findings pipeline remain later work; the full product is not complete.

Known limitations: local actor labels are not authenticated identities; lease tokens prevent stale local writes but are not a remote-security boundary. No continuous worker/scheduler, retention/pagination or distributed enforcement exists. All runs are simulations. A future tool runner must implement real cancellation and transport safeguards. Linux/Kali, PostgreSQL and live target behavior are **NOT VERIFIED**. Local Windows tests passing do not certify production security.
