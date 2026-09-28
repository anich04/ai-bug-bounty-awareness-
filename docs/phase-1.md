# Phase 1 — scope and policy engine

Implemented a strict program policy contract, persistent current/historical policies, deterministic target/action checks, exclusion precedence, expiry/ambiguity blocking, redirect checks, aggregate sliding-window rate budgets and mandatory approval requirements. Execution remains disabled.

## Files created or changed

Created `abh/policy.py`, `abh/programs.py`, `abh/scope.py`, `configs/lab-program.example.json`, `tests/test_scope.py`, `docs/scope-policy.md` and this record.

Updated `abh/database.py` for transactional schema version 2 and its storage boundary; `abh/cli.py` for program import/list/show and scope check commands; `abh/config.py` for current-stage messages; `abh/__init__.py` and `pyproject.toml` to version 0.2.0; `tests/test_foundation.py` for the new schema; and README, architecture, configuration and development documentation.

Existing Phase 0 source and the historical completion record were preserved. No prior application code was discarded. No additional runtime dependencies were added.

## Verification

Verified on Windows with Python 3.12 on 2026-09-28:

- `python -m unittest discover -s tests -v`: **43 passed, 0 failed** (14 foundation tests and 29 policy, persistence, rate and migration tests, with additional parameterized cases).
- `python -m abh init`: upgraded the existing local Phase 0 database to schema version 2 successfully.
- `python -m abh doctor`: healthy database, schema 2, dry-run true, human approval true, execution disabled.
- `python -m abh programs import configs/lab-program.example.json`: imported the ambiguous local-lab template successfully.
- `python -m abh programs list`: returned the imported policy and revision.
- `python -m abh scope check http://localhost:8080/ --program local-lab --action probe_http --method HEAD`: returned `BLOCKED / ambiguous_authorization`, exit 1, as expected. No HTTP request was made.

Automated coverage includes hostname/scheme/port/path normalization, exact and wildcard boundaries, explicit IPv4/IPv6, exclusions, ambiguous inputs, method/action policies, mandatory approval, expiry, redirect rechecking, historical policy preservation, hash mismatch blocking, atomic policy replacement, migration preservation/rollback, clock rollback, restart persistence and concurrent budget reservations. Twenty concurrent attempts against a three-request budget admitted exactly three reservations. CLI tests also verify waiting-for-approval exit code 3 and blocked exit code 1.

Tests use synthetic policies, temporary databases and no external targets. No automated failures remain. The expected negative CLI result above is a successful fail-closed check, not a test failure.

One initial migration test failed because the fixture did not supply the original table's timestamp default. The migration was strengthened to write its timestamp explicitly; the preservation and rollback tests then passed.

## Remaining work and risks

Phase 2 is the job system and orchestrator, and has not started. There is no approval-grant UI, target execution, dashboard or live integration. Policy confirmation is a local human assertion, not independent proof of authorization. URI normalization is deliberately restrictive; path encoding and some valid URL forms remain unsupported. Scope previews are not execution permits. Future dispatch must enforce current policy, approval, budget and redirect/DNS protections together.

SQLite files and audit history remain editable by the local user. Hashes are not signatures. Rate history has no retention policy yet. Distributed enforcement, PostgreSQL, Linux/Kali and live targets are NOT VERIFIED. Production authorization/security has not been claimed.
