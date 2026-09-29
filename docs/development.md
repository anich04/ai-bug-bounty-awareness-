# Development

Use Python 3.11+ on Windows or Linux. Runtime and test suite use only the Python standard library. Run `python -m unittest discover -s tests -v` from the repository root. Tests isolate their data in temporary directories and never contact external targets.

The source package lives in `abh/`; provider placeholder configuration is in `configs/`, tests in `tests/`, and documentation here. Generated databases and logs belong in ignored `data/` directories. Keep real secrets out of committed files.

Phase 2 adds jobs, a transactional state machine, fixed ownership/routing, dry-run approval, retries, worker leases, cancellation and emergency stop. Agent runtimes, assets/findings/evidence tables, Kali/Burp interfaces, model calls, dashboard and scheduling remain excluded. Add these only after explicit authorization of their respective phases.

The scope guard fails closed on unknown, excluded, expired or ambiguous authorization. Job claims bind current policy, approval, rate reservation and worker ownership in one SQLite transaction. Completion rechecks policy and the worker lease. Future adapters must bind these checks to actual requests and each redirect, including transport/DNS protections. A cached policy check is not sufficient for execution. Emergency stop persistently closes admission and cancels outstanding simulations. It cannot kill future external tools that have not been implemented.

Phase 2 uses an injected clock in tests to verify backoff, lease expiry, policy expiry and clock rollback without sleeping. Tests use separate SQLite connections for concurrent claims and rate reservations. No service or daemon is installed. `jobs run-next` processes at most one simulation and exits; a continuous runtime belongs to later phases.
