# Development

Use Python 3.11+ on Windows or Linux. Runtime and test suite use only the Python standard library. Run `python -m unittest discover -s tests -v` from the repository root. Tests isolate their data in temporary directories and never contact external targets.

The source package lives in `abh/`; provider placeholder configuration is in `configs/`, tests in `tests/`, and documentation here. Generated databases and logs belong in ignored `data/` directories. Keep real secrets out of committed files.

Phase 3 adds fixed built-in agent handlers, versioned input/output contracts, persisted run history and structured handoffs. Assets/findings/evidence storage, Kali/Burp interfaces, model calls, dashboard and scheduling remain excluded. Add these only after explicit authorization of their respective phases.

The scope guard fails closed on unknown, excluded, expired or ambiguous authorization. Job claims bind current policy, approval, rate reservation and worker ownership in one SQLite transaction. Completion rechecks policy and the worker lease. Future adapters must bind these checks to actual requests and each redirect, including transport/DNS protections. A cached policy check is not sufficient for execution. Emergency stop persistently closes admission and cancels outstanding simulations. It cannot kill future external tools that have not been implemented.

Tests use an injected clock to verify backoff, lease expiry, policy expiry and clock rollback without sleeping, plus separate SQLite connections for concurrent claims, handoffs and rate reservations. No service or daemon is installed. `jobs run-next` processes one legacy simulation; `agents run-next` processes one offline agent job. A continuous service belongs to later phases. Agent tests inject malformed outputs, exceptions, cancellation and policy changes into the built-in handlers to verify that unsafe or stale results cannot be published.
