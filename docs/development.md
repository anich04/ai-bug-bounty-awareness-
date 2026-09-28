# Development

Use Python 3.11+ on Windows or Linux. Runtime and test suite use only the Python standard library. Run `python -m unittest discover -s tests -v` from the repository root. Tests isolate their data in temporary directories and never contact external targets.

The source package lives in `abh/`; provider placeholder configuration is in `configs/`, tests in `tests/`, and documentation here. Generated databases and logs belong in ignored `data/` directories. Keep real secrets out of committed files.

Phase 1 includes scope rules, program/action policies, rate budgets, approval requirements and their persistence. Jobs, agent runtimes, assets/findings/evidence tables, Kali/Burp interfaces, model calls, dashboard and scheduling remain excluded. Add these only after explicit authorization of their respective phases.

The scope guard fails closed on unknown, excluded, expired or ambiguous authorization. Future adapters must bind its checks and budget consumption to the actual normalized request at dispatch, including each redirect, with policy invalidation and transport/DNS protections. A cached Phase 1 check is not sufficient for execution. Emergency stop belongs with job execution; no command claims to stop nonexistent jobs today.
