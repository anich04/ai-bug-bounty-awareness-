# Phase 9 - local review dashboard

Phase 9 adds a loopback-only dashboard for local review work. The server binds to `127.0.0.1`, generates a per-process access token, checks the expected host and origin on API requests, and serves static assets with restrictive security headers. The dashboard is for local triage, evidence inspection, job approval controls, human finding review and report approval. It does not submit reports, call model providers, run Kali tools or connect to Burp live APIs.

Run it from the project directory:

```text
python -m abh dashboard
```

Open the printed local URL. Keep that URL private because the fragment contains the local bearer token for this session. Evidence bytes remain in the ignored local SQLite database, and source control does not include `.env`, logs, tokens or evidence.

The dashboard exposes overview, program, object, job, integration and finding-review data from the local database. Finding detail includes the provenance chain, raw evidence preview/download, human review checks and a local report-draft workflow. All review and approval actions use the same backend policy and snapshot gates as the CLI.

Validation: 154 tests passed, 0 failed. Dashboard tests cover token-gated APIs, host and origin blocking, emergency stop, bad routes and bad actions. Browser visual QA was performed against a synthetic local demo database. Remaining integrations are still explicit future work: live Kali execution, live Burp control, live model transport, notifications and external submission are not configured.
