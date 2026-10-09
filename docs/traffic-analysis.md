# Passive HTTP traffic analysis

Version 0.11 adds candidate discovery from imported request/response bytes.
This is a focused detection milestone following the Phase 9 dashboard. The
scheduled-workflow phase remains separate future work.

## Use the dashboard

Open **Analyze traffic**, select the program, and import Burp XML exported with
Base64 requests/responses. Each file stays in the local evidence vault. Click
**Analyze** beside a capture, then review the resulting **Findings** or read and
download its assessment. A policy must explicitly allow `analyze_http`. Scope,
expiry, artifact integrity and emergency stop are checked at analysis time.

The analysis command itself requests offline processing of existing evidence;
it is not a live-execution approval. Live job approvals remain separate.

## CLI

```text
python -m abh analysis rules
python -m abh burp import traffic.xml --program YOUR_PROGRAM
python -m abh analysis run IMPORT_RECORD_ID
python -m abh analysis report ANALYSIS_RECORD_ID assessment.md
```

Report export refuses to overwrite an existing file. Assessments contain
observed facts, potential impact, pattern confidence, evidence IDs, byte hashes
and validation steps. Secret/cookie values are omitted from derived findings
and assessments; original captures remain inspectable locally and may contain
credentials. Keep evidence and assessment exports outside source control.

## Current rules and deliberate limits

| Rule | Evidence required | Remaining validation |
| --- | --- | --- |
| Credentialed CORS | Cross-origin request cookie, matching allowed origin, Allow-Credentials true, successful JSON with potentially sensitive fields | Browser read, SameSite behavior, private-data semantics and intended sharing |
| Session cookie | Recognized session-like cookie missing Secure or HttpOnly | Actual cookie purpose and eligible security impact |
| Exposed configuration | Successful .env response with multiple assignments and secret-like field names | Ownership, real secrets versus examples and program eligibility |
| External redirect | Recorded redirect matches a supplied destination parameter and changes host | Intended navigation and eligible impact |
| Server trace | 5xx response with multiple recognizable runtime trace markers | Sensitive details and concrete eligible impact |

Rules do not assign P1/P2/P3 or CVSS. Confidence describes a pattern, not validity.
Public CORS, preflight responses, blocked requests, a wildcard origin alone,
absent generic security headers and status-only file guesses are not promoted
as bugs. Heuristics can still miss bugs and raise false positives. A lack of
candidates is not a full security assessment.

This version does not infer IDOR from a single response, execute a browser POC,
call an AI provider, crawl a target or run exploits. Controlled account-pair
comparison is a future milestone requiring explicit test-user/object context.

## Integrity and atomicity

Only Burp HTTP items or the supported manual-baseline record format can be
analyzed. Imported scanner issue claims are not promoted. Original artifact
hashes are verified. A write transaction binds scope checks, generated objects,
raw evidence and the analysis record. Reanalysis of the same input, analyzer
version and policy revision returns the existing assessment. New policy
revisions produce new assessments; earlier decisions remain historical.

The parser bounds messages and decoded bodies to 1 MiB, headers to 64 KiB and
chunk count to 10,000. Conflicting or duplicate framing headers, truncated
bodies, unsupported encodings/trailers and malformed HTTP are skipped with a
note. Gzip expansion is bounded. Unsupported messages are not findings.

## Learning demo

Use a separate workspace so synthetic examples are clearly separated from
real captured evidence:

```text
python -m abh --root /path/to/training-workspace init
python -m abh --root /path/to/training-workspace analysis demo
python -m abh --root /path/to/training-workspace dashboard --port 8767
```

The demo generates eight labeled synthetic captures, detects one example for
each of the five rules and rejects three controls. It makes zero network
requests and uses fake credentials on reserved `.test` names. It does not
claim a valid bug on Mercado Libre or any live target. Each generated finding
remains unvalidated and retains its fixture request/response for learning.

References: [MDN CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS),
[OWASP cookie attributes](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes).
