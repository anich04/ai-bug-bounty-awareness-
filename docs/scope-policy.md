# Scope and policy engine

Phase 1 evaluates locally supplied authorization. It never discovers permission, verifies ownership, resolves DNS or contacts a target. Importing a program is a human assertion about policy; the example starts ambiguous and cannot authorize anything.

## Program contract

Use `configs/lab-program.example.json` as the template. Unknown fields, unknown actions, duplicate JSON keys, duplicate rule/action IDs, invalid booleans, invalid bounds and ambiguous rule syntax are rejected.

| Field | Meaning |
| --- | --- |
| id | Stable ASCII identifier, up to 64 characters |
| name | Human-readable program name |
| authorization_status | `confirmed` or `ambiguous`; ambiguous always blocks |
| authorization_source | Human-supplied policy provenance, no secrets |
| valid_until | ISO 8601 timestamp with timezone; blocks at and after expiry |
| scope | Explicit include/exclude rules |
| actions | Explicit allow/deny and approval/method policies; missing actions deny |
| rate_limit | Aggregate requests and window_seconds, required |

Rules contain `id`, `effect` and `host`, plus optional `schemes`, `ports` and `path_prefix`. Omission of a constraint means the human policy covers all values of that component; specify constraints for narrow authorization. Null or empty constraints are invalid. Lists do not imply scheme/port pairings: use separate rules if only particular pairs are authorized.

Program updates require `--replace`. The update is atomic, preserves the rate history and keeps the old policy document by SHA-256 revision. Inspect history with `python -m abh programs show PROGRAM --revision HASH`. Historical policies cannot be selected for current scope checks.

## Matching behavior

- Hostnames are ASCII, case-normalized, and allow exactly one terminal DNS dot. Use explicit punycode for internationalized domains. Unicode input is blocked to avoid guessing mappings.
- Exact hosts authorize that host only. `*.lab.example` covers strict subdomains, including nested subdomains, but never the apex or a suffix lookalike. Only a leading `*.` is supported. Public-suffix interpretation is not performed; the human must not import an overbroad wildcard.
- IPv4 and IPv6 require explicit rules. No IP inherits permission from a hostname. CIDR rules are unsupported. IPv6 URLs require brackets; plain rule hosts use an IPv6 literal. Zone identifiers, IPv4-mapped dotted IPv6 and legacy integer/octal/hex IP spellings are rejected conservatively.
- HTTP and HTTPS URLs get their effective port (80 or 443 when absent). A nondefault port needs an applicable rule. Bare hosts may match unconstrained rules, but never satisfy missing scheme/path/port constraints on an inclusion.
- Exclusions override all inclusions. An exclusion that could apply to a bare host blocks it even if more URL detail is needed. No approval can override an exclusion, expired policy or missing authorization.
- Paths match exact paths or descendants on slash boundaries. `/app` matches `/app/item` but not `/apple`. Includes are case-sensitive; exclusions also block case variants conservatively. Root `/` includes every supported absolute path.
- Percent-encoded paths, dot segments, trailing dots on segments, repeated slashes, backslashes, semicolon parameters, non-ASCII paths and other unsupported path punctuation are blocked. These restrictions intentionally reject some legitimate URLs until target-specific normalization can be established safely.
- URL credentials, fragments, whitespace/control characters, malformed authorities and invalid ports are blocked. Query parameters do not grant or narrow scope and are omitted from decision output. Query-sensitive authorization cannot be expressed in this version.
- No CNAME or third-party ownership inference is made. A third-party host needs its own explicit policy; a wildcard remains a human assertion that its matching hosts are authorized.

## Actions and approvals

Only the action names in `abh.policy.ACTIONS` are accepted. HTTP collection/validation actions require an explicit URL and HTTP method. A policy's optional method list further restricts methods. Unknown methods and absent/denied action policies block.

`requires_human_approval()` defaults to requiring approval for everything. Even when embedded callers evaluate a less restrictive policy, report submission, state-changing actions, high-volume actions, sensitive-account actions and non-safe HTTP methods always require review. A policy flag cannot turn off these mandatory gates. The CLI keeps the global approval setting enabled.

The scope-check CLI returns `BLOCKED` (exit 1) or `WAITING_FOR_HUMAN_APPROVAL` (exit 3). Embedded checks can return `POLICY_ALLOWED` if the global approval requirement is disabled and no mandatory gate applies, but always return `execution_enabled=false`. `ok=true` means the check found no policy prohibition; it does not mean the action has been approved. The later job system now records job-specific approval for offline processing only; no live-execution API exists.

## Redirects

```text
python -m abh scope check http://localhost:8080/ --program local-lab --action probe_http --method HEAD --redirect /admin
```

This checks the source and then resolves/checks the supplied Location, without a network request. Raw relative paths are checked before URL joining, so dot-segment normalization cannot hide an ambiguous redirect. Each observed hop must be checked independently; a safe first redirect grants no permission to later hops. Automatic redirect following is not implemented. A future adapter must handle redirect method changes and authentication-header forwarding safely.

## Persistent rate budgets

The sliding window covers `(now - window_seconds, now]` and is aggregate across all targets/actions in a program. Unknown programs fail closed. `RateLimiter.reserve()` holds a SQLite immediate transaction, reloads the current policy and reserves one unit if available. Separate writers cannot exceed the configured count. A reservation is only budget accounting, never target/action authorization.

`scope check` peeks without consuming request budget. It still records the latest observed clock value and the decision audit. Clock rollback blocks availability until wall time catches up. Existing usage survives restarts and policy replacement. Failed transactions roll back reservations. Events are retained without pruning so expanding the policy window cannot silently discard previous usage.

This is a development limiter on one SQLite database. Host clock tampering, distributed enforcement, retention/archival and atomic integration with future job dispatch remain later work. Callers must never use separate preview and reserve calls as an execution approval.

## Audit and limits

Resolved policy checks record who, what, when, why, normalized host, action, decision, revision and correlation ID. Unknown programs or unavailable storage cause a failed command; the CLI's generic failure event is the fallback when no valid program can be audited. Policy snapshots are preserved, but raw request evidence belongs to a later phase.

No network layer exists yet. DNS rebinding, address pinning, proxy behavior, server-specific URL interpretations and race-free execution enforcement must be validated when the tool layer is introduced. These policy checks are not a production authorization boundary on their own.
