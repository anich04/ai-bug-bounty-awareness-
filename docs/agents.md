# Agent framework: Phase 3

Five fixed agents implement useful deterministic processing of supplied data. They do not use an AI model, discover assets, crawl sites, validate real vulnerabilities or submit reports. Those integrations belong to later phases. Tester, Evidence and Monitor remain deferred.

## Charters

| Agent | Required policy action | Input data | Current output | Boundary |
| --- | --- | --- | --- | --- |
| Scout | review_policy | Empty object | Summary of the exact stored structured policy, exclusions, action policies, expiry and rate | Cannot parse natural-language rules or create authorization |
| Mapper | discover_assets | assets: array of identifiers | Normalized scope classification for each supplied asset | No discovery or DNS calls |
| Crawler | collect_urls, method GET | urls: array of URLs | Normalized endpoint scope classification | No crawling, requests or authentication inference |
| Validator | validate_candidate, method GET | observations and hypothesis | Supplied facts, interpretation, uncertainty and preliminary checks | Always needs evidence; cannot assert reproduction or a validated vulnerability |
| Reporter | draft_report | questions with exact labels | Incomplete report scaffold, empty answers and evidence | No unsupported claims or submission |

Run `python -m abh agents list` or `agents show NAME` to inspect the built-in registry. Unknown agents and arbitrary module names cannot be loaded. `Agent` defines the runtime protocol; `BaseAgent` supplies the versioned result envelope. The registry and handler mappings are fixed, not user-configurable import strings.

## Inputs and outputs

Each input has exactly `{"version": 1, "data": {...}}`. Ready-to-edit examples are in `configs/agents/`. Version must be integer 1. Unknown fields, duplicate JSON keys, duplicate observation/question IDs, oversized text or more than 100 items per list are rejected. Canonical input and output documents are limited to 128 KiB. Do not include credentials or secrets in agent data.

Validator observations have an `id`, a supplied `fact` string and `evidence_refs` containing opaque identifiers. These are not verified evidence files. Hypothesis text remains separate from facts. The agent reports `real`, `reproducible`, `security_relevant` and `duplicate` as unknown; `evidence_sufficient` is false. Evidence ingestion, reproducibility and actual deduplication await later phases.

Reporter questions have `id`, `label` and boolean `required`. Output preserves these exact values and order, with `answer=null` and `evidence=[]`. It is a scaffold, not a submission-ready report. The runtime rejects changes to supplied questions or Validator facts/hypothesis.

Every output includes contract version, agent, job ID, policy revision, input hash, data and uncertainty. It explicitly declares no tool execution, network requests, findings or submissions. Invalid output contracts are permanently failed without publishing output. Unexpected handler exceptions use a fixed reason code and the bounded retry policy; raw exception text is never stored.

## Running an agent

```text
python -m abh init
python -m abh agents enqueue scout http://localhost:8080/ --program local-lab --input configs/agents/scout.example.json --key scout-review-1
python -m abh jobs show JOB_ID
python -m abh jobs approve JOB_ID
python -m abh agents run-next scout
python -m abh agents runs --job JOB_ID
python -m abh agents run-show RUN_ID
```

Use a confirmed, unexpired policy explicitly permitting the relevant action on that target. The example lab policy remains ambiguous and does not silently grant these actions. `jobs show` exposes the stored input and its hash for human review before approval. There is no API to attach or change payloads on an already-approved job.

Agent jobs use the existing approval, scope, rate-budget, concurrency, lease and stop controls. Enqueue persists job and input together. Claim creates a run for that attempt in the same transaction. Completion rechecks current policy, input hash and worker lease before storing output and completing the job together. The generic `jobs run-next` simulator skips agent jobs; `agents run-next` skips generic jobs.

## Structured handoffs

The permitted chain is Scout -> Mapper -> Crawler -> Validator -> Reporter. It is a protocol, not an automatically running workflow. Each explicit handoff supplies the next agent's bounded input:

```text
python -m abh agents handoff PARENT_JOB_ID --to mapper --input configs/agents/mapper.example.json
```

The parent must have a successful persisted agent output under the current policy. A child preserves the same program, target and correlation ID, and records the parent's owner as its source. The next action is independently checked; a denied next action yields a blocked child. A permitted child waits for new human approval. The handler cannot approve it.

Each parent/destination pair creates at most one child. Repeating identical input returns that child; conflicting input errors. State, input and lineage insertion are transactional, so a failed handoff cannot leave an orphan job. Changing program/target, jumping routes, using an unfinished/legacy job or using stale policy is rejected. Payload classifications never expand the job's authorized target.

## Persistence and limits

Schema 4 adds agent inputs, per-attempt runs, and handoffs. Run records track owner, worker, input/output hashes, status, reason and timestamps. Retry, lease expiry, cancellation and emergency stop close the corresponding run. Old attempts cannot publish output through a new lease. Historical runs can be inspected with `run-show`.

This remains trusted local code with a local database, not a sandbox for untrusted plugins. Hashes detect inconsistent storage but are not signatures. Actor labels are not authenticated identities. Processing is bounded by contract sizes and uses no arbitrary tools; a future extensible/provider runtime needs process timeouts and isolation. No background workers, evidence storage, model integration or live traffic processing were added in Phase 3.
