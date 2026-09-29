# Controlled Kali tool layer (Phase 5)

This development implementation has two fixed adapters:

| Operation | Planned utility | Input | Output |
|---|---|---|---|
| resolve_dns | /usr/bin/dig | One bare authorized hostname, A lookup | DNS status and A/AAAA/CNAME answer records |
| probe_http | /usr/bin/curl | One authorized HTTP/S URL, HEAD | Status and ordered response headers |

No arbitrary command, executable, option, resolver, proxy, request body, credential or shell input is accepted. Plans set timeouts and output limits. curl plans disable startup configuration, restrict protocols, disable URL globbing, bypass proxy configuration and omit redirect-following. dig plans disable startup configuration and search expansion and bound retry/time settings. DNS answers never authorize discovered IPs or aliases; redirect locations require a separately scoped and approved job.

Flag semantics were checked against the [official curl manual](https://curl.se/docs/manpage.html) and [Kali's BIND tools documentation](https://www.kali.org/tools/bind9/). Installed Kali binary paths, versions and compatibility are **NOT VERIFIED**: no Kali VM connection is configured. Plans must not be used as standalone authorization for live execution.

## Dry-run workflow

```text
python -m abh init
python -m abh tools list
python -m abh tools enqueue probe_http https://YOUR_AUTHORIZED_HOST/app --program YOUR_PROGRAM
python -m abh jobs show JOB_ID
python -m abh jobs approve JOB_ID
python -m abh tools run-next
python -m abh tools runs --job JOB_ID
python -m abh tools run-show RUN_ID
```

Approval remains explicit for each job. A plan-only run succeeds with `executed: false`, `source: dry_run_plan`, null observations and no artifacts. This means the planning workflow completed; it does not mean a target was reached. Shared job budget is reserved even for dry runs. If capacity or rate budget is exhausted the worker stays idle, preserving queued work. `jobs show` exposes reason/events and bound tool input for review.

To parse an existing local test capture, provide `--input capture.json` at enqueue time:

```json
{
  "version": 1,
  "capture": {
    "stdout_base64": "SFRUUC8xLjEgMjAwIE9LDQoNCg==",
    "stderr_base64": "",
    "exit_code": 0,
    "elapsed_ms": 10
  }
}
```

The sample decodes to a synthetic HTTP 200 header block; it is not evidence of a real request. All supplied captures receive `source: supplied_capture_unverified`, including original byte artifact references. Capture contents are included in the immutable input hash and idempotency fingerprint before approval. No worker can substitute a new capture at dispatch time.

```text
python -m abh tools export RUN_ID stdout capture.bin
python -m abh tools export RUN_ID stderr stderr.bin
```

Exports preserve original bytes, verify hashes and sizes and refuse overwrites. Tool artifacts are linked to runs, jobs and policy revisions without inventing findings. They remain in the ignored local database. Tool-run records expose structured output hashes; events and fixed error codes record failures without copying stderr into ordinary logs. Captures may contain private response data; storage access remains the local workspace boundary.

## Bounds and failure behavior

Input version is 1, and exact fields are required. Each output stream is limited to 65,536 decoded bytes. DNS answers are capped at 100 records and HTTP headers at 200. Capture duration above 6,000 ms produces `tool_timeout`; nonzero exit codes produce `tool_exit_nonzero`; malformed or unsupported output produces `invalid_tool_output`. These failures retain original supplied captures and end the job as failed. Resubmitting corrected data requires a new job and approval.

Duration and exit code are supplied metadata, not measured execution. The parsers reject incomplete headers, informational-only responses, multiple response blocks/body data, unsupported DNS records and failed/missing DNS status. This is deliberately a narrow parser contract; it does not claim universal curl/dig output compatibility.

Claim and publish recheck policy revision, authorization, approval, lease and emergency stop through the job system. Publication stores structured results and artifact links atomically. Failed capture-integrity checks roll back newly added blobs/links. Cancellation, stop and lease recovery also close the corresponding tool-run attempt. Expired attempts may retry through the existing queue; stale leases cannot publish.

## Remaining integration work

Live subprocess/SSH/VM execution is disabled, including when an approved job succeeds. The current configuration still requires DRY_RUN=true. There are no target requests, root commands, scanners or exploitation adapters.

Before live lab execution, implement a constrained VM transport with measured deadlines, output streaming limits, process termination on cancellation, environment isolation and DNS/redirect enforcement. Verify installed binaries and run local-lab acceptance tests. These controls are not satisfied merely by copying a command plan into a shell. Additional collection operations and automatic ingestion into observations are future work.
