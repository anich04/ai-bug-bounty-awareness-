# Data and evidence (Phase 4)

The local data layer records this hierarchy:

Program → Asset → Endpoint → Observation → Candidate finding → Evidence

A draft report belongs to one finding and references evidence from that same finding. Every object records its immutable ID, parent, program, current policy revision, UTC import timestamp, local actor label, normalized target and SHA-256 of its canonical JSON. Policy history is retained independently. Actor labels and supplied capture timestamps are declarations, not authenticated identities or independently verified times.

## Import workflow

Run `python -m abh init` to upgrade to schema 5. Import a policy that accurately represents your authorized lab. The provided policy example is deliberately ambiguous and blocks new data imports until you supply a confirmed policy.

Save each payload below to a separate JSON file. Use returned IDs as the next object's `--parent`:

```text
python -m abh data add asset --program YOUR_PROGRAM --input asset.json
python -m abh data add endpoint --program YOUR_PROGRAM --parent ASSET_ID --input endpoint.json
python -m abh data add observation --program YOUR_PROGRAM --parent ENDPOINT_ID --input observation.json
python -m abh data add finding --program YOUR_PROGRAM --parent OBSERVATION_ID --input finding.json
python -m abh data add evidence --program YOUR_PROGRAM --parent FINDING_ID --input evidence.json --artifact capture.bin
python -m abh data add report --program YOUR_PROGRAM --parent FINDING_ID --input report.json
```

Asset:
```json
{"target":"https://your-authorized-lab.example/app"}
```
Endpoint:
```json
{"target":"https://your-authorized-lab.example/app/item","method":"GET"}
```
Observation (a supplied statement, not verified by this engine):
```json
{"fact":"Describe only what your existing evidence records."}
```
Finding:
```json
{"title":"Candidate title","hypothesis":"An unvalidated explanation to investigate."}
```
Evidence:
```json
{"label":"Original response capture","category":"response","origin":"raw_import","captured_at":"2026-09-29T10:00:00Z"}
```
Report (preserves question order and exact labels; null means unanswered):
```json
{"title":"Draft report","questions":[{"id":"impact","label":"What is the impact?","answer":null,"evidence_ids":["EVIDENCE_ID"]}]}
```

Evidence categories: request, response, screenshot, video, log, reproduction, other. Use `origin: generated` for derived text, explanations or other generated artifacts. A generated artifact may be cited but never becomes raw evidence. Importing an artifact of either origin does not validate a finding. MIME detection, tool capture and automatic reproduction are not implemented in Phase 4.

## Inspect and export

```text
python -m abh data list --program YOUR_PROGRAM --kind finding
python -m abh data show OBJECT_ID
python -m abh data provenance REPORT_ID
python -m abh data export EVIDENCE_ID exported-response.bin
```

`show` verifies object hashes and, for evidence, the bytes and metadata. Report creation verifies referenced artifacts. `provenance` returns the parent chain and report evidence with artifact verification. `list` checks object hashes but does not read artifact bytes. Export checks integrity before creating a file and refuses to overwrite an existing path. It writes original bytes without text decoding or newline conversion. The output path is explicitly supplied by the operator, never derived from artifact metadata.

## Storage and boundaries

Artifacts are content-addressed SQLite BLOBs in `artifacts`, with immutable import records in `data_objects` and relational links in `evidence_artifacts` and `report_evidence`. Storing bytes and records in one transaction prevents partial imports and orphan files. Equal byte content shares one blob, but each import retains its own origin, actor, timestamp and finding linkage. Maximum artifact size is 10 MiB; large video capture storage is deferred. Back up the local database while the application is stopped. `data/`, `.env`, logs and evidence are excluded from Git.

Every new object must match current confirmed scope. Historical objects remain readable after policy changes. Endpoint hosts must match their parent asset; endpoints and all inherited targets are checked against current path scope. Structured targets reject query strings; preserve complete requests (including queries) in raw evidence. No request is executed by an import. Parent kinds, program boundaries and report evidence ownership are checked within the write transaction.

Objects are append-only through the application API. To revise a report, create a new draft; old drafts retain their own questions, answers and evidence IDs. Hashes detect accidental alteration; they are not signatures and do not defend against an attacker rewriting both database content and its hashes. Direct database edits are unsupported.

Finding status is always `candidate_unvalidated`; report status is always `draft_unvalidated`. There is no data approval or submission action. Provenance explicitly returns `approval: null` and `submission_enabled: false`. Existing job approvals authorize only their existing offline jobs, never these findings or reports. Agent-run ingestion, multi-observation correlation, validation decisions and report approval/submission belong to later phases.
