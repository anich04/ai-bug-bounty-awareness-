# Phase 7 — model contracts and offline telemetry

Implemented provider-independent routing, explicit configuration, OpenAI Responses request/response contracts, Claude Messages contracts and configurable Kimi chat-completion contracts. Unknown tasks and disabled providers fail closed. No arbitrary tool calls are accepted from responses. Partial, malformed and oversized outputs are rejected.

```text
python -m abh models health
python -m abh models health --config configs/models.example.json
python -m abh models ingest openai response.json --program PROGRAM_ID --task analysis
python -m abh models usage --program PROGRAM_ID
```

`ModelRouter.request` builds an inspectable body without reading credentials. Health exposes only credential presence. Provider response imports are generated_unverified, not raw proof. Original imported response bytes and structured usage are persisted with hashes; token counts are preserved when supplied and missing counts/cost/latency remain null. No billed usage is inferred from an offline import.

Configuration: copy models.example.json to a local file, explicitly select model IDs and task routes. Do not store API keys in JSON. Credential environment names are OPENAI_API_KEY, ANTHROPIC_API_KEY and KIMI_API_KEY. Runtime transport is disabled: enabled configuration enables request planning only. No API account, model availability or billing compatibility has been tested.

OpenAI contract reference: [Responses API](https://developers.openai.com/api/reference/typescript/resources/beta/subresources/responses/methods/create), fetched during implementation. Claude and Kimi reference search results were available, but full page retrieval failed; live configuration REQUIRES CURRENT DOCUMENTATION VERIFICATION. Kimi K3 model ID, endpoint, context limit, API access requirements and pricing remain explicit deployment checks, with no old model substituted.

144 tests passed, 0 failed, including disabled-provider behavior, secret-free health, task routing, request contracts, endpoint constraints, provider parsing and rejected outputs. Phase 7's offline development boundary is implemented; paid/live provider transport and account acceptance testing remain incomplete. Proceeding to the local finding pipeline under the user's uninterrupted-work authorization.
