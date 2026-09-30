# Phase 6 — Burp Community import

Burp Community is the user's installed edition. The first adapter supports exported HTTP traffic and existing issue XML; it does not invoke the Professional scanner or claim a live Burp connection. Local process inspection did not find Burp or a VM process. VM connectivity remains NOT VERIFIED.

```text
python -m abh init
python -m abh burp status
python -m abh burp import exported-items.xml --program PROGRAM_ID
python -m abh burp list --program PROGRAM_ID
python -m abh burp show RECORD_ID
python -m abh burp export RECORD_ID 0/0/response response.bin
```

Export selected messages from Burp as XML with Base64 encoding enabled. Imports retain the complete original export and each message as hashed artifacts. Metadata includes scope target, original URL, import timestamp, policy revision and imported_unverified status. Scanner issue imports are third-party claims, never validated findings.

Limits: UTF-8 XML, 10 MiB per export, 100 items, 1 MiB per message, 20 request/response pairs per issue. External declarations and entity definitions are rejected; simple Burp element DTD declarations are accepted. Scope is checked for every entry before the import transaction commits. Request method/path/Host must match exported metadata. Current parser support requires one Host header and origin-form HTTP/1.0, HTTP/1.1 or HTTP/2 request lines; unsupported exports fail closed. Base64 is mandatory to preserve exact bytes. Query strings remain in the original URL and messages; policy scope follows existing path semantics.

`BurpAdapter` is the integration boundary. Future supported MCP/API adapters can implement it without changing the data layer. No API endpoints, edition-specific capabilities or live availability are invented.

References: [PortSwigger message export](https://portswigger.net/burp/documentation/desktop/tools/message-editor), [issue XML settings](https://portswigger.net/burp/documentation/desktop/running-scans/reporting/report-settings).

Validation: 138 tests passed, 0 failed. Nine new tests cover exact binary exports, XML declarations/entities, scope, request consistency, duplicate fields, imported issue status, corruption, limits and migration. Schema 7 adds integration records and artifact links. Live Burp/VM compatibility is NOT VERIFIED. Next: model-provider layer; the user authorized uninterrupted phase progression.
