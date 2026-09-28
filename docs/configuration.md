# Configuration reference

| Variable | Default | Accepted values |
| --- | --- | --- |
| ABH_ENV | development | development, test |
| DRY_RUN | true | true only in the current development release |
| REQUIRE_HUMAN_APPROVAL | true | true only in the current development release |
| DATABASE_URL | sqlite:///data/abh.db | Persistent SQLite file |
| LOG_LEVEL | INFO | DEBUG, INFO, WARNING, ERROR, CRITICAL |
| LOG_FILE | data/abh.jsonl | Local file path |

Precedence: process environment, workspace `.env`, defaults. `.env` uses one KEY=VALUE per line, optional matching quotes, blank lines and full-line comments. There is no interpolation, executable syntax, multiline value support or inline comment parsing. Boolean spelling is case-insensitive but restricted to true/false; typos fail closed. UTF-8 BOM files are supported.

Absolute SQLite path examples: `sqlite:///C:/local/abh.db` on Windows and `sqlite:////home/user/abh.db` on Linux. Relative paths use `--root`. URI query parameters and in-memory databases are deliberately unsupported.

Keep `.env` local and private. Unknown variables are ignored by the foundation. The Kimi example contains placeholders only; all endpoint, authentication, model, context, membership and pricing details require current provider documentation verification in Phase 7. No provider is contacted now.

Events use INFO severity, so WARNING or higher suppress successful file command events. This development file log is not a security audit trail, and concurrent multi-process log rotation is not supported yet. Policy imports and resolved scope decisions are also saved in SQLite, independently of LOG_LEVEL. Queries, credentials and raw target paths are not included in those audit records; only the normalized hostname is stored.
