# Phase 8 — local human-reviewed finding pipeline

`abh findings show ID` joins a candidate, evidence, policy and review history. `duplicates ID` detects exact normalized title/hypothesis/target matches within a program; it does not automatically classify them.

`review ID --input review.json` accepts decision (validated, false_positive, duplicate, needs_evidence), checks (real, reproducible, in_scope, security_relevant, not_duplicate, evidence_sufficient), rationale, actor and duplicate_of (null except duplicates). All six checks are required booleans. Validation requires all checks true and nonempty raw-import evidence. This is a human attestation, not autonomous proof.

`draft ID --input draft.json` accepts title, questions and actor. Questions retain the Phase 4 exact-label/answer/evidence_ids contract. Current human validation is mandatory. `approve-report REPORT_ID` requires complete answers and raw evidence references, records approval and never submits.

Review fingerprints include immutable finding, full evidence records and current policy revision. Changed evidence or policy requires revalidation; old drafts cannot be approved against a different snapshot. False-positive and duplicate decisions prevent report approval. Composed operations use one write transaction. Imported scanner/model claims do not automatically create validated findings.

150 tests passed, 0 failed. Six new pipeline checks cover raw-evidence gates, snapshot invalidation, report approval, unanswered questions, duplicate decisions and rejection after drafting. Automated testing/hypothesis generation and semantic claim verification remain unavailable; this milestone is a working local review workflow.
