---
description: Audit one part of SH-20 (circuit, verifier, sealing, vault, indexer) as docs/AUDIT-PROMPT.md says
argument-hint: circuit | verifier | sealing | vault | indexer
---

Read `docs/AUDIT-PROMPT.md` and run the part named here: $ARGUMENTS

Follow it to the end: the properties before the code, a reproducer for each finding, the report in
`docs/audit/<today, UTC>-<part>.md`, every suite of the part run and named. If no part is named, run the
first one that has no report in `docs/audit/` yet, in the order the prompt gives.
