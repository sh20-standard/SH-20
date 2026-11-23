---
description: Audit one part of SH-20 as docs/AUDIT-PROMPT.md says: security (circuit, verifier, sealing, vault, indexer) or code (code <part>)
argument-hint: circuit | verifier | sealing | vault | indexer | code <indexer | indexer-rs | vault | circuit | explorer | tooling>
---

Read `docs/AUDIT-PROMPT.md` and run the part named here: $ARGUMENTS

Follow it to the end: the properties (or the duties) before the code, a reproducer or a measurement for
each finding, the report in `docs/audit/<today, UTC>-<part>.md` (`-code-<part>.md` for the code audit),
every suite of the part run and named. If no part is named, run the
first one that has no report in `docs/audit/` yet, in the order the prompt gives.
