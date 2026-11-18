# SH-20

Fungible shielded tokens on Bitcoin L1. Anyone deploys a unique 4-character ticker, anyone mints it
for a public price in BTC, and transfers hide the amount, the sender, the recipient and the ticker.
No soft fork, no sidechain, no admin key.

**Status: draft v0.3. Not activated on any network. Not audited.**

| | |
| --- | --- |
| Design | [`docs/DESIGN.md`](docs/DESIGN.md) |
| Wire format and rules | [`docs/SPEC-WIRE.md`](docs/SPEC-WIRE.md) |
| Reference indexer | [`indexer/`](indexer/) — Node ≥ 20, no dependencies, `npm test` |
| Spend circuit | [`circuit/`](circuit/) — PLONK on the public Hermez setup, 480-byte proofs, `cargo test --release` |
| Contributor handoff | [`CLAUDE.md`](CLAUDE.md) |

Next milestone: the spend circuit on real phones and in a browser wallet, then a public signet run.

MIT License.
