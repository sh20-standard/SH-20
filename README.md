# SH-20

Fungible shielded tokens on Bitcoin L1. Anyone deploys a unique 4-character ticker, anyone mints it
for a public price in BTC, and transfers hide the amount, the sender, the recipient and the ticker.
No soft fork, no sidechain, no admin key.

**Status: draft v0.2. Not activated on any network. Not audited.**

| | |
| --- | --- |
| Design | [`docs/DESIGN.md`](docs/DESIGN.md) |
| Wire format and rules | [`docs/SPEC-WIRE.md`](docs/SPEC-WIRE.md) |
| Reference indexer | [`indexer/`](indexer/) — Node ≥ 20, no dependencies, `npm test` |
| Contributor handoff | [`CLAUDE.md`](CLAUDE.md) |

Next milestone: the spend circuit (Halo2-KZG on the public Hermez setup), then a public signet run.

MIT License.
