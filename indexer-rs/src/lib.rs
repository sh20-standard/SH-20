//! A second SH-20 indexer, written from `docs/SPEC-WIRE.md` (draft v0.3) alone.
//!
//! Clean room: the reference indexer's code was never opened. `docs/SPEC-GAPS.md` keeps the
//! record: what the spec left open, where each point was settled, what has no vector yet.

pub mod api;
pub mod blocks;
pub mod chain;
pub mod envelope;
pub mod events;
pub mod field;
pub mod follow;
pub mod json;
pub mod raw;
pub mod server;
pub mod sources;
pub mod state;
pub mod tree;
pub mod verifier;

pub use chain::{Block, Tx, TxIn, TxOut};
pub use envelope::{DecodeError, Envelope, Ticker};
pub use events::Event;
pub use state::{BlockResult, Indexer, ListingStatus, Note, NoteKind, Profile, PublicKind};
pub use verifier::{PlonkVerifier, PublicInputs, RejectAll, SpendVerifier, TestVerifier};
