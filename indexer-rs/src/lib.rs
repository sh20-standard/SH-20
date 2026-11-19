//! A second SH-20 indexer, written from `docs/SPEC-WIRE.md` (draft v0.3) alone.
//!
//! Clean room: the reference indexer's code was never opened. What the spec left open, and
//! what was chosen, is in `docs/SPEC-GAPS.md`.

pub mod chain;
pub mod envelope;
pub mod events;
pub mod field;
pub mod json;
pub mod state;
pub mod tree;
pub mod verifier;

pub use chain::{Block, Tx, TxIn, TxOut};
pub use envelope::{DecodeError, Envelope, Ticker};
pub use events::Event;
pub use state::{BlockResult, Indexer, ListingStatus, Profile};
pub use verifier::{PublicInputs, RejectAll, SpendVerifier, TestVerifier};
