//! The bodies `wire` writes against the envelopes of the indexer's vectors
//! (indexer/vectors/v0.3.json, written by the reference codec): each envelope is read field by
//! field at the offsets of docs/SPEC-WIRE.md §4, written again by this crate, and must come back
//! byte for byte, with the `bodyHash` the vectors give.

use ark_bn254::Fr;
use ark_ff::PrimeField;
use sh20_circuit::{model, wire, PROOF_BYTES};

fn vectors() -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../indexer/vectors/v0.3.json");
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// The bytes and the `bodyHash` of one envelope of the vectors.
fn envelope(doc: &str, name: &str) -> (Vec<u8>, String) {
    let entry = doc.split_once(&format!("\"{name}\": {{")).unwrap_or_else(|| panic!("no envelope {name}")).1;
    let entry = entry.split_once('}').expect("end of the entry").0;
    let field = |key: &str| entry.split_once(&format!("\"{key}\": \"")).unwrap_or_else(|| panic!("{name}: no {key}")).1.split_once('"').unwrap().0.to_string();
    (hex::decode(field("hex")).expect("hex"), field("bodyHash"))
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> &'a [u8] {
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        head
    }
    fn u8(&mut self) -> u8 {
        self.take(1)[0]
    }
    fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.take(4).try_into().unwrap())
    }
    fn u64(&mut self) -> u64 {
        u64::from_le_bytes(self.take(8).try_into().unwrap())
    }
    fn fr(&mut self) -> Fr {
        Fr::from_le_bytes_mod_order(self.take(32))
    }
    fn ticker(&mut self) -> &'a [u8; 4] {
        self.take(4).try_into().unwrap()
    }
    /// psLen ‖ payScript
    fn pay_script(&mut self) -> &'a [u8] {
        let n = self.u8() as usize;
        self.take(n)
    }
    /// anchorHeight ‖ nf0 ‖ nf1 ‖ 3 × (leaf ‖ pk_eph ‖ ct), then the proof and nothing more.
    fn spend(&mut self) -> (u32, [Fr; 2], [wire::Output; 3]) {
        let anchor = self.u32();
        let nf = [self.fr(), self.fr()];
        let outs = std::array::from_fn(|_| wire::Output { leaf: self.fr(), pk_eph: self.take(32).try_into().unwrap(), ct: self.take(28).try_into().unwrap() });
        assert_eq!(self.0.len(), PROOF_BYTES, "the proof ends the envelope");
        (anchor, nf, outs)
    }
}

/// Checks that `body` is the envelope without its proof, and hashes to the vectors' `bodyHash`.
fn same(name: &str, bytes: &[u8], body_hash: &str, body: Vec<u8>) {
    assert_eq!(hex::encode(&body), hex::encode(&bytes[..bytes.len() - PROOF_BYTES]), "{name}");
    assert_eq!(format!("{:064x}", model::to_big(&model::body_hash(&body))), body_hash, "{name}: bodyHash");
    let proof: [u8; PROOF_BYTES] = bytes[bytes.len() - PROOF_BYTES..].try_into().unwrap();
    assert_eq!(wire::envelope(body, &proof), bytes, "{name}");
}

/// The header of an envelope of type `ty`, then the reader of what follows.
fn after_header<'a>(name: &str, bytes: &'a [u8], ty: u8) -> Reader<'a> {
    assert_eq!(bytes[..6], [b'S', b'H', b'2', b'0', wire::VERSION, ty], "{name}");
    Reader(&bytes[6..])
}

#[test]
fn a_transfer_and_a_burn() {
    let doc = vectors();
    let (bytes, hash) = envelope(&doc, "transfer");
    assert_eq!(bytes.len(), 830);
    let (anchor, nf, outs) = after_header("transfer", &bytes, wire::TYPE_TRANSFER).spend();
    same("transfer", &bytes, &hash, wire::transfer_body(anchor, &nf, &outs));

    let (bytes, hash) = envelope(&doc, "burn");
    assert_eq!(bytes.len(), 842);
    let mut r = after_header("burn", &bytes, wire::TYPE_BURN);
    let (ticker, v_pub) = (r.ticker(), r.u64());
    let (anchor, nf, outs) = r.spend();
    assert_eq!((ticker, v_pub), (b"SH20", 10));
    same("burn", &bytes, &hash, wire::burn_body(ticker, v_pub, anchor, &nf, &outs));
}

/// A LIST: 884 bytes and its payScript, the lock key in the body between `lockVout` and the payScript.
#[test]
fn a_list() {
    let doc = vectors();
    for name in ["list", "list2", "list8"] {
        let (bytes, hash) = envelope(&doc, name);
        let mut r = after_header(name, &bytes, wire::TYPE_LIST);
        let (ticker, amount, price, lock_vout) = (r.ticker(), r.u64(), r.u64(), r.u8());
        let lock_key: &[u8; 32] = r.take(32).try_into().unwrap();
        let pay_script = r.pay_script();
        let (anchor, nf, outs) = r.spend();
        assert_eq!(bytes.len(), 884 + pay_script.len(), "{name}");
        assert!(amount > 0 && price > 0 && !pay_script.is_empty(), "{name}");
        let listing = wire::Listing { ticker, amount, price, lock_vout, lock_key, pay_script };
        same(name, &bytes, &hash, wire::list_body(&listing, anchor, &nf, &outs));

        // the key is in the body: another key is another body, and another hash for the proof to sign
        let mut other = *lock_key;
        other[0] ^= 1;
        let moved = wire::list_body(&wire::Listing { lock_key: &other, ..listing }, anchor, &nf, &outs);
        assert_ne!(format!("{:064x}", model::to_big(&model::body_hash(&moved))), hash, "{name}");
    }
}

/// A DEPLOY with its burn: with a team opening and without, with a payScript and without.
#[test]
fn a_deploy() {
    let doc = vectors();
    let mut seen = Vec::new();
    for name in ["deployWithTeam", "deployNoTeam", "deployPay2", "deployBeta", "deployPay516a"] {
        let (bytes, hash) = envelope(&doc, name);
        let mut r = after_header(name, &bytes, wire::TYPE_DEPLOY);
        let (ticker, max, lim, pre) = (r.ticker(), r.u64(), r.u64(), r.u64());
        let (start, end, unlock) = (r.u32(), r.u32(), r.u32());
        let (price, pay_mode) = (r.u64(), r.u8());
        let pay_script = r.pay_script();
        let team = if pre > 0 { r.fr() } else { Fr::from(0u64) };
        let (anchor, nf, outs) = r.spend();
        // SPEC-WIRE §4: 88 bytes with a team opening, and 824 of spend; 32 less without one
        assert_eq!(bytes.len(), 56 + pay_script.len() + if pre > 0 { 32 } else { 0 } + 824, "{name}");
        assert_eq!(pay_script.is_empty(), pay_mode != 2, "{name}");
        let token = wire::Deploy { ticker, max, lim, pre, start, end, unlock, price, pay_mode, pay_script, team };
        same(name, &bytes, &hash, wire::deploy_body(&token, anchor, &nf, &outs));
        seen.push((pre > 0, pay_mode));
    }
    // every shape the body has: a team opening or none, each pay mode
    for shape in [(true, 1), (false, 1), (true, 2), (true, 0), (false, 2)] {
        assert!(seen.contains(&shape), "no DEPLOY of the vectors has the shape {shape:?}");
    }
}
