#!/usr/bin/env python3
"""Checks that docs/AUDIT.md still names lines and tests that exist. The CI runs it.

    python3 docs/tools/check-audit-refs.py          one line per problem, exit 1 if there is one
    python3 docs/tools/check-audit-refs.py --fix    rewrites the line numbers that moved

docs/AUDIT.md cites code by line ("`_checkSpend` (l. 267)") and tests by title. A change elsewhere
moves those lines and renames those tests without touching the document. This script holds, for
every citation, what the cited line must hold, and reads the numbers from the document itself:

  CITES  one entry per citation, in the order of the document: the words of docs/AUDIT.md around
         the numbers, with {} for each number, then for each {} the file and a piece of the text of
         that line. Spaces and line breaks in the words match any run of them.
  OLD    the same for the lines of an older commit (the descriptions of §8.1 to §8.6, which keep
         the lines of f0cb20e): the numbers are fixed here, and compared with that commit when the
         clone has it (the CI's shallow clone does not).
  TESTS  the test titles the document quotes, with their file.

It fails when a cited line does not hold its text, when the document has a line reference with no
entry here, when an entry's words are no longer in the document, when a quoted test is not in its
file or no longer quoted, and when a link of the document leads to no file.

When it fails on your change:
  - a line moved: run it with --fix, then read the sentence around each number it rewrote, since a
    line that moved may also have changed what it does;
  - a line is gone, or holds something else: correct docs/AUDIT.md and the entry by hand;
  - you added or reworded a citation: add or correct its entry, at its place in the order.
"""
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
DOC = "docs/AUDIT.md"
SELF = "docs/tools/check-audit-refs.py"

# files cited more than once
GADGETS = "circuit/src/gadgets.rs"
SPEND = "circuit/src/spend.rs"
CS = "circuit/src/cs.rs"
FFI = "circuit/src/ffi.rs"
PKEYS = "circuit/src/plonk/keys.rs"
INDEXER = "indexer/src/indexer.js"
CODEC = "indexer/src/codec.js"
SCHNORR = "indexer/src/schnorr.js"
SUBTLE = "circuit/js/subtle.js"
V = "vault/src/"
OLD_VAULT = "f0cb20e"  # the commit §8 first read

# (words of docs/AUDIT.md with {} for each line number, then (file, text of that line) for each {})
CITES = [
    # §1 Scope
    ("(`structure`, l. {})", (PKEYS, "fn structure(")),
    ("`sh20_verify` (l. {})", (FFI, "fn sh20_verify(")),
    ("`_checkSpend` (l. {}) and its callers", (INDEXER, "_checkSpend(spend, body, vPub, tPub, H) {")),
    # §2 The relation
    ("(../circuit/src/spend.rs) l. {}.", (SPEND, "pub fn synthesize(")),
    ("rows 0 to 8 | l. {}–{} |", (SPEND, 'cs.at("public")'), (SPEND, "cs.public_input(w.t_pub)")),
    ("`Cs::public_input` (`cs.rs` l. {})", (CS, "pub fn public_input(")),
    ("for the five notes | l. {}–{} |", (SPEND, 'cs.at("ticker")'), (SPEND, "let head = gadgets::poseidon(")),
    ("`poseidon` (l. {}) | 620", (GADGETS, "pub fn poseidon(")),
    ("`0 ≤ v_i < 2^64` | l. {}–{} |", (SPEND, 'cs.at(format!("in{i} value"))'), (SPEND, "gadgets::range(cs, v, 64);")),
    ("`to_bits` (l. {})", (GADGETS, "pub fn to_bits(")),
    ("`NK_i = nk_i·B8` | l. {}–{} |", (SPEND, 'cs.at(format!("in{i} nullifier key"))'), (SPEND, "gadgets::fixed_mul(cs, &nk_bits")),
    ("`scalar_bits` (l. {}), `fixed_mul` (l. {})", (GADGETS, "pub fn scalar_bits("), (GADGETS, "pub fn fixed_mul(")),
    ("H(npk_i, rho_i))` | l. {}–{} |", (SPEND, 'cs.at(format!("in{i} note"))'), (SPEND, "let leaf = note_leaf(cs, head, v, npk, rho);")),
    ("`note_leaf` (`spend.rs` l. {})", (SPEND, "fn note_leaf(")),
    ("(1 − [v_i = 0]) = 0` | l. {}–{} |", (SPEND, 'cs.at(format!("in{i} membership"))'), (SPEND, "cs.gate(diff, dummy,")),
    ("`merkle_root` (l. {})", (GADGETS, "pub fn merkle_root(")),
    ("`Cs::is_zero` (`cs.rs` l. {})", (CS, "pub fn is_zero(")),
    ("`nf_i = H_3(nk_i, leaf_i, index_i)` | l. {}–{} |", (SPEND, 'cs.at(format!("in{i} nullifier"))'), (SPEND, "cs.assert_eq(nfh, nf_i);")),
    ("(8·Ak_i)` | l. {}–{} |", (SPEND, 'cs.at(format!("in{i} signature"))'), (SPEND, "gadgets::eddsa_verify(cs, ak, r8, s, body);")),
    ("`eddsa_verify` (l. {}): `assert_on_curve` (l. {})", (GADGETS, "pub fn eddsa_verify("), (GADGETS, "pub fn assert_on_curve(")),
    ("`canonical_bits_254` (l. {}), `ec_add` (l. {}), `var_mul` (l. {})",
     (GADGETS, "pub fn canonical_bits_254("), (GADGETS, "pub fn ec_add("), (GADGETS, "pub fn var_mul(")),
    ("H(npk'_k, rho'_k))` | l. {}–{} |", (SPEND, 'cs.at(format!("out{k} value"))'), (SPEND, "cs.assert_eq(leaf, out_leaf_k);")),
    ("`vPub·(t − tPub) = 0` | l. {}–{} |", (SPEND, 'cs.at("public value")'), (SPEND, "cs.assert_mul_zero(v_pub, dt);")),
    ("+ vPub` in `F` | l. {}–{} |", (SPEND, 'cs.at("conservation")'), (SPEND, "cs.assert_eq(sum_in, sum_out);")),
    ("(`Cs::gate`, `cs.rs` l. {})", (CS, "pub fn gate(")),
    # §2 The rules an indexer adds
    ("`codec.js` `fr()` l. {};", (CODEC, "fr() {")),
    ("(`ffi.rs` l. {}) |", (FFI, "plonk::fr_from_bytes(")),
    ("`_checkSpend` l. {}–{} |", (INDEXER, "anchorWindow: W, anchorMinDepth: K"), (INDEXER, "throw new Reject('unknown anchor')")),
    ("then recorded | l. {}–{}, `_commitSpend` l. {} |",
     (INDEXER, "const [n0, n1] = spend.nf;"), (INDEXER, "throw new Reject('nullifier already spent')"), (INDEXER, "this._add(this.nullifiers, hexFr(x))")),
    ("room for three leaves | l. {}–{} |", (INDEXER, "const outLeaves = spend.outs.map("), (INDEXER, "this._roomFor(N_OUT);")),
    ("from the bytes before the proof | l. {} |", (INDEXER, "const bodyHash = BigInt(")),
    ('`(D, t("SH20"))` | l. {}, {}, {}, {} |',
     (INDEXER, "this._checkSpend(env.spend, body, 0n, 0n, H)"), (INDEXER, "this._checkSpend(env.spend, body, env.vPub, t.t, H)"),
     (INDEXER, "this._checkSpend(env.spend, body, env.amount, t.t, H)"), (INDEXER, "this._checkSpend(env.spend, body, D, tickerT(this.genesis), H)")),
    ("`_outOfPool` l. {}, called at l. {}, {}, {} |",
     (INDEXER, "_outOfPool(ticker, v, apply = true) {"), (INDEXER, "this._outOfPool(this.genesis, D, false);"),
     (INDEXER, "this._outOfPool(t.ticker, env.vPub, false);"), (INDEXER, "this._outOfPool(t.ticker, env.amount, false);")),
    ("`adapters/plonk.js` l. {}–{} |", ("indexer/src/adapters/plonk.js", "update(DOMAIN.VK, 'utf8')"), ("indexer/src/adapters/plonk.js", "is not the pinned")),
    ("`rejectAllVerifier` l. {} |", (INDEXER, "export const rejectAllVerifier")),
    ("`_list` l. {}; `codec.js` l. {} |", (INDEXER, "lock output must be P2TR to lockKey"), (CODEC, "const lockKey = r.bytes(32);")),
    # §2 The proof system
    ("(`srs.rs` l. {})", ("circuit/src/plonk/srs.rs", "pub const POT18_BLAKE2B")),
    ("(`keys.rs` `setup`, l. {})", (PKEYS, "pub fn setup(")),
    ("(`plonk/mod.rs` l. {})", ("circuit/src/plonk/mod.rs", "pub fn from_bytes(b: &[u8]) -> Option<Proof>")),
    ("(`verifier.rs` l. {})", ("circuit/src/plonk/verifier.rs", "fn check(vk: &VerifyingKey")),
    ("(`transcript.rs` l. {})", ("circuit/src/plonk/transcript.rs", "pub fn beta_gamma(")),
    # §6.1
    ("(`_take`, `indexer.js` l. {})", (INDEXER, "_take(env, tx, spentLocks) {")),
    ("`codec.js` l. {} and l. {})", (CODEC, "const lockKey = r.bytes(32);"), (CODEC, "throw new CodecError('lockKey must be 32 bytes')")),
    ("(`indexer.js` l. {}), and records the key from the envelope, not from the transaction (l. {})",
     (INDEXER, "lock output must be P2TR to lockKey"), (INDEXER, "lockKey: env.lockKey.toString('hex')")),
    ("(`_claim`, l. {})", (INDEXER, "throw new Reject('bad CLAIM signature')")),
    # §6.2, §6.4, §6.6
    ("`finish_add` (l. {}):", (GADGETS, "fn finish_add(")),
    ("`canonical_bits_254` (l. {}): the comparison", (GADGETS, "pub fn canonical_bits_254(")),
    ("`scalar_bits` (l. {}) on `nk`", (GADGETS, "pub fn scalar_bits(")),
    ("`add_const_if` (l. {}):", (GADGETS, "fn add_const_if(")),
    ("`poseidon` (l. {}): the partial rounds", (GADGETS, "pub fn poseidon(")),
    ("`spend.rs` l. {}: the gate that waives", (SPEND, "cs.gate(diff, dummy,")),
    ("(`gadgets.rs` l. {}–{}; four gates each", (GADGETS, "assert_on_curve(cs, a);"), (GADGETS, "assert_on_curve(cs, r8);")),
    ("`sh20_prove` (`ffi.rs` l. {})", (FFI, "fn sh20_prove(")),
    # §6.10
    ("(`_deploy`, `indexer.js` l. {};", (INDEXER, "DEPLOY commit confirmed less than")),
    # §8, the "Checked" paragraphs and the open findings
    ("Checked: `app.js` l. {} stops", (V + "app.js", "gatewayKind() === 'path'")),
    ("`refuseSharedOrigin` (`keys.js` l. {})", (V + "keys.js", "function refuseSharedOrigin")),
    ("Checked: `offerTerms` (`market.js` l. {}), called by `copyOffer` (`ui/market-panel.js` l. {})",
     (V + "market.js", "export async function offerTerms"), (V + "ui/market-panel.js", "async function copyOffer")),
    ("Checked: `listingCheck` (`consensus.js` l. {}) and `TAKE_QUORUM = 2` (l. {})",
     (V + "consensus.js", "export async function listingCheck"), (V + "consensus.js", "export const TAKE_QUORUM = 2")),
    ("`checkedListing` (`ui/market-panel.js` l. {}) and again just before the TAKE is built (l. {})",
     (V + "ui/market-panel.js", "async function checkedListing"), (V + "ui/market-panel.js", "fresh.enough")),
    ("Checked: `exportBackup` (`keys.js` l. {}) throws without a key; `setPassphrase` (l. {}), `restore` (l. {}) and `#checkUnchanged` (l. {})",
     (V + "keys.js", "exportBackup() {"), (V + "keys.js", "async setPassphrase"), (V + "keys.js", "static async restore"), (V + "keys.js", "#checkUnchanged() {")),
    ("for the passphrase (`ui/vault-panel.js` l. {})", (V + "ui/vault-panel.js", "const showWords")),
    ("passphrase stays optional (`ui/vault-panel.js` l. {})", (V + "ui/vault-panel.js", "without a passphrase")),
    ("Checked: `digestAgreement` (`consensus.js` l. {}), called at every sync (`ui/notes-panel.js` l. {})",
     (V + "consensus.js", "export async function digestAgreement"), (V + "ui/notes-panel.js", "digestAgreement(")),
    ("(`refusalAgreed`, `consensus.js` l. {})", (V + "consensus.js", "export async function refusalAgreed")),
    ("(`requireProfile`, `ui/context.js` l. {})", (V + "ui/context.js", "export async function requireProfile")),
    ("Checked: `scanOutput` (`notekeys.js` l. {})", (V + "notekeys.js", "export async function scanOutput")),
    ("`matchNotes` (`match.js` l. {})", (V + "match.js", "export async function matchNotes")),
    ("`Sync.scanned(from)` (`sync.js` l. {})", (V + "sync.js", "async scanned(from = null)")),
    ("(`isLowOrder`, l. {}), and `x25519` (l. {})", (SUBTLE, "export function isLowOrder(u)"), (SUBTLE, "export async function x25519(")),
    ("`indexer/src/schnorr.js` `sign` (l. {})", (SCHNORR, "export function sign(secret")),
    ("before `bip340Sign` (l. {}) returns it", (V + "secp256k1.js", "export function bip340Sign(")),
    ("`lock()` (`keys.js` l. {})", (V + "keys.js", "lock() {")),
    ("goes through `lockVault` (`ui/vault-panel.js` l. {})", (V + "ui/vault-panel.js", "export function lockVault(")),
    ("`lock()` (`keys.js` l. {}) zeroes the master secret, the viewing key", (V + "keys.js", "lock() {")),
    ("(`ui/spends.js` l. {}): the next proof", (V + "ui/spends.js", "built.witness.fill(0);")),
    ("by the vault's own rule (`keys.js` l. {})", (V + "keys.js", "async lockOutput(index)")),
    # §8, the table "Read and found as intended"
    ("| `bip39.js` l. {}, l. {}; `keys.js` l. {} |",
     (V + "bip39.js", "export const newMnemonic"), (V + "bip39.js", "export async function mnemonicToSeed"), (V + "keys.js", "static async fromWords")),
    ("| `keys.js` l. {}; `taproot.js` l. {} |", (V + "keys.js", "async lockOutput(index)"), (V + "taproot.js", "export function keyPathOutput")),
    ("| `keys.js` l. {}; `spend.js` l. {} |", (V + "keys.js", "async receive(out)"), (V + "spend.js", "does not open with this vault")),
    ("| `send.js` l. {}, l. {}; `spend.js` l. {} |",
     (V + "send.js", "await decodeAddress(NETWORK_HRP"), (V + "send.js", "export function shuffled"), (V + "spend.js", "await seal(o.address")),
    ("| `notekeys.js` l. {}; `sync.js` |", (V + "notekeys.js", "export function nullifierOf")),
    ("(§6.8) | `spend.js` l. {} |", (V + "spend.js", "function dummyInput")),
    ("| `spend.js` l. {}–{}; `send.js` l. {} |",
     (V + "spend.js", "const bytes = serializeEnvelope(env)"), (V + "spend.js", "eddsaVerify(x.keys.ak"), (V + "send.js", "export async function proveSpend")),
    ("| `prover-worker.js` l. {};", (V + "prover-worker.js", "export function proveWithFreshSeed")),
    ("| `prover.js` l. {} |", (V + "prover.js", "the proving key gives verifying key")),
    ("| `taproot.js` l. {} |", (V + "taproot.js", "export function sigMsg")),
    ("| `market.js` l. {}–{}, l. {} |",
     (V + "market.js", "function offerSkeleton"), (V + "market.js", "schnorrVerify(Buffer.from(l.lockKey)"), (V + "market.js", "the lock output is not P2TR")),
    ("| `secp256k1.js` l. {}; `taproot.js` l. {}, l. {} |",
     (V + "secp256k1.js", "export function bip340Sign("), (V + "taproot.js", "export function signKeyPath"), (V + "taproot.js", "export function signReveal")),
    ("| `keys.js` l. {}, l. {} |", (V + "keys.js", "async function aesKey"), (V + "keys.js", "async #record()")),
    ("| `app.js` l. {}, l. {}; `ui/context.js` l. {}; `ui/spends.js` l. {} and `ui/tokens-panel.js` l. {} |",
     (V + "app.js", "window.top !== window.self"), (V + "app.js", "await available()"), (V + "ui/context.js", "asks the vault to use other servers"),
     (V + "ui/spends.js", "sameUnsignedTx(done.tx"), (V + "ui/tokens-panel.js", "sameUnsignedTx(done.tx")),
]

# (commit, words of docs/AUDIT.md with {}, then (file, line, text of that line at the commit) for each {})
OLD = [
    (OLD_VAULT, "[`app.js`](../vault/src/app.js) l. {}. On", (V + "app.js", 137, "This page is served from a path gateway")),
    (OLD_VAULT, "`copyOffer` (`app.js` l. {}) signs the listing returned by `ownListing` (l. {})",
     (V + "app.js", 1070, "async function copyOffer(rec)"), (V + "app.js", 1012, "async function ownListing(rec)")),
    (OLD_VAULT, "(`pending[].revealHex`, l. {})", (V + "app.js", 1015, "?.revealHex")),
    (OLD_VAULT, "accepted on its txid (`market.js` l. {})", (V + "market.js", 123, "Esplora returned another transaction than the listing")),
    (OLD_VAULT, "reports the same terms (l. {})", (V + "market.js", 139, "if (indexed) {")),
    (OLD_VAULT, "`signOffer` (l. {}) signs", (V + "market.js", 94, "export function signOffer(")),
    (OLD_VAULT, "`checkedListing` (`app.js` l. {}) asks", (V + "app.js", 997, "async function checkedListing(listTxid)")),
    (OLD_VAULT, "[`keys.js`](../vault/src/keys.js) l. {}: the record is", (V + "keys.js", 160, "return { v: 0, plain: inner }")),
    (OLD_VAULT, "(a `confirm`, `app.js` l. {})", (V + "app.js", 189, "Create the vault without a passphrase?")),
    (OLD_VAULT, "(`exportBackup`, l. {})", (V + "keys.js", 171, "exportBackup() {")),
    (OLD_VAULT, "(`open`, l. {}, takes `rec.plain`", (V + "keys.js", 132, "if (rec.plain) {")),
    (OLD_VAULT, '"Show recovery words" (`app.js` l. {})', (V + "app.js", 159, "st.showWords = !st.showWords")),
    (OLD_VAULT, "own root (l. {}): consistency with itself", (V + "sync.js", 106, "const want = String(status.root).toLowerCase();")),
    (OLD_VAULT, "[`notekeys.js`](../vault/src/notekeys.js) l. {} catches", (V + "notekeys.js", 34, "} catch {")),
    (OLD_VAULT, "without X25519 (`app.js` l. {})", (V + "app.js", 34, "if (!(await available())) {")),
]

# (file, the title as docs/AUDIT.md quotes it): a Rust test function, or the start or a part of the
# title of a JavaScript test
T, I, J = "circuit/tests/", "indexer/test/", "circuit/js/test/"
TESTS = [
    (T + "spend.rs", "adversarial_witnesses_are_rejected"),
    (T + "spend.rs", "valid_spends_satisfy_the_circuit"),
    (T + "spend.rs", "the_gates_do_not_depend_on_the_witness"),
    (T + "spend.rs", "leaf_tag_matches_the_indexer"),
    (T + "spend.rs", "ticker_ids_match_the_indexer"),
    (T + "constraints.rs", "every_variable_alone_is_pinned"),
    (T + "constraints.rs", "every_choice_of_the_prover_reaches_a_check"),
    (T + "constraints.rs", "the_probe_sees_a_missing_check"),
    (T + "gadgets.rs", "on_curve_accepts_the_curve_and_nothing_else"),
    (T + "gadgets.rs", "ranges_end_where_they_say"),
    (T + "gadgets.rs", "the_second_decomposition_of_a_field_element_is_refused"),
    (T + "gadgets.rs", "keys_of_small_order_do_not_sign"),
    (T + "gadgets.rs", "a_key_outside_the_prime_subgroup_still_signs_for_its_owner"),
    (T + "prove.rs", "rejected_witnesses_have_no_proof"),
    (T + "prove.rs", "transfer_burn_and_dummies_prove_and_verify"),
    (T + "prove.rs", "shipped_key_is_reproducible"),
    (T + "prove.rs", "a_key_file_that_is_not_the_pinned_one_is_refused"),
    (T + "prove.rs", "field_helpers"),
    (T + "plonk.rs", "prove_and_verify"),
    (T + "plonk.rs", "a_proof_made_by_snarkjs_is_accepted"),
    (T + "vectors.rs", "poseidon_matches_circomlibjs_for_every_width"),
    (T + "vectors.rs", "small_order_keys_do_not_verify"),
    (T + "vectors.rs", "the_wallet_vectors_are_the_ones_the_model_writes"),
    (I + "plonk.test.js", "a verifying key other than the pinned one is refused"),
    (I + "plonk.test.js", "real TRANSFER and BURN proofs are accepted, and only once"),
    (I + "plonk.test.js", "a proof does not carry over to an altered envelope"),
    (I + "plonk.test.js", "a TRANSFER proof cannot be replayed as a BURN"),
    (I + "indexer.test.js", "TRANSFER: anchor window, nullifiers, proof"),
    (I + "indexer.test.js", "the default verifier accepts no proof at all"),
    (I + "indexer.test.js", "turnstile: no spend takes more of a ticker out of the pool than went in, even with a broken circuit"),
    (I + "indexer.test.js", "turnstile: TAKE, CLAIM and team unlocks bring units back into the pool, and a rollback restores it"),
    (I + "indexer.test.js", "a LIST copied into another transaction cannot point its lock at the copier"),
    (I + "indexer.test.js", "LIST needs a P2TR lock to its lockKey, of at least 330 sats"),
    (I + "codec.test.js", "strict parsing rejects malformed envelopes"),
    (I + "codec.test.js", "carrier rules: one envelope per transaction"),
    (J + "notes.test.js", "scanning refuses anything altered"),
    (J + "notes.test.js", "a note whose plaintext lies about its leaf is ignored"),
    (J + "webcrypto.test.js", "X25519: a failure of the platform is thrown, never read as a point of low order"),
    ("vault/test/audit8.test.js", "8.1 no vault is created"),
    ("vault/test/audit8.test.js", "8.1 the page says where"),
    ("vault/test/audit8.test.js", "8.2 an offer is signed only for terms the vault vouches for"),
    ("vault/test/audit8.test.js", "8.3 an indexer that answers and does not know the listing refuses it"),
    ("vault/test/audit8.test.js", "8.4 no backup in clear"),
    ("vault/test/audit8.test.js", "8.4 a clear backup restored with a passphrase"),
    ("vault/test/audit8.test.js", "8.4 a tab that holds the vault"),
    ("vault/test/audit8.test.js", "8.5 every sync compares the root and the digest"),
    ("vault/test/audit8.test.js", "8.6 a scan that could not be made throws"),
    ("vault/test/audit8.test.js", "8.6 a note whose scan throws does not stop the others"),
    ("vault/test/secp256k1.test.js", "8.7 k·G takes the same time"),
    ("vault/test/autolock.test.js", "8.8 the vault locks itself after ten minutes"),
]

# a line reference of the document: "l. 12", "l. 12–14", "l. 12, 14, 16" (each number is one)
REFERENCE = re.compile(r"\bl\.\s+\d+(?:(?:–|,\s+)\d+)*")


def words_pattern(words):
    """The words as a pattern: {} is a number, any run of spaces or line breaks is one."""
    out = []
    for i, part in enumerate(words.split("{}")):
        if i:
            out.append(r"(\d+)")
        out.append(r"\s+".join(re.escape(w) for w in part.split(" ")))
    return re.compile("".join(out))


def lines_of(path, commit=None):
    """The lines of a file of the tree, or of a commit; None when it is not there."""
    if commit is None:
        p = ROOT / path
        return p.read_text(encoding="utf-8").split("\n") if p.is_file() else None
    r = subprocess.run(["git", "-C", str(ROOT), "show", f"{commit}:{path}"], capture_output=True)
    return r.stdout.decode("utf-8").split("\n") if r.returncode == 0 else None


def has_commit(commit):
    try:
        r = subprocess.run(["git", "-C", str(ROOT), "cat-file", "-e", commit + "^{commit}"], capture_output=True)
    except OSError:  # no git here
        return False
    return r.returncode == 0


def test_titles(path):
    """What a test file defines: Rust test functions, or the titles given to test() and it()."""
    text = (ROOT / path).read_text(encoding="utf-8")
    if path.endswith(".rs"):
        return re.findall(r"#\[test\]\s*(?:#\[[^\]]*\]\s*)*fn\s+(\w+)\s*\(", text)
    return [m.group(2) for m in re.finditer(r"\b(?:test|it)\(\s*(['\"`])(.*?)\1", text)]


def main(fix):
    doc_path = ROOT / DOC
    doc = doc_path.read_text(encoding="utf-8")
    line_of = lambda pos: doc.count("\n", 0, pos) + 1
    problems = []
    rewrites = []  # (start, end, new number): the numbers --fix can rewrite
    covered = set()  # where in the document a number belongs to an entry
    cursor = 0  # the end of the last citation found: the entries follow the document's order
    old_seen = {}  # commit -> whether this clone has it

    def find(words, n):
        """The citation `words` after the last one found, or None after reporting."""
        nonlocal cursor
        numbers = words.count("{}")
        if numbers != n:
            problems.append(f"{SELF}: the entry {words!r} has {numbers} numbers and {n} lines")
            return None
        pattern = words_pattern(words)
        m = pattern.search(doc, cursor)
        if not m:
            earlier = pattern.search(doc)
            hint = f"; it is at line {line_of(earlier.start())}, and the entries follow the document's order" if earlier else "; if the sentence was reworded, correct the entry"
            problems.append(f"{SELF}: after line {line_of(cursor)} of {DOC}, no citation reads {words!r}{hint}")
            return None
        cursor = m.end()
        covered.update(m.start(i) for i in range(1, n + 1))
        return m

    for words, *holds in CITES:
        m = find(words, len(holds))
        for i, (path, text) in enumerate(holds if m else [], 1):
            cited, at = int(m.group(i)), f"{DOC}:{line_of(m.start(i))}"
            lines = lines_of(path)
            if lines is None:
                problems.append(f"{at}: cites {path} l. {cited}, and that file is gone")
            elif not 1 <= cited <= len(lines) or text not in lines[cited - 1]:
                now = [n + 1 for n, line in enumerate(lines) if text in line]
                if len(now) == 1:
                    rewrites.append((m.start(i), m.end(i), now[0]))
                    problems.append(f"{at}: {path} l. {cited} should hold {text!r}; that text is now at l. {now[0]} (--fix rewrites the number)")
                elif now:
                    problems.append(f"{at}: {path} l. {cited} should hold {text!r}; that text is at l. {', '.join(map(str, now))}: correct the number by hand")
                else:
                    problems.append(f"{at}: {path} l. {cited} should hold {text!r}; no line of the file does: correct the sentence and its entry")

    cursor = 0
    for commit, words, *holds in OLD:
        m = find(words, len(holds))
        if commit not in old_seen:
            old_seen[commit] = has_commit(commit)
        for i, (path, fixed, text) in enumerate(holds if m else [], 1):
            cited, at = int(m.group(i)), f"{DOC}:{line_of(m.start(i))}"
            if cited != fixed:
                problems.append(f"{at}: cites {path} l. {cited} of {commit}; its entry says l. {fixed}")
            elif old_seen[commit]:
                lines = lines_of(path, commit)
                if lines is None or not 1 <= cited <= len(lines) or text not in lines[cited - 1]:
                    problems.append(f"{at}: {path} l. {cited} of {commit} does not hold {text!r}")

    # Every line reference of the document belongs to an entry.
    for m in REFERENCE.finditer(doc):
        if any(m.start() + n.start() not in covered for n in re.finditer(r"\d+", m.group(0))):
            problems.append(f"{DOC}:{line_of(m.start())}: the line reference {m.group(0)!r} has no entry in {SELF}: add one (the file, and a piece of the text that line holds)")

    # Every quoted test is in its file, and still quoted.
    flat = re.sub(r"\s+", " ", doc)
    defined = {}
    for path, title in TESTS:
        if path not in defined:
            defined[path] = test_titles(path) if (ROOT / path).is_file() else None
        if defined[path] is None:
            problems.append(f"{DOC}: quotes the test {title!r} of {path}, and that file is gone")
        elif not any(title == t if path.endswith(".rs") else title in t for t in defined[path]):
            problems.append(f"{DOC}: quotes the test {title!r}, and {path} has no test of that name: renamed or removed")
        if title not in flat:
            problems.append(f"{SELF}: {DOC} no longer quotes the test {title!r} of {path}: remove its entry")

    # Every relative link leads to a file.
    links = sorted(l for l in set(re.findall(r"\]\(([^)#\s]+)\)", doc)) if "://" not in l)
    for link in links:
        if not (doc_path.parent / link).exists():
            problems.append(f"{DOC}: the link ({link}) leads to no file")

    if fix and rewrites:
        for start, end, new in sorted(rewrites, reverse=True):
            doc = doc[:start] + str(new) + doc[end:]
        doc_path.write_text(doc, encoding="utf-8")
        print(f"{DOC}: {len(rewrites)} line number(s) rewritten. Read the sentence around each of them: a line that moved may do something else.")
        return main(False)

    for p in problems:
        print(p)
    unseen = sorted(c for c, seen in old_seen.items() if not seen)
    note = f" (fixed in the table; not compared with {', '.join(unseen)}, which this clone does not have)" if unseen else ""
    counts = f"{sum(len(e) - 1 for e in CITES)} lines, {sum(len(e) - 2 for e in OLD)} lines of older commits{note}, {len(TESTS)} tests and {len(links)} links"
    print(f"{DOC}: {counts} checked, {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    if set(sys.argv[1:]) - {"--fix"}:
        sys.exit(__doc__)
    sys.exit(main("--fix" in sys.argv[1:]))
