pragma circom 2.1.6;

// Building blocks for spend.circom.
//
// Derived from Tacit's Bitcoin shielded pool (dapp/circuits/btc-pool/btc_pool_templates.circom),
// MIT License, Copyright (c) 2026 ross. Changes for SH-20: the note leaf (docs/SPEC-WIRE.md §2).
//
// Hashes are circomlib Poseidon over BN254 Fr; keys live on BabyJubJub at circomlib's Base8.

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/compconstant.circom";
include "circomlib/circuits/escalarmulfix.circom";
include "circomlib/circuits/switcher.circom";

function BASE8_U() { return 5299619240641551281634865583518297030282874472190772894086521144482721001553; }
function BASE8_V() { return 16950150798460657717958625567821834550301663161624707787222815936182638968203; }
// Prime subgroup order l of BabyJubJub, minus one.
function BJJ_L_MINUS_1() { return 2736030358979909402780800718157159386076813972158567259200215660948447373040; }
// SHA256("sh20/v0/leaf") mod r (indexer/src/constants.js DOMAIN.LEAF).
function TAG_LEAF() { return 3964790311269703051632412659544446401452490375142520467617899154258410484374; }

// out = k·Base8 for a canonical scalar 0 ≤ k < l. l < 2^251, so Num2Bits(251) plus k ≤ l−1 gives each
// point exactly one scalar.
template CanonicalKeyMul() {
    signal input k;
    signal output out[2];

    component bits = Num2Bits(251);
    bits.in <== k;

    component lt = CompConstant(BJJ_L_MINUS_1());
    for (var i = 0; i < 251; i++) lt.in[i] <== bits.out[i];
    lt.in[251] <== 0;
    lt.in[252] <== 0;
    lt.in[253] <== 0;
    lt.out === 0;

    var B[2];
    B[0] = BASE8_U();
    B[1] = BASE8_V();
    component m = EscalarMulFix(251, B);
    for (var i = 0; i < 251; i++) m.e[i] <== bits.out[i];
    out[0] <== m.out[0];
    out[1] <== m.out[1];
}

// in ≠ 0, by exhibiting its inverse.
template NonZero() {
    signal input in;
    signal inv;
    inv <-- in != 0 ? 1 / in : 0;
    in * inv === 1;
}

// Poseidon(2) Merkle path of fixed depth. index < 2^depth is enforced by the bit decomposition.
template MerkleRoot(depth) {
    signal input leaf;
    signal input index;
    signal input path[depth];
    signal output root;

    component bits = Num2Bits(depth);
    bits.in <== index;

    component sw[depth];
    component h[depth];
    for (var i = 0; i < depth; i++) {
        sw[i] = Switcher();
        sw[i].L <== i == 0 ? leaf : h[i - 1].out;
        sw[i].R <== path[i];
        sw[i].sel <== bits.out[i];
        h[i] = Poseidon(2);
        h[i].inputs[0] <== sw[i].outL;
        h[i].inputs[1] <== sw[i].outR;
    }
    root <== h[depth - 1].out;
}

// head = H(TAG_LEAF, t). One per proof: the five notes share the same private t.
template LeafHead() {
    signal input t;
    signal output out;

    component h = Poseidon(2);
    h.inputs[0] <== TAG_LEAF();
    h.inputs[1] <== t;
    out <== h.out;
}

// leaf = H(H(head, v), H(npk, rho)) with head = H(TAG_LEAF, t)      (indexer/src/notes.js)
template NoteLeaf() {
    signal input head;
    signal input v;
    signal input npk;
    signal input rho;
    signal output out;

    component hv = Poseidon(2);
    hv.inputs[0] <== head;
    hv.inputs[1] <== v;
    component hk = Poseidon(2);
    hk.inputs[0] <== npk;
    hk.inputs[1] <== rho;
    component h = Poseidon(2);
    h.inputs[0] <== hv.out;
    h.inputs[1] <== hk.out;
    out <== h.out;
}
