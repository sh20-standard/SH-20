pragma circom 2.1.6;

// SH-20 spend relation (docs/SPEC-WIRE.md §4): 2 input notes, 3 output notes, one private ticker.
//
// Derived from Tacit's Bitcoin shielded pool (dapp/circuits/btc-pool/spend.circom), MIT License,
// Copyright (c) 2026 ross. Changes for SH-20: the ticker is private (one t for the five notes, bound to
// tPub only when value leaves), the SH-20 note leaf, the public inputs and their order, and no
// transparent boundary (no exit / deposit commitments, no empty slots).
//
//   npk  = Poseidon(Ak.x, Ak.y, NK.x, NK.y)        Ak = per-note spend key, NK = nk·Base8
//   leaf = H(H(H(TAG_LEAF, t), v), H(npk, rho))    H = Poseidon(2)
//   nf   = Poseidon(nk, leaf, index)               0 ≤ nk < l, index < 2^32
//   tree = Poseidon(2), depth 32
//
// Public inputs, in the order the verifier passes them:
//   root, nf[0], nf[1], outLeaf[0], outLeaf[1], outLeaf[2], bodyHash, vPub, tPub
//
// Every slot is live. An input with v = 0 is a dummy: it skips membership only, so its nullifier is
// still derived from nk, its leaf and its index, and it is still signed. A dummy output is a note
// with v = 0.
//
// Spend authority: EdDSA-Poseidon under Ak over bodyHash. The witness holds the signature, never the
// spend scalar, so a delegated prover can only prove the body the owner signed.
//
//   Σ inV = Σ outV + vPub, every term < 2^64          vPub · (t − tPub) = 0

include "./templates.circom";
include "circomlib/circuits/eddsaposeidon.circom";

template Sh20Spend(depth, nIn, nOut) {
    // public (declaration order = verifier order)
    signal input root;
    signal input nf[nIn];
    signal input outLeaf[nOut];
    signal input bodyHash;
    signal input vPub;
    signal input tPub;

    // private
    signal input t;
    signal input inV[nIn];
    signal input inRho[nIn];
    signal input inNk[nIn];
    signal input inAk[nIn][2];
    signal input inIndex[nIn];
    signal input inPath[nIn][depth];
    signal input sigR8[nIn][2];
    signal input sigS[nIn];
    signal input outV[nOut];
    signal input outNpk[nOut];
    signal input outRho[nOut];

    component head = LeafHead();
    head.t <== t;

    component inRange[nIn];
    component nk[nIn];
    component npk[nIn];
    component leaf[nIn];
    component tree[nIn];
    component inZero[nIn];
    component nfh[nIn];
    component sig[nIn];

    var sumIn = 0;
    for (var i = 0; i < nIn; i++) {
        inRange[i] = Num2Bits(64);
        inRange[i].in <== inV[i];

        nk[i] = CanonicalKeyMul();
        nk[i].k <== inNk[i];

        npk[i] = Poseidon(4);
        npk[i].inputs[0] <== inAk[i][0];
        npk[i].inputs[1] <== inAk[i][1];
        npk[i].inputs[2] <== nk[i].out[0];
        npk[i].inputs[3] <== nk[i].out[1];

        leaf[i] = NoteLeaf();
        leaf[i].head <== head.out;
        leaf[i].v <== inV[i];
        leaf[i].npk <== npk[i].out;
        leaf[i].rho <== inRho[i];

        // membership unless v = 0
        tree[i] = MerkleRoot(depth);
        tree[i].leaf <== leaf[i].out;
        tree[i].index <== inIndex[i];
        for (var j = 0; j < depth; j++) tree[i].path[j] <== inPath[i][j];
        inZero[i] = IsZero();
        inZero[i].in <== inV[i];
        (tree[i].root - root) * (1 - inZero[i].out) === 0;

        nfh[i] = Poseidon(3);
        nfh[i].inputs[0] <== inNk[i];
        nfh[i].inputs[1] <== leaf[i].out;
        nfh[i].inputs[2] <== inIndex[i];
        nfh[i].out === nf[i];

        sig[i] = EdDSAPoseidonVerifier();
        sig[i].enabled <== 1;
        sig[i].Ax <== inAk[i][0];
        sig[i].Ay <== inAk[i][1];
        sig[i].R8x <== sigR8[i][0];
        sig[i].R8y <== sigR8[i][1];
        sig[i].S <== sigS[i];
        sig[i].M <== bodyHash;

        sumIn += inV[i];
    }

    component outRange[nOut];
    component outH[nOut];
    var sumOut = vPub;
    for (var k = 0; k < nOut; k++) {
        outRange[k] = Num2Bits(64);
        outRange[k].in <== outV[k];

        outH[k] = NoteLeaf();
        outH[k].head <== head.out;
        outH[k].v <== outV[k];
        outH[k].npk <== outNpk[k];
        outH[k].rho <== outRho[k];
        outH[k].out === outLeaf[k];

        sumOut += outV[k];
    }

    component pubRange = Num2Bits(64);
    pubRange.in <== vPub;

    // value leaves the pool only under the public ticker
    vPub * (t - tPub) === 0;

    sumIn === sumOut;
}

component main {public [root, nf, outLeaf, bodyHash, vPub, tPub]} = Sh20Spend(32, 2, 3);
