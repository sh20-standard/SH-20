pragma circom 2.1.6;

// x³ + x + 5 = y with y public. A small relation of our own, proved by snarkjs' PLONK prover so
// that the verifier in src/plonk/ is checked against a proof it did not make
// (bench/cross-check.sh, tests/fixtures/snarkjs/).

template Cubic() {
    signal input x;
    signal output y;
    signal x2;
    signal x3;
    x2 <== x * x;
    x3 <== x2 * x;
    y <== x3 + x + 5;
}

component main = Cubic();
