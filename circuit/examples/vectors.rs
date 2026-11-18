//! Writes the wallet reference vectors: cargo run --release --example vectors -- js/vectors.json

fn main() {
    let out = std::env::args().nth(1).expect("output file");
    std::fs::write(&out, sh20_circuit::vectors::reference_vectors()).expect("write");
    println!("{out} written");
}
