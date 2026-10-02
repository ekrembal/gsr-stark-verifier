//! Bounded SHA/WHIR/transcript differential diagnostic; execution only.
#[path = "../../../../tests/sha256_vectors.rs"]
mod vectors;

fn main() {
    let output = vectors::run();
    risc0_zkvm::guest::env::commit_slice(&output);
}
