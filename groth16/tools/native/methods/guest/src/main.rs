#![no_main]
#![no_std]

use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

fn main() {
    env::commit_slice(b"groth16 GSR verifier fixture v1");
}
