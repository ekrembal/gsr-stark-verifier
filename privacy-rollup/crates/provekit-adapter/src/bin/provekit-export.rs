//! `provekit-export <pkv> <vk.out> [<proof.np> <proof.out>]`: writes the guest (postcard) encodings
//! of a verifier key and optionally a proof, and prints the verifier key's SHA-256.
use provekit_common::{file::read, NoirProof};
use sha2::{Digest, Sha256};

fn main() -> anyhow::Result<()> {
    let a: Vec<String> = std::env::args().collect();
    let vk = pr_provekit_adapter::guest_verifier_bytes(&pr_provekit_adapter::load_verifier(a[1].as_ref())?)?;
    std::fs::write(&a[2], &vk)?;
    println!("{}", hex::encode(Sha256::digest(&vk)));
    if a.len() == 5 {
        let proof: NoirProof = read(a[3].as_ref())?;
        std::fs::write(&a[4], pr_provekit_adapter::guest_proof_bytes(&proof)?)?;
    }
    Ok(())
}
