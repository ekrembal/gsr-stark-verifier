//! The settlement guest: verifies every join-split proof in a batch, applies the state transition,
//! and commits the 196-byte `BatchJournal` that the GSR covenant rebuilds from `OP_TX`.
//!
//! Input frames: `postcard(BatchWitness)`, then, iff the batch is non-empty, the postcard ProveKit
//! verifier key followed by one postcard `NoirProof` per transaction (in batch order). The verifier
//! key is pinned by its SHA-256, so the image ID fixes the join-split circuit.
use pr_protocol_types::Canonical;
use pr_state_transition::{apply_batch, BatchWitness};
use provekit_common::{NoirProof, Verifier};
use provekit_verifier::Verify;
use risc0_zkvm::guest::env;
use risc0_zkvm::sha::{Impl, Sha256};

const VERIFIER_KEY_SHA256: [u8; 32] = *include_bytes!("../../../../fixtures/joinsplit/verifier-key.sha256");

fn main() {
    let witness: BatchWitness = postcard::from_bytes(&env::read_frame()).expect("batch witness");
    if !witness.transactions.is_empty() {
        let vk = env::read_frame();
        assert_eq!(Impl::hash_bytes(&vk).as_bytes(), &VERIFIER_KEY_SHA256, "join-split verifier key");
        let verifier: Verifier = postcard::from_bytes(&vk).expect("verifier key");
        for t in &witness.transactions {
            let proof: NoirProof = postcard::from_bytes(&env::read_frame()).expect("proof");
            let statement: Vec<_> = t.public.public_inputs().iter().map(pr_crypto::to_fr).collect();
            assert!(proof.public_inputs.0 == statement, "proof public inputs differ from the statement");
            verifier.verify_ref(&proof).expect("join-split proof");
        }
    }
    let effects = apply_batch(&witness).expect("state transition");
    env::commit_slice(&effects.journal.encode());
}
