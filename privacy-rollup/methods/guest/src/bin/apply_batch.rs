//! The settlement guest: verifies every join-split proof in a batch, applies the state transition,
//! and commits the 196-byte `BatchJournal` that the GSR covenant rebuilds from `OP_TX`.
//!
//! Input frames: `postcard(BatchWitness)`, then one postcard `NoirProof` per transaction (in batch
//! order). The join-split verifier configuration is compiled into the image (exported from the
//! ProveKit key with SHA-256 `FixedJoinSplitVerifier::KEY_HASH`), so the image ID fixes the circuit.
use pr_protocol_types::Canonical;
use pr_state_transition::{apply_batch, BatchWitness};
use provekit_common::NoirProof;
use provekit_verifier::FixedJoinSplitVerifier;
use risc0_zkvm::guest::env;

fn main() {
    let witness: BatchWitness = postcard::from_bytes(&env::read_frame()).expect("batch witness");
    if !witness.transactions.is_empty() {
        let verifier = FixedJoinSplitVerifier::compiled().expect("verifier configuration");
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
