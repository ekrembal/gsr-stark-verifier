//! The settlement guest: checks every join-split of a batch, applies the state transition, and
//! commits the 196-byte `BatchJournal` that the GSR covenant rebuilds from `OP_TX`.
//!
//! Input frame: `postcard(BatchWitness)`. Each transaction's join-split is not re-proven here: the
//! user proved it with the `joinsplit` guest, and this guest requires that receipt as an assumption
//! (`env::verify` on the statement's canonical encoding). The operator supplies the receipts with
//! `ExecutorEnv::add_assumption`, and recursion (`resolve_zk`) discharges them, so the final receipt
//! is unconditional. The join-split image ID is compiled in, so `APPLY_BATCH_ID` fixes the circuit.
use pr_protocol_types::Canonical;
use pr_state_transition::{apply_batch, BatchWitness};
use risc0_zkvm::guest::env;

const JOINSPLIT_ID: [u32; 8] = include!("../joinsplit_id.rs");

fn main() {
    let witness: BatchWitness = postcard::from_bytes(&env::read_frame()).expect("batch witness");
    for t in &witness.transactions {
        env::verify(JOINSPLIT_ID, &t.public.encode()).expect("join-split receipt");
    }
    let effects = apply_batch(&witness).expect("state transition");
    env::commit_slice(&effects.journal.encode());
}
