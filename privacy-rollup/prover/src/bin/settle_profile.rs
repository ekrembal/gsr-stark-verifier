//! `settle_profile <witness.json> <profile.pb>`
//!
//! Executes the `apply_batch` guest on a batch witness with each join-split statement supplied as
//! an unproven assumption claim (no receipts needed) and writes a RISC Zero pprof cycle profile.
use anyhow::{ensure, Result};
use pr_protocol_types::Canonical;
use pr_state_transition::BatchWitness;
use risc0_zkvm::{default_executor, ExecutorEnv, ReceiptClaim};

fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().collect();
    ensure!(a.len() == 3, "usage: settle_profile <witness.json> <profile.pb>");
    let witness: BatchWitness = serde_json::from_str(&std::fs::read_to_string(&a[1])?)?;
    let mut env = ExecutorEnv::builder();
    env.write_frame(&postcard::to_allocvec(&witness)?);
    for t in &witness.transactions {
        env.add_assumption(ReceiptClaim::ok(pr_methods::JOINSPLIT_ID, t.public.encode()));
    }
    env.enable_profiler(&a[2]);
    let info = default_executor().execute(env.build()?, pr_methods::APPLY_BATCH_ELF)?;
    ensure!(
        info.journal.bytes == pr_prover::settle::expected_journal(&witness)?,
        "guest journal differs from the native transition"
    );
    println!("{} transactions: {} cycles, {} segments", witness.transactions.len(), info.cycles(), info.segments.len());
    Ok(())
}
