//! `settle exec|prove <witness.json> <out-dir> [<joinsplit-receipt.bin>...]`
//!
//! Runs the `apply_batch` guest on a batch witness (JSON `BatchWitness`, as written by the
//! operator) with one zero-knowledge join-split receipt per transaction (from `joinsplit prove`)
//! added as an assumption; with `prove`, proves it (see `pr_prover::settle`). Writes `journal.bin`
//! and, when proving, `stats.json`, `receipt.json` / `seal.bin` in the format the GSR verifier
//! generator reads.
use std::{fs, path::Path, time::Instant};

use anyhow::{ensure, Context, Result};
use pr_prover::settle::{execute_settlement, prove_settlement};
use pr_prover::user::decode_receipt;
use pr_state_transition::BatchWitness;
use risc0_zkvm::sha::Digestible;

fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().collect();
    ensure!(
        a.len() >= 4 && (a[1] == "exec" || a[1] == "prove"),
        "usage: settle exec|prove <witness.json> <out-dir> [joinsplit-receipts..]"
    );
    let witness: BatchWitness = serde_json::from_str(&fs::read_to_string(&a[2])?)?;
    let out = Path::new(&a[3]);
    fs::create_dir_all(out)?;
    let mut receipts = Vec::new();
    for path in &a[4..] {
        receipts.push(decode_receipt(&fs::read(path)?).with_context(|| path.clone())?);
    }
    println!("image id {}", hex::encode(risc0_zkvm::sha::Digest::from(pr_methods::APPLY_BATCH_ID)));
    let t = Instant::now();
    if a[1] == "exec" {
        let (journal, cycles, segments) = execute_settlement(&witness, &receipts)?;
        println!("executed: {cycles} cycles, {segments} segments, {:?}", t.elapsed());
        fs::write(out.join("journal.bin"), &journal)?;
        return Ok(());
    }
    let s = prove_settlement(&witness, &receipts)?;
    let stats = serde_json::to_value(&s.stats)?;
    println!("{stats}");
    fs::write(out.join("stats.json"), serde_json::to_string_pretty(&stats)?)?;
    fs::write(out.join("journal.bin"), &s.journal)?;
    fs::write(out.join("seal.bin"), s.seal_bytes())?;
    fs::write(out.join("receipt.json"), serde_json::to_string_pretty(&s.receipt_json()?)?)?;
    println!("padded receipt verified natively; claim {}", s.receipt.claim.digest());
    Ok(())
}
