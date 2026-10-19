//! `settle_bench <witness.json> [workers]`
//!
//! Proves the `apply_batch` guest on a batch witness up to the joined conditional receipt, with each
//! join-split statement as an open assumption claim (no user receipts needed), and prints the
//! settlement stats as JSON. The witness must spend the genesis state (no predecessor proof).
//! `resolve_zk` (one per transaction) and the padded-SHA identity step are not run; they do not
//! depend on the batch contents beyond the transaction count.
use anyhow::{ensure, Result};
use pr_protocol_types::Canonical;
use pr_prover::settle::{prove_conditional, prove_workers};
use pr_state_transition::BatchWitness;
use risc0_zkvm::ReceiptClaim;

fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().collect();
    ensure!(a.len() == 2 || a.len() == 3, "usage: settle_bench <witness.json> [workers]");
    let witness: BatchWitness = serde_json::from_str(&std::fs::read_to_string(&a[1])?)?;
    let workers = a.get(2).map(|w| w.parse()).transpose()?.unwrap_or_else(prove_workers);
    let claims: Vec<ReceiptClaim> =
        witness.transactions.iter().map(|t| ReceiptClaim::ok(pr_methods::JOINSPLIT_ID, t.public.encode())).collect();
    let c = prove_conditional(&witness, &claims, None, workers)?;
    ensure!(c.assumed.len() == claims.len(), "every join-split claim must stay an open assumption");
    println!("{}", serde_json::to_string(&c.stats)?);
    Ok(())
}
