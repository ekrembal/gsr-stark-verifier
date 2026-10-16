//! User-side join-split proving.
//!
//! `joinsplit id`                              print `JOINSPLIT_ID` as the array in `methods/guest/src/joinsplit_id.rs`
//! `joinsplit prove <witness.json> <out.bin>`  prove the `joinsplit` guest on a private witness and
//!                                             re-prove it under the zero-knowledge `identity_zk`
//!                                             program; writes `postcard(SuccinctReceipt)`
//! `joinsplit verify <tx.json>`                  check a `RollupTransaction`'s receipt as the operator does
//!
//! Only the zero-knowledge receipt leaves the device: the segment, lift and join proofs (which are
//! not hiding) stay local. Its claim is `ReceiptClaim::ok(JOINSPLIT_ID, public.encode())`.
use std::{fs, time::Instant};

use anyhow::{ensure, Context, Result};
use pr_joinsplit::JoinSplitWitness;
use pr_protocol_types::{Canonical, JoinSplitPublic, RollupTransaction};
use risc0_zkvm::{
    default_prover, recursion, sha::Digestible, ExecutorEnv, ProverOpts, ReceiptClaim, SuccinctReceipt, VerifierContext,
};

/// Accepts `receipt` only if it is a zero-knowledge seal of the join-split guest on `public`.
fn verify(receipt: &SuccinctReceipt<ReceiptClaim>, public: &JoinSplitPublic) -> Result<()> {
    receipt.verify_integrity_zk_with_context(&VerifierContext::default()).context("zero-knowledge seal")?;
    let expected = ReceiptClaim::ok(pr_methods::JOINSPLIT_ID, public.encode());
    ensure!(receipt.claim.digest() == expected.digest(), "receipt claim is not this join-split statement");
    Ok(())
}

fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().collect();
    ensure!(a.len() >= 2, "usage: joinsplit id | prove <witness.json> <out.bin> | verify <tx.json>");
    match a[1].as_str() {
        "id" => {
            println!("{:?}", pr_methods::JOINSPLIT_ID);
        }
        "prove" => {
            ensure!(a.len() == 4, "usage: joinsplit prove <witness.json> <out.bin>");
            ensure!(std::env::var_os("RISC0_DEV_MODE").is_none(), "unset RISC0_DEV_MODE");
            let witness: JoinSplitWitness = serde_json::from_str(&fs::read_to_string(&a[2])?)?;
            witness.check().map_err(|e| anyhow::anyhow!("witness: {e}"))?;
            let env = ExecutorEnv::builder().write_frame(&postcard::to_allocvec(&witness)?).build()?;
            let t = Instant::now();
            let info = default_prover().prove_with_opts(env, pr_methods::JOINSPLIT_ELF, &ProverOpts::succinct())?;
            let succinct_s = t.elapsed().as_secs_f64();
            ensure!(info.receipt.journal.bytes == witness.public.encode(), "journal is not the statement");
            let t = Instant::now();
            let hidden = recursion::identity_zk(info.receipt.inner.succinct()?)?;
            let zk_s = t.elapsed().as_secs_f64();
            verify(&hidden, &witness.public)?;
            let bytes = postcard::to_allocvec(&hidden)?;
            fs::write(&a[3], &bytes)?;
            println!(
                "{}",
                serde_json::json!({
                    "cycles_total": info.stats.total_cycles,
                    "cycles_user": info.stats.user_cycles,
                    "segments": info.stats.segments,
                    "succinct_seconds": succinct_s,
                    "identity_zk_seconds": zk_s,
                    "receipt_bytes": bytes.len(),
                    "seal_words": hidden.seal.len(),
                    "claim": hidden.claim.digest().to_string(),
                })
            );
        }
        "verify" => {
            ensure!(a.len() == 3, "usage: joinsplit verify <tx.json>");
            let tx: RollupTransaction = serde_json::from_str(&fs::read_to_string(&a[2])?)?;
            let receipt: SuccinctReceipt<ReceiptClaim> = postcard::from_bytes(&tx.receipt)?;
            verify(&receipt, &tx.public)?;
            println!("ok");
        }
        _ => anyhow::bail!("unknown command {}", a[1]),
    }
    Ok(())
}
