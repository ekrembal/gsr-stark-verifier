//! User-side join-split proving.
//!
//! `joinsplit id`                                      print `JOINSPLIT_ID` as the array in `methods/guest/src/joinsplit_id.rs`
//! `joinsplit prove <witness.json> <out.bin> [<po2>]`  prove the `joinsplit` guest on a private witness and
//!                                                     re-prove it under the zero-knowledge `identity_zk`
//!                                                     program; writes `postcard(SuccinctReceipt)`
//! `joinsplit verify <tx.json>`                        check a `RollupTransaction`'s receipt as the operator does
use std::fs;

use anyhow::{ensure, Result};
use pr_joinsplit::JoinSplitWitness;
use pr_protocol_types::RollupTransaction;
use pr_prover::user::{decode_receipt, prove_joinsplit, verify_joinsplit_receipt};

fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().collect();
    ensure!(a.len() >= 2, "usage: joinsplit id | prove <witness.json> <out.bin> [<po2>] | verify <tx.json>");
    match a[1].as_str() {
        "id" => println!("{:?}", pr_methods::JOINSPLIT_ID),
        "prove" => {
            ensure!(a.len() == 4 || a.len() == 5, "usage: joinsplit prove <witness.json> <out.bin> [<segment-po2>]");
            let witness: JoinSplitWitness = serde_json::from_str(&fs::read_to_string(&a[2])?)?;
            let po2 = a.get(4).map(|p| p.parse()).transpose()?;
            let (bytes, stats) = prove_joinsplit(&witness, po2)?;
            fs::write(&a[3], &bytes)?;
            println!("{}", serde_json::to_string(&stats)?);
        }
        "verify" => {
            ensure!(a.len() == 3, "usage: joinsplit verify <tx.json>");
            let tx: RollupTransaction = serde_json::from_str(&fs::read_to_string(&a[2])?)?;
            verify_joinsplit_receipt(&decode_receipt(&tx.receipt)?, &tx.public)?;
            println!("ok");
        }
        _ => anyhow::bail!("unknown command {}", a[1]),
    }
    Ok(())
}
