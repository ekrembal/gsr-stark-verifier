//! pr-sdk-wasm deposit <seed-hex> <status.json> <funding.json> <fee-sats> <out-dir>
//!     writes witness.json and external.json (private: they stay on the device)
//! pr-sdk-wasm prove <witness.json> <external.json> <po2|default> <out-dir>
//!     writes receipt.bin and submission.json (what is sent to the batcher)
//! pr-sdk-wasm profile <witness.json> <po2|default> <segments>
//!     executes, then proves (with lift/join) only the first <segments> segments; no receipt
//! pr-sdk-wasm verify <submission.json>
//!
//! Each command prints one JSON object of measured timings to stdout.
use std::path::Path;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use pr_sdk::api::{FundingInput, Status, Submission};
use pr_sdk::pr_mempool::FundingCoin;
use pr_sdk::pr_protocol_types::ExternalData;
use pr_sdk::{JoinSplitWitness, Wallet};
use rand_core::OsRng;
use serde_json::json;

fn read_json<T: serde::de::DeserializeOwned>(path: &str) -> Result<T> {
    serde_json::from_slice(&std::fs::read(path).with_context(|| format!("reading {path}"))?)
        .with_context(|| format!("parsing {path}"))
}

fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let out = match a.first().map(String::as_str) {
        Some("deposit") if a.len() == 6 => {
            let seed: [u8; 32] = hex::decode(&a[1])?.try_into().map_err(|_| anyhow::anyhow!("seed is 32 bytes"))?;
            let status: Status = read_json(&a[2])?;
            let funding: Vec<FundingInput> = read_json(&a[3])?;
            let coins: Vec<FundingCoin> = funding.iter().map(|f| f.coin.clone()).collect();
            let t = Instant::now();
            let built = Wallet::from_seed(&seed).deposit(&mut OsRng, &status, &coins, a[4].parse()?, 10)?;
            let seconds = t.elapsed().as_secs_f64();
            let dir = Path::new(&a[5]);
            std::fs::write(dir.join("witness.json"), serde_json::to_vec(&built.witness)?)?;
            std::fs::write(dir.join("external.json"), serde_json::to_vec(&built.external)?)?;
            json!({"stage": "witness", "witness_build_seconds": seconds, "deposit_sats": built.witness.public.deposit_sats})
        }
        Some("prove") if a.len() == 5 => {
            let witness: JoinSplitWitness = read_json(&a[1])?;
            let external: ExternalData = read_json(&a[2])?;
            let po2 = if a[3] == "default" { None } else { Some(a[3].parse()?) };
            let t = Instant::now();
            let (tx, stats) = pr_sdk::prove(&witness, &external, po2)?;
            let wall = t.elapsed().as_secs_f64();
            let dir = Path::new(&a[4]);
            std::fs::write(dir.join("receipt.bin"), &tx.receipt)?;
            let sub = pr_sdk::submission(&tx, Vec::new());
            std::fs::write(dir.join("submission.json"), serde_json::to_vec(&sub)?)?;
            json!({"stage": "prove", "wall_seconds": wall, "stats": stats, "transaction_hex_bytes": sub.transaction.len()})
        }
        Some("profile") if a.len() == 4 => {
            let witness: JoinSplitWitness = read_json(&a[1])?;
            let po2 = if a[2] == "default" { None } else { Some(a[2].parse()?) };
            let t = Instant::now();
            let stats = pr_sdk::profile_joinsplit(&witness, po2, a[3].parse()?)?;
            json!({"stage": "profile", "wall_seconds": t.elapsed().as_secs_f64(), "stats": stats})
        }
        Some("verify") if a.len() == 2 => {
            let sub: Submission = read_json(&a[1])?;
            let t = Instant::now();
            let tx = pr_sdk::decode_transaction(&sub.transaction)?;
            pr_sdk::verify_transaction(&tx)?;
            json!({"stage": "verify", "verify_seconds": t.elapsed().as_secs_f64(), "receipt_bytes": tx.receipt.len()})
        }
        _ => bail!("usage: see the header of prover/sdk-wasm/src/main.rs"),
    };
    println!("{out}");
    Ok(())
}
