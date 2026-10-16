//! A command-line wallet over `pr-sdk`, talking to a `pr-batcher`. Witnesses stay on this machine;
//! only the public statement, external data, receipt and funding are submitted.
//!
//! wallet address <seed-hex>
//! wallet deposit <url> <seed-hex> <funding.json> <fee-sats> <submission-out.json> [po2]
//!     funding.json: [FundingInput]; the submission sent is also written to <submission-out.json>
//! wallet deposit-address <url> <seed-hex> <value-sats> <fee-sats> <refund-xonly-hex> <refund-delay> <out.json>
//!     a non-interactive Taproot escrow address; pay `amount_sats` to `script_pubkey` from any wallet
//! wallet register <url> <deposit-address.json> <txid> <vout>      register the paid escrow output
//! wallet scan    <url> <seed-hex>
//! wallet send    <url> <seed-hex> <leaf> <to-address|self> <amount-sats> <fee-sats> [po2]
//! wallet withdraw <url> <seed-hex> <leaf> <script-pubkey-hex> <amount-sats> <fee-sats> [po2]
//! wallet settle  <url>                                                 request a batch, wait for it
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use pr_sdk::api::{EscrowRegistration, FundingInput, Stage};
use pr_sdk::client::Client;
use pr_sdk::pr_protocol_types::TxOut;
use pr_sdk::{decode_address, encode_address, fe_from_hex, prove, submission, DepositAddress, OutputSpec, Wallet};
use rand_core::OsRng;
use serde_json::json;

fn wallet(seed: &str) -> Result<Wallet> {
    let seed: [u8; 32] = hex::decode(seed)?.try_into().map_err(|_| anyhow::anyhow!("seed is not 32 bytes"))?;
    Ok(Wallet::from_seed(&seed))
}

fn po2(a: &[String], i: usize) -> Result<Option<u32>> {
    a.get(i).map(|s| s.parse()).transpose().context("po2")
}

fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let out = match a.first().map(String::as_str) {
        Some("address") if a.len() == 2 => json!({"address": encode_address(&wallet(&a[1])?.address())}),
        Some("deposit") if (6..=7).contains(&a.len()) => {
            let (client, w) = (Client::new(&a[1])?, wallet(&a[2])?);
            let funding: Vec<FundingInput> = serde_json::from_slice(&std::fs::read(&a[3])?)?;
            let status = client.status()?;
            let t = Instant::now();
            let coins: Vec<_> = funding.iter().map(|f| f.coin.clone()).collect();
            let built = w.deposit(&mut OsRng, &status, &coins, a[4].parse()?, 1)?;
            let witness_seconds = t.elapsed().as_secs_f64();
            let (tx, stats) = prove(&built.witness, &built.external, po2(&a, 6)?)?;
            let sub = submission(&tx, funding);
            std::fs::write(&a[5], serde_json::to_vec(&sub)?)?;
            let r = client.submit(&sub)?;
            json!({"witness_seconds": witness_seconds, "prove": stats, "pending": r.pending,
                   "deposit_sats": tx.public.deposit_sats, "fee_sats": tx.public.fee_sats})
        }
        Some("deposit-address") if a.len() == 8 => {
            let (client, w) = (Client::new(&a[1])?, wallet(&a[2])?);
            let refund: [u8; 32] = hex::decode(&a[5])?.try_into().map_err(|_| anyhow::anyhow!("refund key"))?;
            let d = w.deposit_address(
                &mut OsRng,
                &client.escrow_terms()?,
                a[3].parse()?,
                a[4].parse()?,
                &refund,
                a[6].parse()?,
            )?;
            std::fs::write(&a[7], serde_json::to_vec_pretty(&d)?)?;
            json!({"script_pubkey": d.script_pubkey, "amount_sats": d.amount_sats, "refund_delay": d.refund_delay})
        }
        Some("register") if a.len() == 5 => {
            let client = Client::new(&a[1])?;
            let d: DepositAddress = serde_json::from_slice(&std::fs::read(&a[2])?)?;
            let reg = EscrowRegistration {
                outpoint: (a[3].clone(), a[4].parse()?),
                opening: d.opening,
                refund_leaf: d.refund_leaf,
            };
            serde_json::to_value(client.register_escrow(&reg)?)?
        }
        Some("scan") if a.len() == 3 => {
            let (client, w) = (Client::new(&a[1])?, wallet(&a[2])?);
            let status = client.status()?;
            let notes = w.scan(&fe_from_hex(&status.rollup_id)?, &client.notes(0)?);
            json!(notes
                .iter()
                .map(|n| json!({"leaf": n.leaf_index, "value": n.note.value,
                "nullifier": hex::encode(n.nullifier.0)}))
                .collect::<Vec<_>>())
        }
        Some(cmd @ ("send" | "withdraw")) if (7..=8).contains(&a.len()) => {
            let (client, w) = (Client::new(&a[1])?, wallet(&a[2])?);
            let status = client.status()?;
            let leaf: u64 = a[3].parse()?;
            let notes = w.scan(&fe_from_hex(&status.rollup_id)?, &client.notes(0)?);
            let note = notes.into_iter().find(|n| n.leaf_index == leaf).context("no owned note at that leaf")?;
            let amount: u64 = a[5].parse()?;
            let (payments, withdrawal) = if cmd == "send" {
                let recipient = if a[4] == "self" { w.address() } else { decode_address(&a[4])? };
                (vec![OutputSpec { value: amount, recipient, memo: [0; 32], self_key: None }], Vec::new())
            } else {
                (Vec::new(), vec![TxOut { value: amount, script_pubkey: hex::decode(&a[4]).context("script-pubkey")? }])
            };
            let t = Instant::now();
            let path = client.path(leaf)?;
            let built = w.transfer(&mut OsRng, &status, &[(note, path)], payments, withdrawal, a[6].parse()?, 1)?;
            let witness_seconds = t.elapsed().as_secs_f64();
            let (tx, stats) = prove(&built.witness, &built.external, po2(&a, 7)?)?;
            let r = client.submit(&submission(&tx, Vec::new()))?;
            json!({"witness_seconds": witness_seconds, "prove": stats, "pending": r.pending,
                   "withdrawal_sats": tx.public.withdrawal_sats, "fee_sats": tx.public.fee_sats})
        }
        Some("settle") if a.len() == 2 => {
            let client = Client::new(&a[1])?;
            let n = client.settle()?.batch_number;
            loop {
                let r = client.batch(n)?;
                match r.stage {
                    Stage::Confirmed => break serde_json::to_value(r)?,
                    Stage::Failed => bail!("batch {n} failed: {}", r.error.unwrap_or_default()),
                    _ => std::thread::sleep(Duration::from_secs(5)),
                }
            }
        }
        _ => bail!("usage: see the header of prover/sdk/examples/wallet.rs"),
    };
    println!("{out}");
    Ok(())
}
