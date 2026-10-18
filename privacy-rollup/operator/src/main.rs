//! Operator CLI over `pr_operator::Store`.
//!
//! ```text
//! pr-operator init     <dir> <descriptor.json>
//! pr-operator genesis  <dir> <tx-hex>                   # genesis tx: spends genesis_nonce, rollup at output 0
//! pr-operator submit   <dir> <tx.json> [<funding.json>] # verify the join-split receipt, reserve, queue
//! pr-operator build    <dir> <request.json> <out-dir>   # witness, guest frames, annex, journal
//! pr-operator accept   <dir> <annex-hex> <tx-hex>       # mined settlement (witnesses optional)
//! pr-operator rollback <dir>
//! pr-operator status   <dir>
//! ```
//! Txids are hex in serialization (internal) byte order. `tx.json` is a `RollupTransaction` whose
//! `receipt` is the user's zero-knowledge receipt of the `joinsplit` guest (`joinsplit prove`);
//! `funding.json` the `FundingCoin`s its deposit spends, in declaration order. Transactions settled by
//! an accepted batch leave the pool; after a rollback they must be resubmitted.
use std::fs;
use std::path::Path;

use anyhow::{bail, ensure, Result};
use pr_mempool::FundingCoin;
use pr_operator::{parse_transaction_json, Settled, Store, MAX_TX_JSON_BYTES};
use pr_protocol_types::{Canonical, RollupDescriptor};
use serde::Deserialize;

/// Next-batch request; the batch is the pool's fee-ordered selection. `successor_script_pubkey` is
/// derived by the covenant template from the new state root; without it `build` only reports the new
/// root (the root never depends on it).
#[derive(Deserialize)]
struct Request {
    rollup_script_pubkey: String,
    successor_script_pubkey: Option<String>,
}

fn submit(store: &Store, tx: &Path, funding: Option<&String>) -> Result<usize> {
    let len = fs::metadata(tx)?.len();
    ensure!(len <= MAX_TX_JSON_BYTES, "tx.json is {len} bytes, more than {MAX_TX_JSON_BYTES}");
    let tx = parse_transaction_json(&fs::read(tx)?)?;
    let funding: Vec<FundingCoin> = match funding {
        Some(p) => serde_json::from_slice(&fs::read(p)?)?,
        None => Vec::new(),
    };
    store.submit(tx, funding)
}

fn build(store: &Store, request: &Path, out: &Path) -> Result<()> {
    let req: Request = serde_json::from_slice(&fs::read(request)?)?;
    let successor = match &req.successor_script_pubkey {
        Some(s) => hex::decode(s)?,
        None => Vec::new(),
    };
    let b = store.build(hex::decode(&req.rollup_script_pubkey)?, successor)?;
    fs::create_dir_all(out)?;
    let mut frames = Vec::new();
    for (i, e) in b.entries.iter().enumerate() {
        let name = format!("receipt{i}.bin");
        fs::write(out.join(&name), &e.tx.receipt)?;
        frames.push(name);
    }
    let (effects, witness) = (&b.effects, &b.witness);
    let summary = serde_json::json!({
        "batch_number": effects.new_state.batch_number,
        "old_state_root": hex::encode(effects.annex.old_state_root),
        "new_state_root": hex::encode(effects.new_state.root()),
        "backing_sats": effects.new_state.backing_sats,
        "settlement_tx": hex::encode(witness.settlement.plain().serialize_legacy()),
        "complete": req.successor_script_pubkey.is_some(),
        "transactions": b.entries.len(),
        "assumption_receipts": frames,
        "annex": hex::encode(&effects.annex_bytes),
        "journal": hex::encode(effects.journal.encode()),
        "inputs": witness.settlement.inputs.iter().map(|i| serde_json::json!({
            "txid": hex::encode(i.prevout.txid), "vout": i.prevout.vout, "amount": i.amount,
            "script_pubkey": hex::encode(&i.script_pubkey), "sequence": i.sequence})).collect::<Vec<_>>(),
        "outputs": witness.settlement.outputs.iter().map(|o| serde_json::json!({
            "value": o.value, "script_pubkey": hex::encode(&o.script_pubkey)})).collect::<Vec<_>>(),
    });
    fs::write(out.join("batch.json"), serde_json::to_vec_pretty(&summary)?)?;
    fs::write(out.join("witness.json"), serde_json::to_vec(witness)?)?;
    println!("{}", serde_json::to_string(&summary["new_state_root"])?);
    Ok(())
}

fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().collect();
    ensure!(a.len() >= 3, "usage: pr-operator <command> <dir> ...");
    let store = Store::new(&a[2]);
    match a[1].as_str() {
        "init" => {
            ensure!(a.len() == 4, "usage: pr-operator init <dir> <descriptor.json>");
            let d: RollupDescriptor = serde_json::from_slice(&fs::read(&a[3])?)?;
            let state = store.init(&d)?;
            println!(
                "{}",
                serde_json::json!({
                "rollup_id": hex::encode(state.rollup_id.0), "state_root": hex::encode(state.root())})
            );
        }
        "genesis" => {
            let utxo = store.genesis(&a[3])?;
            println!("{}", serde_json::json!({"txid": hex::encode(utxo.txid), "vout": utxo.vout}));
        }
        "submit" => println!("{}", submit(&store, Path::new(&a[3]), a.get(4))?),
        "build" => build(&store, Path::new(&a[3]), Path::new(&a[4]))?,
        "accept" => {
            let spent = a.get(5).map(|j| serde_json::from_str(j)).transpose()?.unwrap_or_default();
            let s = Settled { annex: a[3].clone(), tx: a[4].clone(), spent };
            let replica = store.accept(s)?;
            println!("{}", store.status(&replica)?);
        }
        "rollback" => {
            let replica = store.rollback()?;
            println!("{}", store.status(&replica)?);
        }
        "status" => println!("{}", store.status(&store.load()?.0)?),
        c => bail!("unknown command {c}"),
    }
    Ok(())
}
