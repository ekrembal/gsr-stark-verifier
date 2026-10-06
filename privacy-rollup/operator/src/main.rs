//! Operator CLI. The operator's durable state is the rollup descriptor, the chain of accepted
//! settlements (annex, rollup value, rollup outpoint) and the pending pool; every start replays the
//! chain through the scanner and re-admits the pool against the replayed tip, so restart and reorg
//! handling share one code path.
//!
//! ```text
//! pr-operator init     <dir> <descriptor.json>
//! pr-operator genesis  <dir> <txid-hex> <vout>          # rollup outpoint created by the genesis tx
//! pr-operator submit   <dir> <tx.json> [<funding.json>] # verify the join-split receipt, reserve, queue
//! pr-operator build    <dir> <request.json> <out-dir>   # witness, guest frames, annex, journal
//! pr-operator accept   <dir> <annex-hex> <value> <txid-hex> <vout>
//! pr-operator rollback <dir>
//! pr-operator status   <dir>
//! ```
//! Txids are hex in serialization (internal) byte order. `tx.json` is a `RollupTransaction` whose
//! `receipt` is the user's zero-knowledge receipt of the `joinsplit` guest (`joinsplit prove`);
//! `funding.json` the `FundingCoin`s its deposit spends, in declaration order. Transactions settled by
//! an accepted batch leave the pool; after a rollback they must be resubmitted.
use std::fs;
use std::path::Path;

use anyhow::{bail, ensure, Context, Result};
use pr_mempool::{assemble_settlement, batch_transactions, Entry, FundingCoin, Mempool};
use pr_protocol_types::{Canonical, Outpoint, RollupDescriptor, RollupTransaction, TxOut};
use pr_scanner::Replica;
use pr_state_transition::apply_batch;
use risc0_zkvm::{sha::Digestible, ReceiptClaim, SuccinctReceipt, VerifierContext};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct Settled {
    annex: String,
    value: u64,
    txid: String,
    vout: u32,
}

#[derive(Serialize, Deserialize, Default)]
struct Chain {
    genesis: Option<(String, u32)>,
    settlements: Vec<Settled>,
}

const PENDING: &str = "pending.json";
/// Image ID of the user-side `joinsplit` guest, as compiled into `apply_batch`.
const JOINSPLIT_ID: [u32; 8] = include!("../../methods/guest/src/joinsplit_id.rs");

/// Accepts a transaction only if its receipt is a zero-knowledge (`identity_zk`) seal of the
/// `joinsplit` guest whose journal is the transaction's own statement.
fn verify_receipt(tx: &RollupTransaction) -> Result<()> {
    let receipt: SuccinctReceipt<ReceiptClaim> = postcard::from_bytes(&tx.receipt).context("receipt encoding")?;
    receipt.verify_integrity_zk_with_context(&VerifierContext::default()).context("zero-knowledge seal")?;
    let expected = ReceiptClaim::ok(JOINSPLIT_ID, tx.public.encode());
    ensure!(receipt.claim.digest() == expected.digest(), "receipt is not of this statement");
    Ok(())
}

/// Next-batch request; the batch is the pool's fee-ordered selection. `successor_script_pubkey` is
/// derived by the covenant template from the new state root; without it `build` only reports the new
/// root (the root never depends on it).
#[derive(Deserialize)]
struct Request {
    rollup_script_pubkey: String,
    reward: Option<(u64, String)>,
    successor_script_pubkey: Option<String>,
}

fn outpoint(txid: &str, vout: u32) -> Result<Outpoint> {
    let txid: [u8; 32] = hex::decode(txid)?.try_into().map_err(|_| anyhow::anyhow!("txid length"))?;
    Ok(Outpoint { txid, vout })
}

fn load(dir: &Path) -> Result<(Replica, Chain)> {
    let descriptor: RollupDescriptor = serde_json::from_slice(&fs::read(dir.join("descriptor.json"))?)?;
    let chain: Chain = serde_json::from_slice(&fs::read(dir.join("chain.json"))?)?;
    let (txid, vout) = chain.genesis.clone().context("genesis outpoint not recorded")?;
    let mut replica = Replica::new(descriptor, outpoint(&txid, vout)?);
    for s in &chain.settlements {
        replica
            .accept_annex_bytes(&hex::decode(&s.annex)?, s.value, outpoint(&s.txid, s.vout)?)
            .map_err(|e| anyhow::anyhow!("replaying batch: {e:?}"))?;
    }
    Ok((replica, chain))
}

fn load_pool(dir: &Path, replica: &Replica) -> Result<Mempool> {
    let path = dir.join(PENDING);
    let entries: Vec<Entry> = if path.exists() { serde_json::from_slice(&fs::read(path)?)? } else { Vec::new() };
    Ok(Mempool::restore(entries, replica))
}

fn save_pool(dir: &Path, pool: &Mempool) -> Result<()> {
    fs::write(dir.join(PENDING), serde_json::to_vec(&pool.entries)?)?;
    Ok(())
}

/// Bound on a submitted `tx.json`: a `MAX_RECEIPT_BYTES` receipt as a JSON byte array is at most
/// 4 MiB, plus the statement and external data.
const MAX_TX_JSON_BYTES: u64 = 8 << 20;

fn submit(dir: &Path, tx: &Path, funding: Option<&String>) -> Result<usize> {
    let (replica, _) = load(dir)?;
    let mut pool = load_pool(dir, &replica)?;
    let len = fs::metadata(tx)?.len();
    ensure!(len <= MAX_TX_JSON_BYTES, "tx.json is {len} bytes, more than {MAX_TX_JSON_BYTES}");
    let tx: RollupTransaction = serde_json::from_slice(&fs::read(tx)?)?;
    let tx =
        RollupTransaction::decode(&tx.encode()).map_err(|e| anyhow::anyhow!("non-canonical transaction: {e:?}"))?;
    let funding: Vec<FundingCoin> = match funding {
        Some(p) => serde_json::from_slice(&fs::read(p)?)?,
        None => Vec::new(),
    };
    pool.submit(tx, funding, &replica, |t| verify_receipt(t).is_ok())
        .map_err(|e| anyhow::anyhow!("rejected: {e:?}"))?;
    save_pool(dir, &pool)?;
    Ok(pool.entries.len())
}

fn save(dir: &Path, chain: &Chain) -> Result<()> {
    fs::write(dir.join("chain.json"), serde_json::to_vec_pretty(chain)?)?;
    Ok(())
}

fn status(dir: &Path, replica: &Replica) -> Result<serde_json::Value> {
    let tip = replica.tip();
    let anchor = tip.anchors.0.last().context("anchor")?;
    Ok(serde_json::json!({
        "anchor": {"root": hex::encode(anchor.commitment_root.0), "commitment_count": anchor.commitment_count,
                   "batch_number": anchor.batch_number},
        "rollup_id": hex::encode(tip.state.rollup_id.0),
        "batch_number": tip.state.batch_number,
        "state_root": hex::encode(tip.state.root()),
        "commitment_count": tip.state.commitment_count,
        "nullifier_next_index": tip.state.nullifier_next_index,
        "backing_sats": tip.state.backing_sats,
        "utxo": [hex::encode(tip.utxo.txid), tip.utxo.vout],
        "pending": load_pool(dir, replica)?.entries.len(),
    }))
}

fn build(dir: &Path, request: &Path, out: &Path) -> Result<()> {
    let (replica, _) = load(dir)?;
    let req: Request = serde_json::from_slice(&fs::read(request)?)?;
    let entries = load_pool(dir, &replica)?.select();
    let reward = match &req.reward {
        Some((value, spk)) => Some(TxOut { value: *value, script_pubkey: hex::decode(spk)? }),
        None => None,
    };
    let successor = match &req.successor_script_pubkey {
        Some(s) => hex::decode(s)?,
        None => Vec::new(),
    };
    let settlement =
        assemble_settlement(&replica, hex::decode(&req.rollup_script_pubkey)?, successor, &entries, reward)
            .context("batch withdraws more than it backs")?;
    let witness = replica.witness(batch_transactions(&entries), settlement);
    let effects = apply_batch(&witness).map_err(|e| anyhow::anyhow!("transition: {e:?}"))?;
    fs::create_dir_all(out)?;
    let mut frames = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        let name = format!("receipt{i}.bin");
        fs::write(out.join(&name), &e.tx.receipt)?;
        frames.push(name);
    }
    let summary = serde_json::json!({
        "batch_number": effects.new_state.batch_number,
        "old_state_root": hex::encode(effects.annex.old_state_root),
        "new_state_root": hex::encode(effects.new_state.root()),
        "backing_sats": effects.new_state.backing_sats,
        "complete": req.successor_script_pubkey.is_some(),
        "transactions": entries.len(),
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
    fs::write(out.join("witness.json"), serde_json::to_vec(&witness)?)?;
    println!("{}", serde_json::to_string(&summary["new_state_root"])?);
    Ok(())
}

fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().collect();
    ensure!(a.len() >= 3, "usage: pr-operator <command> <dir> ...");
    let dir = Path::new(&a[2]);
    match a[1].as_str() {
        "init" => {
            ensure!(a.len() == 4, "usage: pr-operator init <dir> <descriptor.json>");
            fs::create_dir_all(dir)?;
            let d: RollupDescriptor = serde_json::from_slice(&fs::read(&a[3])?)?;
            fs::write(dir.join("descriptor.json"), serde_json::to_vec_pretty(&d)?)?;
            save(dir, &Chain::default())?;
            let (state, _, _) = pr_state_transition::genesis(&d);
            println!(
                "{}",
                serde_json::json!({
                "rollup_id": hex::encode(state.rollup_id.0), "state_root": hex::encode(state.root())})
            );
        }
        "genesis" => {
            let mut chain: Chain = serde_json::from_slice(&fs::read(dir.join("chain.json"))?)?;
            ensure!(chain.genesis.is_none(), "genesis already recorded");
            outpoint(&a[3], a[4].parse()?)?;
            chain.genesis = Some((a[3].clone(), a[4].parse()?));
            save(dir, &chain)?;
        }
        "submit" => println!("{}", submit(dir, Path::new(&a[3]), a.get(4))?),
        "build" => build(dir, Path::new(&a[3]), Path::new(&a[4]))?,
        "accept" => {
            let (mut replica, mut chain) = load(dir)?;
            let s = Settled { annex: a[3].clone(), value: a[4].parse()?, txid: a[5].clone(), vout: a[6].parse()? };
            replica
                .accept_annex_bytes(&hex::decode(&s.annex)?, s.value, outpoint(&s.txid, s.vout)?)
                .map_err(|e| anyhow::anyhow!("annex rejected: {e:?}"))?;
            chain.settlements.push(s);
            save(dir, &chain)?;
            save_pool(dir, &load_pool(dir, &replica)?)?;
            println!("{}", status(dir, &replica)?);
        }
        "rollback" => {
            let (_, mut chain) = load(dir)?;
            if chain.settlements.pop().is_none() {
                bail!("nothing to roll back");
            }
            save(dir, &chain)?;
            let replica = load(dir)?.0;
            save_pool(dir, &load_pool(dir, &replica)?)?;
            println!("{}", status(dir, &replica)?);
        }
        "status" => println!("{}", status(dir, &load(dir)?.0)?),
        c => bail!("unknown command {c}"),
    }
    Ok(())
}
