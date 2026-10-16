//! Operator state store, shared by the `pr-operator` CLI and the `pr-batcher` service. The durable
//! state is the rollup descriptor, the chain of accepted settlements (annex, rollup value, rollup
//! outpoint) and the pending pool; every load replays the chain through the scanner and re-admits
//! the pool against the replayed tip, so restart and reorg handling share one code path.
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context, Result};
use pr_mempool::{assemble_settlement, batch_transactions, Entry, FundingCoin, Mempool};
use pr_protocol_types::{Canonical, Outpoint, RollupDescriptor, RollupTransaction, TxOut};
use pr_scanner::Replica;
use pr_state_transition::{apply_batch, BatchEffects, BatchWitness};
use risc0_zkvm::{sha::Digestible, ReceiptClaim, SuccinctReceipt, VerifierContext};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Settled {
    pub annex: String,
    pub value: u64,
    pub txid: String,
    pub vout: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Chain {
    pub genesis: Option<(String, u32)>,
    pub settlements: Vec<Settled>,
}

const PENDING: &str = "pending.json";
/// Image ID of the user-side `joinsplit` guest, as compiled into `apply_batch`.
pub const JOINSPLIT_ID: [u32; 8] = include!("../../methods/guest/src/joinsplit_id.rs");

/// Bound on a submitted `tx.json`: a `MAX_RECEIPT_BYTES` receipt as a JSON byte array is at most
/// 4 MiB, plus the statement and external data.
pub const MAX_TX_JSON_BYTES: u64 = 8 << 20;

/// Accepts a transaction only if its receipt is a zero-knowledge (`identity_zk`) seal of the
/// `joinsplit` guest whose journal is the transaction's own statement.
pub fn verify_receipt(tx: &RollupTransaction) -> Result<()> {
    let receipt: SuccinctReceipt<ReceiptClaim> = postcard::from_bytes(&tx.receipt).context("receipt encoding")?;
    receipt.verify_integrity_zk_with_context(&VerifierContext::default()).context("zero-knowledge seal")?;
    let expected = ReceiptClaim::ok(JOINSPLIT_ID, tx.public.encode());
    ensure!(receipt.claim.digest() == expected.digest(), "receipt is not of this statement");
    Ok(())
}

/// Parses a JSON `RollupTransaction` of at most `MAX_TX_JSON_BYTES` and requires it to round-trip
/// through the canonical decoder (which bounds the receipt by `MAX_RECEIPT_BYTES`).
pub fn parse_transaction_json(bytes: &[u8]) -> Result<RollupTransaction> {
    let len = bytes.len() as u64;
    ensure!(len <= MAX_TX_JSON_BYTES, "tx.json is {len} bytes, more than {MAX_TX_JSON_BYTES}");
    let tx: RollupTransaction = serde_json::from_slice(bytes)?;
    RollupTransaction::decode(&tx.encode()).map_err(|e| anyhow::anyhow!("non-canonical transaction: {e:?}"))
}

pub fn outpoint(txid: &str, vout: u32) -> Result<Outpoint> {
    let txid: [u8; 32] = hex::decode(txid)?.try_into().map_err(|_| anyhow::anyhow!("txid length"))?;
    Ok(Outpoint { txid, vout })
}

/// A settlement assembled from the pool's fee-ordered selection.
pub struct BuiltBatch {
    pub entries: Vec<Entry>,
    pub witness: BatchWitness,
    pub effects: BatchEffects,
}

/// The operator directory.
pub struct Store {
    pub dir: PathBuf,
}

impl Store {
    pub fn new(dir: impl AsRef<Path>) -> Store {
        Store { dir: dir.as_ref().to_path_buf() }
    }

    /// Creates the directory with `descriptor` and an empty chain; returns the genesis state.
    pub fn init(&self, descriptor: &RollupDescriptor) -> Result<pr_protocol_types::RollupState> {
        fs::create_dir_all(&self.dir)?;
        ensure!(!self.dir.join("chain.json").exists(), "{} is already initialised", self.dir.display());
        fs::write(self.dir.join("descriptor.json"), serde_json::to_vec_pretty(descriptor)?)?;
        self.save(&Chain::default())?;
        Ok(pr_state_transition::genesis(descriptor).0)
    }

    pub fn descriptor(&self) -> Result<RollupDescriptor> {
        Ok(serde_json::from_slice(&fs::read(self.dir.join("descriptor.json"))?)?)
    }

    pub fn chain(&self) -> Result<Chain> {
        Ok(serde_json::from_slice(&fs::read(self.dir.join("chain.json"))?)?)
    }

    pub fn genesis(&self, txid: &str, vout: u32) -> Result<()> {
        let mut chain = self.chain()?;
        ensure!(chain.genesis.is_none(), "genesis already recorded");
        outpoint(txid, vout)?;
        chain.genesis = Some((txid.to_owned(), vout));
        self.save(&chain)
    }

    pub fn load(&self) -> Result<(Replica, Chain)> {
        let chain = self.chain()?;
        let (txid, vout) = chain.genesis.clone().context("genesis outpoint not recorded")?;
        let mut replica = Replica::new(self.descriptor()?, outpoint(&txid, vout)?);
        for s in &chain.settlements {
            replica
                .accept_annex_bytes(&hex::decode(&s.annex)?, s.value, outpoint(&s.txid, s.vout)?)
                .map_err(|e| anyhow::anyhow!("replaying batch: {e:?}"))?;
        }
        Ok((replica, chain))
    }

    pub fn load_pool(&self, replica: &Replica) -> Result<Mempool> {
        let path = self.dir.join(PENDING);
        let entries: Vec<Entry> = if path.exists() { serde_json::from_slice(&fs::read(path)?)? } else { Vec::new() };
        Ok(Mempool::restore(entries, replica))
    }

    pub fn save_pool(&self, pool: &Mempool) -> Result<()> {
        write_atomic(&self.dir.join(PENDING), &serde_json::to_vec(&pool.entries)?)
    }

    fn save(&self, chain: &Chain) -> Result<()> {
        write_atomic(&self.dir.join("chain.json"), &serde_json::to_vec_pretty(chain)?)
    }

    /// Verifies the receipt, admits the transaction against the tip and queues it; returns the pool size.
    pub fn submit(&self, tx: RollupTransaction, funding: Vec<FundingCoin>) -> Result<usize> {
        let (replica, _) = self.load()?;
        let mut pool = self.load_pool(&replica)?;
        pool.submit(tx, funding, &replica, |t| verify_receipt(t).is_ok())
            .map_err(|e| anyhow::anyhow!("rejected: {e:?}"))?;
        self.save_pool(&pool)?;
        Ok(pool.entries.len())
    }

    /// Assembles the next settlement from the pool. `successor` is the covenant output for the new
    /// root; the new root never depends on it, so it may be empty for a first pass.
    pub fn build(
        &self,
        rollup_script_pubkey: Vec<u8>,
        successor: Vec<u8>,
        reward: Option<TxOut>,
    ) -> Result<BuiltBatch> {
        let (replica, _) = self.load()?;
        let entries = self.load_pool(&replica)?.select();
        let settlement = assemble_settlement(&replica, rollup_script_pubkey, successor, &entries, reward)
            .context("batch withdraws more than it backs")?;
        let witness = replica.witness(batch_transactions(&entries), settlement);
        let effects = apply_batch(&witness).map_err(|e| anyhow::anyhow!("transition: {e:?}"))?;
        Ok(BuiltBatch { entries, witness, effects })
    }

    /// Records a mined settlement and drops what it settled from the pool.
    pub fn accept(&self, settled: Settled) -> Result<Replica> {
        let (mut replica, mut chain) = self.load()?;
        replica
            .accept_annex_bytes(&hex::decode(&settled.annex)?, settled.value, outpoint(&settled.txid, settled.vout)?)
            .map_err(|e| anyhow::anyhow!("annex rejected: {e:?}"))?;
        chain.settlements.push(settled);
        self.save(&chain)?;
        self.save_pool(&self.load_pool(&replica)?)?;
        Ok(replica)
    }

    pub fn rollback(&self) -> Result<Replica> {
        let (_, mut chain) = self.load()?;
        if chain.settlements.pop().is_none() {
            bail!("nothing to roll back");
        }
        self.save(&chain)?;
        let replica = self.load()?.0;
        self.save_pool(&self.load_pool(&replica)?)?;
        Ok(replica)
    }

    /// The tip as wallets need it (anchor for new join-splits) plus the pool size.
    pub fn status(&self, replica: &Replica) -> Result<serde_json::Value> {
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
            "pending": self.load_pool(replica)?.entries.len(),
        }))
    }
}

/// Writes `bytes` to a sibling temporary file and renames it over `path`.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, path)?;
    Ok(())
}
