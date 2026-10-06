//! The batcher: admits proven transactions into the operator pool, periodically (or on request)
//! proves the next settlement, builds and broadcasts the Bitcoin transaction, and records the batch
//! in the operator chain once its rollup output has the configured number of confirmations.
//!
//! Durability: every step that matters is on disk before the next one starts. `inflight.json` holds
//! the fully signed settlement before it is broadcast, so a restart re-broadcasts or confirms it
//! instead of building a conflicting one, and the chain only advances after confirmation.
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, ensure, Context, Result};
use pr_operator::{verify_receipt, write_atomic, Settled, Store};
use pr_protocol_types::{Annex, Canonical, Outpoint};
use pr_sdk::api::{Anchor, BatchReport, FundingInput, MerklePath, NoteBatch, Notes, Stage, Submission, SubmitResponse};
use pr_sdk::{decode_receipt, decode_transaction};
use serde::{Deserialize, Serialize};

use crate::rpc::Rpc;
use crate::tx::{display_txid, serialize_segwit, weight};

pub const MAX_FUNDING_INPUTS: usize = 16;
pub const MAX_WITNESS_ITEMS: usize = 32;
pub const MAX_WITNESS_ITEM_BYTES: usize = 4096;

#[derive(Clone, Debug)]
pub enum Broadcast {
    /// `sendrawtransaction` (subject to the node's mempool policy).
    Send,
    /// `generateblock <address> [raw]` (regtest: mines the settlement directly).
    Mine(String),
}

#[derive(Clone, Debug)]
pub struct Config {
    pub template: PathBuf,
    pub covenant_cli: PathBuf,
    pub python: String,
    pub broadcast: Broadcast,
    pub confirmations: u64,
    pub poll: Duration,
    /// Smallest pool that is worth a settlement (0 allows empty batches).
    pub min_transactions: usize,
}

impl Config {
    pub fn from_env(broadcast: Broadcast) -> Config {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let path = |var: &str, default: PathBuf| std::env::var_os(var).map(PathBuf::from).unwrap_or(default);
        Config {
            template: path("PR_COVENANT_TEMPLATE", root.join("fixtures/apply-batch/receipt-template.json")),
            covenant_cli: path("PR_COVENANT_CLI", root.join("tools/covenant_cli.py")),
            python: std::env::var("PYTHON").unwrap_or_else(|_| "python3".to_owned()),
            broadcast,
            confirmations: 1,
            poll: Duration::from_secs(2),
            min_transactions: 1,
        }
    }
}

/// Why a request was refused.
#[derive(Debug)]
pub enum Rejection {
    Invalid(String),
    Conflict(String),
    NotFound(String),
    Internal(anyhow::Error),
}

impl From<anyhow::Error> for Rejection {
    fn from(e: anyhow::Error) -> Self {
        Rejection::Internal(e)
    }
}

/// A settlement that is fully built and may already be on the network.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Inflight {
    pub batch_number: u64,
    pub raw: String,
    pub txid: String,
    pub txid_internal: String,
    pub annex: String,
    pub value: u64,
    pub funding: Vec<String>,
    pub broadcast: bool,
}

pub struct Batcher {
    pub store: Store,
    pub cfg: Config,
    rpc: Rpc,
    lock: Mutex<()>,
    settling: AtomicBool,
    reports: Mutex<BTreeMap<u64, BatchReport>>,
    witnesses: Mutex<BTreeMap<String, Vec<String>>>,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn outpoint_key(o: &Outpoint) -> String {
    format!("{}:{}", hex::encode(o.txid), o.vout)
}

fn read_or_default<T: serde::de::DeserializeOwned + Default>(path: &Path) -> Result<T> {
    Ok(if path.exists() { serde_json::from_slice(&fs::read(path)?)? } else { T::default() })
}

impl Batcher {
    pub fn open(dir: &Path, cfg: Config, rpc: Rpc) -> Result<Arc<Batcher>> {
        let store = Store::new(dir);
        store.load().context("operator directory (run `pr-batcher init` and `genesis` first)")?;
        let reports: BTreeMap<u64, BatchReport> = read_or_default(&dir.join("reports.json"))?;
        let witnesses = read_or_default(&dir.join("funding-witnesses.json"))?;
        Ok(Arc::new(Batcher {
            store,
            cfg,
            rpc,
            lock: Mutex::new(()),
            settling: AtomicBool::new(false),
            reports: Mutex::new(reports),
            witnesses: Mutex::new(witnesses),
        }))
    }

    /// A batcher over a directory without genesis or RPC: only the covenant helpers are usable.
    pub fn open_uninitialized(dir: &Path, cfg: Config) -> Result<Arc<Batcher>> {
        Ok(Arc::new(Batcher {
            store: Store::new(dir),
            cfg,
            rpc: Rpc::new("http://127.0.0.1:0", "", "")?,
            lock: Mutex::new(()),
            settling: AtomicBool::new(false),
            reports: Mutex::new(BTreeMap::new()),
            witnesses: Mutex::new(BTreeMap::new()),
        }))
    }

    fn path(&self, name: &str) -> PathBuf {
        self.store.dir.join(name)
    }

    fn guard(&self) -> std::sync::MutexGuard<'_, ()> {
        self.lock.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn update(&self, n: u64, f: impl FnOnce(&mut BatchReport)) {
        let mut reports = self.reports.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(r) = reports.get_mut(&n) {
            f(r);
            eprintln!("batch {n}: {:?}{}", r.stage, r.error.as_deref().map(|e| format!(": {e}")).unwrap_or_default());
        }
        if let Err(e) = serde_json::to_vec_pretty(&*reports)
            .map_err(anyhow::Error::from)
            .and_then(|b| write_atomic(&self.path("reports.json"), &b))
        {
            eprintln!("writing reports.json: {e:#}");
        }
    }

    pub fn reports(&self) -> Vec<BatchReport> {
        self.reports.lock().unwrap_or_else(|p| p.into_inner()).values().cloned().collect()
    }

    pub fn report(&self, n: u64) -> Option<BatchReport> {
        self.reports.lock().unwrap_or_else(|p| p.into_inner()).get(&n).cloned()
    }

    pub fn status(&self) -> Result<serde_json::Value> {
        let _g = self.guard();
        let (replica, _) = self.store.load()?;
        let mut s = self.store.status(&replica)?;
        s["settling"] = self.settling.load(Ordering::SeqCst).into();
        Ok(s)
    }

    /// Admits a proven transaction: bounded canonical decoding, zero-knowledge receipt of this
    /// statement, then the pool's state-transition, duplicate and funding rules.
    pub fn submit(&self, sub: Submission) -> Result<SubmitResponse, Rejection> {
        let tx = decode_transaction(&sub.transaction).map_err(|e| Rejection::Invalid(format!("{e:#}")))?;
        let funding = validate_funding(&sub.funding).map_err(|e| Rejection::Invalid(format!("{e:#}")))?;
        verify_receipt(&tx).map_err(|e| Rejection::Invalid(format!("receipt: {e:#}")))?;
        let _g = self.guard();
        let pending = self.store.submit(tx, sub.funding.iter().map(|f| f.coin.clone()).collect()).map_err(|e| {
            let msg = format!("{e:#}");
            if ["Spent", "Reserved", "Duplicate"].iter().any(|k| msg.contains(k)) {
                Rejection::Conflict(msg)
            } else {
                Rejection::Invalid(msg)
            }
        })?;
        let mut w = self.witnesses.lock().unwrap_or_else(|p| p.into_inner());
        w.extend(funding);
        write_atomic(&self.path("funding-witnesses.json"), &serde_json::to_vec(&*w).map_err(anyhow::Error::from)?)?;
        Ok(SubmitResponse { pending })
    }

    /// Outputs of every settled batch from `from` on, for wallet scanning.
    pub fn notes(&self, from: u64) -> Result<Notes> {
        let _g = self.guard();
        let (replica, chain) = self.store.load()?;
        let mut batches = Vec::new();
        for (k, s) in chain.settlements.iter().enumerate() {
            let annex = Annex::decode(&hex::decode(&s.annex)?).map_err(|e| anyhow::anyhow!("annex: {e:?}"))?;
            if annex.body.batch_number < from {
                continue;
            }
            batches.push(NoteBatch {
                batch_number: annex.body.batch_number,
                first_leaf: replica.history[k].state.commitment_count,
                outputs: annex.body.outputs,
            });
        }
        Ok(Notes { batches })
    }

    /// Membership path of `leaf` against the tip anchor.
    pub fn merkle_path(&self, leaf: u64) -> Result<MerklePath, Rejection> {
        let _g = self.guard();
        let (replica, _) = self.store.load()?;
        if leaf >= replica.commitments.count() {
            return Err(Rejection::NotFound(format!("leaf {leaf} is not in the tree")));
        }
        let a = replica.tip().anchors.0.last().context("anchor")?;
        if a.commitment_count != replica.commitments.count() || a.commitment_root != replica.commitments.root() {
            return Err(Rejection::Internal(anyhow::anyhow!("tip anchor is not the current tree")));
        }
        Ok(MerklePath {
            leaf,
            commitment: replica.commitments.leaf(leaf),
            anchor: Anchor {
                root: hex::encode(a.commitment_root.0),
                commitment_count: a.commitment_count,
                batch_number: a.batch_number,
            },
            siblings: replica.commitments.path(leaf).to_vec(),
        })
    }

    fn inflight(&self) -> Result<Option<Inflight>> {
        let p = self.path("inflight.json");
        Ok(if p.exists() { Some(serde_json::from_slice(&fs::read(p)?)?) } else { None })
    }

    /// Starts proving the next settlement in the background; returns its batch number.
    pub fn start_settlement(self: &Arc<Self>) -> Result<u64, Rejection> {
        if self.settling.swap(true, Ordering::SeqCst) {
            return Err(Rejection::Conflict("a settlement is already in progress".into()));
        }
        let start = || -> Result<u64, Rejection> {
            if self.inflight()?.is_some() {
                return Err(Rejection::Conflict("a broadcast settlement awaits confirmation".into()));
            }
            let _g = self.guard();
            let (replica, _) = self.store.load()?;
            let pending = self.store.load_pool(&replica)?.entries.len();
            if pending < self.cfg.min_transactions {
                return Err(Rejection::Conflict(format!(
                    "pool holds {pending} transactions, fewer than {}",
                    self.cfg.min_transactions
                )));
            }
            Ok(replica.tip().state.batch_number + 1)
        };
        let n = match start() {
            Ok(n) => n,
            Err(e) => {
                self.settling.store(false, Ordering::SeqCst);
                return Err(e);
            }
        };
        self.reports.lock().unwrap_or_else(|p| p.into_inner()).insert(
            n,
            BatchReport {
                batch_number: n,
                stage: Stage::Proving,
                transactions: 0,
                txid: None,
                block_hash: None,
                error: None,
                prove: None,
                weight: None,
                started_unix: now(),
                finished_unix: None,
            },
        );
        self.update(n, |_| {});
        let me = self.clone();
        tokio::spawn(async move {
            let result = me.clone().settle(n).await;
            if let Err(e) = result {
                me.update(n, |r| {
                    r.stage = Stage::Failed;
                    r.error = Some(format!("{e:#}"));
                    r.finished_unix = Some(now());
                });
            }
            me.settling.store(false, Ordering::SeqCst);
        });
        Ok(n)
    }

    /// Resumes a settlement that was built (and possibly broadcast) before a restart.
    pub fn resume(self: &Arc<Self>) -> Result<()> {
        if let Some(f) = self.inflight()? {
            self.settling.store(true, Ordering::SeqCst);
            let me = self.clone();
            tokio::spawn(async move {
                let n = f.batch_number;
                if let Err(e) = me.clone().finish(f).await {
                    me.update(n, |r| r.error = Some(format!("{e:#}")));
                    eprintln!("batch {n}: {e:#}");
                }
                me.settling.store(false, Ordering::SeqCst);
            });
        }
        Ok(())
    }

    async fn settle(self: Arc<Self>, n: u64) -> Result<()> {
        let me = self.clone();
        let inflight = tokio::task::spawn_blocking(move || me.build_and_prove(n)).await??;
        self.finish(inflight).await
    }

    fn covenant(&self, args: &[&str]) -> Result<serde_json::Value> {
        let out = Command::new(&self.cfg.python)
            .arg(&self.cfg.covenant_cli)
            .args(args)
            .output()
            .with_context(|| format!("running {}", self.cfg.covenant_cli.display()))?;
        ensure!(out.status.success(), "covenant_cli {}: {}", args[0], String::from_utf8_lossy(&out.stderr));
        Ok(serde_json::from_slice(&out.stdout)?)
    }

    /// The covenant output for `root`; the leaf takes seconds to generate, so it is cached.
    pub fn covenant_script_pubkey(&self, rollup_id: &str, root: &str) -> Result<Vec<u8>> {
        let path = self.path("covenants.json");
        let mut cache: BTreeMap<String, String> = read_or_default(&path)?;
        if let Some(spk) = cache.get(root) {
            return Ok(hex::decode(spk)?);
        }
        let template = self.cfg.template.to_string_lossy().into_owned();
        let v = self.covenant(&["script", &template, rollup_id, root])?;
        let spk = v["script_pubkey"].as_str().context("script_pubkey")?.to_owned();
        cache.insert(root.to_owned(), spk.clone());
        write_atomic(&path, &serde_json::to_vec_pretty(&cache)?)?;
        Ok(hex::decode(spk)?)
    }

    fn build_and_prove(&self, n: u64) -> Result<Inflight> {
        let (b, old_root, rollup_id) = {
            let _g = self.guard();
            let (replica, _) = self.store.load()?;
            let tip = replica.tip().state;
            ensure!(tip.batch_number + 1 == n, "tip moved to batch {}", tip.batch_number);
            let (rollup_id, old_root) = (hex::encode(tip.rollup_id.0), hex::encode(tip.root()));
            let spk = self.covenant_script_pubkey(&rollup_id, &old_root)?;
            let first = self.store.build(spk.clone(), Vec::new(), None)?;
            let new_root = hex::encode(first.effects.new_state.root());
            let successor = self.covenant_script_pubkey(&rollup_id, &new_root)?;
            let b = self.store.build(spk, successor, None)?;
            ensure!(hex::encode(b.effects.new_state.root()) == new_root, "new root depends on the successor");
            (b, old_root, rollup_id)
        };
        let settlement = &b.witness.settlement;
        let witnesses = self.witnesses.lock().unwrap_or_else(|p| p.into_inner()).clone();
        let mut funding = Vec::new();
        let mut stacks = vec![Vec::new()];
        for i in &settlement.inputs[1..] {
            let key = outpoint_key(&i.prevout);
            let stack = witnesses.get(&key).with_context(|| format!("no witness for funding input {key}"))?;
            stacks.push(stack.iter().map(hex::decode).collect::<Result<Vec<_>, _>>()?);
            funding.push(key);
        }
        self.update(n, |r| r.transactions = b.entries.len());
        let receipts = b.entries.iter().map(|e| decode_receipt(&e.tx.receipt)).collect::<Result<Vec<_>>>()?;
        let proof = pr_prover::settle::prove_settlement(&b.witness, &receipts)?;
        ensure!(proof.journal == b.effects.journal.encode(), "proven journal is not the operator's");
        let dir = self.path(&format!("batches/{n}"));
        fs::create_dir_all(&dir)?;
        fs::write(dir.join("witness.json"), serde_json::to_vec(&b.witness)?)?;
        fs::write(dir.join("stats.json"), serde_json::to_vec_pretty(&proof.stats)?)?;
        fs::write(dir.join("seal.bin"), proof.seal_bytes())?;
        fs::write(dir.join("receipt.json"), serde_json::to_vec_pretty(&proof.receipt_json()?)?)?;
        let stats = serde_json::to_value(&proof.stats)?;
        self.update(n, |r| {
            r.stage = Stage::Witness;
            r.prove = Some(stats);
        });

        let annex = hex::encode(&b.effects.annex_bytes);
        let new_root = hex::encode(b.effects.new_state.root());
        let template = self.cfg.template.to_string_lossy().into_owned();
        let receipt_json = dir.join("receipt.json").to_string_lossy().into_owned();
        let seal = dir.join("seal.bin").to_string_lossy().into_owned();
        let w =
            self.covenant(&["witness", &template, &rollup_id, &old_root, &receipt_json, &seal, &new_root, &annex])?;
        let successor = w["successor_script_pubkey"].as_str().context("successor")?;
        ensure!(hex::decode(successor)? == settlement.outputs[0].script_pubkey, "successor output mismatch");
        stacks[0] = w["stack"]
            .as_array()
            .context("stack")?
            .iter()
            .map(|s| hex::decode(s.as_str().unwrap_or("-")))
            .collect::<Result<Vec<_>, _>>()?;
        let raw = serialize_segwit(settlement, &stacks);
        let txid = display_txid(settlement);
        let wt = weight(settlement, &raw);
        let inflight = Inflight {
            batch_number: n,
            raw: hex::encode(&raw),
            txid: txid.clone(),
            txid_internal: hex::encode(settlement.txid()),
            annex,
            value: settlement.outputs[0].value,
            funding,
            broadcast: false,
        };
        write_atomic(&self.path("inflight.json"), &serde_json::to_vec_pretty(&inflight)?)?;
        fs::write(dir.join("settlement.hex"), &inflight.raw)?;
        self.update(n, |r| {
            r.txid = Some(txid);
            r.weight = Some(wt);
        });
        Ok(inflight)
    }

    async fn broadcast(&self, f: &Inflight) -> Result<Option<String>> {
        match &self.cfg.broadcast {
            Broadcast::Send => match self.rpc.send_raw_transaction(&f.raw).await {
                Ok(_) => Ok(None),
                Err(e) if format!("{e}").contains("already") => Ok(None),
                Err(e) => Err(e),
            },
            Broadcast::Mine(address) => Ok(Some(self.rpc.generate_block(address, &f.raw).await?)),
        }
    }

    /// Broadcasts `f` (unless it already is on chain), waits for confirmations, then records it.
    async fn finish(self: Arc<Self>, mut f: Inflight) -> Result<()> {
        let n = f.batch_number;
        let known = self.rpc.confirmations(&f.txid, 0).await?;
        if known.is_none() {
            let block = self.broadcast(&f).await?;
            self.update(n, |r| r.block_hash = block);
        }
        f.broadcast = true;
        write_atomic(&self.path("inflight.json"), &serde_json::to_vec_pretty(&f)?)?;
        self.update(n, |r| r.stage = Stage::Broadcast);
        let mut misses = 0;
        loop {
            match self.rpc.confirmations(&f.txid, 0).await? {
                Some(c) if c >= self.cfg.confirmations => break,
                Some(_) => misses = 0,
                None => {
                    misses += 1;
                    if misses > 3 {
                        if let Err(e) = self.broadcast(&f).await {
                            bail!("settlement left the mempool and cannot be re-broadcast: {e:#}");
                        }
                        misses = 0;
                    }
                }
            }
            tokio::time::sleep(self.cfg.poll).await;
        }
        {
            let _g = self.guard();
            self.store.accept(Settled {
                annex: f.annex.clone(),
                value: f.value,
                txid: f.txid_internal.clone(),
                vout: 0,
            })?;
            fs::remove_file(self.path("inflight.json"))?;
            let mut w = self.witnesses.lock().unwrap_or_else(|p| p.into_inner());
            for k in &f.funding {
                w.remove(k);
            }
            write_atomic(&self.path("funding-witnesses.json"), &serde_json::to_vec(&*w)?)?;
        }
        self.update(n, |r| {
            r.stage = Stage::Confirmed;
            r.finished_unix = Some(now());
        });
        Ok(())
    }
}

/// Bounds and decodes the funding witnesses; returns them keyed by outpoint.
fn validate_funding(funding: &[FundingInput]) -> Result<Vec<(String, Vec<String>)>> {
    ensure!(funding.len() <= MAX_FUNDING_INPUTS, "more than {MAX_FUNDING_INPUTS} funding inputs");
    let mut out = Vec::new();
    for f in funding {
        ensure!(f.witness.len() <= MAX_WITNESS_ITEMS, "more than {MAX_WITNESS_ITEMS} witness items");
        for item in &f.witness {
            ensure!(item.len() <= 2 * MAX_WITNESS_ITEM_BYTES, "witness item over {MAX_WITNESS_ITEM_BYTES} bytes");
            hex::decode(item).context("witness item is not hex")?;
        }
        out.push((outpoint_key(&f.coin.outpoint), f.witness.clone()));
    }
    Ok(out)
}
