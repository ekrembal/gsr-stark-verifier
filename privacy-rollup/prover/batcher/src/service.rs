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
use pr_sdk::api::{
    Anchor, BatchReport, EscrowRegistration, EscrowState, EscrowTerms, FundingInput, MerklePath, NoteBatch, Notes,
    Stage, Submission, SubmitResponse,
};
use pr_sdk::pr_mempool::{entry_weight, escrow_weight, Entry, EscrowCoin};
use pr_sdk::pr_protocol_types::{
    ciphertext_kind, DUST_LIMIT, EMPTY_SETTLEMENT_WEIGHT, MAX_BATCH_ESCROWS, MAX_MONEY, MAX_SETTLEMENT_WEIGHT,
};
use pr_sdk::pr_state_transition::escrow;
use pr_sdk::{decode_receipt, decode_transaction};
use serde::{Deserialize, Serialize};

use crate::cpfp::RewardKey;
use crate::fees::{self, FeePlan, FeeQuote, SettlePolicy};
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
    /// `sendrawtransaction` / `submitpackage` on a miner's node: settlements carry an annex and are
    /// nonstandard, so public relay drops them.
    Direct(Rpc),
}

/// Where the feerate comes from.
#[derive(Clone, Debug)]
pub enum FeeRate {
    Fixed(f64),
    /// `estimatesmartfee <target_blocks>`, never below `floor` (and `floor` without an estimate).
    Estimate {
        target_blocks: u16,
        floor: f64,
    },
}

/// Blocks searched back from the tip for a settlement that spent the rollup output.
pub const SPENDER_SEARCH_DEPTH: u64 = 288;
/// vsize of the CPFP child: one P2TR key-path input, one P2TR output.
pub const CPFP_CHILD_VSIZE: u64 = 111;

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
    /// Smallest escrow refund delay (blocks) accepted; escrows are swept only while their age is at
    /// most half their refund delay, so a refund cannot race a sweep.
    pub min_refund_delay: u16,
    pub fee_rate: FeeRate,
    /// Receives fee surplus; also the CPFP anchor, so it should be a key of the node's wallet.
    pub reward_script: Option<Vec<u8>>,
    /// Secret key of a BIP86 `reward_script`, which lets [`Batcher::bump`] sign CPFP children.
    pub reward_key: Option<Vec<u8>>,
    /// Batch size the verifier spend is priced over in quotes, and that triggers an automatic settlement.
    pub target_transactions: usize,
    /// Longest an admitted transaction waits for an automatic settlement once fees cover it.
    pub max_wait: Duration,
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
            min_refund_delay: 144,
            fee_rate: FeeRate::Fixed(1.0),
            reward_script: None,
            reward_key: None,
            target_transactions: 8,
            max_wait: Duration::from_secs(3600),
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
    #[serde(default)]
    pub escrows: Vec<String>,
    pub broadcast: bool,
    #[serde(default)]
    pub miner_fee: u64,
    #[serde(default)]
    pub weight: u64,
    /// Output index, value and scriptPubKey of the reward (CPFP anchor) output.
    #[serde(default)]
    pub reward: Option<(u32, u64, String)>,
    /// CPFP children broadcast with the settlement, hex.
    #[serde(default)]
    pub bumps: Vec<String>,
}

/// `POST /v1/bump`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BumpRequest {
    pub sat_per_vb: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BumpResponse {
    pub child_txid: String,
    pub child_fee: u64,
    pub package_sat_per_vb: f64,
}

/// What an automatic settlement would carry now.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Readiness {
    pub ready: bool,
    pub transactions: usize,
    pub escrows: usize,
    pub fees: u64,
    pub required: u64,
    pub oldest_age_secs: u64,
    pub sat_per_vb: f64,
}

/// A registered escrow output.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Registered {
    pub coin: EscrowCoin,
    pub refund_delay: u16,
}

pub struct Batcher {
    pub store: Store,
    pub cfg: Config,
    rpc: Rpc,
    lock: Mutex<()>,
    settling: AtomicBool,
    reports: Mutex<BTreeMap<u64, BatchReport>>,
    witnesses: Mutex<BTreeMap<String, Vec<String>>>,
    escrows: Mutex<BTreeMap<String, Registered>>,
    rate: Mutex<f64>,
    /// Admission time (unix) by first output commitment or escrow outpoint.
    received: Mutex<BTreeMap<String, u64>>,
}

fn initial_rate(r: &FeeRate) -> f64 {
    match *r {
        FeeRate::Fixed(f) => f,
        FeeRate::Estimate { floor, .. } => floor,
    }
}

fn entry_key(e: &Entry) -> String {
    hex::encode(e.tx.public.output_commitments[0].0)
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
        let escrows = read_or_default(&dir.join("escrows.json"))?;
        let received = read_or_default(&dir.join("received.json"))?;
        let rate = Mutex::new(initial_rate(&cfg.fee_rate));
        Ok(Arc::new(Batcher {
            store,
            cfg,
            rpc,
            lock: Mutex::new(()),
            settling: AtomicBool::new(false),
            reports: Mutex::new(reports),
            witnesses: Mutex::new(witnesses),
            escrows: Mutex::new(escrows),
            rate,
            received: Mutex::new(received),
        }))
    }

    /// A batcher over a directory without genesis or RPC: only the covenant helpers are usable.
    pub fn open_uninitialized(dir: &Path, cfg: Config) -> Result<Arc<Batcher>> {
        let rate = Mutex::new(initial_rate(&cfg.fee_rate));
        Ok(Arc::new(Batcher {
            store: Store::new(dir),
            cfg,
            rpc: Rpc::new("http://127.0.0.1:0", "", "")?,
            lock: Mutex::new(()),
            settling: AtomicBool::new(false),
            reports: Mutex::new(BTreeMap::new()),
            witnesses: Mutex::new(BTreeMap::new()),
            escrows: Mutex::new(BTreeMap::new()),
            rate,
            received: Mutex::new(BTreeMap::new()),
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
        let coins: Vec<_> = sub.funding.iter().map(|f| f.coin.clone()).collect();
        let entry = Entry { tx, funding: coins, arrival: 0 };
        let floor = fees::admission_floor(entry_weight(&entry), self.rate());
        if entry.tx.public.fee_sats < floor {
            return Err(Rejection::Invalid(format!(
                "fee_sats {} is below the floor {floor} for {} WU at {} sat/vB",
                entry.tx.public.fee_sats,
                entry_weight(&entry),
                self.rate()
            )));
        }
        let key = entry_key(&entry);
        let Entry { tx, .. } = entry;
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
        self.mark_received(key)?;
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
            let pending = self.store.load_pool(&replica)?.entries.len() + self.escrow_map().len();
            if pending < self.cfg.min_transactions {
                return Err(Rejection::Conflict(format!(
                    "pool holds {pending} transactions, fewer than {}",
                    self.cfg.min_transactions
                )));
            }
            let escrows: Vec<EscrowCoin> = self.escrow_map().values().map(|r| r.coin.clone()).collect();
            let entries = self.store.select(&replica, &escrows)?;
            if let Err(s) = self.price(&entries, &escrows) {
                return Err(Rejection::Conflict(format!(
                    "fees {} do not cover the settlement: {} required at {} sat/vB",
                    s.fees,
                    s.required,
                    self.rate()
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
                fees: None,
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
        self.refresh_rate().await?;
        if !self.sync().await?.is_empty() {
            bail!("another settlement advanced the rollup; batch {n} is rebuilt on the new tip next time");
        }
        self.prune_spent_funding().await?;
        let escrows = self.sweepable_escrows().await?;
        let me = self.clone();
        let inflight = tokio::task::spawn_blocking(move || me.build_and_prove(n, escrows)).await??;
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

    fn escrow_map(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Registered>> {
        self.escrows.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn save_escrows(&self, m: &BTreeMap<String, Registered>) -> Result<()> {
        write_atomic(&self.path("escrows.json"), &serde_json::to_vec_pretty(m)?)
    }

    /// What a depositor needs to build an address; the sweep body is the same for every root.
    pub fn escrow_terms(&self) -> Result<EscrowTerms> {
        let path = self.path("escrow-terms.json");
        if path.exists() {
            return Ok(serde_json::from_slice(&fs::read(path)?)?);
        }
        let (rollup_id, root) = {
            let _g = self.guard();
            let (replica, _) = self.store.load()?;
            let tip = replica.tip().state;
            (hex::encode(tip.rollup_id.0), hex::encode(tip.root()))
        };
        let template = self.cfg.template.to_string_lossy().into_owned();
        let v = self.covenant(&["escrow-body", &template, &rollup_id, &root])?;
        let terms = EscrowTerms {
            rollup_id,
            body: v["body"].as_str().context("body")?.to_owned(),
            confirmations: self.cfg.confirmations,
            min_refund_delay: self.cfg.min_refund_delay,
        };
        write_atomic(&path, &serde_json::to_vec_pretty(&terms)?)?;
        Ok(terms)
    }

    /// Admits a paid escrow: its opening must open the output on chain to a note of this rollup with
    /// this batcher's sweep body and a long enough refund delay.
    pub async fn register_escrow(&self, reg: EscrowRegistration) -> Result<EscrowState, Rejection> {
        let invalid = |m: String| Rejection::Invalid(m);
        let terms = self.escrow_terms()?;
        let (txid, vout) = reg.outpoint.clone();
        let mut outpoint = pr_operator::outpoint(&txid, vout).map_err(|e| invalid(format!("{e:#}")))?;
        outpoint.txid.reverse();
        let key = outpoint_key(&outpoint);
        if self.escrow_map().contains_key(&key) {
            return Err(Rejection::Conflict(format!("escrow {txid}:{vout} is already registered")));
        }
        let e = &reg.opening;
        let body = hex::decode(&terms.body).map_err(anyhow::Error::from)?;
        if e.sweep_leaf.len() != 34 + body.len() || e.sweep_leaf[34..] != body[..] {
            return Err(invalid("sweep leaf does not use this batcher's sweep body".into()));
        }
        if ciphertext_kind(&e.ciphertext).is_none() || e.value < DUST_LIMIT || e.value > MAX_MONEY {
            return Err(invalid("escrow note is malformed or dust".into()));
        }
        let refund = hex::decode(&reg.refund_leaf).map_err(|_| invalid("refund leaf is not hex".into()))?;
        let delay = refund_delay(&refund)
            .ok_or_else(|| invalid("refund leaf is not <delay> CSV DROP <key> CHECKSIG".into()))?;
        if escrow::tapleaf_hash(escrow::REFUND_LEAF_VERSION, &refund) != e.sibling {
            return Err(invalid("refund leaf is not the sweep leaf's sibling".into()));
        }
        if delay < self.cfg.min_refund_delay {
            return Err(invalid(format!("refund delay {delay} is below {}", self.cfg.min_refund_delay)));
        }
        let (amount, spk, confirmations) = self
            .rpc
            .txout(&txid, vout)
            .await?
            .ok_or_else(|| Rejection::NotFound(format!("{txid}:{vout} is not an unspent output")))?;
        let rollup_id = pr_sdk::fe_from_hex(&terms.rollup_id)?;
        if !escrow::check_escrow(&rollup_id, e, &spk) {
            return Err(invalid("opening does not open the output's scriptPubKey".into()));
        }
        if e.value.checked_add(e.fee_sats) != Some(amount) {
            return Err(invalid(format!("output pays {amount} sats, the opening {} + {}", e.value, e.fee_sats)));
        }
        let coin = EscrowCoin { outpoint, amount, script_pubkey: spk, opening: e.clone() };
        let mut m = self.escrow_map();
        m.insert(key.clone(), Registered { coin, refund_delay: delay });
        self.save_escrows(&m)?;
        drop(m);
        self.mark_received(key)?;
        Ok(EscrowState { outpoint: reg.outpoint, amount, confirmations, reserved_by: None })
    }

    /// Every registered escrow with its current confirmations (`gettxout`).
    pub async fn escrow_states(&self) -> Result<Vec<EscrowState>> {
        let reserved = self.inflight()?.map(|f| (f.batch_number, f.escrows)).unwrap_or_default();
        let list: Vec<Registered> = self.escrow_map().values().cloned().collect();
        let mut out = Vec::new();
        for r in list {
            let o = &r.coin.outpoint;
            let (txid, vout) = (display_hex(&o.txid), o.vout);
            let confirmations = self.rpc.txout(&txid, vout).await?.map_or(0, |t| t.2);
            let by = reserved.1.contains(&outpoint_key(o)).then_some(reserved.0);
            out.push(EscrowState { outpoint: (txid, vout), amount: r.coin.amount, confirmations, reserved_by: by });
        }
        Ok(out)
    }

    /// Revalidates every registered escrow against the UTXO set: drops spent (refunded) ones and
    /// returns those with enough confirmations and still far from their refund height.
    async fn sweepable_escrows(&self) -> Result<Vec<EscrowCoin>> {
        let list: Vec<(String, Registered)> = self.escrow_map().iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        let mut gone = Vec::new();
        let mut out = Vec::new();
        let mut escrow_budget = (MAX_SETTLEMENT_WEIGHT - EMPTY_SETTLEMENT_WEIGHT) / 2;
        for (k, r) in list {
            let o = &r.coin.outpoint;
            match self.rpc.txout(&display_hex(&o.txid), o.vout).await? {
                None => gone.push(k),
                Some((amount, spk, c)) if amount == r.coin.amount && spk == r.coin.script_pubkey => {
                    if c >= self.cfg.confirmations
                        && c.saturating_mul(2) <= r.refund_delay as u64
                        && out.len() < MAX_BATCH_ESCROWS
                        && escrow_budget >= escrow_weight(&r.coin)
                    {
                        escrow_budget -= escrow_weight(&r.coin);
                        out.push(r.coin);
                    }
                }
                Some(_) => gone.push(k),
            }
        }
        if !gone.is_empty() {
            let mut m = self.escrow_map();
            for k in &gone {
                eprintln!("escrow {k} is no longer unspent; dropped");
                m.remove(k);
            }
            self.save_escrows(&m)?;
        }
        Ok(out)
    }

    fn build_and_prove(&self, n: u64, escrows: Vec<EscrowCoin>) -> Result<Inflight> {
        let (b, old_root, rollup_id) = {
            let _g = self.guard();
            let (replica, _) = self.store.load()?;
            let tip = replica.tip().state;
            ensure!(tip.batch_number + 1 == n, "tip moved to batch {}", tip.batch_number);
            let (rollup_id, old_root) = (hex::encode(tip.rollup_id.0), hex::encode(tip.root()));
            let spk = self.covenant_script_pubkey(&rollup_id, &old_root)?;
            let entries = self.store.select(&replica, &escrows)?;
            let plan = self.price(&entries, &escrows).map_err(|s| {
                anyhow::anyhow!(
                    "fees {} do not cover the settlement: {} required at {} sat/vB",
                    s.fees,
                    s.required,
                    self.rate()
                )
            })?;
            let reward = plan.reward.clone();
            self.update(n, |r| r.fees = serde_json::to_value(&plan).ok());
            let first = self.store.build_with_escrows(spk.clone(), Vec::new(), &escrows, reward.clone())?;
            let new_root = hex::encode(first.effects.new_state.root());
            let successor = self.covenant_script_pubkey(&rollup_id, &new_root)?;
            let b = self.store.build_with_escrows(spk, successor, &escrows, reward)?;
            ensure!(hex::encode(b.effects.new_state.root()) == new_root, "new root depends on the successor");
            (b, old_root, rollup_id)
        };
        let settlement = &b.witness.settlement;
        let witnesses = self.witnesses.lock().unwrap_or_else(|p| p.into_inner()).clone();
        let mut funding = Vec::new();
        let mut swept = Vec::new();
        let mut stacks = vec![Vec::new()];
        for i in &settlement.inputs[1..] {
            let key = outpoint_key(&i.prevout);
            if let Some(e) = escrows.iter().find(|e| e.outpoint == i.prevout) {
                let control = escrow::sweep_control_block(&e.opening).context("escrow control block")?;
                stacks.push(vec![e.opening.sweep_leaf.clone(), control]);
                swept.push(key);
                continue;
            }
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
        let paid_in: u64 = settlement.inputs.iter().map(|i| i.amount).sum();
        let paid_out: u64 = settlement.outputs.iter().map(|o| o.value).sum();
        let reward = self.cfg.reward_script.as_ref().and_then(|spk| {
            let i = settlement.outputs.iter().rposition(|o| &o.script_pubkey == spk)?;
            Some((i as u32, settlement.outputs[i].value, hex::encode(spk)))
        });
        let inflight = Inflight {
            batch_number: n,
            raw: hex::encode(&raw),
            txid: txid.clone(),
            txid_internal: hex::encode(settlement.txid()),
            annex,
            value: settlement.outputs[0].value,
            funding,
            escrows: swept,
            broadcast: false,
            miner_fee: paid_in - paid_out,
            weight: wt,
            reward,
            bumps: Vec::new(),
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
            Broadcast::Direct(miner) => {
                if f.bumps.is_empty() {
                    match miner.send_raw_transaction(&f.raw).await {
                        Ok(_) => {}
                        Err(e) if format!("{e}").contains("already") => {}
                        Err(e) => return Err(e),
                    }
                } else {
                    let mut package = vec![f.raw.clone()];
                    package.extend(f.bumps.iter().cloned());
                    miner.submit_package(&package).await?;
                }
                Ok(None)
            }
        }
    }

    /// Broadcasts `f` (unless it already is on chain), waits for confirmations, then records it.
    async fn finish(self: Arc<Self>, mut f: Inflight) -> Result<()> {
        let n = f.batch_number;
        let known = self.rpc.confirmations(&f.txid, 0).await?;
        if known.is_none() {
            self.ensure_current(&f).await?;
            self.abandon_if_conflicted(&f).await?;
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
                        self.ensure_current(&f).await?;
                        if let Some(g) = self.inflight()? {
                            f.bumps = g.bumps;
                        }
                        if let Err(e) = self.broadcast(&f).await {
                            self.abandon_if_conflicted(&f).await?;
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
            self.store.accept(Settled { annex: f.annex.clone(), tx: f.raw.clone() })?;
            fs::remove_file(self.path("inflight.json"))?;
            let mut w = self.witnesses.lock().unwrap_or_else(|p| p.into_inner());
            for k in &f.funding {
                w.remove(k);
            }
            write_atomic(&self.path("funding-witnesses.json"), &serde_json::to_vec(&*w)?)?;
            let mut m = self.escrow_map();
            for k in &f.escrows {
                m.remove(k);
            }
            self.save_escrows(&m)?;
        }
        self.update(n, |r| {
            r.stage = Stage::Confirmed;
            r.finished_unix = Some(now());
        });
        Ok(())
    }
}

impl Batcher {
    /// After a failed re-broadcast: if an escrow or funding input of `f` was spent elsewhere (a
    /// refund or a depositor double spend), the settlement can never confirm, so drop it, drop the
    /// spent escrows and let the next settlement be rebuilt without them.
    async fn abandon_if_conflicted(&self, f: &Inflight) -> Result<()> {
        let mut spent = Vec::new();
        for k in f.escrows.iter().chain(&f.funding) {
            let (txid, vout) = k.split_once(':').context("outpoint key")?;
            let txid = display_hex(&hex::decode(txid)?.try_into().map_err(|_| anyhow::anyhow!("txid"))?);
            if self.rpc.txout(&txid, vout.parse()?).await?.is_none() {
                spent.push(k.clone());
            }
        }
        if spent.is_empty() {
            return Ok(());
        }
        {
            let _g = self.guard();
            let mut m = self.escrow_map();
            for k in &spent {
                m.remove(k);
            }
            self.save_escrows(&m)?;
        }
        self.drop_entries_funded_by(&spent)?;
        fs::remove_file(self.path("inflight.json"))?;
        bail!("settlement inputs {spent:?} were spent elsewhere; abandoned batch {}", f.batch_number)
    }
}

impl Batcher {
    pub fn rate(&self) -> f64 {
        *self.rate.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Re-reads the feerate (`estimatesmartfee` for [`FeeRate::Estimate`]).
    pub async fn refresh_rate(&self) -> Result<f64> {
        let r = match self.cfg.fee_rate {
            FeeRate::Fixed(f) => f,
            FeeRate::Estimate { target_blocks, floor } => {
                self.rpc.estimate_sat_per_vb(target_blocks).await?.map_or(floor, |e| e.max(floor))
            }
        };
        *self.rate.lock().unwrap_or_else(|p| p.into_inner()) = r;
        Ok(r)
    }

    pub fn reward_script(&self) -> Option<&[u8]> {
        self.cfg.reward_script.as_deref()
    }

    pub fn quote(&self) -> FeeQuote {
        fees::quote(self.rate(), self.cfg.target_transactions)
    }

    fn price(&self, entries: &[Entry], escrows: &[EscrowCoin]) -> Result<FeePlan, fees::Shortfall> {
        let weight = entries.iter().map(entry_weight).sum::<u64>() + escrows.iter().map(escrow_weight).sum::<u64>();
        let paid = entries.iter().map(|e| e.tx.public.fee_sats).sum::<u64>()
            + escrows.iter().map(|c| c.opening.fee_sats).sum::<u64>();
        fees::plan(weight, paid, self.rate(), self.cfg.reward_script.as_deref())
    }

    fn mark_received(&self, key: String) -> Result<()> {
        let mut r = self.received.lock().unwrap_or_else(|p| p.into_inner());
        r.entry(key).or_insert_with(now);
        write_atomic(&self.path("received.json"), &serde_json::to_vec(&*r)?)
    }

    /// Whether an automatic settlement should start now (see [`SettlePolicy`]).
    pub async fn readiness(&self) -> Result<Readiness> {
        let sat_per_vb = self.refresh_rate().await?;
        let escrows = self.sweepable_escrows().await?;
        let entries = {
            let _g = self.guard();
            let (replica, _) = self.store.load()?;
            self.store.select(&replica, &escrows)?
        };
        let received = self.received.lock().unwrap_or_else(|p| p.into_inner()).clone();
        let t = now();
        let oldest = entries
            .iter()
            .map(entry_key)
            .chain(escrows.iter().map(|c| outpoint_key(&c.outpoint)))
            .filter_map(|k| received.get(&k).copied())
            .min()
            .map_or(0, |r| t.saturating_sub(r));
        let content = entries.iter().map(entry_weight).sum::<u64>() + escrows.iter().map(escrow_weight).sum::<u64>();
        let (fees_paid, required, covered) = match self.price(&entries, &escrows) {
            Ok(p) => (p.fees, p.miner_fee, true),
            Err(s) => (s.fees, s.required, false),
        };
        let policy = SettlePolicy {
            min_transactions: self.cfg.min_transactions,
            target_transactions: self.cfg.target_transactions,
            max_wait_secs: self.cfg.max_wait.as_secs(),
        };
        let pending = entries.len() + escrows.len();
        Ok(Readiness {
            ready: policy.ready(pending, content, covered, oldest),
            transactions: entries.len(),
            escrows: escrows.len(),
            fees: fees_paid,
            required,
            oldest_age_secs: oldest,
            sat_per_vb,
        })
    }

    /// Starts a settlement if [`Batcher::readiness`] says so.
    pub async fn auto_settle(self: &Arc<Self>) -> Result<Option<u64>> {
        if self.settling.load(Ordering::SeqCst) || self.inflight()?.is_some() {
            return Ok(None);
        }
        self.sync().await?;
        if !self.readiness().await?.ready {
            return Ok(None);
        }
        match self.start_settlement() {
            Ok(n) => Ok(Some(n)),
            Err(Rejection::Conflict(_)) => Ok(None),
            Err(Rejection::Internal(e)) => Err(e),
            Err(e) => bail!("{e:?}"),
        }
    }

    fn drop_entries_funded_by(&self, spent: &[String]) -> Result<()> {
        let _g = self.guard();
        let (replica, _) = self.store.load()?;
        let mut pool = self.store.load_pool(&replica)?;
        let before = pool.entries.len();
        pool.entries.retain(|e| !e.funding.iter().any(|c| spent.contains(&outpoint_key(&c.outpoint))));
        if pool.entries.len() != before {
            eprintln!("dropped {} pool transactions whose funding was spent elsewhere", before - pool.entries.len());
            self.store.save_pool(&pool)?;
        }
        let mut w = self.witnesses.lock().unwrap_or_else(|p| p.into_inner());
        for k in spent {
            w.remove(k);
        }
        write_atomic(&self.path("funding-witnesses.json"), &serde_json::to_vec(&*w)?)
    }

    /// Drops pool transactions whose funding coins are no longer unspent (a depositor double spend).
    async fn prune_spent_funding(&self) -> Result<()> {
        let coins: Vec<String> = {
            let _g = self.guard();
            let (replica, _) = self.store.load()?;
            let pool = self.store.load_pool(&replica)?;
            pool.entries.iter().flat_map(|e| e.funding.iter().map(|c| outpoint_key(&c.outpoint))).collect()
        };
        let mut spent = Vec::new();
        for k in coins {
            let (txid, vout) = k.split_once(':').context("outpoint key")?;
            let txid = display_hex(&hex::decode(txid)?.try_into().map_err(|_| anyhow::anyhow!("txid"))?);
            if self.rpc.txout(&txid, vout.parse()?).await?.is_none() {
                spent.push(k);
            }
        }
        if spent.is_empty() {
            return Ok(());
        }
        self.drop_entries_funded_by(&spent)
    }

    /// Fails if `f` no longer spends the tip (another settlement advanced the rollup).
    async fn ensure_current(&self, f: &Inflight) -> Result<()> {
        self.sync().await?;
        ensure!(
            self.inflight()?.is_some_and(|g| g.txid == f.txid),
            "batch {} was superseded by another settlement",
            f.batch_number
        );
        Ok(())
    }

    /// Adopts settlements made by anyone else: while the tip's rollup output is spent by a confirmed
    /// transaction that is not ours, records it (its annex is checked against the replica like any
    /// settlement) and drops a conflicting in-flight settlement. Returns the adopted batch numbers.
    pub async fn sync(&self) -> Result<Vec<u64>> {
        let mut adopted = Vec::new();
        loop {
            let (utxo, n) = {
                let _g = self.guard();
                let (replica, _) = self.store.load()?;
                (replica.tip().utxo, replica.tip().state.batch_number + 1)
            };
            if self.rpc.txout(&display_hex(&utxo.txid), utxo.vout).await?.is_some() {
                break;
            }
            let ours = self.inflight()?;
            if let Some(f) = &ours {
                if self.rpc.confirmations(&f.txid, 0).await?.is_some() {
                    break;
                }
            }
            let Some((txid, raw, annex)) = self.find_spender(&utxo).await? else { break };
            {
                let _g = self.guard();
                self.store
                    .accept(Settled { annex, tx: raw })
                    .with_context(|| format!("adopting settlement {txid} of batch {n}"))?;
            }
            eprintln!("batch {n}: adopted settlement {txid} made by another operator");
            if ours.is_some_and(|f| f.batch_number == n) {
                fs::remove_file(self.path("inflight.json"))?;
                self.update(n, |r| {
                    r.stage = Stage::Failed;
                    r.error = Some(format!("superseded by {txid}"));
                    r.finished_unix = Some(now());
                });
            }
            adopted.push(n);
        }
        Ok(adopted)
    }

    /// The confirmed transaction spending `o` in the last [`SPENDER_SEARCH_DEPTH`] blocks: its txid,
    /// raw hex and input-zero annex.
    async fn find_spender(&self, o: &Outpoint) -> Result<Option<(String, String, String)>> {
        let tip = self.rpc.block_count().await?;
        let txid = display_hex(&o.txid);
        for h in (tip.saturating_sub(SPENDER_SEARCH_DEPTH)..=tip).rev() {
            let b = self.rpc.block_at(h).await?;
            for t in b["tx"].as_array().context("getblock tx")? {
                let i = &t["vin"][0];
                if i["txid"].as_str() == Some(txid.as_str()) && i["vout"].as_u64() == Some(o.vout as u64) {
                    let annex = i["txinwitness"]
                        .as_array()
                        .and_then(|w| w.last())
                        .and_then(|a| a.as_str())
                        .filter(|a| a.starts_with("50"))
                        .context("spender of the rollup output carries no annex")?;
                    let raw = t["hex"].as_str().context("getblock hex")?;
                    let id = t["txid"].as_str().context("getblock txid")?;
                    return Ok(Some((id.to_owned(), raw.to_owned(), annex.to_owned())));
                }
            }
        }
        Ok(None)
    }

    /// CPFP: spends the reward output of the broadcast settlement with a wallet-signed child so the
    /// package pays `sat_per_vb`, and submits both as a package.
    pub async fn bump(&self, sat_per_vb: f64) -> Result<BumpResponse, Rejection> {
        let mut f = self.inflight()?.ok_or_else(|| Rejection::NotFound("no settlement awaits confirmation".into()))?;
        if !f.broadcast {
            return Err(Rejection::Conflict("the settlement is not broadcast yet".into()));
        }
        let (vout, value, spk) =
            f.reward.clone().ok_or_else(|| Rejection::Conflict("the settlement has no reward output".into()))?;
        let parent_vsize = f.weight.div_ceil(4);
        let total = (sat_per_vb * (parent_vsize + CPFP_CHILD_VSIZE) as f64).ceil() as u64;
        let child_fee = total.saturating_sub(f.miner_fee).max(CPFP_CHILD_VSIZE);
        if child_fee + fees::DUST_SATS > value {
            return Err(Rejection::Invalid(format!("reward {value} sats cannot pay a {child_fee} sat child")));
        }
        let secret = self
            .cfg
            .reward_key
            .as_ref()
            .ok_or_else(|| Rejection::Conflict("no reward key is configured (PR_BATCHER_REWARD_KEY)".into()))?;
        let key = RewardKey::from_secret(secret)?;
        if hex::encode(key.script_pubkey()) != spk {
            return Err(Rejection::Conflict("the reward output does not pay the configured reward key".into()));
        }
        let child = key.child(&f.txid, vout, value, child_fee)?;
        let package = [f.raw.clone(), child.clone()];
        let r = match &self.cfg.broadcast {
            Broadcast::Direct(miner) => miner.submit_package(&package).await?,
            _ => self.rpc.submit_package(&package).await?,
        };
        let child_txid = r["tx-results"]
            .as_object()
            .and_then(|m| m.values().filter_map(|v| v["txid"].as_str()).find(|t| *t != f.txid))
            .map(str::to_owned)
            .ok_or_else(|| Rejection::Internal(anyhow::anyhow!("submitpackage: {r}")))?;
        f.bumps.push(child);
        write_atomic(&self.path("inflight.json"), &serde_json::to_vec_pretty(&f).map_err(anyhow::Error::from)?)?;
        let package_sat_per_vb = (f.miner_fee + child_fee) as f64 / (parent_vsize + CPFP_CHILD_VSIZE) as f64;
        Ok(BumpResponse { child_txid, child_fee, package_sat_per_vb })
    }
}

/// Display (RPC) order hex of an internal-order txid.
fn display_hex(txid: &[u8; 32]) -> String {
    let mut t = *txid;
    t.reverse();
    hex::encode(t)
}

/// The delay of a refund leaf `<delay> OP_CHECKSEQUENCEVERIFY OP_DROP <32 bytes> OP_CHECKSIG`.
fn refund_delay(leaf: &[u8]) -> Option<u16> {
    let (delay, rest) = match *leaf.first()? {
        op @ 0x51..=0x60 => ((op - 0x50) as u16, &leaf[1..]),
        n @ 1..=2 => {
            let b = leaf.get(1..1 + n as usize)?;
            let v = b.iter().rev().fold(0u32, |a, x| a << 8 | *x as u32);
            (u16::try_from(v).ok()?, &leaf[1 + n as usize..])
        }
        _ => return None,
    };
    let key = rest.strip_prefix(&[0xb2, 0x75, 0x20][..])?;
    (key.len() == 33 && key[32] == 0xac && escrow::refund_leaf(key[..32].try_into().ok()?, delay) == leaf)
        .then_some(delay)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refund_delay_parses_only_canonical_refund_leaves() {
        for d in [1u16, 16, 17, 127, 128, 144, 255, 256, 32767] {
            assert_eq!(refund_delay(&escrow::refund_leaf(&[7; 32], d)), Some(d));
        }
        let mut leaf = escrow::refund_leaf(&[7; 32], 144);
        assert_eq!(refund_delay(&leaf[..leaf.len() - 1]), None);
        leaf.push(0x51);
        assert_eq!(refund_delay(&leaf), None);
        assert_eq!(refund_delay(&[0x02, 0x90, 0x00, 0xb2, 0x75]), None);
        assert_eq!(refund_delay(&[0x01, 0x90]), None);
    }
}
