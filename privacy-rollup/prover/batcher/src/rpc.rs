//! Minimal Bitcoin Core JSON-RPC client. Credentials come from the environment, never from files
//! in the repository: `BITCOIN_RPC_URL` plus either `BITCOIN_RPC_COOKIE` (path of the node's
//! `.cookie`) or `BITCOIN_RPC_USER` / `BITCOIN_RPC_PASSWORD`.
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

#[derive(Clone)]
pub struct Rpc {
    url: String,
    user: String,
    password: String,
    http: reqwest::Client,
}

impl std::fmt::Debug for Rpc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rpc").field("url", &self.url).finish_non_exhaustive()
    }
}

impl Rpc {
    pub fn new(url: &str, user: &str, password: &str) -> Result<Rpc> {
        let http = reqwest::Client::builder().timeout(Duration::from_secs(120)).build()?;
        Ok(Rpc { url: url.to_owned(), user: user.to_owned(), password: password.to_owned(), http })
    }

    pub fn from_env() -> Result<Rpc> {
        Rpc::from_env_with_url(&std::env::var("BITCOIN_RPC_URL").context("BITCOIN_RPC_URL is not set")?)
    }

    /// The environment's credentials against another node (e.g. a miner's, for direct submission).
    pub fn from_env_with_url(url: &str) -> Result<Rpc> {
        let url = url.to_owned();
        if let Ok(cookie) = std::env::var("BITCOIN_RPC_COOKIE") {
            let c = std::fs::read_to_string(&cookie).with_context(|| format!("reading {cookie}"))?;
            let (user, password) = c.trim().split_once(':').context("malformed cookie")?;
            return Rpc::new(&url, user, password);
        }
        let user = std::env::var("BITCOIN_RPC_USER").context("set BITCOIN_RPC_COOKIE or BITCOIN_RPC_USER")?;
        let password = std::env::var("BITCOIN_RPC_PASSWORD").context("BITCOIN_RPC_PASSWORD is not set")?;
        Rpc::new(&url, &user, &password)
    }

    pub async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({"jsonrpc": "1.0", "id": "pr-batcher", "method": method, "params": params});
        let r = self.http.post(&self.url).basic_auth(&self.user, Some(&self.password)).json(&body).send().await?;
        let status = r.status();
        let text = r.text().await?;
        let v: Value = serde_json::from_str(&text).with_context(|| format!("{method}: HTTP {status}: {text}"))?;
        if !v["error"].is_null() {
            bail!("{method}: {}", v["error"]["message"].as_str().unwrap_or(&v["error"].to_string()));
        }
        Ok(v["result"].clone())
    }

    pub async fn send_raw_transaction(&self, raw: &str) -> Result<String> {
        Ok(self.call("sendrawtransaction", json!([raw])).await?.as_str().context("txid")?.to_owned())
    }

    /// Mines a block holding exactly `raw` (regtest; bypasses mempool policy such as the annex rule).
    pub async fn generate_block(&self, address: &str, raw: &str) -> Result<String> {
        Ok(self.call("generateblock", json!([address, [raw]])).await?["hash"].as_str().context("hash")?.to_owned())
    }

    /// Confirmations of output `vout` of `txid` (display order) while unspent; `None` if it is
    /// neither in the UTXO set nor in the mempool.
    pub async fn confirmations(&self, txid: &str, vout: u32) -> Result<Option<u64>> {
        let v = self.call("gettxout", json!([txid, vout, true])).await?;
        Ok(if v.is_null() { None } else { Some(v["confirmations"].as_u64().unwrap_or(0)) })
    }

    /// An unspent output's amount (sats), scriptPubKey and confirmations (0 in the mempool).
    pub async fn txout(&self, txid: &str, vout: u32) -> Result<Option<(u64, Vec<u8>, u64)>> {
        let v = self.call("gettxout", json!([txid, vout, true])).await?;
        if v.is_null() {
            return Ok(None);
        }
        let btc = v["value"].as_f64().context("gettxout value")?;
        let spk = hex::decode(v["scriptPubKey"]["hex"].as_str().context("gettxout scriptPubKey")?)?;
        Ok(Some(((btc * 1e8).round() as u64, spk, v["confirmations"].as_u64().unwrap_or(0))))
    }

    /// `estimatesmartfee` in sat/vB; `None` while the node has too little data (e.g. regtest).
    pub async fn estimate_sat_per_vb(&self, target_blocks: u16) -> Result<Option<f64>> {
        let v = self.call("estimatesmartfee", json!([target_blocks])).await?;
        Ok(v["feerate"].as_f64().map(|btc_per_kvb| btc_per_kvb * 1e5))
    }

    pub async fn block_count(&self) -> Result<u64> {
        self.call("getblockcount", json!([])).await?.as_u64().context("getblockcount")
    }

    /// `getblock <hash at height> 3` (transactions with their prevouts).
    pub async fn block_at(&self, height: u64) -> Result<Value> {
        let hash = self.call("getblockhash", json!([height])).await?;
        self.call("getblock", json!([hash, 3])).await
    }

    /// `submitpackage [raw..]` (parent first).
    pub async fn submit_package(&self, raws: &[String]) -> Result<Value> {
        self.call("submitpackage", json!([raws])).await
    }
}

/// An RPC amount (BTC, as a string so no float rounding is involved).
pub fn btc(sats: u64) -> String {
    format!("{}.{:08}", sats / 100_000_000, sats % 100_000_000)
}
