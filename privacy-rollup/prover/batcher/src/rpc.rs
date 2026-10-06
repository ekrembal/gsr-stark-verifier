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

impl Rpc {
    pub fn new(url: &str, user: &str, password: &str) -> Result<Rpc> {
        let http = reqwest::Client::builder().timeout(Duration::from_secs(120)).build()?;
        Ok(Rpc { url: url.to_owned(), user: user.to_owned(), password: password.to_owned(), http })
    }

    pub fn from_env() -> Result<Rpc> {
        let url = std::env::var("BITCOIN_RPC_URL").context("BITCOIN_RPC_URL is not set")?;
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
}
