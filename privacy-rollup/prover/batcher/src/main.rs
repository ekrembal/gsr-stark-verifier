//! pr-batcher init  <dir> <descriptor.json>       create the operator directory; prints the genesis covenant output
//! pr-batcher genesis <dir> <txid-hex> <vout>      record the funded genesis outpoint (display txid)
//! pr-batcher serve <dir> [--listen ADDR] [--web DIR] [--interval SECS] [--mine-to ADDRESS]
//!                        [--confirmations N] [--min-transactions N]
//!
//! Bitcoin Core RPC is configured from the environment (see `rpc.rs`).
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use pr_batcher::rpc::Rpc;
use pr_batcher::service::{Batcher, Broadcast, Config, Rejection};
use pr_operator::Store;
use pr_protocol_types::RollupDescriptor;

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

#[tokio::main]
async fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    match a.first().map(String::as_str) {
        Some("init") if a.len() == 3 => {
            let store = Store::new(&a[1]);
            let descriptor: RollupDescriptor = serde_json::from_slice(&std::fs::read(&a[2])?)?;
            let state = store.init(&descriptor)?;
            let cfg = Config::from_env(Broadcast::Send);
            let b = Batcher::open_uninitialized(&store.dir, cfg)?;
            let (rollup_id, root) = (hex::encode(state.rollup_id.0), hex::encode(state.root()));
            let spk = tokio::task::spawn_blocking(move || b.covenant_script_pubkey(&rollup_id, &root)).await??;
            println!(
                "{}",
                serde_json::json!({"rollup_id": hex::encode(state.rollup_id.0), "state_root": hex::encode(state.root()),
                                   "script_pubkey": hex::encode(spk), "seed_sats": descriptor.seed_sats})
            );
        }
        Some("genesis") if a.len() == 4 => {
            let mut txid = hex::decode(&a[2])?;
            txid.reverse();
            Store::new(&a[1]).genesis(&hex::encode(txid), a[3].parse()?)?;
        }
        Some("serve") if a.len() >= 2 => {
            let broadcast = flag(&a, "--mine-to").map(Broadcast::Mine).unwrap_or(Broadcast::Send);
            let mut cfg = Config::from_env(broadcast);
            if let Some(n) = flag(&a, "--confirmations") {
                cfg.confirmations = n.parse()?;
            }
            if let Some(n) = flag(&a, "--min-transactions") {
                cfg.min_transactions = n.parse()?;
            }
            let rpc = Rpc::from_env()?;
            rpc.call("getblockchaininfo", serde_json::json!([])).await.context("Bitcoin Core RPC")?;
            let b = Batcher::open(&PathBuf::from(&a[1]), cfg, rpc)?;
            b.resume()?;
            if let Some(secs) = flag(&a, "--interval") {
                let period = Duration::from_secs(secs.parse()?);
                let b = b.clone();
                tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(period).await;
                        match b.start_settlement() {
                            Ok(n) => eprintln!("batch {n}: started by the interval timer"),
                            Err(Rejection::Conflict(_)) => {}
                            Err(e) => eprintln!("interval settlement: {e:?}"),
                        }
                    }
                });
            }
            let listen = flag(&a, "--listen").unwrap_or_else(|| "127.0.0.1:8080".to_owned());
            let app = pr_batcher::http::router(b, flag(&a, "--web").map(PathBuf::from));
            let listener = tokio::net::TcpListener::bind(&listen).await?;
            eprintln!("pr-batcher listening on http://{listen}");
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    tokio::signal::ctrl_c().await.ok();
                })
                .await?;
        }
        _ => bail!("usage: see the header of prover/batcher/src/main.rs"),
    }
    Ok(())
}
