//! pr-batcher init  <dir> <descriptor.json>       create the operator directory; prints the genesis covenant output
//! pr-batcher genesis <dir> <tx-hex>              record the genesis tx (spends genesis_nonce, rollup at output 0)
//! pr-batcher serve <dir> [--listen ADDR] [--web DIR] [--interval SECS] [--mine-to ADDRESS]
//!                        [--confirmations N] [--min-transactions N] [--min-refund-delay BLOCKS]
//!                        [--fee-rate SAT_PER_VB | --fee-target BLOCKS [--fee-floor SAT_PER_VB]]
//!                        [--reward-script HEX] [--target-transactions N] [--max-wait SECS]
//!                        [--auto SECS] [--submit-url URL]
//!
//! `--interval` starts a settlement every SECS whenever the pool is non-empty; `--auto` checks the
//! fee policy every SECS instead (fees must cover the settlement; full batch or `--max-wait`).
//! `PR_BATCHER_REWARD_KEY` (hex secret key) pays fee surplus to its BIP86 P2TR output and enables
//! `POST /v1/bump` (CPFP); `--reward-script` pays surplus to any script without CPFP.
//! `--submit-url` sends settlements and CPFP packages to that node (a miner) instead.
//!
//! Bitcoin Core RPC is configured from the environment (see `rpc.rs`).
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use pr_batcher::rpc::Rpc;
use pr_batcher::service::{Batcher, Broadcast, Config, FeeRate, Rejection};
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
        Some("genesis") if a.len() == 3 => {
            Store::new(&a[1]).genesis(&a[2])?;
        }
        Some("serve") if a.len() >= 2 => {
            let broadcast = match (flag(&a, "--mine-to"), flag(&a, "--submit-url")) {
                (Some(addr), None) => Broadcast::Mine(addr),
                (None, Some(url)) => Broadcast::Direct(Rpc::from_env_with_url(&url)?),
                (None, None) => Broadcast::Send,
                _ => bail!("--mine-to and --submit-url are exclusive"),
            };
            let mut cfg = Config::from_env(broadcast);
            if let Some(n) = flag(&a, "--confirmations") {
                cfg.confirmations = n.parse()?;
            }
            if let Some(n) = flag(&a, "--min-transactions") {
                cfg.min_transactions = n.parse()?;
            }
            if let Some(n) = flag(&a, "--min-refund-delay") {
                cfg.min_refund_delay = n.parse()?;
            }
            if let Some(r) = flag(&a, "--fee-rate") {
                cfg.fee_rate = FeeRate::Fixed(r.parse()?);
            }
            if let Some(t) = flag(&a, "--fee-target") {
                let floor = flag(&a, "--fee-floor").map(|f| f.parse()).transpose()?.unwrap_or(1.0);
                cfg.fee_rate = FeeRate::Estimate { target_blocks: t.parse()?, floor };
            }
            if let Some(h) = flag(&a, "--reward-script") {
                cfg.reward_script = Some(hex::decode(h)?);
            }
            if let Ok(k) = std::env::var("PR_BATCHER_REWARD_KEY") {
                let k = hex::decode(k.trim()).context("PR_BATCHER_REWARD_KEY is not hex")?;
                cfg.reward_script = Some(pr_batcher::cpfp::RewardKey::from_secret(&k)?.script_pubkey());
                cfg.reward_key = Some(k);
            }
            if let Some(n) = flag(&a, "--target-transactions") {
                cfg.target_transactions = n.parse()?;
            }
            if let Some(n) = flag(&a, "--max-wait") {
                cfg.max_wait = Duration::from_secs(n.parse()?);
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
            if let Some(secs) = flag(&a, "--auto") {
                let period = Duration::from_secs(secs.parse()?);
                let b = b.clone();
                tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(period).await;
                        match b.auto_settle().await {
                            Ok(Some(n)) => eprintln!("batch {n}: started by the fee policy"),
                            Ok(None) => {}
                            Err(e) => eprintln!("automatic settlement: {e:#}"),
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
