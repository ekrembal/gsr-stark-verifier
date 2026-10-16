//! `joinsplit_fixture <out-dir> [po2]` proves a fresh deposit join-split against an empty tree and
//! writes the `fixtures/joinsplit-receipt` files (`receipt.bin`, `public.json`, `external.json`) used
//! by the SDK and batcher receipt tests. Regenerate after any change to the join-split guest.
use std::path::PathBuf;

use anyhow::{Context, Result};
use pr_commitment_tree::Tree;
use pr_sdk::api::{Anchor, Status};
use pr_sdk::pr_mempool::FundingCoin;
use pr_sdk::pr_protocol_types::Outpoint;
use pr_sdk::{prove, verify_transaction, Wallet};
use rand_core::OsRng;

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let out = PathBuf::from(args.next().context("usage: joinsplit_fixture <out-dir> [po2]")?);
    let po2 = args.next().map(|p| p.parse()).transpose()?;
    let tree = Tree::new();
    let status = Status {
        anchor: Anchor { root: hex::encode(tree.root().0), commitment_count: tree.count(), batch_number: 0 },
        rollup_id: hex::encode([0x1e; 32]),
        batch_number: 0,
        state_root: hex::encode([0; 32]),
        commitment_count: tree.count(),
        nullifier_next_index: 1,
        backing_sats: 0,
        utxo: (hex::encode([3; 32]), 0),
        pending: 0,
    };
    let mut txid = [0; 32];
    rand_core::RngCore::fill_bytes(&mut OsRng, &mut txid);
    let coin =
        FundingCoin { outpoint: Outpoint { txid, vout: 2 }, amount: 20_000, script_pubkey: vec![0x00, 0x20, 1, 2] };
    let built = Wallet::from_seed(&[1; 32]).deposit(&mut OsRng, &status, &[coin], 700, 10)?;
    let (tx, stats) = prove(&built.witness, &built.external, po2)?;
    verify_transaction(&tx)?;
    std::fs::create_dir_all(&out)?;
    std::fs::write(out.join("receipt.bin"), &tx.receipt)?;
    std::fs::write(out.join("public.json"), serde_json::to_vec(&tx.public)?)?;
    std::fs::write(out.join("external.json"), serde_json::to_vec(&tx.external)?)?;
    println!("{stats:?}");
    Ok(())
}
