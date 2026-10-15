//! `cycles [--prove] [out.json]`: executes both guests on the native lifecycle of `tests/tests/scenario.rs`
//! (Alice deposits, pays Bob, an empty batch, Bob withdraws) and reports their cycle counts.
//!
//! Every user join-split runs through the `joinsplit` guest. Every batch runs through `apply_batch`,
//! with each transaction's join-split claim added as an unresolved assumption, so no proof is made.
//! Both journals must equal the native evaluation.
//!
//! With `--prove`, it also times succinct proofs of the transfer join-split and of its one-transaction
//! settlement (segments, lift, join, and `resolve` of the join-split receipt), and of the empty batch.
//! The settlement resolves the plain succinct join-split receipt, not its `identity_zk` re-proof, so it
//! uses `resolve` where the operator uses `resolve_zk`; both are one recursion step.
use std::time::Instant;

use anyhow::{ensure, Result};
use pr_joinsplit::JoinSplitWitness;
use pr_protocol_types::{Canonical, TxOut};
use pr_state_transition::{apply_batch, BatchWitness};
use pr_tests::{coin, Harness, Wallet};
use pr_wallet_core::SpendInput;
use risc0_zkvm::{default_prover, ExecutorEnv, ExecutorImpl, ProverOpts, Receipt, ReceiptClaim};

const WITHDRAW_SPK: [u8; 22] = [0x00, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];

fn run(env: ExecutorEnv, elf: &[u8]) -> Result<(serde_json::Value, Vec<u8>)> {
    let t = Instant::now();
    let session = ExecutorImpl::from_elf(env, elf)?.run()?;
    let journal = session.journal.as_ref().map(|j| j.bytes.clone()).unwrap_or_default();
    Ok((
        serde_json::json!({
            "cycles_user": session.user_cycles,
            "cycles_total": session.total_cycles,
            "segments": session.segments.len(),
            "execute_seconds": t.elapsed().as_secs_f64(),
        }),
        journal,
    ))
}

fn joinsplit(w: &JoinSplitWitness) -> Result<serde_json::Value> {
    let env = ExecutorEnv::builder().write_frame(&postcard::to_allocvec(w)?).build()?;
    let (stats, journal) = run(env, pr_methods::JOINSPLIT_ELF)?;
    ensure!(journal == w.public.encode(), "joinsplit journal differs from the native statement");
    Ok(stats)
}

fn batch(w: &BatchWitness) -> Result<serde_json::Value> {
    let expected = apply_batch(w).map_err(|e| anyhow::anyhow!("native transition: {e:?}"))?.journal.encode();
    let mut env = ExecutorEnv::builder();
    env.write_frame(&postcard::to_allocvec(w)?);
    for t in &w.transactions {
        env.add_assumption(ReceiptClaim::ok(pr_methods::JOINSPLIT_ID, t.public.encode()));
    }
    let (mut stats, journal) = run(env.build()?, pr_methods::APPLY_BATCH_ELF)?;
    ensure!(journal == expected, "apply_batch journal differs from the native transition");
    stats["transactions"] = w.transactions.len().into();
    Ok(stats)
}

fn prove(env: ExecutorEnv, elf: &[u8], expected: &[u8]) -> Result<(serde_json::Value, Receipt)> {
    let t = Instant::now();
    let info = default_prover().prove_with_opts(env, elf, &ProverOpts::succinct())?;
    let seconds = t.elapsed().as_secs_f64();
    ensure!(info.receipt.journal.bytes == expected, "proven journal differs from the native evaluation");
    let stats = serde_json::json!({
        "cycles_total": info.stats.total_cycles,
        "segments": info.stats.segments,
        "succinct_seconds": seconds,
    });
    Ok((stats, info.receipt))
}

fn prove_joinsplit(w: &JoinSplitWitness) -> Result<(serde_json::Value, Receipt)> {
    let env = ExecutorEnv::builder().write_frame(&postcard::to_allocvec(w)?).build()?;
    prove(env, pr_methods::JOINSPLIT_ELF, &w.public.encode())
}

fn prove_batch(w: &BatchWitness, receipts: &[Receipt]) -> Result<serde_json::Value> {
    let expected = apply_batch(w).map_err(|e| anyhow::anyhow!("native transition: {e:?}"))?.journal.encode();
    let mut env = ExecutorEnv::builder();
    env.write_frame(&postcard::to_allocvec(w)?);
    for r in receipts {
        env.add_assumption(r.clone());
    }
    Ok(prove(env.build()?, pr_methods::APPLY_BATCH_ELF, &expected)?.0)
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let proving = args.iter().any(|a| a == "--prove");
    let out_path = args.iter().find(|a| *a != "--prove").cloned();
    let mut h = Harness::new();
    let (mut alice, mut bob) = (Wallet::new(1), Wallet::new(2));
    let mut report = serde_json::Map::new();

    let funding = vec![coin(0x31, 60_000)];
    let change = TxOut { value: 10_000, script_pubkey: vec![0x51, 0x20, 0x31] };
    let b = h.deposit_builder(1_000, &funding, 50_000, Some(change));
    let js = h.build(&b, [SpendInput::Dummy, SpendInput::Dummy], [alice.pay(49_000), alice.pay(0)]);
    report.insert("joinsplit_deposit".into(), joinsplit(&js.witness)?);
    h.submit(&js, funding).unwrap();
    let e = h.settle(Some(TxOut { value: 600, script_pubkey: vec![0x51, 0x20, 0x99] })).unwrap();
    report.insert("batch_deposit".into(), batch(h.last_witness.as_ref().unwrap())?);
    alice.scan(&h.replica, &e);

    let b = h.builder(500);
    let note = alice.notes[0].clone();
    let js = h.build(&b, [alice.spend(&h.replica, &note), SpendInput::Dummy], [bob.pay(30_000), alice.pay(18_500)]);
    report.insert("joinsplit_transfer".into(), joinsplit(&js.witness)?);
    let js_receipt = if proving {
        let (stats, receipt) = prove_joinsplit(&js.witness)?;
        report.insert("prove_joinsplit_transfer".into(), stats);
        Some(receipt)
    } else {
        None
    };
    h.submit(&js, vec![]).unwrap();
    let e = h.settle(None).unwrap();
    report.insert("batch_transfer".into(), batch(h.last_witness.as_ref().unwrap())?);
    if let Some(r) = js_receipt {
        report.insert("prove_batch_transfer".into(), prove_batch(h.last_witness.as_ref().unwrap(), &[r])?);
    }
    bob.scan(&h.replica, &e);

    h.settle(None).unwrap();
    report.insert("batch_empty".into(), batch(h.last_witness.as_ref().unwrap())?);
    if proving {
        report.insert("prove_batch_empty".into(), prove_batch(h.last_witness.as_ref().unwrap(), &[])?);
    }

    let mut b = h.builder(1_000);
    b.withdrawal = Some((WITHDRAW_SPK.to_vec(), 29_000));
    let note = bob.notes[0].clone();
    let js = h.build(&b, [bob.spend(&h.replica, &note), SpendInput::Dummy], [bob.pay(0), bob.pay(0)]);
    report.insert("joinsplit_withdraw".into(), joinsplit(&js.witness)?);
    h.submit(&js, vec![]).unwrap();
    h.settle(None).unwrap();
    report.insert("batch_withdraw".into(), batch(h.last_witness.as_ref().unwrap())?);

    let out = serde_json::to_string_pretty(&report)?;
    println!("{out}");
    if let Some(path) = out_path {
        std::fs::write(path, out + "\n")?;
    }
    Ok(())
}
