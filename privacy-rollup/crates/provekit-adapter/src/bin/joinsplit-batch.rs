//! `joinsplit-batch <joinsplit.pkp> <joinsplit.pkv> <out-dir>`: a deposit batch with a real ProveKit
//! proof (the earlier, ProveKit-in-guest settlement path; kept for the verifier benchmarks). The
//! wallet builds the join-split, ProveKit proves it, the mempool admits it only after native
//! verification, and the operator assembles the settlement. Writes `witness.json`, `vk.pc`,
//! `proof0.pc` and `joinsplit-witness.json` (the private witness, input of `joinsplit prove`), and
//! prints the native journal.
use std::{fs, path::Path, time::Instant};

use anyhow::Result;
use pr_protocol_types::{Canonical, RollupTransaction};
use pr_tests::{coin, Harness, Wallet};
use pr_wallet_core::{ProverToml, SpendInput};

fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().collect();
    anyhow::ensure!(a.len() == 4, "usage: joinsplit-batch <pkp> <pkv> <out-dir>");
    let out = Path::new(&a[3]);
    fs::create_dir_all(out)?;
    let verifier = pr_provekit_adapter::load_verifier(a[2].as_ref())?;
    let mut h = Harness::new();
    let alice = Wallet::new(1);
    let funding = vec![coin(0x41, 20_000)];
    let b = h.deposit_builder(700, &funding, 20_000, None);
    let js = h.build(&b, [SpendInput::Dummy, SpendInput::Dummy], [alice.pay(19_300), alice.pay(0)]);
    let t = Instant::now();
    let proof = pr_provekit_adapter::prove(
        pr_provekit_adapter::load_prover(a[1].as_ref())?,
        &js.witness.prover_toml(),
        &js.witness.public,
    )?;
    println!(
        "provekit proof in {:?}: narg {} B, hints {} B",
        t.elapsed(),
        proof.whir_r1cs_proof.narg_string.len(),
        proof.whir_r1cs_proof.hints.len()
    );
    let (narg, hints) = (&proof.whir_r1cs_proof.narg_string, &proof.whir_r1cs_proof.hints);
    let tx = RollupTransaction { public: js.witness.public, external: js.external.clone(), receipt: Vec::new() };
    let t = Instant::now();
    fs::write(out.join("joinsplit-witness.json"), serde_json::to_vec(&js.witness)?)?;
    h.mempool
        .submit(tx.clone(), funding, &h.replica, |tx| {
            pr_provekit_adapter::verify(&verifier, &tx.public, narg, hints).is_ok()
        })
        .map_err(|e| anyhow::anyhow!("mempool: {e:?}"))?;
    println!("native verification + admission in {:?}", t.elapsed());
    let mut forged = tx.public;
    forged.fee_sats += 1;
    anyhow::ensure!(pr_provekit_adapter::verify(&verifier, &forged, narg, hints).is_err(), "forged statement verified");
    let selected = h.mempool.select();
    let settlement = h.settlement(&selected, None);
    let w = h.replica.witness(pr_mempool::batch_transactions(&selected), settlement);
    let effects = pr_state_transition::apply_batch(&w).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    fs::write(out.join("witness.json"), serde_json::to_vec(&w)?)?;
    fs::write(out.join("vk.pc"), pr_provekit_adapter::guest_verifier_bytes(&verifier)?)?;
    fs::write(out.join("proof0.pc"), pr_provekit_adapter::guest_proof_bytes(&proof)?)?;
    println!("journal {}", hex_str(&effects.journal.encode()));
    Ok(())
}

fn hex_str(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
