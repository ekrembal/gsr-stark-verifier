//! `settle exec|prove <witness.json> <out-dir> [<vk.pc> <proof.pc>...]`
//!
//! Runs the `apply_batch` guest on a batch witness (JSON `BatchWitness`, as written by the
//! operator) and, with `prove`, produces a `sha-256-padded` succinct receipt verified natively
//! against `APPLY_BATCH_ID`. Writes `journal.bin` and, when proving, `receipt.json` / `seal.bin`
//! in the format the GSR verifier generator reads.
use std::{fs, path::Path, time::Instant};

use anyhow::{ensure, Context, Result};
use pr_protocol_types::Canonical;
use pr_state_transition::{apply_batch, BatchWitness};
use risc0_zkvm::{
    default_executor, default_prover, sha::Digestible, ExecutorEnv, InnerReceipt, ProverOpts, Receipt, ReceiptClaim,
    SuccinctReceipt, SuccinctReceiptVerifierParameters, VerifierContext,
};

fn receipt_json(
    receipt: &SuccinctReceipt<ReceiptClaim>,
    params: &SuccinctReceiptVerifierParameters,
    journal: &[u8],
) -> Result<serde_json::Value> {
    let claim = receipt.claim.as_value()?;
    let output = claim.output.as_value()?.as_ref().context("claim has no output")?;
    let (sys_exit, user_exit) = claim.exit_code.into_pair();
    Ok(serde_json::json!({
        "hashfn": receipt.hashfn,
        "control_id": receipt.control_id.to_string(),
        "control_inclusion_proof": {
            "index": receipt.control_inclusion_proof.index,
            "digests": receipt.control_inclusion_proof.digests.iter().map(|d| d.to_string()).collect::<Vec<_>>(),
        },
        "control_root": params.control_root.to_string(),
        "inner_control_root": params.inner_control_root.map(|d| d.to_string()),
        "proof_system_info": std::str::from_utf8(&params.proof_system_info.0)?,
        "circuit_info": std::str::from_utf8(&params.circuit_info.0)?,
        "verifier_parameters": receipt.verifier_parameters.to_string(),
        "claim_digest": receipt.claim.digest().to_string(),
        "claim": {
            "input": claim.input.digest().to_string(),
            "pre": claim.pre.digest().to_string(),
            "post": claim.post.digest().to_string(),
            "sys_exit": sys_exit,
            "user_exit": user_exit,
            "output": claim.output.digest().to_string(),
            "journal_digest": output.journal.digest().to_string(),
            "assumptions_digest": output.assumptions.digest().to_string(),
        },
        "journal": hex::encode(journal),
    }))
}

fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().collect();
    ensure!(
        a.len() >= 4 && (a[1] == "exec" || a[1] == "prove"),
        "usage: settle exec|prove <witness.json> <out-dir> [vk proofs..]"
    );
    let witness_json = fs::read_to_string(&a[2])?;
    let witness: BatchWitness = serde_json::from_str(&witness_json)?;
    let out = Path::new(&a[3]);
    fs::create_dir_all(out)?;
    let expected = apply_batch(&witness).map_err(|e| anyhow::anyhow!("native transition: {e:?}"))?.journal.encode();
    ensure!(
        witness.transactions.is_empty() || a.len() == 5 + witness.transactions.len(),
        "need vk + one proof per transaction"
    );

    let mut env = ExecutorEnv::builder();
    let frame = postcard::to_allocvec(&witness)?;
    env.write_frame(&frame);
    let extra: Vec<Vec<u8>> = a[4..].iter().map(fs::read).collect::<std::io::Result<_>>()?;
    if !witness.transactions.is_empty() {
        for f in &extra {
            env.write_frame(f);
        }
    }
    let env = env.build()?;
    println!("image id {}", hex::encode(risc0_zkvm::sha::Digest::from(pr_methods::APPLY_BATCH_ID)));
    let t = Instant::now();
    if a[1] == "exec" {
        let info = default_executor().execute(env, pr_methods::APPLY_BATCH_ELF)?;
        ensure!(info.journal.bytes == expected, "guest journal differs from the native transition");
        println!("executed: {} cycles, {} segments, {:?}", info.cycles(), info.segments.len(), t.elapsed());
        fs::write(out.join("journal.bin"), &info.journal.bytes)?;
        return Ok(());
    }
    let info = default_prover().prove_with_opts(env, pr_methods::APPLY_BATCH_ELF, &ProverOpts::succinct())?;
    println!("succinct receipt in {:?}, stats {:?}", t.elapsed(), info.stats);
    ensure!(info.receipt.journal.bytes == expected, "guest journal differs from the native transition");
    let (receipt, params) = risc0_zkvm::recursion::identity_sha256_padded(info.receipt.inner.succinct()?)?;
    let ctx = VerifierContext::empty()
        .with_suites(VerifierContext::default_hash_suites())
        .with_succinct_verifier_parameters(params.clone());
    Receipt::new(InnerReceipt::Succinct(receipt.clone()), expected.clone())
        .verify_with_context(&ctx, pr_methods::APPLY_BATCH_ID)
        .context("native verification of the padded receipt")?;
    fs::write(out.join("journal.bin"), &expected)?;
    fs::write(out.join("seal.bin"), bytemuck::cast_slice::<u32, u8>(&receipt.seal))?;
    fs::write(out.join("receipt.json"), serde_json::to_string_pretty(&receipt_json(&receipt, &params, &expected)?)?)?;
    println!("padded receipt verified natively; claim {}", receipt.claim.digest());
    Ok(())
}
