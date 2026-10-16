//! `settle exec|prove <witness.json> <out-dir> [<joinsplit-receipt.bin>...]`
//!
//! Runs the `apply_batch` guest on a batch witness (JSON `BatchWitness`, as written by the
//! operator) with one zero-knowledge join-split receipt per transaction (from `joinsplit prove`)
//! added as an assumption. With `prove`, it proves the conditional execution, lifts and joins its
//! segments, discharges every assumption with `resolve_zk`, and wraps the unconditional result in a
//! `sha-256-padded` succinct receipt verified natively against `APPLY_BATCH_ID`. Writes
//! `journal.bin`, `stats.json` and, when proving, `receipt.json` / `seal.bin` in the format the GSR
//! verifier generator reads.
use std::{fs, path::Path, time::Instant};

use anyhow::{ensure, Context, Result};
use pr_protocol_types::Canonical;
use pr_state_transition::{apply_batch, BatchWitness};
use risc0_zkvm::{
    default_executor, get_prover_server, recursion, sha::Digestible, Assumption, ExecutorEnv, ExecutorImpl,
    InnerReceipt, MaybePruned, Output, ProverOpts, Receipt, ReceiptClaim, SuccinctReceipt,
    SuccinctReceiptVerifierParameters, VerifierContext,
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
        "usage: settle exec|prove <witness.json> <out-dir> [joinsplit-receipts..]"
    );
    let witness_json = fs::read_to_string(&a[2])?;
    let witness: BatchWitness = serde_json::from_str(&witness_json)?;
    let out = Path::new(&a[3]);
    fs::create_dir_all(out)?;
    let expected = apply_batch(&witness).map_err(|e| anyhow::anyhow!("native transition: {e:?}"))?.journal.encode();
    ensure!(a.len() == 4 + witness.transactions.len(), "need one join-split receipt per transaction");

    let ctx = VerifierContext::default();
    let mut assumptions = Vec::new();
    for (path, t) in a[4..].iter().zip(&witness.transactions) {
        let r: SuccinctReceipt<ReceiptClaim> = postcard::from_bytes(&fs::read(path)?)?;
        r.verify_integrity_zk_with_context(&ctx).with_context(|| format!("{path}: zero-knowledge seal"))?;
        let claim = ReceiptClaim::ok(pr_methods::JOINSPLIT_ID, t.public.encode());
        ensure!(r.claim.digest() == claim.digest(), "{path}: not a receipt of this transaction's statement");
        assumptions.push(r);
    }
    let mut env = ExecutorEnv::builder();
    env.write_frame(&postcard::to_allocvec(&witness)?);
    for r in &assumptions {
        env.add_assumption(r.claim.clone());
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
    // Segments are proven directly: the composite prover would require a receipt for every
    // assumption, while here they are discharged by `resolve_zk` after lift and join.
    let session = ExecutorImpl::from_elf(env, pr_methods::APPLY_BATCH_ELF)?.run()?;
    let journal = session.journal.as_ref().context("guest did not commit a journal")?;
    ensure!(journal.bytes == expected, "guest journal differs from the native transition");
    let prover = get_prover_server(&ProverOpts::composite())?;
    let mut segments = Vec::new();
    for s in &session.segments {
        segments.push(prover.prove_segment(&ctx, &s.resolve()?)?);
    }
    let assumed: Vec<Assumption> = session.assumptions.iter().map(|(a, _)| a.clone()).collect();
    let output = MaybePruned::Value(Some(Output {
        journal: MaybePruned::Pruned(journal.digest()),
        assumptions: assumed.into(),
    }));
    let last = segments.last_mut().context("session is empty")?;
    ensure!(last.claim.output.digest() == output.digest(), "final segment output differs from the session output");
    last.claim.output = output;
    let segment_s = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let mut conditional = recursion::lift(&segments[0])?;
    for s in &segments[1..] {
        conditional = recursion::join(&conditional, &recursion::lift(s)?)?;
    }
    let lift_join_s = t.elapsed().as_secs_f64();
    let t = Instant::now();
    for r in &assumptions {
        conditional = recursion::resolve_zk(&conditional, r)?;
    }
    let resolve_s = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let (receipt, params) = recursion::identity_sha256_padded(&conditional)?;
    let padded_s = t.elapsed().as_secs_f64();
    let ctx = VerifierContext::empty()
        .with_suites(VerifierContext::default_hash_suites())
        .with_succinct_verifier_parameters(params.clone());
    Receipt::new(InnerReceipt::Succinct(receipt.clone()), expected.clone())
        .verify_with_context(&ctx, pr_methods::APPLY_BATCH_ID)
        .context("native verification of the padded receipt")?;
    let stats = serde_json::json!({
        "transactions": witness.transactions.len(),
        "cycles_total": session.total_cycles,
        "cycles_user": session.user_cycles,
        "segments": session.segments.len(),
        "segment_proving_seconds": segment_s,
        "lift_join_seconds": lift_join_s,
        "resolve_zk_seconds": resolve_s,
        "identity_sha256_padded_seconds": padded_s,
        "seal_words": receipt.seal.len(),
    });
    println!("{stats}");
    fs::write(out.join("stats.json"), serde_json::to_string_pretty(&stats)?)?;
    fs::write(out.join("journal.bin"), &expected)?;
    fs::write(out.join("seal.bin"), bytemuck::cast_slice::<u32, u8>(&receipt.seal))?;
    fs::write(out.join("receipt.json"), serde_json::to_string_pretty(&receipt_json(&receipt, &params, &expected)?)?)?;
    println!("padded receipt verified natively; claim {}", receipt.claim.digest());
    Ok(())
}
