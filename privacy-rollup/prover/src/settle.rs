//! Settlement proving: runs the `apply_batch` guest on a batch witness with one zero-knowledge
//! join-split receipt per transaction added as an assumption, proves the conditional execution,
//! lifts and joins its segments, discharges every assumption with `resolve_zk`, and wraps the
//! unconditional result in a `sha-256-padded` succinct receipt verified natively against
//! `APPLY_BATCH_ID`.
use anyhow::{ensure, Context, Result};
use pr_protocol_types::Canonical;
use pr_state_transition::{apply_batch, BatchWitness};
use risc0_zkvm::{
    default_executor, get_prover_server, recursion, sha::Digestible, Assumption, ExecutorEnv, ExecutorImpl,
    InnerReceipt, MaybePruned, Output, ProverOpts, Receipt, ReceiptClaim, SuccinctReceipt,
    SuccinctReceiptVerifierParameters, VerifierContext,
};
use serde::{Deserialize, Serialize};

use crate::Clock;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SettlementStats {
    pub transactions: usize,
    pub cycles_total: u64,
    pub cycles_user: u64,
    pub segments: usize,
    pub segment_proving_seconds: f64,
    pub lift_join_seconds: f64,
    pub resolve_zk_seconds: f64,
    pub identity_sha256_padded_seconds: f64,
    pub seal_words: usize,
}

/// A padded-SHA settlement receipt and the journal it proves.
pub struct Settlement {
    pub receipt: SuccinctReceipt<ReceiptClaim>,
    pub params: SuccinctReceiptVerifierParameters,
    pub journal: Vec<u8>,
    pub stats: SettlementStats,
}

impl Settlement {
    /// The seal as the GSR verifier generator reads it (`seal.bin`).
    pub fn seal_bytes(&self) -> Vec<u8> {
        bytemuck::cast_slice::<u32, u8>(&self.receipt.seal).to_vec()
    }

    /// `receipt.json` in the format the GSR verifier generator reads.
    pub fn receipt_json(&self) -> Result<serde_json::Value> {
        let receipt = &self.receipt;
        let params = &self.params;
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
            "journal": hex::encode(&self.journal),
        }))
    }
}

/// Checks one receipt per transaction, in order, and returns them as assumptions.
fn assumptions(
    witness: &BatchWitness,
    receipts: &[SuccinctReceipt<ReceiptClaim>],
) -> Result<Vec<SuccinctReceipt<ReceiptClaim>>> {
    ensure!(receipts.len() == witness.transactions.len(), "need one join-split receipt per transaction");
    for (i, (r, t)) in receipts.iter().zip(&witness.transactions).enumerate() {
        crate::user::verify_joinsplit_receipt(r, &t.public).with_context(|| format!("transaction {i}"))?;
    }
    Ok(receipts.to_vec())
}

fn env<'a>(witness: &BatchWitness, assumptions: &[SuccinctReceipt<ReceiptClaim>]) -> Result<ExecutorEnv<'a>> {
    let mut env = ExecutorEnv::builder();
    env.write_frame(&postcard::to_allocvec(witness)?);
    for r in assumptions {
        env.add_assumption(r.claim.clone());
    }
    env.build()
}

/// The journal the guest must commit, from the native transition.
pub fn expected_journal(witness: &BatchWitness) -> Result<Vec<u8>> {
    Ok(apply_batch(witness).map_err(|e| anyhow::anyhow!("native transition: {e:?}"))?.journal.encode())
}

/// Executes the guest without proving; returns the journal (checked against the native transition)
/// and the total cycle count and segment count.
pub fn execute_settlement(
    witness: &BatchWitness,
    receipts: &[SuccinctReceipt<ReceiptClaim>],
) -> Result<(Vec<u8>, u64, usize)> {
    let expected = expected_journal(witness)?;
    let assumptions = assumptions(witness, receipts)?;
    let info = default_executor().execute(env(witness, &assumptions)?, pr_methods::APPLY_BATCH_ELF)?;
    ensure!(info.journal.bytes == expected, "guest journal differs from the native transition");
    Ok((expected, info.cycles(), info.segments.len()))
}

pub fn prove_settlement(witness: &BatchWitness, receipts: &[SuccinctReceipt<ReceiptClaim>]) -> Result<Settlement> {
    let expected = expected_journal(witness)?;
    let assumptions = assumptions(witness, receipts)?;
    let ctx = VerifierContext::default();
    let t = Clock::start();
    // Segments are proven directly: the composite prover would require a receipt for every
    // assumption, while here they are discharged by `resolve_zk` after lift and join.
    let session = ExecutorImpl::from_elf(env(witness, &assumptions)?, pr_methods::APPLY_BATCH_ELF)?.run()?;
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
    let segment_proving_seconds = t.seconds();
    let t = Clock::start();
    let mut conditional = recursion::lift(&segments[0])?;
    for s in &segments[1..] {
        conditional = recursion::join(&conditional, &recursion::lift(s)?)?;
    }
    let lift_join_seconds = t.seconds();
    let t = Clock::start();
    for r in &assumptions {
        conditional = recursion::resolve_zk(&conditional, r)?;
    }
    let resolve_zk_seconds = t.seconds();
    let t = Clock::start();
    let (receipt, params) = recursion::identity_sha256_padded(&conditional)?;
    let identity_sha256_padded_seconds = t.seconds();
    let vctx = VerifierContext::empty()
        .with_suites(VerifierContext::default_hash_suites())
        .with_succinct_verifier_parameters(params.clone());
    Receipt::new(InnerReceipt::Succinct(receipt.clone()), expected.clone())
        .verify_with_context(&vctx, pr_methods::APPLY_BATCH_ID)
        .context("native verification of the padded receipt")?;
    let stats = SettlementStats {
        transactions: witness.transactions.len(),
        cycles_total: session.total_cycles,
        cycles_user: session.user_cycles,
        segments: session.segments.len(),
        segment_proving_seconds,
        lift_join_seconds,
        resolve_zk_seconds,
        identity_sha256_padded_seconds,
        seal_words: receipt.seal.len(),
    };
    Ok(Settlement { receipt, params, journal: expected, stats })
}
