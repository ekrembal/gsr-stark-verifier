//! User-side join-split proving. Only the zero-knowledge receipt leaves the device: the segment,
//! lift and join proofs (which are not hiding) stay local. Its claim is
//! `ReceiptClaim::ok(JOINSPLIT_ID, public.encode())`.
use anyhow::{ensure, Context, Result};
use pr_joinsplit::JoinSplitWitness;
use pr_protocol_types::{Canonical, JoinSplitPublic, MAX_RECEIPT_BYTES};
use risc0_zkvm::{
    get_prover_server, recursion, sha::Digestible, ExecutorEnv, ExecutorImpl, ProverOpts, ReceiptClaim,
    SimpleSegmentRef, SuccinctReceipt, VerifierContext,
};
use serde::{Deserialize, Serialize};

use crate::Clock;

/// Wall-clock seconds of every stage of one user proof, measured on the proving device.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct UserProofStats {
    pub segment_po2: Option<u32>,
    pub cycles_total: u64,
    pub cycles_user: u64,
    pub segments: usize,
    pub segments_proven: usize,
    pub segment_seconds: Vec<f64>,
    pub witness_check_seconds: f64,
    pub execute_seconds: f64,
    pub segment_proving_seconds: f64,
    pub lift_join_seconds: f64,
    pub identity_zk_seconds: f64,
    pub verify_seconds: f64,
    pub total_seconds: f64,
    pub receipt_bytes: usize,
    pub seal_words: usize,
}

/// Accepts `receipt` only if it is a zero-knowledge seal of the join-split guest on `public`.
pub fn verify_joinsplit_receipt(receipt: &SuccinctReceipt<ReceiptClaim>, public: &JoinSplitPublic) -> Result<()> {
    receipt.verify_integrity_zk_with_context(&VerifierContext::default()).context("zero-knowledge seal")?;
    let expected = ReceiptClaim::ok(pr_methods::JOINSPLIT_ID, public.encode());
    ensure!(receipt.claim.digest() == expected.digest(), "receipt claim is not this join-split statement");
    Ok(())
}

/// Decodes a transaction's receipt bytes (`postcard(SuccinctReceipt)`), bounded by `MAX_RECEIPT_BYTES`.
pub fn decode_receipt(bytes: &[u8]) -> Result<SuccinctReceipt<ReceiptClaim>> {
    ensure!(bytes.len() <= MAX_RECEIPT_BYTES, "receipt is {} bytes, more than {MAX_RECEIPT_BYTES}", bytes.len());
    postcard::from_bytes(bytes).context("receipt encoding")
}

/// Proves the `joinsplit` guest on `witness` and re-proves the result under `identity_zk`. Returns
/// `postcard(SuccinctReceipt)`, the `receipt` of a `RollupTransaction`. `segment_po2` bounds the
/// segment size (and so the prover's peak memory); `None` keeps the executor default.
pub fn prove_joinsplit(witness: &JoinSplitWitness, segment_po2: Option<u32>) -> Result<(Vec<u8>, UserProofStats)> {
    let (receipt, stats) = prove_segments(witness, segment_po2, None)?;
    Ok((receipt.context("full proof produced no receipt")?, stats))
}

/// Executes the guest and proves (and lifts and joins) only its first `max_segments` segments,
/// for profiling devices too slow to finish a proof. No receipt is produced.
pub fn profile_joinsplit(
    witness: &JoinSplitWitness,
    segment_po2: Option<u32>,
    max_segments: usize,
) -> Result<UserProofStats> {
    Ok(prove_segments(witness, segment_po2, Some(max_segments))?.1)
}

fn prove_segments(
    witness: &JoinSplitWitness,
    segment_po2: Option<u32>,
    max_segments: Option<usize>,
) -> Result<(Option<Vec<u8>>, UserProofStats)> {
    ensure!(std::env::var_os("RISC0_DEV_MODE").is_none(), "unset RISC0_DEV_MODE");
    let total = Clock::start();
    let mut stats = UserProofStats { segment_po2, ..Default::default() };
    let t = Clock::start();
    witness.check().map_err(|e| anyhow::anyhow!("witness: {e}"))?;
    stats.witness_check_seconds = t.seconds();

    let mut env = ExecutorEnv::builder();
    env.write_frame(&postcard::to_allocvec(witness)?);
    if let Some(po2) = segment_po2 {
        env.segment_limit_po2(po2);
    }
    let env = env.build()?;
    let t = Clock::start();
    let session = ExecutorImpl::from_elf(env, pr_methods::JOINSPLIT_ELF)?
        .run_with_callback(|s| Ok(Box::new(SimpleSegmentRef::new(s))))?;
    stats.execute_seconds = t.seconds();
    let journal = session.journal.as_ref().context("guest did not commit a journal")?;
    ensure!(journal.bytes == witness.public.encode(), "journal is not the statement");
    stats.cycles_total = session.total_cycles;
    stats.cycles_user = session.user_cycles;
    stats.segments = session.segments.len();

    let ctx = VerifierContext::default();
    let prover = get_prover_server(&ProverOpts::succinct())?;
    let mut conditional: Option<SuccinctReceipt<ReceiptClaim>> = None;
    let limit = max_segments.unwrap_or(usize::MAX).min(session.segments.len());
    for s in &session.segments[..limit] {
        let t = Clock::start();
        let segment = prover.prove_segment(&ctx, &s.resolve()?)?;
        stats.segment_proving_seconds += t.seconds();
        stats.segment_seconds.push(t.seconds());
        let t = Clock::start();
        let lifted = recursion::lift(&segment)?;
        conditional = Some(match conditional {
            None => lifted,
            Some(acc) => recursion::join(&acc, &lifted)?,
        });
        stats.lift_join_seconds += t.seconds();
        stats.segments_proven += 1;
    }
    if limit < session.segments.len() {
        stats.total_seconds = total.seconds();
        return Ok((None, stats));
    }
    let succinct = conditional.context("session is empty")?;

    let t = Clock::start();
    let hidden = recursion::identity_zk(&succinct)?;
    stats.identity_zk_seconds = t.seconds();
    let t = Clock::start();
    verify_joinsplit_receipt(&hidden, &witness.public)?;
    stats.verify_seconds = t.seconds();
    let bytes = postcard::to_allocvec(&hidden)?;
    stats.receipt_bytes = bytes.len();
    stats.seal_words = hidden.seal.len();
    stats.total_seconds = total.seconds();
    Ok((Some(bytes), stats))
}
