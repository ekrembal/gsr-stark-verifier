//! Settlement proving: runs the `apply_batch` guest on a batch witness with one zero-knowledge
//! join-split receipt per transaction added as an assumption, proves the conditional execution,
//! lifts and joins its segments, discharges every assumption with `resolve_zk`, and wraps the
//! unconditional result in a `sha-256-padded` succinct receipt verified natively against
//! `APPLY_BATCH_ID`.
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};

use anyhow::{ensure, Context, Result};
use pr_protocol_types::Canonical;
use pr_state_transition::{apply_batch, BatchWitness};
use risc0_zkvm::{
    default_executor, get_prover_server, recursion, sha::Digestible, Assumption, ExecutorEnv, ExecutorImpl,
    InnerReceipt, MaybePruned, Output, ProverOpts, Receipt, ReceiptClaim, Segment, SegmentReceipt, SuccinctReceipt,
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
    pub workers: usize,
}

/// Number of segments (and later lifts and joins) proven concurrently, from `PR_PROVE_WORKERS`
/// (default 1). Each worker runs its own CPU prover, which is itself multi-threaded, so this trades
/// memory (one segment's proving buffers per worker) for better core utilisation.
pub fn prove_workers() -> usize {
    std::env::var("PR_PROVE_WORKERS").ok().and_then(|w| w.parse().ok()).filter(|&w| w > 0).unwrap_or(1)
}

/// Runs `f` on every item with up to `workers` threads, keeping the input order.
fn parallel_map<T: Sync, R: Send>(items: &[T], workers: usize, f: impl Fn(&T) -> Result<R> + Sync) -> Result<Vec<R>> {
    if workers <= 1 || items.len() <= 1 {
        return items.iter().map(f).collect();
    }
    let next = AtomicUsize::new(0);
    let out: Mutex<Vec<Option<Result<R>>>> = Mutex::new((0..items.len()).map(|_| None).collect());
    std::thread::scope(|scope| {
        for _ in 0..workers.min(items.len()) {
            scope.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some(item) = items.get(i) else { break };
                let r = f(item);
                out.lock().unwrap_or_else(|p| p.into_inner())[i] = Some(r);
            });
        }
    });
    out.into_inner().unwrap_or_else(|p| p.into_inner()).into_iter().map(|r| r.context("worker did not run")?).collect()
}

/// Lifts every segment receipt and joins them pairwise, level by level, in order. Each level's
/// joins are independent, so they run on `workers` threads.
fn lift_and_join(segments: &[SegmentReceipt], workers: usize) -> Result<SuccinctReceipt<ReceiptClaim>> {
    let mut level = parallel_map(segments, workers, recursion::lift)?;
    while level.len() > 1 {
        let pairs: Vec<&[SuccinctReceipt<ReceiptClaim>]> = level.chunks(2).collect();
        level = parallel_map(&pairs, workers, |p| match p {
            [a, b] => recursion::join(a, b),
            [a] => Ok(a.clone()),
            _ => unreachable!("chunks(2)"),
        })?;
    }
    level.pop().context("session is empty")
}

/// A conditional receipt for the batch (assumptions still open), and how it was produced.
pub struct Conditional {
    pub receipt: SuccinctReceipt<ReceiptClaim>,
    /// Open assumptions in the session's (head-first) order.
    pub assumed: Vec<Assumption>,
    pub journal: Vec<u8>,
    pub stats: SettlementStats,
}

/// Executes and proves the `apply_batch` guest with `claims` as assumptions, up to the joined
/// conditional receipt. Segments are proven directly: the composite prover would require a receipt
/// for every assumption, while here they are discharged later by `resolve_zk`.
pub fn prove_conditional(witness: &BatchWitness, claims: &[ReceiptClaim], workers: usize) -> Result<Conditional> {
    let expected = expected_journal(witness)?;
    let mut env = ExecutorEnv::builder();
    env.write_frame(&postcard::to_allocvec(witness)?);
    for c in claims {
        env.add_assumption(c.clone());
    }
    let t = Clock::start();
    let session = ExecutorImpl::from_elf(env.build()?, pr_methods::APPLY_BATCH_ELF)?.run()?;
    let journal = session.journal.as_ref().context("guest did not commit a journal")?;
    ensure!(journal.bytes == expected, "guest journal differs from the native transition");
    let resolved: Vec<Segment> = session.segments.iter().map(|s| s.resolve()).collect::<Result<_>>()?;
    let mut segments = parallel_map(&resolved, workers, |s| {
        get_prover_server(&ProverOpts::composite())?.prove_segment(&VerifierContext::default(), s)
    })?;
    drop(resolved);
    let assumed: Vec<Assumption> = session.assumptions.iter().map(|(a, _)| a.clone()).collect();
    let output = MaybePruned::Value(Some(Output {
        journal: MaybePruned::Pruned(journal.digest()),
        assumptions: assumed.clone().into(),
    }));
    let last = segments.last_mut().context("session is empty")?;
    ensure!(last.claim.output.digest() == output.digest(), "final segment output differs from the session output");
    last.claim.output = output;
    let segment_proving_seconds = t.seconds();
    let t = Clock::start();
    let receipt = lift_and_join(&segments, workers)?;
    let stats = SettlementStats {
        transactions: witness.transactions.len(),
        cycles_total: session.total_cycles,
        cycles_user: session.user_cycles,
        segments: session.segments.len(),
        segment_proving_seconds,
        lift_join_seconds: t.seconds(),
        workers,
        ..SettlementStats::default()
    };
    Ok(Conditional { receipt, assumed, journal: expected, stats })
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
    let assumptions = assumptions(witness, receipts)?;
    let claims: Vec<ReceiptClaim> =
        assumptions.iter().map(|r| r.claim.as_value().cloned()).collect::<Result<_, _>>()?;
    let Conditional { receipt: mut conditional, assumed, journal: expected, mut stats } =
        prove_conditional(witness, &claims, prove_workers())?;
    let t = Clock::start();
    // The executor prepends each verified claim, so resolve in the session's (head-first) order.
    for a in &assumed {
        let r = assumptions
            .iter()
            .find(|r| r.claim.digest() == a.claim)
            .context("no join-split receipt for an assumption")?;
        conditional = recursion::resolve_zk(&conditional, r)?;
    }
    stats.resolve_zk_seconds = t.seconds();
    let t = Clock::start();
    let (receipt, params) = recursion::identity_sha256_padded(&conditional)?;
    stats.identity_sha256_padded_seconds = t.seconds();
    let vctx = VerifierContext::empty()
        .with_suites(VerifierContext::default_hash_suites())
        .with_succinct_verifier_parameters(params.clone());
    Receipt::new(InnerReceipt::Succinct(receipt.clone()), expected.clone())
        .verify_with_context(&vctx, pr_methods::APPLY_BATCH_ID)
        .context("native verification of the padded receipt")?;
    stats.seal_words = receipt.seal.len();
    Ok(Settlement { receipt, params, journal: expected, stats })
}

#[cfg(test)]
mod tests {
    use super::parallel_map;

    #[test]
    fn parallel_map_keeps_order_and_errors() {
        let items: Vec<u32> = (0..37).collect();
        for workers in [1, 2, 3, 8, 64] {
            let out = parallel_map(&items, workers, |&i| Ok(i * i)).unwrap();
            assert_eq!(out, items.iter().map(|i| i * i).collect::<Vec<_>>());
            let err = parallel_map(&items, workers, |&i| if i == 20 { anyhow::bail!("item {i}") } else { Ok(i) });
            assert_eq!(err.unwrap_err().to_string(), "item 20");
        }
    }
}
