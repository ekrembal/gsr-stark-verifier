//! Local, resumable real proving benchmark. A selected segment range is only a
//! partial execution claim; integrity verification does not certify the full guest.
use std::{fs, path::Path, time::Instant};

use anyhow::{ensure, Context, Result};
use risc0_zkvm::{
    compute_image_id, get_prover_server, ExecutorEnv, ExecutorImpl, InnerReceipt, NullSegmentRef, ProverOpts, Receipt,
    ReceiptClaim, Segment, SegmentReceipt, SuccinctReceipt, SuccinctReceiptVerifierParameters, VerifierContext,
};

fn save(path: &Path, bytes: &[u8]) -> Result<()> {
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, bytes)?;
    fs::rename(temporary, path)?;
    Ok(())
}

fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().collect();
    ensure!(a.len() >= 4, "usage: proof_chain_bench <encode-witness|capture|prove|lift|join|padded> <directory> <args...>");
    // Direct local prover; explicitly reject environment-enabled fake proofs.
    ensure!(std::env::var("RISC0_DEV_MODE").is_err(), "unset RISC0_DEV_MODE");
    let out = Path::new(&a[2]);
    fs::create_dir_all(out)?;
    let start = Instant::now();
    let ctx = VerifierContext::default();
    let opts = ProverOpts::composite().with_dev_mode(false);
    let prover = get_prover_server(&opts)?;
    let result = match a[1].as_str() {
        "encode-witness" => {
            use pr_protocol_types::Canonical;
            let witness: pr_state_transition::BatchWitness = serde_json::from_slice(&fs::read(&a[3])?)?;
            let expected = pr_state_transition::apply_batch(&witness)
                .map_err(|e| anyhow::anyhow!("native transition: {e:?}"))?.journal.encode();
            let frame = postcard::to_allocvec(&witness)?;
            save(&out.join("witness.pc"), &frame)?;
            save(&out.join("expected-journal.bin"), &expected)?;
            serde_json::json!({"frame_bytes":frame.len(),"journal_bytes":expected.len()})
        }
        "capture" => {
            ensure!(a.len() >= 8, "capture dir program expected-journal first count po2 [frames...]");
            let program = fs::read(&a[3])?;
            let expected = fs::read(&a[4])?;
            let first: u32 = a[5].parse()?;
            let count: u32 = a[6].parse()?;
            ensure!(count > 0 && count <= 4, "capture at most four segments per bounded experiment");
            let end = first.checked_add(count).context("segment range overflow")?;
            let po2: u32 = a[7].parse()?;
            ensure!((15..=22).contains(&po2), "bounded segment po2 must be 15..22");
            let mut env = ExecutorEnv::builder();
            env.segment_limit_po2(po2).session_limit(Some(2_000_000_000));
            for f in &a[8..] {
                env.write_frame(&fs::read(f)?);
            }
            let mut selected = Vec::new();
            let session = ExecutorImpl::from_elf(env.build()?, &program)?.run_with_callback(|segment| {
                if (first..end).contains(&segment.index) {
                    let bytes = postcard::to_allocvec(&segment)?;
                    save(&out.join(format!("segment-{}.pc", segment.index)), &bytes)?;
                    selected.push(serde_json::json!({"index":segment.index,"po2":segment.po2(),"bytes":bytes.len()}));
                }
                Ok(Box::new(NullSegmentRef))
            })?;
            let journal = &session.journal.context("guest did not commit a journal")?.bytes;
            ensure!(*journal == expected, "guest journal differs from the supplied reference");
            ensure!(selected.len() == count as usize, "requested segment range was not reached");
            save(&out.join("journal.bin"), journal)?;
            let metadata = serde_json::json!({"image_id":compute_image_id(&program)?.to_string(),"first":first,"count":count,"complete":first == 0 && session.segments.len() == count as usize,"segments":session.segments.len(),"user_cycles":session.user_cycles,"total_cycles":session.total_cycles,"paging_cycles":session.paging_cycles,"reserved_cycles":session.reserved_cycles,"selected":selected});
            save(&out.join("capture.json"), &serde_json::to_vec_pretty(&metadata)?)?;
            metadata
        }
        "prove" => {
            let index: u32 = a[3].parse()?;
            let segment: Segment = postcard::from_bytes(&fs::read(out.join(format!("segment-{index}.pc")))?)?;
            ensure!(segment.index == index, "segment index mismatch");
            let receipt = prover.prove_segment(&ctx, &segment)?;
            receipt.verify_integrity_with_context(&ctx)?;
            save(&out.join(format!("receipt-{index}.pc")), &postcard::to_allocvec(&receipt)?)?;
            serde_json::json!({"index":index,"po2":segment.po2(),"seal_bytes":receipt.seal.len()*4,"integrity_verified":true})
        }
        "lift" => {
            let index: u32 = a[3].parse()?;
            let receipt: SegmentReceipt = postcard::from_bytes(&fs::read(out.join(format!("receipt-{index}.pc")))?)?;
            receipt.verify_integrity_with_context(&ctx)?;
            let lifted = prover.lift(&receipt)?;
            lifted.verify_integrity_with_context(&ctx)?;
            save(&out.join(format!("lift-{index}.pc")), &postcard::to_allocvec(&lifted)?)?;
            serde_json::json!({"index":index,"seal_bytes":lifted.seal.len()*4,"integrity_verified":true})
        }
        "join" => {
            ensure!(a.len() == 5, "join dir first second");
            let left: SuccinctReceipt<ReceiptClaim> =
                postcard::from_bytes(&fs::read(out.join(format!("lift-{}.pc", a[3])))?)?;
            let right: SuccinctReceipt<ReceiptClaim> =
                postcard::from_bytes(&fs::read(out.join(format!("lift-{}.pc", a[4])))?)?;
            left.verify_integrity_with_context(&ctx)?;
            right.verify_integrity_with_context(&ctx)?;
            let joined = prover.join(&left, &right)?;
            joined.verify_integrity_with_context(&ctx)?;
            save(&out.join("joined.pc"), &postcard::to_allocvec(&joined)?)?;
            serde_json::json!({"seal_bytes":joined.seal.len()*4,"integrity_verified":true})
        }
        "padded" => {
            let stem = &a[3];
            ensure!(stem == "joined" || stem.strip_prefix("lift-").and_then(|s| s.parse::<u32>().ok()).is_some(),
                "padded dir joined|lift-N");
            let joined: SuccinctReceipt<ReceiptClaim> = postcard::from_bytes(&fs::read(out.join(format!("{stem}.pc")))?)?;
            joined.verify_integrity_with_context(&ctx)?;
            let (padded, params): (_, SuccinctReceiptVerifierParameters) =
                risc0_zkvm::recursion::identity_sha256_padded(&joined)?;
            let ctx = VerifierContext::empty()
                .with_suites(VerifierContext::default_hash_suites())
                .with_succinct_verifier_parameters(params.clone());
            padded.verify_integrity_with_context(&ctx)?;
            let metadata: serde_json::Value = serde_json::from_slice(&fs::read(out.join("capture.json"))?)?;
            let complete = metadata["complete"] == true;
            if complete {
                let image_bytes = hex::decode(metadata["image_id"].as_str().context("missing image id")?)?;
                let image = risc0_zkvm::sha::Digest::try_from(image_bytes.as_slice())?;
                Receipt::new(InnerReceipt::Succinct(padded.clone()), fs::read(out.join("journal.bin"))?)
                    .verify_with_context(&ctx, image)?;
            }
            let mut corrupt = padded.clone();
            ensure!(!corrupt.seal.is_empty(), "empty seal");
            corrupt.seal[0] ^= 1;
            ensure!(corrupt.verify_integrity_with_context(&ctx).is_err(), "corrupted padded seal accepted");
            save(&out.join("padded.pc"), &postcard::to_allocvec(&padded)?)?;
            save(&out.join("padded-parameters.pc"), &postcard::to_allocvec(&params)?)?;
            serde_json::json!({"seal_bytes":padded.seal.len()*4,"hashfn":padded.hashfn,"integrity_verified":true,"complete_guest_verified":complete,"corrupt_seal_rejected":true})
        }
        _ => anyhow::bail!("unknown operation"),
    };
    println!(
        "{}",
        serde_json::json!({"operation":a[1],"seconds":start.elapsed().as_secs_f64(),"real_local_proof":!matches!(a[1].as_str(), "capture" | "encode-witness"),"result":result})
    );
    Ok(())
}
