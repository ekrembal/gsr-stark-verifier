//! Frozen-input execution spool and independent checks for resumable real proofs.
//! This tool never changes the guest, circuit, proof parameters, or verifier rules.
use std::{fs, io::Write, path::Path, time::Instant};

use anyhow::{ensure, Context, Result};
use risc0_zkvm::{
    compute_image_id,
    sha::{Digest, Digestible},
    ExecutorEnv, ExecutorImpl, InnerReceipt, NullSegmentRef, Receipt, ReceiptClaim, SegmentReceipt, SuccinctReceipt,
    SuccinctReceiptVerifierParameters, VerifierContext,
};

fn save(path: &Path, bytes: &[u8]) -> Result<()> {
    let temp = path.with_extension("tmp");
    let mut file = fs::File::create(&temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(temp, path)?;
    fs::File::open(path.parent().context("output parent")?)?.sync_all()?;
    Ok(())
}

fn claim_json(claim: &ReceiptClaim) -> serde_json::Value {
    let (sys_exit, user_exit) = claim.exit_code.into_pair();
    serde_json::json!({
        "digest":claim.digest().to_string(), "pre":claim.pre.digest().to_string(),
        "post":claim.post.digest().to_string(), "input":claim.input.digest().to_string(),
        "output":claim.output.digest().to_string(), "sys_exit":sys_exit, "user_exit":user_exit,
    })
}

fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().collect();
    ensure!(a.len() >= 3, "capture|segment|succinct|full ...");
    ensure!(std::env::var_os("RISC0_DEV_MODE").is_none(), "unset RISC0_DEV_MODE");
    let start = Instant::now();
    let result = match a[1].as_str() {
        "capture" => {
            ensure!(a.len() >= 7, "capture dir program journal po2 expected-count [frames...]");
            let dir = Path::new(&a[2]);
            fs::create_dir_all(dir)?;
            ensure!(
                !dir.join("segments.spool").exists() && !dir.join("capture.json").exists(),
                "refusing to overwrite an execution checkpoint"
            );
            let program = fs::read(&a[3])?;
            let expected = fs::read(&a[4])?;
            let po2: u32 = a[5].parse()?;
            let count: usize = a[6].parse()?;
            ensure!((15..=22).contains(&po2) && (1..=512).contains(&count), "capture bounds");
            let mut env = ExecutorEnv::builder();
            env.segment_limit_po2(po2).session_limit(Some(2_000_000_000));
            for frame in &a[7..] {
                env.write_frame(&fs::read(frame)?);
            }
            let mut spool = fs::File::create(dir.join("segments.spool.tmp"))?;
            let mut selected = Vec::new();
            let mut offset = 0usize;
            let session = ExecutorImpl::from_elf(env.build()?, &program)?.run_with_callback(|segment| {
                ensure!(
                    segment.index as usize == selected.len() && selected.len() < count,
                    "unexpected segment sequence/count"
                );
                let bytes = postcard::to_allocvec(&segment)?;
                ensure!(offset + bytes.len() <= 64 * 1024 * 1024, "64 MiB spool limit");
                spool.write_all(&bytes)?;
                selected.push(serde_json::json!({"index":segment.index,"po2":segment.po2(),
                    "offset":offset,"bytes":bytes.len()}));
                offset += bytes.len();
                Ok(Box::new(NullSegmentRef))
            })?;
            let journal = session.journal.context("missing journal")?.bytes;
            ensure!(journal == expected && selected.len() == count, "journal/count mismatch");
            spool.sync_all()?;
            fs::rename(dir.join("segments.spool.tmp"), dir.join("segments.spool"))?;
            save(&dir.join("journal.bin"), &journal)?;
            let metadata = serde_json::json!({"image_id":compute_image_id(&program)?.to_string(),
                "complete":true,"first":0,"count":count,"segments":session.segments.len(),
                "selected":selected,"spool_bytes":offset,"user_cycles":session.user_cycles,
                "total_cycles":session.total_cycles,"paging_cycles":session.paging_cycles,
                "reserved_cycles":session.reserved_cycles});
            save(&dir.join("capture.json"), &serde_json::to_vec_pretty(&metadata)?)?;
            metadata
        }
        "segment" => {
            let r: SegmentReceipt = postcard::from_bytes(&fs::read(&a[2])?)?;
            r.verify_integrity_with_context(&VerifierContext::default())?;
            serde_json::json!({"integrity_verified":true,"index":r.index,
                "seal_bytes":r.seal.len()*4,"claim":claim_json(&r.claim)})
        }
        "succinct" => {
            let r: SuccinctReceipt<ReceiptClaim> = postcard::from_bytes(&fs::read(&a[2])?)?;
            r.verify_integrity()?;
            serde_json::json!({"integrity_verified":true,"seal_bytes":r.seal.len()*4,
                "claim":claim_json(r.claim.as_value()?)})
        }
        "full" => {
            ensure!(a.len() == 5 || a.len() == 6, "full receipt.pc journal.bin image-hex [parameters.pc]");
            let r: SuccinctReceipt<ReceiptClaim> = postcard::from_bytes(&fs::read(&a[2])?)?;
            let journal = fs::read(&a[3])?;
            let image_bytes = hex::decode(&a[4])?;
            let image = Digest::try_from(image_bytes.as_slice())?;
            let params = if a.len() == 6 {
                Some(postcard::from_bytes::<SuccinctReceiptVerifierParameters>(&fs::read(&a[5])?)?)
            } else {
                None
            };
            let ctx = if let Some(params) = &params {
                VerifierContext::empty()
                    .with_suites(VerifierContext::default_hash_suites())
                    .with_succinct_verifier_parameters(params.clone())
            } else {
                VerifierContext::default()
            };
            let receipt = Receipt::new(InnerReceipt::Succinct(r.clone()), journal.clone());
            receipt.verify_with_context(&ctx, image)?;
            let claim = r.claim.as_value()?;
            let output = claim.output.as_value()?.as_ref().context("no claim output")?;
            ensure!(output.assumptions.digest() == Digest::ZERO, "unresolved assumptions");
            ensure!(claim.exit_code.into_pair() == (0, 0), "unsuccessful exit");
            let mut bad_journal = journal.clone();
            if bad_journal.is_empty() {
                bad_journal.push(1);
            } else {
                bad_journal[0] ^= 1;
            }
            ensure!(
                Receipt::new(InnerReceipt::Succinct(r.clone()), bad_journal).verify_with_context(&ctx, image).is_err(),
                "wrong journal accepted"
            );
            let mut bad_image = image_bytes.clone();
            bad_image[0] ^= 1;
            ensure!(
                receipt.verify_with_context(&ctx, Digest::try_from(bad_image.as_slice())?).is_err(),
                "wrong image accepted"
            );
            let mut corrupt = r.clone();
            ensure!(!corrupt.seal.is_empty(), "empty seal");
            corrupt.seal[0] ^= 1;
            ensure!(corrupt.verify_integrity_with_context(&ctx).is_err(), "corrupt seal accepted");
            if let Some(params) = &params {
                let (sys_exit, user_exit) = claim.exit_code.into_pair();
                let export = serde_json::json!({"hashfn":r.hashfn,"control_id":r.control_id.to_string(),
                    "control_inclusion_proof":{"index":r.control_inclusion_proof.index,
                        "digests":r.control_inclusion_proof.digests.iter().map(|d|d.to_string()).collect::<Vec<_>>()},
                    "control_root":params.control_root.to_string(),
                    "inner_control_root":params.inner_control_root.map(|d|d.to_string()),
                    "proof_system_info":std::str::from_utf8(&params.proof_system_info.0)?,
                    "circuit_info":std::str::from_utf8(&params.circuit_info.0)?,
                    "verifier_parameters":r.verifier_parameters.to_string(),"claim_digest":r.claim.digest().to_string(),
                    "claim":{"input":claim.input.digest().to_string(),"pre":claim.pre.digest().to_string(),
                        "post":claim.post.digest().to_string(),"sys_exit":sys_exit,"user_exit":user_exit,
                        "output":claim.output.digest().to_string(),"journal_digest":output.journal.digest().to_string(),
                        "assumptions_digest":output.assumptions.digest().to_string()},"journal":hex::encode(&journal)});
                let dir = Path::new(&a[2]).parent().context("receipt parent")?;
                save(&dir.join("receipt.json"), &serde_json::to_vec_pretty(&export)?)?;
                save(&dir.join("seal.bin"), bytemuck::cast_slice::<u32, u8>(&r.seal))?;
            }
            serde_json::json!({"complete_guest_verified":true,"assumptions_empty":true,
                "successful_exit":true,"wrong_journal_rejected":true,"wrong_image_rejected":true,
                "corrupt_seal_rejected":true,"seal_bytes":r.seal.len()*4,"hashfn":r.hashfn,
                "claim":claim_json(claim)})
        }
        _ => anyhow::bail!("unknown operation"),
    };
    println!("{}", serde_json::json!({"operation":a[1],"seconds":start.elapsed().as_secs_f64(),"result":result}));
    Ok(())
}
