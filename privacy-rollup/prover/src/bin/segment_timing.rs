//! Proves the first few segments of a join-split verification session and reports per-step times.
use std::time::Instant;

use risc0_zkvm::{get_prover_server, ExecutorEnv, ExecutorImpl, ProverOpts, VerifierContext};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let vk = std::fs::read(&args[1])?;
    let proof = std::fs::read(&args[2])?;
    let count: usize = args.get(3).map_or(Ok(3), |s| s.parse())?;
    let env = ExecutorEnv::builder().write_frame(&vk).write_frame(&proof).build()?;
    let t = Instant::now();
    let session = ExecutorImpl::from_elf(env, pr_methods::VERIFY_JOINSPLIT_ELF)?.run()?;
    println!("executed {} segments in {:?}", session.segments.len(), t.elapsed());
    let prover = get_prover_server(&ProverOpts::succinct())?;
    let ctx = VerifierContext::default();
    let mut acc = None;
    for seg in session.segments.iter().take(count) {
        let seg = seg.resolve()?;
        let t = Instant::now();
        let receipt = prover.prove_segment(&ctx, &seg)?;
        let p = t.elapsed();
        let t = Instant::now();
        let lifted = prover.lift(&receipt)?;
        let l = t.elapsed();
        let t = Instant::now();
        acc = Some(match acc {
            None => lifted,
            Some(a) => prover.join(&a, &lifted)?,
        });
        println!("segment {} po2 {}: prove {:?} lift {:?} join {:?}", seg.index, seg.po2(), p, l, t.elapsed());
    }
    Ok(())
}
