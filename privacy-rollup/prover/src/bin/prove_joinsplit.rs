use std::time::Instant;

use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let vk = std::fs::read(&args[1])?;
    let proof = std::fs::read(&args[2])?;
    let env = ExecutorEnv::builder().write_frame(&vk).write_frame(&proof).build()?;
    let t = Instant::now();
    let info = default_prover().prove_with_opts(env, pr_methods::VERIFY_JOINSPLIT_ELF, &ProverOpts::succinct())?;
    println!("succinct receipt in {:?}, stats {:?}", t.elapsed(), info.stats);
    let succinct = info.receipt.inner.succinct()?;
    let t = Instant::now();
    let (padded, _params) = risc0_zkvm::recursion::identity_sha256_padded(succinct)?;
    println!("padded identity in {:?}, seal {} words", t.elapsed(), padded.seal.len());
    Ok(())
}
