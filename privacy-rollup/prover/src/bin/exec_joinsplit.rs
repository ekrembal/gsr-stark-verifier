//! Executes the verify_joinsplit guest on postcard-encoded ProveKit verifier key and proof files.
use risc0_zkvm::{default_executor, ExecutorEnv};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let vk = std::fs::read(&args[1])?;
    let proof = std::fs::read(&args[2])?;
    println!("vk {} bytes, proof {} bytes (postcard)", vk.len(), proof.len());
    let env = ExecutorEnv::builder().write_frame(&vk).write_frame(&proof).build()?;
    let info = default_executor().execute(env, pr_methods::VERIFY_JOINSPLIT_ELF)?;
    println!("total cycles {} segments {}", info.cycles(), info.segments.len());
    Ok(())
}
