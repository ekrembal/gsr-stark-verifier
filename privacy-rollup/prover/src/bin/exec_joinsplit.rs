//! Executes the verify_joinsplit guest on postcard-encoded ProveKit verifier key and proof files.
use risc0_zkvm::{default_executor, ExecutorEnv};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    anyhow::ensure!(
        args.len() == 3 || args.len() == 4,
        "usage: exec_joinsplit <vk.pc> <proof.pc> [combined-guest.bin]"
    );
    let vk = std::fs::read(&args[1])?;
    let proof = std::fs::read(&args[2])?;
    println!("vk {} bytes, proof {} bytes (postcard)", vk.len(), proof.len());
    let program = if args.len() == 4 { std::fs::read(&args[3])? } else { pr_methods::VERIFY_JOINSPLIT_ELF.to_vec() };
    let env = ExecutorEnv::builder().session_limit(Some(2_000_000_000)).write_frame(&vk).write_frame(&proof).build()?;
    let started = std::time::Instant::now();
    let info = default_executor().execute(env, &program)?;
    println!("total cycles {} segments {}", info.cycles(), info.segments.len());
    println!(
        "{}",
        serde_json::json!({"cycles": info.cycles(), "segments": info.segments.len(), "runtime_seconds": started.elapsed().as_secs_f64(), "journal": hex::encode(&info.journal.bytes), "vk_bytes": vk.len(), "proof_bytes": proof.len()})
    );
    Ok(())
}
