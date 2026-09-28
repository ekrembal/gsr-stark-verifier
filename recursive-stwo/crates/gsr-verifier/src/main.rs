use anyhow::{bail, Context, Result};
use gsr_verifier::*;
use std::{path::Path, process::Command};
fn write(path: &str, value: &impl serde::Serialize) -> Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_vec(value)?)?;
    eprintln!("Wrote {path}");
    Ok(())
}
fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let command = args.get(1).map(String::as_str).unwrap_or("help");
    let arg = |i, default: &str| args.get(i).cloned().unwrap_or_else(|| default.into());
    match command {
        "differential-reference" => write(
            &arg(2, "build/differential.json"),
            &differential_reference()?,
        ),
        "verify-native" => {
            let b = if args.len() > 4 {
                ProofBundle::import(&std::fs::read(&args[3])?, &std::fs::read(&args[4])?)?
            } else {
                ProofBundle::reference()?
            };
            write(
                &arg(2, "fixtures/native-reference.json"),
                &b.reference_report()?,
            )
        }
        "freeze-profile" => write(
            &arg(2, "profiles/bws-v1.json"),
            &freeze_reference_profile()?,
        ),
        "compile" => {
            let p = VerifierProfile::read(arg(3, "profiles/bws-v1.json"))?;
            write(&arg(2, "build/compiled-verifier.json"), &p.compile())
        }
        "prepare-witness" => {
            let p = VerifierProfile::read(arg(3, "profiles/bws-v1.json"))?;
            let b = if args.len() > 5 {
                ProofBundle::import(&std::fs::read(&args[4])?, &std::fs::read(&args[5])?)?
            } else {
                ProofBundle::reference()?
            };
            let w = prepare_witness(&p, &b)?;
            write(&arg(2, "build/prepared-witness.json"), &w)?;
            // Diagnostic budget only. The measurement command replaces it with
            // the exact transaction-derived eligible-weight budget.
            write(
                "build/verifier.json",
                &meter_input(&p.compiled, &w, 40_000_000_000),
            )
        }
        "measure" | "regtest-demo" => {
            let tool = if command == "measure" {
                "tools/measure.py"
            } else {
                "tools/regtest-demo.py"
            };
            let status = Command::new("python3")
                .arg(tool)
                .arg(arg(2, "build/verifier.json"))
                .status()
                .context("Python/Core tooling")?;
            if !status.success() {
                bail!("{command} failed");
            }
            if command == "measure" {
                let report: CostReport =
                    serde_json::from_slice(&std::fs::read("build/cost-report.json")?)?;
                anyhow::ensure!(report.limits_pass, "resource limits exceeded");
            }
            Ok(())
        }
        "help" | "--help" | "-h" => {
            println!("Commands (run from the recursive-stwo directory):\n  verify-native [report.json]\n  freeze-profile [profile.json]  # regenerate pinned reference template\n  compile [compiled.json] [profile.json]\n  prepare-witness [witness.json] [profile.json] [hybrid.bin final.bin]\n  measure [verifier.json]\n  regtest-demo [verifier.json]");
            Ok(())
        }
        _ => bail!("unknown command: {command}"),
    }
}
