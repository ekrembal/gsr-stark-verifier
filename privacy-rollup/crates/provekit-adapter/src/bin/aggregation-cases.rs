//! Produce local malformed input frames from a known valid, public fixture.
use std::{fs, path::Path};

use provekit_common::{FieldElement, NoirProof};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    anyhow::ensure!(args.len() == 3, "usage: aggregation-cases <proof.pc> <output-dir>");
    anyhow::ensure!(!cfg!(debug_assertions), "use --release: the fixture uses release postcard layout");
    let proof: NoirProof = postcard::from_bytes(&fs::read(&args[1])?)?;
    let out = Path::new(&args[2]);
    fs::create_dir_all(out)?;
    let mut cases = Vec::new();
    let mut changed = proof.clone();
    changed.public_inputs.0[0] += FieldElement::from(1u64);
    cases.push(("public-input", changed));
    let mut changed = proof.clone();
    changed.whir_r1cs_proof.narg_string[0] ^= 1;
    cases.push(("narg-first", changed));
    let mut changed = proof.clone();
    let middle = changed.whir_r1cs_proof.hints.len() / 2;
    changed.whir_r1cs_proof.hints[middle] ^= 1;
    cases.push(("hint-middle", changed));
    let mut changed = proof.clone();
    changed.whir_r1cs_proof.narg_string.push(0);
    cases.push(("narg-extra", changed));
    for (name, changed) in cases {
        fs::write(out.join(format!("{name}.pc")), postcard::to_allocvec(&changed)?)?;
    }
    Ok(())
}
