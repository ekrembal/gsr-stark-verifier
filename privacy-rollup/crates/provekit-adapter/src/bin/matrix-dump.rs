//! Export exact, indexed matrix rows for independent symbolic analysis.
use anyhow::{ensure, Result};
use provekit_common::Verifier;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{BufWriter, Write},
};

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(args.len() == 3 || args.len() == 4, "usage: matrix-dump vk.pc output.json [whir-config.pc]");
    let bytes = fs::read(&args[1])?;
    let verifier: Verifier = postcard::from_bytes(&bytes)?;
    let r1cs = &verifier.r1cs;
    if let Some(path) = args.get(3) {
        fs::write(path, postcard::to_allocvec(verifier.whir_for_witness.as_ref().unwrap())?)?;
    }
    let matrices: Vec<_> = [&r1cs.a, &r1cs.b, &r1cs.c]
        .into_iter()
        .map(|matrix| {
            (0..matrix.num_rows)
                .map(|row| matrix.iter_row(row).map(|(col, value)| (col, value.index())).collect::<Vec<_>>())
                .collect::<Vec<_>>()
        })
        .collect();
    let output = serde_json::json!({
        "vk_sha256":hex::encode(Sha256::digest(&bytes)),
        "rows":r1cs.num_constraints(), "columns":r1cs.num_witnesses(),
        "w1_size":verifier.whir_for_witness.as_ref().unwrap().w1_size,
        "coefficients":r1cs.interner.values().iter().map(ToString::to_string).collect::<Vec<_>>(),
        "matrices":matrices,
    });
    let mut writer = BufWriter::new(fs::File::create(&args[2])?);
    serde_json::to_writer(&mut writer, &output)?;
    writer.flush()?;
    Ok(())
}
