fn main() {
    println!("cargo:rerun-if-env-changed=GSR_FUSED_BN254");
    let mut options = risc0_build::GuestOptions::default();
    match std::env::var("GSR_FUSED_BN254").as_deref() {
        Ok("1") => options.features.push("fused-bn254".to_owned()),
        Err(std::env::VarError::NotPresent) | Ok("0") => {}
        _ => panic!("GSR_FUSED_BN254 must be unset, 0, or 1"),
    }
    println!("cargo:rerun-if-env-changed=GSR_FUSED_DOT32");
    match std::env::var("GSR_FUSED_DOT32").as_deref() {
        Ok("1") => options.features.push("fused-dot32".to_owned()),
        Err(std::env::VarError::NotPresent) | Ok("0") => {}
        _ => panic!("GSR_FUSED_DOT32 must be unset, 0, or 1"),
    }
    risc0_build::embed_methods_with_options(std::collections::HashMap::from([("pr-guest", options)]));
}
