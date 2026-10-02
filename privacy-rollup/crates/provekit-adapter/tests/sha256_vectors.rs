#[path = "../../../tests/sha256_vectors.rs"]
mod vectors;

#[test]
fn registry_sha256_reference_and_streaming_vectors() {
    use sha2::{Digest, Sha256};
    assert_eq!(hex::encode(Sha256::digest([])), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_eq!(hex::encode(Sha256::digest(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    let output = vectors::run();
    // Optional export is test evidence consumed by exec_sha256_check, not a
    // replacement for comparing the accelerated guest's complete output bytes.
    if let Some(path) = std::env::var_os("GSR_SHA256_REFERENCE") {
        std::fs::write(path, &output).unwrap();
    }
    println!("SHA vector reference: {} bytes, digest {}", output.len(), hex::encode(Sha256::digest(&output)));
}
