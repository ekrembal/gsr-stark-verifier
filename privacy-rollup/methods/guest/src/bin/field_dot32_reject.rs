//! Negative-only dot32 kernel: alter nondeterministic stores while retaining exactly
//! the honest verifier bytecode and constants. This is never a verifier dispatch.
use risc0_zkvm::guest::env;
#[path = "../../../../vendor/ark-ff/src/fields/models/fp/bn254_montgomery.rs"]
mod fused;
mod fixture {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vendor/ark-ff/src/fields/models/fp/bn254_montgomery_dot32_blob.rs"
    ));
    pub fn modified(mode: u8) -> [u32; 532] {
        let mut blob = BN254_MONT_DOT32_BLOB;
        assert!(mode == 1 || mode == 2);
        assert_eq!(blob[6], 0); // no BIBC inputs
        assert_eq!(blob[8], 0); // no BIBC scalar constants
        let start = 10 + 8 * blob[7] as usize;
        let mut changes = 0;
        for i in 0..blob[9] as usize {
            let pos = start + 2 * i;
            let instruction = blob[pos] as u64 | ((blob[pos + 1] as u64) << 32);
            if instruction & 15 != 4 {
                continue;
            }
            let arena = ((instruction >> 16) & 0xffffff) >> 16;
            let source = if arena == 2 {
                Some(0)
            } else if arena == 13 && mode == 2 {
                Some(2)
            } else {
                None
            };
            if let Some(source) = source {
                blob[pos + 1] = (blob[pos + 1] & 255) | (source << 8);
                changes += 1;
            }
        }
        assert_eq!(changes, mode as usize);
        let verify_start = 4 + blob[0] as usize;
        assert_eq!(&blob[verify_start..], &BN254_MONT_DOT32_BLOB[verify_start..]);
        blob
    }
}

fn main() {
    let frame = env::read_frame();
    assert_eq!(frame.len(), 1);
    let blob = fixture::modified(frame[0]);
    let zero = [0u32; 256];
    let mut result = [0u32; 8];
    unsafe {
        risc0_bigint2::ffi::sys_bigint2_3(blob.as_ptr().cast(), zero.as_ptr(), zero.as_ptr(), result.as_mut_ptr());
    }
    // Mode 1: q=0,r=0 violates the integer relation for zero inputs; proving
    // must reject even though fast execution produces the expected result.
    // Mode 2: q=0,r=p satisfies the relation, but this canonicality check rejects.
    fused::assert_canonical(&result);
    for word in result {
        env::commit_slice(&word.to_le_bytes());
    }
}
