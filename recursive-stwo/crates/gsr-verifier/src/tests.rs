use recursive_stwo_bitcoin_dsl::{
    bar::{AllocBar, Bar},
    basic::str::StrBar,
    bitcoin_system::BitcoinSystemRef,
    gsr, gsr_compiler,
};
use recursive_stwo_primitives::{
    channel::{sha256::Sha256ChannelBar, ChannelBar},
    fields::{m31::M31Bar, qm31::QM31Bar},
};
use std::process::Command;
use stwo_prover::core::fields::{m31::M31, qm31::QM31};
fn execute(build: impl FnOnce(&BitcoinSystemRef)) {
    let (_, program) = gsr::capture(|| {
        let cs = gsr::current().unwrap();
        build(&cs);
        gsr_compiler::compile(cs)
    })
    .unwrap();
    let input = serde_json::json!({"script":hex::encode(program.script),"witness":program.witness.iter().map(hex::encode).collect::<Vec<_>>(),"budget":100_000_000_000u64});
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let path = root.join(format!(
        "build/test-{}.json",
        std::thread::current().name().unwrap_or("primitive")
    ));
    std::fs::write(&path, serde_json::to_vec(&input).unwrap()).unwrap();
    let output = Command::new(root.join("build/harness/gsr-meter"))
        .arg(path)
        .output()
        .expect("build harness first: python3 tools/build-harness.py");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}
#[test]
fn arithmetic_and_encoding() {
    execute(|cs| {
        for a in [0, 1, 127, 128, 129, 255, 256, 32767, 32768, 0x7ffffffe] {
            let x = M31Bar::new_hint(cs, M31(a)).unwrap();
            let enc = x.to_str().unwrap();
            let expected =
                recursive_stwo_bitcoin_dsl::basic::sha256_hash::bitcoin_num_to_bytes(a as i64);
            enc.equalverify(&StrBar::new_constant(cs, expected).unwrap())
                .unwrap();
            for b in [0, 1, 128, 0x7ffffffe] {
                let y = M31Bar::new_hint(cs, M31(b)).unwrap();
                (&x + &y)
                    .equalverify(&M31Bar::new_constant(cs, M31(a) + M31(b)).unwrap())
                    .unwrap();
                (&x - &y)
                    .equalverify(&M31Bar::new_constant(cs, M31(a) - M31(b)).unwrap())
                    .unwrap();
                (&x * &y)
                    .equalverify(&M31Bar::new_constant(cs, M31(a) * M31(b)).unwrap())
                    .unwrap();
            }
        }
    });
}
#[test]
fn extension_and_transcript() {
    execute(|cs| {
        for seed in 0..12 {
            let a = QM31::from_u32_unchecked(seed, 129 + seed, 0x7ffffffe - seed, 32768);
            let b = QM31::from_u32_unchecked(734 + seed, seed, 512, 255);
            let x = QM31Bar::new_hint(cs, a).unwrap();
            let y = QM31Bar::new_hint(cs, b).unwrap();
            (&x * &y)
                .equalverify(&QM31Bar::new_constant(cs, a * b).unwrap())
                .unwrap();
        }
        let mut channel = Sha256ChannelBar::default(cs).unwrap();
        let x = QM31Bar::new_hint(cs, QM31::from_u32_unchecked(0, 128, 129, 32768)).unwrap();
        channel.mix_felts(&[x]);
        for value in channel.draw_m31(19) {
            value
                .equalverify(&M31Bar::new_constant(cs, value.value).unwrap())
                .unwrap();
        }
    });
}

#[test]
fn extension_zero_negation_and_inverse() {
    use num_traits::{One, Zero};
    use stwo_prover::core::fields::FieldExpOps;
    execute(|cs| {
        let a = QM31::from_u32_unchecked(128, 32768, 0, 0x7ffffffe);
        let x = QM31Bar::new_hint(cs, a).unwrap();
        let zero = QM31Bar::new_hint(cs, QM31::zero()).unwrap();
        (&x * &zero)
            .equalverify(&QM31Bar::new_constant(cs, QM31::zero()).unwrap())
            .unwrap();
        (-&x)
            .equalverify(&QM31Bar::new_constant(cs, -a).unwrap())
            .unwrap();
        x.inverse_without_table()
            .equalverify(&QM31Bar::new_constant(cs, a.inverse()).unwrap())
            .unwrap();
        let one = M31Bar::new_hint(cs, M31::one()).unwrap();
        one.inverse_without_table().equalverify(&one).unwrap();
    });
}

#[test]
fn grinding_boundary() {
    use recursive_stwo_bitcoin_dsl::basic::sha256_hash::Sha256HashBar;
    use recursive_stwo_primitives::pow::verify_pow;
    // The low 28 bits of the first big-endian u128 are zero, exactly as in Stwo.
    execute(|cs| {
        let mut digest = vec![0xa5; 32];
        digest[12..16].copy_from_slice(&[0x10, 0, 0, 0]);
        let hash = Sha256HashBar::new_hint(cs, digest.into()).unwrap();
        let channel = Sha256ChannelBar::new_with_digest(&hash).unwrap();
        verify_pow(&channel, 28).unwrap();
    });
}
