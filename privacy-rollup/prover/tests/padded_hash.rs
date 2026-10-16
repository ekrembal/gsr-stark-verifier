//! Limited regression coverage for the existing, unaudited padded-hash patch.
//! Expected pair/RNG values were independently computed with Python hashlib.
use risc0_zkvm::{
    sha::{Digest, Impl, Sha256},
    VerifierContext,
};

#[test]
fn padded_hash_matches_standard_sha_preimages() {
    assert_eq!(
        hex::encode(Impl::hash_bytes(b"abc").as_bytes()),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    let suites = VerifierContext::default_hash_suites();
    let padded = &suites["sha-256-padded"];
    let a = Digest::from([1u32, 2, 3, 4, 5, 6, 7, 8]);
    let b = Digest::from([9u32, 10, 11, 12, 13, 14, 15, 16]);
    assert_eq!(
        hex::encode(padded.hashfn.hash_pair(&a, &b).as_bytes()),
        "77d735ce838418aa151bd96b5b1e78ee63860892e0a95c00fe34178442be9b07"
    );
    assert_ne!(padded.hashfn.hash_pair(&a, &b), suites["sha-256"].hashfn.hash_pair(&a, &b));
    let empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    assert_eq!(hex::encode(padded.hashfn.hash_elem_slice(&[]).as_bytes()), empty);
    assert_eq!(hex::encode(padded.hashfn.hash_ext_elem_slice(&[]).as_bytes()), empty);
    assert_eq!(
        hex::encode(padded.hashfn.hash_elem_slice(&[Default::default(); 37]).as_bytes()),
        "3b18c58c739716e76429634a61375c45b3b5cd470c22ab6d3e14cee23dd992e1"
    );
    assert_eq!(
        hex::encode(padded.hashfn.hash_ext_elem_slice(&[Default::default(); 37]).as_bytes()),
        "2b73f6b3cd6cd9f97ccbbedc2fa1904331b916b2ace865882f72ddd083c79b04"
    );
}

#[test]
fn padded_rng_matches_little_endian_reference_across_rollover_and_mix() {
    let suites = VerifierContext::default_hash_suites();
    let mut rng = suites["sha-256-padded"].rng.new_rng();
    let expected = [
        864902936, 637432098, 2091278837, 640584595, 820774467, 5364302, 1215746311, 1763260454, 1143524733, 848632917,
        760054399, 1122320051,
    ];
    for word in expected {
        assert_eq!(rng.random_bits(31), word);
    }
    rng.mix(&Digest::from([1u32, 2, 3, 4, 5, 6, 7, 8]));
    let expected = [
        1697444210, 1471208715, 1602355125, 260114127, 239792292, 1772011409, 1726429852, 25626467, 593975296,
        1221853630, 986641503, 1627109021,
    ];
    for word in expected {
        assert_eq!(rng.random_bits(31), word);
    }
}
