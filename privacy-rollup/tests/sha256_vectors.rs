//! Shared native/guest vectors. Native uses registry SHA-2; guest uses the pinned
//! RISC Zero fork. Compare the complete output bytes across both builds.
use provekit_common::TranscriptSponge;
use sha2::{compress256, digest::generic_array::GenericArray, Digest, Sha224, Sha256, Sha512};
use whir::{
    hash::{Hash, HashEngine, Sha2},
    transcript::DuplexSpongeInterface,
};

fn data(length: usize) -> Vec<u8> {
    (0..length).map(|i| (i.wrapping_mul(131).wrapping_add(i >> 3).wrapping_add(17) & 255) as u8).collect()
}

pub fn run() -> Vec<u8> {
    let mut output = Vec::new();
    let mut alignments = 0u8;
    for length in [
        0, 1, 2, 3, 31, 32, 55, 56, 57, 63, 64, 65, 95, 111, 112, 119, 120, 127, 128, 129, 255, 256, 257, 511, 512,
        513, 1023, 1024, 1025, 4095, 4096, 4097,
    ] {
        for offset in 0..4 {
            let storage = data(length + 4);
            let message = &storage[offset..offset + length];
            alignments |= 1 << (message.as_ptr() as usize % 4);
            let expected = Sha256::digest(message);
            output.extend_from_slice(&expected);
            output.extend_from_slice(&Sha224::digest(message));
            for chunk in [1, 3, 63, 64, 65, 97] {
                let mut hash = Sha256::new();
                hash.update([]);
                for bytes in message.chunks(chunk) {
                    hash.update(bytes);
                }
                assert_eq!(hash.finalize_reset(), expected, "streaming length={length} offset={offset} chunk={chunk}");
                hash.update(message);
                assert_eq!(hash.finalize_reset(), expected, "reset");
                hash.update(&message[..length / 2]);
                let mut cloned = hash.clone();
                hash.update(&message[length / 2..]);
                cloned.update(&message[length / 2..]);
                assert_eq!(hash.finalize(), expected, "clone source");
                assert_eq!(cloned.finalize(), expected, "clone result");
            }
        }
    }
    assert_eq!(alignments, 0b1111, "exercise every byte alignment modulo four");
    // The fork changes SHA-256 compression (also used by SHA-224), not SHA-512.
    output.extend_from_slice(&Sha512::digest(data(4097)));

    // Check empty compression, arbitrary initial states and both sides of the
    // pinned v3.0.6 syscall's 1000-block chunk boundary, at all four alignments.
    for count in [0, 1, 2, 999, 1000, 1001] {
        for offset in 0..4 {
            let storage = data(count * 64 + 4);
            let message = &storage[offset..offset + count * 64];
            type Block = GenericArray<u8, sha2::digest::consts::U64>;
            assert_eq!(core::mem::size_of::<Block>(), 64);
            assert_eq!(core::mem::align_of::<Block>(), 1);
            // SAFETY: Block is exactly 64 bytes with alignment one. The slice
            // covers count complete blocks of initialized, immutably borrowed
            // bytes. This intentionally retains unaligned input for the test.
            let blocks = unsafe { core::slice::from_raw_parts(message.as_ptr().cast::<Block>(), count) };
            let initial = [0x01020304, 0xfedcba98, 0x76543210, 0x80000000, 0, u32::MAX, 0xaabbccdd, 0x88776655];
            let mut state = initial;
            compress256(&mut state, blocks);
            let mut split = initial;
            for part in blocks.chunks(7) {
                compress256(&mut split, part);
            }
            assert_eq!(state, split, "raw compression count={count} offset={offset}");
            for word in state {
                output.extend_from_slice(&word.to_be_bytes());
            }
        }
    }

    let engine = Sha2::new();
    for size in [0, 1, 31, 32, 55, 56, 63, 64, 65, 128, 511] {
        for count in [0, 1, 3] {
            let storage = data(size * count + 1);
            let input = &storage[1..];
            let mut hashes = vec![Hash::default(); count];
            engine.hash_many(size, input, &mut hashes);
            for (i, hash) in hashes.iter().enumerate() {
                assert_eq!(&hash.0[..], Sha256::digest(&input[i * size..(i + 1) * size]).as_slice());
                output.extend_from_slice(&hash.0);
            }
        }
    }

    for length in [0, 1, 31, 32, 55, 56, 63, 64, 65, 129, 513] {
        let input = data(length);
        let mut whole = TranscriptSponge::default();
        let mut streamed = TranscriptSponge::default();
        whole.absorb(b"gsr-sha256-differential-v1").absorb(&input);
        streamed.absorb(b"gsr-sha256-differential-v1");
        for part in input.chunks(3) {
            streamed.absorb(part);
        }
        let mut a = [0u8; 97];
        let mut b = [0u8; 97];
        whole.squeeze(&mut a);
        for part in b.chunks_mut(7) {
            streamed.squeeze(part);
        }
        assert_eq!(a, b, "streaming transcript length={length}");
        output.extend_from_slice(&a);
        whole.ratchet().absorb(b"after challenge");
        streamed.ratchet().absorb(b"after challenge");
        let mut clone = whole.clone();
        let a = whole.squeeze_array::<65>();
        assert_eq!(a, streamed.squeeze_array::<65>(), "ratchet");
        assert_eq!(a, clone.squeeze_array::<65>(), "transcript clone");
        output.extend_from_slice(&a);
    }
    output
}
