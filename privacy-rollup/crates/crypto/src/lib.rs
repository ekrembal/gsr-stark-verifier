//! Note commitments, nullifiers, spend keys and commitment-tree nodes: tagged SHA-256 (BIP-340 style, as
//! everywhere else in the protocol), so the RISC Zero guests use the SHA-256 accelerator and a Script can
//! recompute any of them with `OP_SHA256`. Each digest has its top three bits cleared (`Fe::from_digest`)
//! so every value stays a canonical field element. Integers are little-endian, as in the encoding.
use pr_protocol_types::hash::{tagged, tags};
use pr_protocol_types::Fe;

fn hash(tag: &str, parts: &[&[u8]]) -> Fe {
    Fe::from_digest(tagged(tag, parts))
}

pub fn spend_authority(secret: &Fe) -> Fe {
    hash(tags::OWNER, &[&secret.0])
}

pub fn nullifier_key(secret: &Fe) -> Fe {
    hash(tags::NULLIFIER_KEY, &[&secret.0])
}

pub fn note_commitment(rollup_id: &Fe, value: u64, authority: &Fe, randomness: &Fe) -> Fe {
    hash(tags::NOTE, &[&rollup_id.0, &value.to_le_bytes(), &authority.0, &randomness.0])
}

pub fn nullifier(nullifier_key: &Fe, commitment: &Fe, leaf_index: u32) -> Fe {
    hash(tags::NULLIFIER, &[&nullifier_key.0, &commitment.0, &leaf_index.to_le_bytes()])
}

pub fn merkle_node(left: &Fe, right: &Fe) -> Fe {
    hash(tags::NOTE_NODE, &[&left.0, &right.0])
}

#[cfg(test)]
mod tests {
    use super::*;
    use pr_protocol_types::hash::sha256;

    #[test]
    fn tagged_sha256_vectors() {
        // SHA256(T || T || left || right) with T = SHA256("gsr-privacy-rollup/note-node"), top three bits cleared.
        let t = sha256(b"gsr-privacy-rollup/note-node");
        let mut d = sha256(&[t, t, [0; 32], [0; 32]].concat());
        d[0] &= 0x1f;
        assert_eq!(merkle_node(&Fe::ZERO, &Fe::ZERO), Fe(d));
        let t = sha256(b"gsr-privacy-rollup/note");
        let mut d = sha256(&[&t[..], &t, &[1; 32], &5u64.to_le_bytes(), &[2; 32], &[3; 32]].concat());
        d[0] &= 0x1f;
        assert_eq!(note_commitment(&Fe([1; 32]), 5, &Fe([2; 32]), &Fe([3; 32])), Fe(d));
    }

    #[test]
    fn canonical_and_domain_separated() {
        let a = Fe::from_u64(7);
        let auth = spend_authority(&a);
        let nk = nullifier_key(&a);
        assert_ne!(auth, nk);
        let c1 = note_commitment(&Fe::from_u64(1), 5, &auth, &Fe::from_u64(9));
        assert_eq!(c1, note_commitment(&Fe::from_u64(1), 5, &auth, &Fe::from_u64(9)));
        assert_ne!(c1, note_commitment(&Fe::from_u64(1), 6, &auth, &Fe::from_u64(9)));
        assert_eq!(nullifier(&nk, &c1, 3), nullifier(&nk, &c1, 3));
        assert_ne!(nullifier(&nk, &c1, 3), nullifier(&nk, &c1, 4));
        for v in [auth, nk, c1, nullifier(&nk, &c1, 3), merkle_node(&c1, &auth)] {
            assert!(Fe::from_canonical(v.0).is_some());
        }
    }
}
