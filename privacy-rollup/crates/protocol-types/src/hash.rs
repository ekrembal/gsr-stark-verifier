//! Domain-separated SHA-256 (BIP-340 style tagged hashes) used for every protocol hash.
use alloc::boxed::Box;

use once_cell::race::OnceBox;
use sha2::{Digest, Sha256};

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn fresh_tagged_hasher(tag: &str) -> Sha256 {
    let t = sha256(tag.as_bytes());
    let mut h = Sha256::new();
    h.update(t);
    h.update(t);
    h
}

/// A SHA-256 state that has absorbed `sha256(tag) || sha256(tag)` (exactly one block). The states
/// for the protocol's own tags are computed once, so each tagged hash costs only its data blocks.
pub fn tagged_hasher(tag: &str) -> Sha256 {
    macro_rules! cached {
        ($($name:ident),* $(,)?) => {
            match tag {
                $(tags::$name => {
                    static H: OnceBox<Sha256> = OnceBox::new();
                    H.get_or_init(|| Box::new(fresh_tagged_hasher(tags::$name))).clone()
                })*
                _ => fresh_tagged_hasher(tag),
            }
        };
    }
    cached!(
        STATE,
        ANCHORS,
        ANCHOR_NODE,
        COMMITMENT_FRONTIER,
        BATCH_BODY,
        DATA_HISTORY,
        EXTERNAL_DATA,
        NULLIFIER_LEAF,
        NULLIFIER_NODE,
        ROLLUP_ID,
        NOTE_KEY,
        OWNER,
        NULLIFIER_KEY,
        NOTE,
        NULLIFIER,
        NOTE_NODE,
    )
}

pub fn tagged(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut h = tagged_hasher(tag);
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

pub mod tags {
    pub const STATE: &str = "gsr-privacy-rollup/state";
    pub const ANCHORS: &str = "gsr-privacy-rollup/anchors";
    pub const ANCHOR_NODE: &str = "gsr-privacy-rollup/anchor-node";
    pub const COMMITMENT_FRONTIER: &str = "gsr-privacy-rollup/commitment-frontier";
    pub const BATCH_BODY: &str = "gsr-privacy-rollup/batch-body";
    pub const DATA_HISTORY: &str = "gsr-privacy-rollup/data-history";
    pub const EXTERNAL_DATA: &str = "gsr-privacy-rollup/external-data";
    pub const NULLIFIER_LEAF: &str = "gsr-privacy-rollup/nullifier-leaf";
    pub const NULLIFIER_NODE: &str = "gsr-privacy-rollup/nullifier-node";
    pub const ROLLUP_ID: &str = "gsr-privacy-rollup/rollup-id";
    pub const NOTE_KEY: &str = "gsr-privacy-rollup/note-key";
    pub const OWNER: &str = "gsr-privacy-rollup/owner";
    pub const NULLIFIER_KEY: &str = "gsr-privacy-rollup/nullifier-key";
    pub const NOTE: &str = "gsr-privacy-rollup/note";
    pub const NULLIFIER: &str = "gsr-privacy-rollup/nullifier";
    pub const NOTE_NODE: &str = "gsr-privacy-rollup/note-node";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cached_tagged_hashers_match_fresh_ones() {
        for tag in [tags::STATE, tags::NULLIFIER_NODE, tags::COMMITMENT_FRONTIER, "uncached/tag"] {
            let mut a = tagged_hasher(tag);
            let mut b = fresh_tagged_hasher(tag);
            a.update(b"data");
            b.update(b"data");
            assert_eq!(a.finalize(), b.finalize(), "{tag}");
        }
    }
}
