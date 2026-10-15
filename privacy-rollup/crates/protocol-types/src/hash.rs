//! Domain-separated SHA-256 (BIP-340 style tagged hashes) used for everything outside the
//! join-split circuit.
use sha2::{Digest, Sha256};

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn tagged_hasher(tag: &str) -> Sha256 {
    let t = sha256(tag.as_bytes());
    let mut h = Sha256::new();
    h.update(t);
    h.update(t);
    h
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
    pub const BATCH_BODY: &str = "gsr-privacy-rollup/batch-body";
    pub const DATA_HISTORY: &str = "gsr-privacy-rollup/data-history";
    pub const EXTERNAL_DATA: &str = "gsr-privacy-rollup/external-data";
    pub const NULLIFIER_LEAF: &str = "gsr-privacy-rollup/nullifier-leaf";
    pub const NULLIFIER_NODE: &str = "gsr-privacy-rollup/nullifier-node";
    pub const ROLLUP_ID: &str = "gsr-privacy-rollup/rollup-id";
    pub const NOTE_KEY: &str = "gsr-privacy-rollup/note-key";
}
