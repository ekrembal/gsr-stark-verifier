//! Canonical, fixed-width protocol types for the BTC privacy rollup (see `spec/encoding.md`).
//!
//! Every type has exactly one byte encoding. Decoders reject trailing bytes, non-canonical field
//! elements, out-of-range amounts, unknown tags and non-minimal lengths.
#![no_std]
extern crate alloc;

pub mod codec;
pub mod hash;
pub mod types;

pub use codec::{Canonical, DecodeError, Reader, Writer};
pub use types::*;

pub const PROTOCOL_VERSION: u32 = 1;
pub const COMMITMENT_TREE_DEPTH: usize = 32;
pub const NULLIFIER_TREE_DEPTH: usize = 32;
pub const ANCHOR_WINDOW: usize = 64;
pub const MAX_MONEY: u64 = 2_100_000_000_000_000;
pub const DUST_LIMIT: u64 = 330;
pub const MAX_BATCH_TRANSACTIONS: usize = 8;
pub const MAX_FUNDING_INPUTS: usize = 4;
pub const MAX_SCRIPT_PUBKEY_LEN: usize = 64;
/// ML-KEM-768 ciphertext (1088) || nonce (24) || ChaCha20-Poly1305 sealed note plaintext (104 + 16).
pub const NOTE_CIPHERTEXT_LEN: usize = 1088 + 24 + 120;
pub const NOTE_PLAINTEXT_LEN: usize = 104;
pub const ANNEX_TAG: u8 = 0x50;
pub const ANNEX_MAGIC: [u8; 4] = *b"GSRP";
pub const ANNEX_ENCODING_VERSION: u8 = 1;
pub const TX_VERSION: u32 = 2;
pub const ROLLUP_INPUT_SEQUENCE: u32 = 1;
