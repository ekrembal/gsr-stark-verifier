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
pub const MAX_MONEY: u64 = 2_100_000_000_000_000;
pub const DUST_LIMIT: u64 = 330;
pub const MAX_BATCH_TRANSACTIONS: usize = 16;
/// Weight one settlement may have: the standard-transaction limit.
pub const MAX_SETTLEMENT_WEIGHT: u64 = 400_000;
/// Measured weight of an empty compressed settlement on the optimized GSR node (331,699 WU), rounded up.
pub const EMPTY_SETTLEMENT_WEIGHT: u64 = 332_000;
pub const MAX_FUNDING_INPUTS: usize = 4;
/// Escrow (non-interactive deposit) inputs per settlement; each mints one note.
pub const MAX_BATCH_ESCROWS: usize = 16;
pub const MAX_SCRIPT_PUBKEY_LEN: usize = 64;
/// ML-KEM-768 ciphertext (1088) || nonce (24) || ChaCha20-Poly1305 sealed note plaintext (104 + 16).
pub const NOTE_CIPHERTEXT_LEN: usize = 1088 + 24 + 120;
pub const NOTE_PLAINTEXT_LEN: usize = 104;
/// A note the sender encrypts to itself (change): ChaCha20-Poly1305 sealed plaintext under the sender's
/// outgoing key, nonce derived from the commitment (104 + 16).
pub const SELF_CIPHERTEXT_LEN: usize = NOTE_PLAINTEXT_LEN + 16;
/// Withdrawal outputs one join-split may declare; their values sum to `withdrawal_sats`.
pub const MAX_WITHDRAWALS_PER_TX: usize = 4;
/// Depth of the SHA-256 anchor history tree (leaf `i` is the anchor after batch `i`).
pub const ANCHOR_TREE_DEPTH: usize = 32;
pub const ANNEX_TAG: u8 = 0x50;
pub const ANNEX_MAGIC: [u8; 4] = *b"GSRP";
pub const ANNEX_ENCODING_VERSION: u8 = 1;
pub const TX_VERSION: u32 = 2;
pub const ROLLUP_INPUT_SEQUENCE: u32 = 1;
pub const FUNDING_INPUT_SEQUENCE: u32 = 0xffff_ffff;
/// Marks an escrow input: the sweep leaf requires it and the transition allows it only on escrow inputs, so an
/// escrow can never be claimed as a join-split's funding coin.
pub const ESCROW_INPUT_SEQUENCE: u32 = 0xffff_fffd;
