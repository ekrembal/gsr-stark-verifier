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
/// BIP 341 annex payloads starting with 0x00 are unstructured data (the standardness rule of bitcoin/bitcoin#36466).
pub const ANNEX_UNSTRUCTURED: u8 = 0x00;
pub const ANNEX_MAGIC: [u8; 4] = *b"GSRP";
pub const ANNEX_ENCODING_VERSION: u8 = 1;
pub const TX_VERSION: u32 = 2;
pub const ROLLUP_INPUT_SEQUENCE: u32 = 1;
/// BIP 68 relative lock of one block: a funding coin must be confirmed, so a settlement has no unconfirmed parent.
pub const FUNDING_INPUT_SEQUENCE: u32 = 1;
/// Marks an escrow input: the sweep leaf requires it and the transition allows it only on escrow inputs, so an
/// escrow can never be claimed as a join-split's funding coin. As a BIP 68 lock it requires two confirmations.
pub const ESCROW_INPUT_SEQUENCE: u32 = 2;
/// Every withdrawal output is `P2TR(NUMS, {leaf})` with a 0xc0 leaf starting `OP_1 OP_CHECKSEQUENCEVERIFY OP_DROP`,
/// so nothing in a settlement is spendable before it confirms and no descendant can pin it.
pub const WITHDRAWAL_LEAF_PREFIX: [u8; 3] = [0x51, 0xb2, 0x75];
pub const WITHDRAWAL_LEAF_VERSION: u8 = 0xc0;
pub const MAX_WITHDRAWAL_LEAF_LEN: usize = 1024;

/// Output 1 of every settlement: `OP_RETURN <new_state_root>`, value 0. The rollup output itself pays the
/// same fixed address in every state, so this is where the state root lives in non-witness data.
pub fn state_root_script(root: &[u8; 32]) -> alloc::vec::Vec<u8> {
    [&[0x6a, 0x20][..], root].concat()
}
