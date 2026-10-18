use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use crate::codec::{Canonical, DecodeError, Reader, Writer};
use crate::hash::{tagged, tags};
use crate::*;

/// BN254 scalar-field modulus, big-endian.
pub const BN254_MODULUS: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d, 0x28, 0x33, 0xe8,
    0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

/// A canonical BN254 scalar, 32 bytes big-endian, strictly below the modulus.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Fe(pub [u8; 32]);

impl Fe {
    pub const ZERO: Fe = Fe([0; 32]);

    pub fn from_canonical(b: [u8; 32]) -> Option<Fe> {
        (b < BN254_MODULUS).then_some(Fe(b))
    }
    /// Clears the top three bits, so any 32-byte digest maps to a canonical element.
    pub fn from_digest(mut b: [u8; 32]) -> Fe {
        b[0] &= 0x1f;
        Fe(b)
    }
    pub fn from_u64(v: u64) -> Fe {
        let mut b = [0u8; 32];
        b[24..].copy_from_slice(&v.to_be_bytes());
        Fe(b)
    }
    pub fn is_zero(&self) -> bool {
        self.0 == [0; 32]
    }
    /// Splits a 256-bit digest into the (hi, lo) 128-bit halves used as circuit public inputs.
    pub fn split_digest(d: &[u8; 32]) -> (Fe, Fe) {
        let mut hi = [0u8; 32];
        let mut lo = [0u8; 32];
        hi[16..].copy_from_slice(&d[..16]);
        lo[16..].copy_from_slice(&d[16..]);
        (Fe(hi), Fe(lo))
    }
}

impl Canonical for Fe {
    fn encode_to(&self, w: &mut Writer) {
        w.bytes(&self.0);
    }
    fn decode_from(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Fe::from_canonical(r.array()?).ok_or(DecodeError::NonCanonicalField)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Outpoint {
    /// Transaction id in serialization (little-endian) byte order.
    pub txid: [u8; 32],
    pub vout: u32,
}

impl Canonical for Outpoint {
    fn encode_to(&self, w: &mut Writer) {
        w.bytes(&self.txid).u32(self.vout);
    }
    fn decode_from(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Outpoint { txid: r.array()?, vout: r.u32()? })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TxOut {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

impl Canonical for TxOut {
    fn encode_to(&self, w: &mut Writer) {
        w.u64(self.value).var_bytes(&self.script_pubkey);
    }
    fn decode_from(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let value = r.amount()?;
        let script_pubkey = r.var_bytes(MAX_SCRIPT_PUBKEY_LEN)?.to_vec();
        Ok(TxOut { value, script_pubkey })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorEntry {
    pub batch_number: u64,
    pub commitment_root: Fe,
    pub commitment_count: u64,
}

impl Canonical for AnchorEntry {
    fn encode_to(&self, w: &mut Writer) {
        w.u64(self.batch_number);
        self.commitment_root.encode_to(w);
        w.u64(self.commitment_count);
    }
    fn decode_from(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(AnchorEntry { batch_number: r.u64()?, commitment_root: Fe::decode_from(r)?, commitment_count: r.u64()? })
    }
}

/// Leaf of the anchor history tree.
pub fn anchor_leaf(e: &AnchorEntry) -> [u8; 32] {
    tagged(tags::ANCHORS, &[&e.encode()])
}

fn anchor_node(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    tagged(tags::ANCHOR_NODE, &[l, r])
}

/// Root of the anchor history tree given `leaf` at `index` and its `ANCHOR_TREE_DEPTH` siblings,
/// bottom-up. Unused leaves are all-zero.
pub fn anchor_root_from_path(leaf: &[u8; 32], index: u64, path: &[[u8; 32]]) -> Option<[u8; 32]> {
    if path.len() != ANCHOR_TREE_DEPTH || index >> ANCHOR_TREE_DEPTH != 0 {
        return None;
    }
    let mut h = *leaf;
    for (level, sib) in path.iter().enumerate() {
        h = if (index >> level) & 1 == 0 { anchor_node(&h, sib) } else { anchor_node(sib, &h) };
    }
    Some(h)
}

/// Membership of one anchor in the history tree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorProof {
    pub entry: AnchorEntry,
    pub path: Vec<[u8; 32]>,
}

impl AnchorProof {
    /// The entry, if it is leaf `entry.batch_number` of the tree with root `root`.
    pub fn verify(&self, root: &[u8; 32]) -> Option<&AnchorEntry> {
        (anchor_root_from_path(&anchor_leaf(&self.entry), self.entry.batch_number, &self.path).as_ref() == Some(root))
            .then_some(&self.entry)
    }
}

/// Every accepted commitment root, oldest first: entry `i` is the anchor after batch `i` and leaf
/// `i` of an append-only SHA-256 Merkle tree of depth `ANCHOR_TREE_DEPTH`, whose root the state
/// holds. Anchors never leave the history; a statement's own expiry bounds its lifetime.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorHistory(pub Vec<AnchorEntry>);

impl AnchorHistory {
    pub fn commitment(&self) -> [u8; 32] {
        self.root_and_path(None).0
    }
    pub fn find(&self, batch_number: u64) -> Option<&AnchorEntry> {
        usize::try_from(batch_number).ok().and_then(|i| self.0.get(i)).filter(|e| e.batch_number == batch_number)
    }
    pub fn push(&mut self, e: AnchorEntry) {
        self.0.push(e);
    }
    /// Siblings of leaf `index` (which may be the next, still empty, slot).
    pub fn path(&self, index: u64) -> Vec<[u8; 32]> {
        self.root_and_path(Some(index)).1
    }
    fn root_and_path(&self, index: Option<u64>) -> ([u8; 32], Vec<[u8; 32]>) {
        let mut layer: Vec<[u8; 32]> = self.0.iter().map(anchor_leaf).collect();
        let mut empty = [0u8; 32];
        let mut path = Vec::new();
        let mut at = index;
        for _ in 0..ANCHOR_TREE_DEPTH {
            if let Some(i) = at {
                path.push(layer.get((i ^ 1) as usize).copied().unwrap_or(empty));
                at = Some(i >> 1);
            }
            if layer.len() % 2 == 1 {
                layer.push(empty);
            }
            layer = layer.chunks(2).map(|c| anchor_node(&c[0], &c[1])).collect();
            empty = anchor_node(&empty, &empty);
        }
        (layer.first().copied().unwrap_or(empty), path)
    }
}

impl Canonical for AnchorHistory {
    fn encode_to(&self, w: &mut Writer) {
        w.u32(self.0.len() as u32);
        for e in &self.0 {
            e.encode_to(w);
        }
    }
    fn decode_from(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let n = r.u32()? as usize;
        if n == 0 {
            return Err(DecodeError::LengthOutOfRange);
        }
        let mut v = Vec::new();
        for i in 0..n {
            let e = AnchorEntry::decode_from(r)?;
            if e.batch_number != i as u64 {
                return Err(DecodeError::BadOrder);
            }
            v.push(e);
        }
        Ok(AnchorHistory(v))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollupState {
    pub rollup_id: Fe,
    pub protocol_version: u32,
    pub batch_number: u64,
    pub commitment_root: Fe,
    pub commitment_count: u64,
    /// Digest of the canonical commitment frontier for `(commitment_root, commitment_count)`
    /// (`Frontier::digest`): the batch guest authenticates the frontier by this SHA-256 digest
    /// instead of recomputing the 32-level Poseidon2 root.
    pub commitment_frontier: [u8; 32],
    pub nullifier_root: [u8; 32],
    pub nullifier_next_index: u64,
    pub anchor_history_commitment: [u8; 32],
    pub data_history_commitment: [u8; 32],
    pub backing_sats: u64,
    /// Outpoint spent by input 0 of the transaction that created the coin holding this state: the
    /// previous rollup output, or `genesis_nonce` for the genesis state. Lineage is checked by
    /// induction from it, so only the coin descending from `genesis_nonce` can settle.
    pub parent: Outpoint,
}

impl RollupState {
    pub fn root(&self) -> [u8; 32] {
        tagged(tags::STATE, &[&self.encode()])
    }
}

impl Canonical for RollupState {
    fn encode_to(&self, w: &mut Writer) {
        self.rollup_id.encode_to(w);
        w.u32(self.protocol_version).u64(self.batch_number);
        self.commitment_root.encode_to(w);
        w.u64(self.commitment_count)
            .bytes(&self.commitment_frontier)
            .bytes(&self.nullifier_root)
            .u64(self.nullifier_next_index)
            .bytes(&self.anchor_history_commitment)
            .bytes(&self.data_history_commitment)
            .u64(self.backing_sats);
        self.parent.encode_to(w);
    }
    fn decode_from(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(RollupState {
            rollup_id: Fe::decode_from(r)?,
            protocol_version: r.u32()?,
            batch_number: r.u64()?,
            commitment_root: Fe::decode_from(r)?,
            commitment_count: r.u64()?,
            commitment_frontier: r.array()?,
            nullifier_root: r.array()?,
            nullifier_next_index: r.u64()?,
            anchor_history_commitment: r.array()?,
            data_history_commitment: r.array()?,
            backing_sats: r.amount()?,
            parent: Outpoint::decode_from(r)?,
        })
    }
}

/// Fixed parameters that, together with the generated verifier suffix, define one rollup instance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollupDescriptor {
    pub protocol_version: u32,
    /// Outpoint consumed by the genesis transaction; makes `rollup_id` unique.
    pub genesis_nonce: Outpoint,
    /// RISC Zero image ID of the `apply-batch` guest.
    pub image_id: [u8; 32],
    /// x-only Taproot internal key (unspendable NUMS point).
    pub internal_key: [u8; 32],
    /// Unowned sats locked at genesis to keep the rollup output above dust forever.
    pub seed_sats: u64,
}

impl RollupDescriptor {
    pub fn rollup_id(&self) -> Fe {
        let mut w = Writer::new();
        w.u32(self.protocol_version);
        self.genesis_nonce.encode_to(&mut w);
        w.bytes(&self.image_id).bytes(&self.internal_key).u64(self.seed_sats);
        Fe::from_digest(tagged(tags::ROLLUP_ID, &[&w.finish()]))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositDeclaration {
    /// Funding outpoints, consumed as consecutive settlement inputs in this order.
    pub funding: Vec<Outpoint>,
    /// Change returned to the depositor. The transition rejects it: an output spendable before the settlement
    /// confirms could pin it.
    pub change: Option<TxOut>,
}

/// Public per-transaction data bound into the proof through `external_data_commitment`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalData {
    pub deposit: Option<DepositDeclaration>,
    /// Withdrawal outputs (at most `MAX_WITHDRAWALS_PER_TX`); their values sum to `withdrawal_sats`.
    pub withdrawals: Vec<TxOut>,
    pub ciphertexts: [Vec<u8>; 2],
}

impl ExternalData {
    pub fn commitment(&self) -> [u8; 32] {
        tagged(tags::EXTERNAL_DATA, &[&self.encode()])
    }
}

impl Canonical for ExternalData {
    fn encode_to(&self, w: &mut Writer) {
        match &self.deposit {
            None => {
                w.u8(0);
            }
            Some(d) => {
                w.u8(1).u8(d.funding.len() as u8);
                for o in &d.funding {
                    o.encode_to(w);
                }
                match &d.change {
                    None => {
                        w.u8(0);
                    }
                    Some(c) => {
                        w.u8(1);
                        c.encode_to(w);
                    }
                }
            }
        }
        w.u8(self.withdrawals.len() as u8);
        for o in &self.withdrawals {
            o.encode_to(w);
        }
        for c in &self.ciphertexts {
            encode_ciphertext(w, c);
        }
    }
    fn decode_from(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let deposit = if r.bool()? {
            let n = r.u8()? as usize;
            if n == 0 || n > MAX_FUNDING_INPUTS {
                return Err(DecodeError::LengthOutOfRange);
            }
            let mut funding = Vec::with_capacity(n);
            for _ in 0..n {
                funding.push(Outpoint::decode_from(r)?);
            }
            let change = if r.bool()? { Some(TxOut::decode_from(r)?) } else { None };
            Some(DepositDeclaration { funding, change })
        } else {
            None
        };
        let n = r.u8()? as usize;
        if n > MAX_WITHDRAWALS_PER_TX {
            return Err(DecodeError::LengthOutOfRange);
        }
        let mut withdrawals = Vec::with_capacity(n);
        for _ in 0..n {
            withdrawals.push(TxOut::decode_from(r)?);
        }
        let ciphertexts = [decode_ciphertext(r)?, decode_ciphertext(r)?];
        Ok(ExternalData { deposit, withdrawals, ciphertexts })
    }
}

/// A note ciphertext with its kind byte: 0 for an ML-KEM ciphertext (`NOTE_CIPHERTEXT_LEN`), 1 for a
/// self ciphertext (`SELF_CIPHERTEXT_LEN`). Any other length is not encodable.
pub fn ciphertext_kind(c: &[u8]) -> Option<u8> {
    match c.len() {
        NOTE_CIPHERTEXT_LEN => Some(0),
        SELF_CIPHERTEXT_LEN => Some(1),
        _ => None,
    }
}

fn encode_ciphertext(w: &mut Writer, c: &[u8]) {
    w.u8(ciphertext_kind(c).unwrap_or(0xff)).bytes(c);
}

fn decode_ciphertext(r: &mut Reader<'_>) -> Result<Vec<u8>, DecodeError> {
    let len = match r.u8()? {
        0 => NOTE_CIPHERTEXT_LEN,
        1 => SELF_CIPHERTEXT_LEN,
        _ => return Err(DecodeError::LengthOutOfRange),
    };
    Ok(r.take(len)?.to_vec())
}

/// Public statement of one 2-input/2-output join-split proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinSplitPublic {
    pub rollup_id: Fe,
    pub protocol_version: u32,
    pub anchor_root: Fe,
    pub anchor_commitment_count: u64,
    pub anchor_batch_number: u64,
    pub nullifiers: [Fe; 2],
    pub output_commitments: [Fe; 2],
    pub deposit_sats: u64,
    pub withdrawal_sats: u64,
    pub fee_sats: u64,
    pub external_data_commitment: [u8; 32],
    pub expiry_batch_number: u64,
}

impl JoinSplitPublic {
    pub const NUM_PUBLIC_INPUTS: usize = 15;

    /// Public inputs in Noir ABI order (see `circuits/joinsplit-2x2/src/main.nr`).
    pub fn public_inputs(&self) -> [Fe; Self::NUM_PUBLIC_INPUTS] {
        let (hi, lo) = Fe::split_digest(&self.external_data_commitment);
        [
            self.rollup_id,
            Fe::from_u64(self.protocol_version as u64),
            self.anchor_root,
            Fe::from_u64(self.anchor_commitment_count),
            Fe::from_u64(self.anchor_batch_number),
            self.nullifiers[0],
            self.nullifiers[1],
            self.output_commitments[0],
            self.output_commitments[1],
            Fe::from_u64(self.deposit_sats),
            Fe::from_u64(self.withdrawal_sats),
            Fe::from_u64(self.fee_sats),
            hi,
            lo,
            Fe::from_u64(self.expiry_batch_number),
        ]
    }
}

impl Canonical for JoinSplitPublic {
    fn encode_to(&self, w: &mut Writer) {
        self.rollup_id.encode_to(w);
        w.u32(self.protocol_version);
        self.anchor_root.encode_to(w);
        w.u64(self.anchor_commitment_count).u64(self.anchor_batch_number);
        for f in self.nullifiers.iter().chain(self.output_commitments.iter()) {
            f.encode_to(w);
        }
        w.u64(self.deposit_sats)
            .u64(self.withdrawal_sats)
            .u64(self.fee_sats)
            .bytes(&self.external_data_commitment)
            .u64(self.expiry_batch_number);
    }
    fn decode_from(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(JoinSplitPublic {
            rollup_id: Fe::decode_from(r)?,
            protocol_version: r.u32()?,
            anchor_root: Fe::decode_from(r)?,
            anchor_commitment_count: r.u64()?,
            anchor_batch_number: r.u64()?,
            nullifiers: [Fe::decode_from(r)?, Fe::decode_from(r)?],
            output_commitments: [Fe::decode_from(r)?, Fe::decode_from(r)?],
            deposit_sats: r.amount()?,
            withdrawal_sats: r.amount()?,
            fee_sats: r.amount()?,
            external_data_commitment: r.array()?,
            expiry_batch_number: r.u64()?,
        })
    }
}

pub const MAX_RECEIPT_BYTES: usize = 1 << 20;

/// A user transaction as submitted to the mempool: statement, external data and the user's
/// zero-knowledge RISC Zero receipt of the `joinsplit` guest on that statement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollupTransaction {
    pub public: JoinSplitPublic,
    pub external: ExternalData,
    /// `postcard(SuccinctReceipt<ReceiptClaim>)` produced by `joinsplit prove` (`identity_zk` seal).
    pub receipt: Vec<u8>,
    /// The tapscript leaf behind each withdrawal output, in order (see `WITHDRAWAL_LEAF_PREFIX`).
    pub withdrawal_leaves: Vec<Vec<u8>>,
}

impl Canonical for RollupTransaction {
    fn encode_to(&self, w: &mut Writer) {
        self.public.encode_to(w);
        self.external.encode_to(w);
        w.var_bytes(&self.receipt);
        w.u8(self.withdrawal_leaves.len() as u8);
        for l in &self.withdrawal_leaves {
            w.var_bytes(l);
        }
    }
    fn decode_from(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(RollupTransaction {
            public: JoinSplitPublic::decode_from(r)?,
            external: ExternalData::decode_from(r)?,
            receipt: r.var_bytes(MAX_RECEIPT_BYTES)?.to_vec(),
            withdrawal_leaves: {
                let n = r.u8()? as usize;
                if n > MAX_WITHDRAWALS_PER_TX {
                    return Err(DecodeError::LengthOutOfRange);
                }
                (0..n).map(|_| r.var_bytes(MAX_WITHDRAWAL_LEAF_LEN).map(<[u8]>::to_vec)).collect::<Result<_, _>>()?
            },
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteOutput {
    pub commitment: Fe,
    pub ciphertext: Vec<u8>,
}

/// Settlement layout counts; inputs are `[rollup, funding.., escrows..]` and outputs are
/// `[rollup, withdrawals.., changes.., reward?]`. Each escrow input mints one note. No other inputs or
/// outputs are admitted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementLayout {
    pub transactions: u8,
    pub funding_inputs: u8,
    pub withdrawals: u8,
    pub changes: u8,
    pub reward: bool,
    pub escrows: u8,
}

impl SettlementLayout {
    pub fn input_count(&self) -> usize {
        1 + self.funding_inputs as usize + self.escrows as usize
    }
    /// Rollup output, state-root `OP_RETURN`, then withdrawals and changes.
    pub fn output_count(&self) -> usize {
        2 + self.withdrawals as usize + self.changes as usize + self.reward as usize
    }
}

/// Public batch data published in the input-zero annex. Nullifiers and outputs are globally sorted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchBody {
    pub rollup_id: Fe,
    pub batch_number: u64,
    pub predecessor: Outpoint,
    pub layout: SettlementLayout,
    pub nullifiers: Vec<Fe>,
    pub outputs: Vec<NoteOutput>,
}

impl BatchBody {
    pub fn digest(&self) -> [u8; 32] {
        tagged(tags::BATCH_BODY, &[&self.encode()])
    }
}

impl Canonical for BatchBody {
    fn encode_to(&self, w: &mut Writer) {
        self.rollup_id.encode_to(w);
        w.u64(self.batch_number);
        self.predecessor.encode_to(w);
        let l = &self.layout;
        w.u8(l.transactions).u8(l.funding_inputs).u8(l.withdrawals).u8(l.changes).u8(l.reward as u8).u8(l.escrows);
        for n in &self.nullifiers {
            n.encode_to(w);
        }
        for o in &self.outputs {
            o.commitment.encode_to(w);
            encode_ciphertext(w, &o.ciphertext);
        }
    }
    fn decode_from(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let rollup_id = Fe::decode_from(r)?;
        let batch_number = r.u64()?;
        let predecessor = Outpoint::decode_from(r)?;
        let layout = SettlementLayout {
            transactions: r.u8()?,
            funding_inputs: r.u8()?,
            withdrawals: r.u8()?,
            changes: r.u8()?,
            reward: r.bool()?,
            escrows: r.u8()?,
        };
        let n = layout.transactions as usize;
        if n > MAX_BATCH_TRANSACTIONS
            || layout.funding_inputs as usize > n * MAX_FUNDING_INPUTS
            || layout.withdrawals as usize > n * MAX_WITHDRAWALS_PER_TX
            || layout.changes as usize > n
            || layout.escrows as usize > MAX_BATCH_ESCROWS
        {
            return Err(DecodeError::LengthOutOfRange);
        }
        let mut nullifiers: Vec<Fe> = Vec::with_capacity(2 * n);
        for _ in 0..2 * n {
            let f = Fe::decode_from(r)?;
            if f.is_zero() || nullifiers.last().is_some_and(|p| *p >= f) {
                return Err(DecodeError::BadOrder);
            }
            nullifiers.push(f);
        }
        let notes = 2 * n + layout.escrows as usize;
        let mut outputs: Vec<NoteOutput> = Vec::with_capacity(notes);
        for _ in 0..notes {
            let commitment = Fe::decode_from(r)?;
            if outputs.last().is_some_and(|p| p.commitment >= commitment) {
                return Err(DecodeError::BadOrder);
            }
            outputs.push(NoteOutput { commitment, ciphertext: decode_ciphertext(r)? });
        }
        Ok(BatchBody { rollup_id, batch_number, predecessor, layout, nullifiers, outputs })
    }
}

/// The input-zero annex: `0x50 || 0x00 || "GSRP" || version || old_state_root || new_state_root || body`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Annex {
    pub old_state_root: [u8; 32],
    pub new_state_root: [u8; 32],
    pub body: BatchBody,
}

impl Canonical for Annex {
    fn encode_to(&self, w: &mut Writer) {
        w.u8(ANNEX_TAG).u8(ANNEX_UNSTRUCTURED).bytes(&ANNEX_MAGIC).u8(ANNEX_ENCODING_VERSION);
        w.bytes(&self.old_state_root).bytes(&self.new_state_root);
        self.body.encode_to(w);
    }
    fn decode_from(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        if r.u8()? != ANNEX_TAG
            || r.u8()? != ANNEX_UNSTRUCTURED
            || r.array::<4>()? != ANNEX_MAGIC
            || r.u8()? != ANNEX_ENCODING_VERSION
        {
            return Err(DecodeError::BadMagic);
        }
        Ok(Annex { old_state_root: r.array()?, new_state_root: r.array()?, body: BatchBody::decode_from(r)? })
    }
}

/// The RISC Zero journal of `apply-batch`; the covenant rebuilds exactly these 196 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchJournal {
    pub protocol_version: u32,
    pub rollup_id: Fe,
    pub old_state_root: [u8; 32],
    pub new_state_root: [u8; 32],
    pub transaction_inputs_digest: [u8; 32],
    pub transaction_outputs_digest: [u8; 32],
    pub annex_digest: [u8; 32],
}

impl BatchJournal {
    pub const LEN: usize = 4 + 6 * 32;
}

impl Canonical for BatchJournal {
    fn encode_to(&self, w: &mut Writer) {
        w.u32(self.protocol_version);
        self.rollup_id.encode_to(w);
        w.bytes(&self.old_state_root)
            .bytes(&self.new_state_root)
            .bytes(&self.transaction_inputs_digest)
            .bytes(&self.transaction_outputs_digest)
            .bytes(&self.annex_digest);
    }
    fn decode_from(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(BatchJournal {
            protocol_version: r.u32()?,
            rollup_id: Fe::decode_from(r)?,
            old_state_root: r.array()?,
            new_state_root: r.array()?,
            transaction_inputs_digest: r.array()?,
            transaction_outputs_digest: r.array()?,
            annex_digest: r.array()?,
        })
    }
}

pub fn next_data_history(old: &[u8; 32], batch_number: u64, body_digest: &[u8; 32]) -> [u8; 32] {
    tagged(tags::DATA_HISTORY, &[old, &batch_number.to_le_bytes(), body_digest])
}
