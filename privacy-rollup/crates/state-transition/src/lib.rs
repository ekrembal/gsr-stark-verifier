//! The batch state transition: the single function the `apply-batch` guest runs (after verifying
//! every join-split proof) and the operator, scanner and tests run natively.
//!
//! [`apply_batch`] takes the authenticated old state, the private witnesses needed to update it
//! (anchor window, commitment frontier, nullifier insertion paths) and the settlement transaction,
//! checks every protocol rule that is not inside a join-split proof, and returns the new state, the
//! canonical annex and the 196-byte [`BatchJournal`] the covenant rebuilds from `OP_TX`.
pub mod escrow;

use pr_bitcoin_adapter::{PlainTx, SettlementTx};
use pr_commitment_tree::Frontier;
use pr_indexed_nullifier_tree::{verify_batch_insertion, BatchInsertionWitness, NullifierError};
use pr_protocol_types::hash::sha256;
use pr_protocol_types::{
    anchor_leaf, anchor_root_from_path, ciphertext_kind, next_data_history, AnchorEntry, AnchorHistory, AnchorProof,
    Annex, BatchBody, BatchJournal, Canonical, ExternalData, Fe, JoinSplitPublic, NoteOutput, Outpoint,
    RollupDescriptor, RollupState, SettlementLayout, TxOut, DUST_LIMIT, ESCROW_INPUT_SEQUENCE, FUNDING_INPUT_SEQUENCE,
    MAX_BATCH_ESCROWS, MAX_BATCH_TRANSACTIONS, MAX_FUNDING_INPUTS, MAX_MONEY, MAX_SCRIPT_PUBKEY_LEN,
    MAX_WITHDRAWALS_PER_TX, MAX_WITHDRAWAL_LEAF_LEN, PROTOCOL_VERSION, ROLLUP_INPUT_SEQUENCE, TX_VERSION,
    WITHDRAWAL_LEAF_PREFIX, WITHDRAWAL_LEAF_VERSION,
};
use serde::{Deserialize, Serialize};

/// One join-split as seen by the transition: its statement and the public data it commits to. The
/// proof itself is checked separately (in the guest, before this function runs).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchTransaction {
    pub public: JoinSplitPublic,
    pub external: ExternalData,
    /// The leaf behind each withdrawal output, in order.
    pub withdrawal_leaves: Vec<Vec<u8>>,
}

/// Everything the transition needs besides proofs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchWitness {
    pub old_state: RollupState,
    /// Siblings of the next (empty) anchor slot, leaf `old_state.batch_number + 1`.
    pub anchor_slot: Vec<[u8; 32]>,
    /// Membership of each transaction's anchor, in transaction order.
    pub anchor_proofs: Vec<AnchorProof>,
    /// Canonical frontier of the old commitment tree; required iff the batch appends commitments.
    pub frontier: Option<Frontier>,
    pub transactions: Vec<BatchTransaction>,
    /// Insertion witness for the batch's nullifiers, inserted together in ascending order.
    pub nullifier_witness: BatchInsertionWitness,
    pub settlement: SettlementTx,
    /// The transaction that created the rollup coin spent by input 0 (the previous settlement, or
    /// the genesis transaction), without witnesses. Its txid must be input 0's prevout txid.
    pub predecessor_tx: PlainTx,
    /// Openings of the escrow inputs, which follow the funding inputs in order.
    pub escrows: Vec<escrow::EscrowDeposit>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchEffects {
    pub new_state: RollupState,
    /// The anchor this batch appends to the history.
    pub anchor: AnchorEntry,
    pub frontier: Option<Frontier>,
    pub annex: Annex,
    pub annex_bytes: Vec<u8>,
    pub journal: BatchJournal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransitionError {
    UnsupportedVersion,
    AnchorHistoryMismatch,
    TooManyTransactions,
    WrongRollup,
    Expired,
    UnknownAnchor,
    ExternalDataMismatch,
    BadCiphertext,
    DepositMismatch,
    WithdrawalMismatch,
    /// A withdrawal output is not `P2TR(NUMS, {leaf})` for its CSV-prefixed leaf.
    WithdrawalLock,
    DuplicateNullifier,
    ZeroNullifier,
    Nullifier(NullifierError),
    DuplicateCommitment,
    FrontierMissing,
    Frontier,
    TxVersion,
    TxLockTime,
    PredecessorSequence,
    PredecessorAmount,
    InputCount,
    FundingInput,
    FundingAmount,
    OutputCount,
    WithdrawalOutput,
    ChangeOutput,
    RolloverOutput,
    Dust,
    FeeShortfall,
    Overflow,
    /// The rollup input is not output 0 of a transaction whose input 0 spent `old_state.parent`.
    Lineage,
    /// An escrow input does not open to the declared deposit, or there are too many.
    Escrow,
}

fn add(a: u64, b: u64) -> Result<u64, TransitionError> {
    let s = a as u128 + b as u128;
    if s > MAX_MONEY as u128 {
        return Err(TransitionError::Overflow);
    }
    Ok(s as u64)
}

/// The state, anchor window and (empty) commitment frontier a descriptor starts from.
pub fn genesis(descriptor: &RollupDescriptor) -> (RollupState, AnchorHistory, Frontier) {
    let frontier = Frontier::default();
    let mut anchors = AnchorHistory::default();
    anchors.push(AnchorEntry { batch_number: 0, commitment_root: frontier.root(), commitment_count: 0 });
    let state = RollupState {
        rollup_id: descriptor.rollup_id(),
        protocol_version: descriptor.protocol_version,
        batch_number: 0,
        commitment_root: frontier.root(),
        commitment_count: 0,
        commitment_frontier: frontier.digest(),
        nullifier_root: pr_indexed_nullifier_tree::IndexedTree::new().root(),
        nullifier_next_index: 1,
        anchor_history_commitment: anchors.commitment(),
        data_history_commitment: [0; 32],
        backing_sats: descriptor.seed_sats,
        parent: descriptor.genesis_nonce,
    };
    (state, anchors, frontier)
}

/// Inductive lineage: the coin holding `old` is output 0 of `predecessor`, and `predecessor`'s input
/// 0 spent `old.parent`. `rollup_in`'s txid is committed by the journal's input digest, so the
/// private `predecessor` is bound to the transaction the covenant actually spends. By induction from
/// `genesis_nonce` (spendable once), every accepted coin descends from the genesis transaction;
/// a copy of the covenant script can never satisfy this.
pub fn check_lineage(old: &RollupState, rollup_in: &Outpoint, predecessor: &PlainTx) -> Result<(), TransitionError> {
    if rollup_in.vout != 0
        || predecessor.txid() != rollup_in.txid
        || predecessor.inputs.first().map(|i| i.prevout) != Some(old.parent)
    {
        return Err(TransitionError::Lineage);
    }
    Ok(())
}

/// Per-transaction rules that only need the old state and the transaction's authenticated anchor
/// (also run by mempools).
pub fn check_transaction(
    old: &RollupState,
    anchor: Option<&AnchorEntry>,
    next: u64,
    t: &BatchTransaction,
) -> Result<(), TransitionError> {
    let p = &t.public;
    if p.protocol_version != PROTOCOL_VERSION {
        return Err(TransitionError::UnsupportedVersion);
    }
    if p.rollup_id != old.rollup_id {
        return Err(TransitionError::WrongRollup);
    }
    if p.expiry_batch_number < next {
        return Err(TransitionError::Expired);
    }
    match anchor.filter(|e| e.batch_number == p.anchor_batch_number) {
        Some(e) if e.commitment_root == p.anchor_root && e.commitment_count == p.anchor_commitment_count => {}
        _ => return Err(TransitionError::UnknownAnchor),
    }
    if t.external.commitment() != p.external_data_commitment {
        return Err(TransitionError::ExternalDataMismatch);
    }
    if t.external.ciphertexts.iter().any(|c| ciphertext_kind(c).is_none()) {
        return Err(TransitionError::BadCiphertext);
    }
    match &t.external.deposit {
        None if p.deposit_sats == 0 => {}
        Some(d) if p.deposit_sats > 0 && !d.funding.is_empty() && d.funding.len() <= MAX_FUNDING_INPUTS => {
            if d.change.is_some() {
                return Err(TransitionError::ChangeOutput);
            }
        }
        _ => return Err(TransitionError::DepositMismatch),
    }
    let ws = &t.external.withdrawals;
    if ws.len() > MAX_WITHDRAWALS_PER_TX
        || ws.iter().any(|o| o.script_pubkey.len() > MAX_SCRIPT_PUBKEY_LEN)
        || ws.iter().try_fold(0u64, |a, o| a.checked_add(o.value)) != Some(p.withdrawal_sats)
    {
        return Err(TransitionError::WithdrawalMismatch);
    }
    if ws.iter().any(|o| o.value < DUST_LIMIT) {
        return Err(TransitionError::Dust);
    }
    if t.withdrawal_leaves.len() != ws.len()
        || ws
            .iter()
            .zip(&t.withdrawal_leaves)
            .any(|(o, l)| withdrawal_script_pubkey(l).as_ref() != Some(&o.script_pubkey))
    {
        return Err(TransitionError::WithdrawalLock);
    }
    if p.nullifiers.iter().any(Fe::is_zero) {
        return Err(TransitionError::ZeroNullifier);
    }
    Ok(())
}

/// `P2TR(NUMS, {leaf})` for a withdrawal leaf, if the leaf starts with [`WITHDRAWAL_LEAF_PREFIX`]: every spend
/// path then waits one confirmation, so a withdrawal output can't be spent while its settlement is unconfirmed.
pub fn withdrawal_script_pubkey(leaf: &[u8]) -> Option<Vec<u8>> {
    if !leaf.starts_with(&WITHDRAWAL_LEAF_PREFIX) || leaf.len() > MAX_WITHDRAWAL_LEAF_LEN {
        return None;
    }
    let key = escrow::output_key(&escrow::tapleaf_hash(WITHDRAWAL_LEAF_VERSION, leaf))?;
    Some([&[0x51, 0x20][..], &key].concat())
}

/// Applies one batch. Proof verification is the caller's job; everything else is checked here.
pub fn apply_batch(w: &BatchWitness) -> Result<BatchEffects, TransitionError> {
    let old = &w.old_state;
    if old.protocol_version != PROTOCOL_VERSION {
        return Err(TransitionError::UnsupportedVersion);
    }
    let txs = &w.transactions;
    if txs.len() > MAX_BATCH_TRANSACTIONS {
        return Err(TransitionError::TooManyTransactions);
    }
    let next = old.batch_number.checked_add(1).ok_or(TransitionError::Overflow)?;
    if anchor_root_from_path(&[0; 32], next, &w.anchor_slot) != Some(old.anchor_history_commitment)
        || w.anchor_proofs.len() != txs.len()
    {
        return Err(TransitionError::AnchorHistoryMismatch);
    }
    for (t, a) in txs.iter().zip(&w.anchor_proofs) {
        check_transaction(old, a.verify(&old.anchor_history_commitment), next, t)?;
    }

    // Nullifiers: globally sorted, distinct, each inserted with an authenticated witness.
    let mut nullifiers: Vec<Fe> = txs.iter().flat_map(|t| t.public.nullifiers).collect();
    nullifiers.sort();
    if nullifiers.windows(2).any(|p| p[0] == p[1]) {
        return Err(TransitionError::DuplicateNullifier);
    }
    let nullifier_root =
        verify_batch_insertion(&old.nullifier_root, old.nullifier_next_index, &nullifiers, &w.nullifier_witness)
            .map_err(TransitionError::Nullifier)?;
    let nullifier_next_index = old.nullifier_next_index + nullifiers.len() as u64;

    // Output notes: globally sorted by commitment, distinct, appended in that order.
    let mut outputs: Vec<NoteOutput> = txs
        .iter()
        .flat_map(|t| {
            (0..2).map(|j| NoteOutput {
                commitment: t.public.output_commitments[j],
                ciphertext: t.external.ciphertexts[j].clone(),
            })
        })
        .collect();
    let s = &w.settlement;
    let escrow_start = s.inputs.len().checked_sub(w.escrows.len()).ok_or(TransitionError::InputCount)?;
    if w.escrows.len() > MAX_BATCH_ESCROWS {
        return Err(TransitionError::Escrow);
    }
    let mut escrowed = 0u64;
    let mut escrow_fees = 0u64;
    for (e, input) in w.escrows.iter().zip(&s.inputs[escrow_start..]) {
        if ciphertext_kind(&e.ciphertext).is_none() {
            return Err(TransitionError::BadCiphertext);
        }
        if !input.script_sig.is_empty()
            || input.sequence != ESCROW_INPUT_SEQUENCE
            || !escrow::check_escrow(&old.rollup_id, e, &input.script_pubkey)
        {
            return Err(TransitionError::Escrow);
        }
        if e.value < DUST_LIMIT || e.value > MAX_MONEY {
            return Err(TransitionError::Dust);
        }
        if add(e.value, e.fee_sats)? != input.amount {
            return Err(TransitionError::Escrow);
        }
        escrowed = add(escrowed, input.amount)?;
        escrow_fees = add(escrow_fees, e.fee_sats)?;
        outputs.push(e.note(&old.rollup_id));
    }
    outputs.sort_by_key(|a| a.commitment);
    if outputs.windows(2).any(|p| p[0].commitment == p[1].commitment) {
        return Err(TransitionError::DuplicateCommitment);
    }
    let frontier = if outputs.is_empty() {
        None
    } else {
        let mut f = w.frontier.clone().ok_or(TransitionError::FrontierMissing)?;
        f.authenticate_digest(&old.commitment_frontier, old.commitment_count).map_err(|_| TransitionError::Frontier)?;
        for o in &outputs {
            f.append(o.commitment).map_err(|_| TransitionError::Frontier)?;
        }
        Some(f)
    };
    let (commitment_root, commitment_count, commitment_frontier) = match &frontier {
        Some(f) => (f.root(), f.count, f.digest()),
        None => (old.commitment_root, old.commitment_count, old.commitment_frontier),
    };

    // Bitcoin layout: inputs [rollup, funding.., escrows..], outputs [rollup, withdrawals..].
    if s.version != TX_VERSION {
        return Err(TransitionError::TxVersion);
    }
    if s.lock_time != 0 {
        return Err(TransitionError::TxLockTime);
    }
    let funding: Vec<(usize, &Outpoint)> = txs
        .iter()
        .enumerate()
        .flat_map(|(i, t)| t.external.deposit.iter().flat_map(move |d| d.funding.iter().map(move |o| (i, o))))
        .collect();
    if s.inputs.len() != 1 + funding.len() + w.escrows.len() {
        return Err(TransitionError::InputCount);
    }
    let rollup_in = &s.inputs[0];
    if rollup_in.sequence != ROLLUP_INPUT_SEQUENCE || !rollup_in.script_sig.is_empty() {
        return Err(TransitionError::PredecessorSequence);
    }
    if rollup_in.amount != old.backing_sats {
        return Err(TransitionError::PredecessorAmount);
    }
    check_lineage(old, &rollup_in.prevout, &w.predecessor_tx)?;
    let mut funded = vec![0u64; txs.len()];
    for ((i, o), input) in funding.iter().zip(&s.inputs[1..]) {
        if input.prevout != **o || input.sequence != FUNDING_INPUT_SEQUENCE {
            return Err(TransitionError::FundingInput);
        }
        funded[*i] = add(funded[*i], input.amount)?;
    }
    let mut deposits = escrowed;
    let mut withdrawals_total = 0u64;
    let mut fees = escrow_fees;
    let mut withdrawal_outs: Vec<TxOut> = Vec::new();
    let mut change_outs: Vec<TxOut> = Vec::new();
    for (i, t) in txs.iter().enumerate() {
        let p = &t.public;
        deposits = add(deposits, p.deposit_sats)?;
        withdrawals_total = add(withdrawals_total, p.withdrawal_sats)?;
        fees = add(fees, p.fee_sats)?;
        if let Some(d) = &t.external.deposit {
            let change = d.change.as_ref().map_or(0, |c| c.value);
            if funded[i] != add(p.deposit_sats, change)? {
                return Err(TransitionError::FundingAmount);
            }
            change_outs.extend(d.change.clone());
        }
        withdrawal_outs.extend(t.external.withdrawals.iter().cloned());
    }
    let gross_in = add(old.backing_sats, deposits)?;
    let gross_out = add(withdrawals_total, fees)?;
    let backing_sats = gross_in.checked_sub(gross_out).ok_or(TransitionError::Overflow)?;
    if backing_sats < DUST_LIMIT {
        return Err(TransitionError::Dust);
    }

    // No change and no reward output: besides the `1 CSV` successor, outputs are CSV-locked withdrawals.
    let fixed = 1 + withdrawal_outs.len() + change_outs.len();
    if s.outputs.len() != fixed {
        return Err(TransitionError::OutputCount);
    }
    if s.outputs[0].value != backing_sats {
        return Err(TransitionError::RolloverOutput);
    }
    if s.outputs[1..1 + withdrawal_outs.len()] != withdrawal_outs[..] {
        return Err(TransitionError::WithdrawalOutput);
    }
    if s.outputs[1 + withdrawal_outs.len()..fixed] != change_outs[..] {
        return Err(TransitionError::ChangeOutput);
    }
    // Every committed fee goes to the miner.
    let miner_fee = fees;
    let sum_in = s.inputs.iter().try_fold(0u64, |a, i| add(a, i.amount))?;
    let sum_out = s.outputs.iter().try_fold(0u64, |a, o| add(a, o.value))?;
    if sum_in.checked_sub(sum_out) != Some(miner_fee) {
        return Err(TransitionError::FeeShortfall);
    }

    let layout = SettlementLayout {
        transactions: txs.len() as u8,
        funding_inputs: funding.len() as u8,
        withdrawals: withdrawal_outs.len() as u8,
        changes: change_outs.len() as u8,
        reward: false,
        escrows: w.escrows.len() as u8,
    };
    let body = BatchBody {
        rollup_id: old.rollup_id,
        batch_number: next,
        predecessor: rollup_in.prevout,
        layout,
        nullifiers,
        outputs,
    };
    let anchor = AnchorEntry { batch_number: next, commitment_root, commitment_count };
    let anchor_history_commitment = anchor_root_from_path(&anchor_leaf(&anchor), next, &w.anchor_slot)
        .ok_or(TransitionError::AnchorHistoryMismatch)?;
    let new_state = RollupState {
        rollup_id: old.rollup_id,
        protocol_version: old.protocol_version,
        batch_number: next,
        commitment_root,
        commitment_count,
        commitment_frontier,
        nullifier_root,
        nullifier_next_index,
        anchor_history_commitment,
        data_history_commitment: next_data_history(&old.data_history_commitment, next, &body.digest()),
        backing_sats,
        parent: rollup_in.prevout,
    };
    let annex = Annex { old_state_root: old.root(), new_state_root: new_state.root(), body };
    let annex_bytes = annex.encode();
    let journal = BatchJournal {
        protocol_version: old.protocol_version,
        rollup_id: old.rollup_id,
        old_state_root: annex.old_state_root,
        new_state_root: annex.new_state_root,
        transaction_inputs_digest: s.inputs_digest(),
        transaction_outputs_digest: s.outputs_digest(),
        annex_digest: sha256(&annex_bytes),
    };
    Ok(BatchEffects { new_state, anchor, frontier, annex, annex_bytes, journal })
}

#[cfg(test)]
mod withdrawal_tests {
    use super::*;

    /// Known answer from Bitcoin Core's `taproot_construct(NUMS, [OP_1 OP_CSV OP_DROP <[9; 32]> OP_CHECKSIG])`.
    #[test]
    fn withdrawal_script_pubkey_matches_bitcoin_core() {
        let leaf = [&WITHDRAWAL_LEAF_PREFIX[..], &[0x20], &[9; 32], &[0xac]].concat();
        assert_eq!(
            hex::encode(withdrawal_script_pubkey(&leaf).unwrap()),
            "5120c7ee13e21d5552077e7a0b06cc6aec21f6aecf832afcb02867304aa7f5bdc017"
        );
        assert!(withdrawal_script_pubkey(&leaf[3..]).is_none());
        assert!(withdrawal_script_pubkey(&[&leaf[..], &[0; MAX_WITHDRAWAL_LEAF_LEN]].concat()).is_none());
    }
}
