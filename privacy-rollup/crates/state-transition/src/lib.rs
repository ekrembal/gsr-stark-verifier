//! The batch state transition: the single function the `apply-batch` guest runs (after verifying
//! every join-split proof) and the operator, scanner and tests run natively.
//!
//! [`apply_batch`] takes the authenticated old state, the private witnesses needed to update it
//! (anchor window, commitment frontier, nullifier insertion paths) and the settlement transaction,
//! checks every protocol rule that is not inside a join-split proof, and returns the new state, the
//! canonical annex and the 196-byte [`BatchJournal`] the covenant rebuilds from `OP_TX`.
use pr_bitcoin_adapter::SettlementTx;
use pr_commitment_tree::Frontier;
use pr_indexed_nullifier_tree::{verify_insertion, InsertionWitness, NullifierError};
use pr_protocol_types::hash::sha256;
use pr_protocol_types::{
    next_data_history, AnchorEntry, AnchorHistory, Annex, BatchBody, BatchJournal, Canonical, ExternalData, Fe,
    JoinSplitPublic, NoteOutput, Outpoint, RollupDescriptor, RollupState, SettlementLayout, TxOut, ANCHOR_WINDOW,
    DUST_LIMIT, MAX_BATCH_TRANSACTIONS, MAX_FUNDING_INPUTS, MAX_MONEY, MAX_SCRIPT_PUBKEY_LEN, NOTE_CIPHERTEXT_LEN,
    PROTOCOL_VERSION, ROLLUP_INPUT_SEQUENCE, TX_VERSION,
};
use serde::{Deserialize, Serialize};

/// One join-split as seen by the transition: its statement and the public data it commits to. The
/// proof itself is checked separately (in the guest, before this function runs).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchTransaction {
    pub public: JoinSplitPublic,
    pub external: ExternalData,
}

/// Everything the transition needs besides proofs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchWitness {
    pub old_state: RollupState,
    pub anchors: AnchorHistory,
    /// Canonical frontier of the old commitment tree; required iff the batch appends commitments.
    pub frontier: Option<Frontier>,
    pub transactions: Vec<BatchTransaction>,
    /// One insertion witness per nullifier, in ascending nullifier order.
    pub nullifier_witnesses: Vec<InsertionWitness>,
    pub settlement: SettlementTx,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchEffects {
    pub new_state: RollupState,
    pub anchors: AnchorHistory,
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
    DuplicateNullifier,
    ZeroNullifier,
    NullifierWitnessCount,
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
        nullifier_root: pr_indexed_nullifier_tree::IndexedTree::new().root(),
        nullifier_next_index: 1,
        anchor_history_commitment: anchors.commitment(),
        data_history_commitment: [0; 32],
        backing_sats: descriptor.seed_sats,
    };
    (state, anchors, frontier)
}

/// Per-transaction rules that only need the old state and the anchor window (also run by mempools).
pub fn check_transaction(
    old: &RollupState,
    anchors: &AnchorHistory,
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
    match anchors.find(p.anchor_batch_number) {
        Some(e) if e.commitment_root == p.anchor_root && e.commitment_count == p.anchor_commitment_count => {}
        _ => return Err(TransitionError::UnknownAnchor),
    }
    if t.external.commitment() != p.external_data_commitment {
        return Err(TransitionError::ExternalDataMismatch);
    }
    if t.external.ciphertexts.iter().any(|c| c.len() != NOTE_CIPHERTEXT_LEN) {
        return Err(TransitionError::BadCiphertext);
    }
    match &t.external.deposit {
        None if p.deposit_sats == 0 => {}
        Some(d) if p.deposit_sats > 0 && !d.funding.is_empty() && d.funding.len() <= MAX_FUNDING_INPUTS => {
            if let Some(c) = &d.change {
                if c.value < DUST_LIMIT || c.script_pubkey.len() > MAX_SCRIPT_PUBKEY_LEN {
                    return Err(TransitionError::Dust);
                }
            }
        }
        _ => return Err(TransitionError::DepositMismatch),
    }
    match &t.external.withdrawal_script {
        None if p.withdrawal_sats == 0 => {}
        Some(s) if p.withdrawal_sats > 0 && s.len() <= MAX_SCRIPT_PUBKEY_LEN => {
            if p.withdrawal_sats < DUST_LIMIT {
                return Err(TransitionError::Dust);
            }
        }
        _ => return Err(TransitionError::WithdrawalMismatch),
    }
    if p.nullifiers.iter().any(Fe::is_zero) {
        return Err(TransitionError::ZeroNullifier);
    }
    Ok(())
}

/// Applies one batch. Proof verification is the caller's job; everything else is checked here.
pub fn apply_batch(w: &BatchWitness) -> Result<BatchEffects, TransitionError> {
    let old = &w.old_state;
    if old.protocol_version != PROTOCOL_VERSION {
        return Err(TransitionError::UnsupportedVersion);
    }
    if w.anchors.0.is_empty()
        || w.anchors.0.len() > ANCHOR_WINDOW
        || w.anchors.commitment() != old.anchor_history_commitment
    {
        return Err(TransitionError::AnchorHistoryMismatch);
    }
    let txs = &w.transactions;
    if txs.len() > MAX_BATCH_TRANSACTIONS {
        return Err(TransitionError::TooManyTransactions);
    }
    let next = old.batch_number.checked_add(1).ok_or(TransitionError::Overflow)?;
    for t in txs {
        check_transaction(old, &w.anchors, next, t)?;
    }

    // Nullifiers: globally sorted, distinct, each inserted with an authenticated witness.
    let mut nullifiers: Vec<Fe> = txs.iter().flat_map(|t| t.public.nullifiers).collect();
    nullifiers.sort();
    if nullifiers.windows(2).any(|p| p[0] == p[1]) {
        return Err(TransitionError::DuplicateNullifier);
    }
    if w.nullifier_witnesses.len() != nullifiers.len() {
        return Err(TransitionError::NullifierWitnessCount);
    }
    let mut nullifier_root = old.nullifier_root;
    let mut nullifier_next_index = old.nullifier_next_index;
    for (nf, iw) in nullifiers.iter().zip(&w.nullifier_witnesses) {
        nullifier_root =
            verify_insertion(&nullifier_root, nullifier_next_index, nf, iw).map_err(TransitionError::Nullifier)?;
        nullifier_next_index += 1;
    }

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
    outputs.sort_by_key(|a| a.commitment);
    if outputs.windows(2).any(|p| p[0].commitment == p[1].commitment) {
        return Err(TransitionError::DuplicateCommitment);
    }
    let frontier = if outputs.is_empty() {
        None
    } else {
        let mut f = w.frontier.clone().ok_or(TransitionError::FrontierMissing)?;
        f.authenticate(&old.commitment_root, old.commitment_count).map_err(|_| TransitionError::Frontier)?;
        for o in &outputs {
            f.append(o.commitment).map_err(|_| TransitionError::Frontier)?;
        }
        Some(f)
    };
    let (commitment_root, commitment_count) = match &frontier {
        Some(f) => (f.root(), f.count),
        None => (old.commitment_root, old.commitment_count),
    };

    // Bitcoin layout: inputs [rollup, funding..], outputs [rollup, withdrawals.., changes.., reward?].
    let s = &w.settlement;
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
    if s.inputs.len() != 1 + funding.len() {
        return Err(TransitionError::InputCount);
    }
    let rollup_in = &s.inputs[0];
    if rollup_in.sequence != ROLLUP_INPUT_SEQUENCE || !rollup_in.script_sig.is_empty() {
        return Err(TransitionError::PredecessorSequence);
    }
    if rollup_in.amount != old.backing_sats {
        return Err(TransitionError::PredecessorAmount);
    }
    let mut funded = vec![0u64; txs.len()];
    for ((i, o), input) in funding.iter().zip(&s.inputs[1..]) {
        if input.prevout != **o {
            return Err(TransitionError::FundingInput);
        }
        funded[*i] = add(funded[*i], input.amount)?;
    }
    let mut deposits = 0u64;
    let mut withdrawals_total = 0u64;
    let mut fees = 0u64;
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
        if let Some(script) = &t.external.withdrawal_script {
            withdrawal_outs.push(TxOut { value: p.withdrawal_sats, script_pubkey: script.clone() });
        }
    }
    let gross_in = add(old.backing_sats, deposits)?;
    let gross_out = add(withdrawals_total, fees)?;
    let backing_sats = gross_in.checked_sub(gross_out).ok_or(TransitionError::Overflow)?;
    if backing_sats < DUST_LIMIT {
        return Err(TransitionError::Dust);
    }

    let fixed = 1 + withdrawal_outs.len() + change_outs.len();
    if s.outputs.len() != fixed && s.outputs.len() != fixed + 1 {
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
    // F = R + M: the optional reward output takes R, the miner keeps M = F - R >= 0.
    let reward = s.outputs.get(fixed).map_or(0, |o| o.value);
    if s.outputs.get(fixed).is_some_and(|o| o.value < DUST_LIMIT || o.script_pubkey.len() > MAX_SCRIPT_PUBKEY_LEN) {
        return Err(TransitionError::Dust);
    }
    let miner_fee = fees.checked_sub(reward).ok_or(TransitionError::FeeShortfall)?;
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
        reward: s.outputs.len() == fixed + 1,
    };
    let body = BatchBody {
        rollup_id: old.rollup_id,
        batch_number: next,
        predecessor: rollup_in.prevout,
        layout,
        nullifiers,
        outputs,
    };
    let mut anchors = w.anchors.clone();
    anchors.push(AnchorEntry { batch_number: next, commitment_root, commitment_count });
    let new_state = RollupState {
        rollup_id: old.rollup_id,
        protocol_version: old.protocol_version,
        batch_number: next,
        commitment_root,
        commitment_count,
        nullifier_root,
        nullifier_next_index,
        anchor_history_commitment: anchors.commitment(),
        data_history_commitment: next_data_history(&old.data_history_commitment, next, &body.digest()),
        backing_sats,
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
    Ok(BatchEffects { new_state, anchors, frontier, annex, annex_bytes, journal })
}
