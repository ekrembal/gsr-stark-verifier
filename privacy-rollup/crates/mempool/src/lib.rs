//! Operator mempool and batch assembly.
//!
//! The mempool admits a rollup transaction only if its proof verifies, it passes every per-transaction
//! rule of the next batch against the current tip, and none of its nullifiers, output commitments or
//! funding outpoints is already spent (nullifiers) or reserved by another pending transaction. Batch
//! selection is greedy by fee, bounded by `MAX_BATCH_TRANSACTIONS` and a weight budget, and the selection always passes the
//! full transition: the operator never builds a batch the guest would reject.
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use pr_bitcoin_adapter::{SettlementTx, TxInput};
use pr_protocol_types::{
    Canonical, Fe, Outpoint, RollupTransaction, TxOut, EMPTY_SETTLEMENT_WEIGHT, ESCROW_INPUT_SEQUENCE,
    FUNDING_INPUT_SEQUENCE, MAX_BATCH_TRANSACTIONS, MAX_SETTLEMENT_WEIGHT, ROLLUP_INPUT_SEQUENCE, TX_VERSION,
};
use pr_protocol_types::state_root_script;
use pr_scanner::Replica;
use pr_state_transition::escrow::EscrowDeposit;
use pr_state_transition::{check_transaction, BatchTransaction, TransitionError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MempoolError {
    Proof,
    Rule(TransitionError),
    NullifierSpent,
    NullifierReserved,
    CommitmentReserved,
    FundingReserved,
    DuplicateInTransaction,
}

/// A spent output that funds a deposit, as the settlement must reproduce it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FundingCoin {
    pub outpoint: Outpoint,
    pub amount: u64,
    pub script_pubkey: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub tx: RollupTransaction,
    pub funding: Vec<FundingCoin>,
    pub arrival: u64,
}

#[derive(Default, Debug)]
pub struct Mempool {
    pub entries: Vec<Entry>,
    arrivals: u64,
}

fn keys(tx: &RollupTransaction) -> (Vec<Fe>, Vec<Fe>, Vec<Outpoint>) {
    let funding = tx.external.deposit.iter().flat_map(|d| d.funding.clone()).collect();
    (tx.public.nullifiers.to_vec(), tx.public.output_commitments.to_vec(), funding)
}

impl Mempool {
    pub fn new() -> Mempool {
        Mempool::default()
    }

    /// Reloads entries admitted earlier (their proofs were verified on admission), keeping arrival
    /// order and only those that are still admissible against `replica`'s tip.
    pub fn restore(entries: Vec<Entry>, replica: &Replica) -> Mempool {
        let arrivals = entries.iter().map(|e| e.arrival).max().unwrap_or(0);
        let mut m = Mempool { entries: Vec::new(), arrivals };
        for e in entries {
            if m.admissible(&e.tx, replica).is_ok() {
                m.entries.push(e);
            }
        }
        m
    }

    fn reserved(&self) -> (BTreeSet<Fe>, BTreeSet<Fe>, BTreeSet<Outpoint>) {
        let (mut n, mut c, mut f) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
        for e in &self.entries {
            let (a, b, o) = keys(&e.tx);
            n.extend(a);
            c.extend(b);
            f.extend(o);
        }
        (n, c, f)
    }

    fn admissible(&self, tx: &RollupTransaction, replica: &Replica) -> Result<(), MempoolError> {
        let tip = replica.tip();
        let bt = BatchTransaction {
            public: tx.public,
            external: tx.external.clone(),
            withdrawal_leaves: tx.withdrawal_leaves.clone(),
        };
        check_transaction(&tip.state, tip.anchors.find(tx.public.anchor_batch_number), tip.state.batch_number + 1, &bt)
            .map_err(MempoolError::Rule)?;
        let (nfs, cms, funding) = keys(tx);
        if nfs[0] == nfs[1] || cms[0] == cms[1] || funding.iter().collect::<BTreeSet<_>>().len() != funding.len() {
            return Err(MempoolError::DuplicateInTransaction);
        }
        if nfs.iter().any(|n| replica.spent(n)) {
            return Err(MempoolError::NullifierSpent);
        }
        let (rn, rc, rf) = self.reserved();
        if nfs.iter().any(|n| rn.contains(n)) {
            return Err(MempoolError::NullifierReserved);
        }
        if cms.iter().any(|c| rc.contains(c)) {
            return Err(MempoolError::CommitmentReserved);
        }
        if funding.iter().any(|o| rf.contains(o)) {
            return Err(MempoolError::FundingReserved);
        }
        Ok(())
    }

    /// Admits `tx` after `verify` (the ProveKit verifier) accepts its proof. `funding` lists the spent
    /// outputs of its deposit's funding outpoints, in order.
    pub fn submit(
        &mut self,
        tx: RollupTransaction,
        funding: Vec<FundingCoin>,
        replica: &Replica,
        verify: impl Fn(&RollupTransaction) -> bool,
    ) -> Result<(), MempoolError> {
        let declared: Vec<Outpoint> = tx.external.deposit.iter().flat_map(|d| d.funding.clone()).collect();
        if declared != funding.iter().map(|f| f.outpoint).collect::<Vec<_>>() {
            return Err(MempoolError::Rule(TransitionError::FundingInput));
        }
        self.admissible(&tx, replica)?;
        if !verify(&tx) {
            return Err(MempoolError::Proof);
        }
        self.arrivals += 1;
        self.entries.push(Entry { tx, funding, arrival: self.arrivals });
        Ok(())
    }

    /// Drops entries the new tip invalidates (spent nullifiers, expiry, anchors no longer in the history).
    /// Called after every accepted settlement and after a rollback.
    pub fn revalidate(&mut self, replica: &Replica) {
        let entries = std::mem::take(&mut self.entries);
        for e in entries {
            if self.admissible(&e.tx, replica).is_ok() {
                self.entries.push(e);
            }
        }
    }

    /// Highest fee first, ties by arrival; at most `MAX_BATCH_TRANSACTIONS`.
    pub fn select(&self) -> Vec<Entry> {
        self.select_within(MAX_SETTLEMENT_WEIGHT - EMPTY_SETTLEMENT_WEIGHT)
    }

    /// Greedy by fee: at most `MAX_BATCH_TRANSACTIONS` entries whose [`entry_weight`]s fit `budget`.
    pub fn select_within(&self, budget: u64) -> Vec<Entry> {
        let mut v = self.entries.clone();
        v.sort_by(|a, b| b.tx.public.fee_sats.cmp(&a.tx.public.fee_sats).then(a.arrival.cmp(&b.arrival)));
        let mut left = budget;
        v.retain(|e| {
            let w = entry_weight(e);
            let keep = w <= left;
            if keep {
                left -= w;
            }
            keep
        });
        v.truncate(MAX_BATCH_TRANSACTIONS);
        v
    }

    pub fn remove_settled(&mut self, settled: &[Entry]) {
        self.entries.retain(|e| !settled.iter().any(|s| s.arrival == e.arrival));
    }
}

/// Base weight of one funding input (outpoint, empty script, sequence) plus a witness allowance.
pub const FUNDING_INPUT_WEIGHT: u64 = 4 * 41 + 256;

fn output_weight(o: &TxOut) -> u64 {
    4 * (8 + 1 + o.script_pubkey.len() as u64)
}

/// Upper bound on the weight a transaction adds to a settlement: its statement and external data
/// in the annex (1 WU/B), its withdrawal outputs, and its funding inputs.
pub fn entry_weight(e: &Entry) -> u64 {
    let x = &e.tx.external;
    let annex = (e.tx.public.encode().len() + x.encode().len()) as u64;
    annex + x.withdrawals.iter().map(output_weight).sum::<u64>() + e.funding.len() as u64 * FUNDING_INPUT_WEIGHT
}

/// Upper bound on the weight an escrow sweep adds: its input, its sweep witness (leaf, control
/// block) and its opening in the annex.
pub fn escrow_weight(c: &EscrowCoin) -> u64 {
    let o = &c.opening;
    4 * 41 + 8 + o.sweep_leaf.len() as u64 + 65 + 32 * 3 + 16 + 1 + o.ciphertext.len() as u64
}

/// The settlement transaction for `selected` on top of `replica`'s tip: inputs `[rollup, funding..]`,
/// outputs `[rollup', OP_RETURN root, withdrawals..]`, version 2, locktime 0, rollup sequence 1. All batch fees go
/// to the miner. The rollup output pays `rollup_script_pubkey` again; output 1 holds a placeholder root, which the
/// replica's `witness` replaces with the batch's new root.
pub fn assemble_settlement(
    replica: &Replica,
    rollup_script_pubkey: Vec<u8>,
    selected: &[Entry],
) -> Option<SettlementTx> {
    assemble_settlement_with_escrows(replica, rollup_script_pubkey, selected, &[])
}

/// A confirmed escrow output and its private opening.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscrowCoin {
    pub outpoint: Outpoint,
    pub amount: u64,
    pub script_pubkey: Vec<u8>,
    pub opening: EscrowDeposit,
}

/// [`assemble_settlement`] that also sweeps `escrows` (inputs after the funding inputs); each adds its
/// note value to the rollup backing and its fee to the batch fee pool.
pub fn assemble_settlement_with_escrows(
    replica: &Replica,
    rollup_script_pubkey: Vec<u8>,
    selected: &[Entry],
    escrows: &[EscrowCoin],
) -> Option<SettlementTx> {
    let tip = replica.tip();
    let mut inputs = vec![TxInput {
        prevout: tip.utxo,
        amount: tip.state.backing_sats,
        script_pubkey: rollup_script_pubkey.clone(),
        script_sig: Vec::new(),
        sequence: ROLLUP_INPUT_SEQUENCE,
    }];
    for f in selected.iter().flat_map(|e| &e.funding) {
        inputs.push(TxInput {
            prevout: f.outpoint,
            amount: f.amount,
            script_pubkey: f.script_pubkey.clone(),
            script_sig: Vec::new(),
            sequence: FUNDING_INPUT_SEQUENCE,
        });
    }
    for c in escrows {
        inputs.push(TxInput {
            prevout: c.outpoint,
            amount: c.amount,
            script_pubkey: c.script_pubkey.clone(),
            script_sig: Vec::new(),
            sequence: ESCROW_INPUT_SEQUENCE,
        });
    }
    let p = |e: &Entry| e.tx.public;
    let minted: u128 = escrows.iter().map(|c| c.opening.value as u128).sum();
    let backing =
        (tip.state.backing_sats as u128 + minted + selected.iter().map(|e| p(e).deposit_sats as u128).sum::<u128>())
            .checked_sub(selected.iter().map(|e| p(e).withdrawal_sats as u128 + p(e).fee_sats as u128).sum())?;
    let mut outputs = vec![
        TxOut { value: u64::try_from(backing).ok()?, script_pubkey: rollup_script_pubkey },
        TxOut { value: 0, script_pubkey: state_root_script(&[0; 32]) },
    ];
    outputs.extend(selected.iter().flat_map(|e| e.tx.external.withdrawals.iter().cloned()));
    Some(SettlementTx { version: TX_VERSION, lock_time: 0, inputs, outputs })
}

/// The batch transactions of a selection, in settlement order.
pub fn batch_transactions(selected: &[Entry]) -> Vec<BatchTransaction> {
    selected
        .iter()
        .map(|e| BatchTransaction {
            public: e.tx.public,
            external: e.tx.external.clone(),
            withdrawal_leaves: e.tx.withdrawal_leaves.clone(),
        })
        .collect()
}
