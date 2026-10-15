//! Operator mempool and batch assembly.
//!
//! The mempool admits a rollup transaction only if its proof verifies, it passes every per-transaction
//! rule of the next batch against the current tip, and none of its nullifiers, output commitments or
//! funding outpoints is already spent (nullifiers) or reserved by another pending transaction. Batch
//! selection is greedy by fee, bounded by `MAX_BATCH_TRANSACTIONS`, and the selection always passes the
//! full transition: the operator never builds a batch the guest would reject.
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use pr_bitcoin_adapter::{SettlementTx, TxInput};
use pr_protocol_types::{
    Fe, Outpoint, RollupTransaction, TxOut, MAX_BATCH_TRANSACTIONS, ROLLUP_INPUT_SEQUENCE, TX_VERSION,
};
use pr_scanner::Replica;
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
        let bt = BatchTransaction { public: tx.public, external: tx.external.clone() };
        check_transaction(&tip.state, &tip.anchors, tip.state.batch_number + 1, &bt).map_err(MempoolError::Rule)?;
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

    /// Drops entries the new tip invalidates (spent nullifiers, expiry, anchors outside the window).
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
        let mut v = self.entries.clone();
        v.sort_by(|a, b| b.tx.public.fee_sats.cmp(&a.tx.public.fee_sats).then(a.arrival.cmp(&b.arrival)));
        v.truncate(MAX_BATCH_TRANSACTIONS);
        v
    }

    pub fn remove_settled(&mut self, settled: &[Entry]) {
        self.entries.retain(|e| !settled.iter().any(|s| s.arrival == e.arrival));
    }
}

/// The settlement transaction for `selected` on top of `replica`'s tip: inputs `[rollup, funding..]`,
/// outputs `[rollup', withdrawals.., changes.., reward?]`, version 2, locktime 0, rollup sequence 1.
/// The operator keeps `reward` of the batch fees as prover reward; the rest is the miner fee.
pub fn assemble_settlement(
    replica: &Replica,
    rollup_script_pubkey: Vec<u8>,
    successor_script_pubkey: Vec<u8>,
    selected: &[Entry],
    reward: Option<TxOut>,
) -> Option<SettlementTx> {
    let tip = replica.tip();
    let mut inputs = vec![TxInput {
        prevout: tip.utxo,
        amount: tip.state.backing_sats,
        script_pubkey: rollup_script_pubkey,
        script_sig: Vec::new(),
        sequence: ROLLUP_INPUT_SEQUENCE,
    }];
    for f in selected.iter().flat_map(|e| &e.funding) {
        inputs.push(TxInput {
            prevout: f.outpoint,
            amount: f.amount,
            script_pubkey: f.script_pubkey.clone(),
            script_sig: Vec::new(),
            sequence: 0xffff_ffff,
        });
    }
    let p = |e: &Entry| e.tx.public;
    let backing = (tip.state.backing_sats as u128 + selected.iter().map(|e| p(e).deposit_sats as u128).sum::<u128>())
        .checked_sub(selected.iter().map(|e| p(e).withdrawal_sats as u128 + p(e).fee_sats as u128).sum())?;
    let mut outputs = vec![TxOut { value: u64::try_from(backing).ok()?, script_pubkey: successor_script_pubkey }];
    for e in selected {
        if let Some(s) = &e.tx.external.withdrawal_script {
            outputs.push(TxOut { value: e.tx.public.withdrawal_sats, script_pubkey: s.clone() });
        }
    }
    outputs.extend(selected.iter().filter_map(|e| e.tx.external.deposit.as_ref().and_then(|d| d.change.clone())));
    outputs.extend(reward);
    Some(SettlementTx { version: TX_VERSION, lock_time: 0, inputs, outputs })
}

/// The batch transactions of a selection, in settlement order.
pub fn batch_transactions(selected: &[Entry]) -> Vec<BatchTransaction> {
    selected.iter().map(|e| BatchTransaction { public: e.tx.public, external: e.tx.external.clone() }).collect()
}
