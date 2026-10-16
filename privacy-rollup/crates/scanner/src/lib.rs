//! Full rollup replica: rebuilds every tree from genesis plus the annexes of the settlement chain,
//! checks each published state root, serves witnesses to the operator and paths to wallets, and
//! rolls back on reorgs.
use pr_bitcoin_adapter::{PlainTx, SettlementTx};
use pr_commitment_tree::Tree;
use pr_indexed_nullifier_tree::IndexedTree;
use pr_protocol_types::{
    next_data_history, AnchorEntry, AnchorHistory, Annex, Canonical, Fe, Outpoint, RollupDescriptor, RollupState,
    DUST_LIMIT,
};
use pr_state_transition::escrow::EscrowDeposit;
use pr_state_transition::{apply_batch, genesis, BatchEffects, BatchTransaction, BatchWitness, TransitionError};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScanError {
    BadAnnex,
    WrongRollup,
    WrongBatchNumber,
    WrongPredecessor,
    OldRootMismatch,
    NewRootMismatch,
    NullifierRejected,
    CommitmentRejected,
    Transition(TransitionError),
    NothingToRollBack,
    BadGenesis,
}

/// One accepted settlement as the replica remembers it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub state: RollupState,
    pub anchors: AnchorHistory,
    /// Outpoint of the rollup output holding `state`: output 0 of `creating_tx`.
    pub utxo: Outpoint,
    /// The genesis transaction or the settlement that created `utxo`, without witnesses.
    pub creating_tx: PlainTx,
}

#[derive(Clone, Debug)]
pub struct Replica {
    pub descriptor: RollupDescriptor,
    pub commitments: Tree,
    pub nullifiers: IndexedTree,
    /// `history[0]` is genesis; the last entry is the current state.
    pub history: Vec<Checkpoint>,
}

impl Replica {
    /// A replica at genesis. `genesis_tx` must spend `genesis_nonce` as input 0 and hold the rollup
    /// at output 0, otherwise no settlement can ever pass the lineage check.
    pub fn new(descriptor: RollupDescriptor, genesis_tx: PlainTx) -> Result<Replica, ScanError> {
        let (state, anchors, _) = genesis(&descriptor);
        if genesis_tx.inputs.first().map(|i| i.prevout) != Some(descriptor.genesis_nonce)
            || genesis_tx.outputs.first().map(|o| o.value) != Some(descriptor.seed_sats)
        {
            return Err(ScanError::BadGenesis);
        }
        let utxo = Outpoint { txid: genesis_tx.txid(), vout: 0 };
        Ok(Replica {
            descriptor,
            commitments: Tree::new(),
            nullifiers: IndexedTree::new(),
            history: vec![Checkpoint { state, anchors, utxo, creating_tx: genesis_tx }],
        })
    }

    pub fn tip(&self) -> &Checkpoint {
        self.history.last().expect("genesis")
    }

    pub fn state(&self) -> &RollupState {
        &self.tip().state
    }

    /// Builds the transition witness for `transactions` settled by `settlement` on top of the tip.
    pub fn witness(&self, transactions: Vec<BatchTransaction>, settlement: SettlementTx) -> BatchWitness {
        self.witness_with_escrows(transactions, Vec::new(), settlement)
    }

    /// [`Self::witness`] for a batch that also sweeps escrow deposits (inputs after the funding inputs).
    pub fn witness_with_escrows(
        &self,
        transactions: Vec<BatchTransaction>,
        escrows: Vec<EscrowDeposit>,
        settlement: SettlementTx,
    ) -> BatchWitness {
        let mut nullifiers: Vec<Fe> = transactions.iter().flat_map(|t| t.public.nullifiers).collect();
        nullifiers.sort();
        let mut scratch = self.nullifiers.clone();
        let nullifier_witnesses = nullifiers.iter().filter_map(|n| scratch.insert(*n).ok()).collect();
        let tip = self.tip();
        BatchWitness {
            old_state: tip.state,
            anchors: tip.anchors.clone(),
            frontier: if transactions.is_empty() && escrows.is_empty() {
                None
            } else {
                Some(self.commitments.frontier())
            },
            transactions,
            nullifier_witnesses,
            settlement,
            predecessor_tx: tip.creating_tx.clone(),
            escrows,
        }
    }

    /// Operator path: checks a batch with the full transition and commits it.
    pub fn apply_witness(&mut self, w: &BatchWitness) -> Result<BatchEffects, ScanError> {
        let effects = apply_batch(w).map_err(ScanError::Transition)?;
        self.accept_annex(&effects.annex, &w.settlement.plain())?;
        Ok(effects)
    }

    /// Scanner path: replays the annex published by settlement `tx` (witnesses stripped). The replica
    /// recomputes the successor state from it and output 0 and requires the published root.
    pub fn accept_annex(&mut self, annex: &Annex, tx: &PlainTx) -> Result<(), ScanError> {
        let tip = self.tip().clone();
        let rollup_value = tx.outputs.first().map_or(0, |o| o.value);
        let utxo = Outpoint { txid: tx.txid(), vout: 0 };
        let body = &annex.body;
        if body.rollup_id != tip.state.rollup_id {
            return Err(ScanError::WrongRollup);
        }
        if body.batch_number != tip.state.batch_number + 1 {
            return Err(ScanError::WrongBatchNumber);
        }
        if body.predecessor != tip.utxo || tx.inputs.first().map(|i| i.prevout) != Some(tip.utxo) {
            return Err(ScanError::WrongPredecessor);
        }
        if annex.old_state_root != tip.state.root() {
            return Err(ScanError::OldRootMismatch);
        }
        if rollup_value < DUST_LIMIT {
            return Err(ScanError::NewRootMismatch);
        }
        let mut commitments = self.commitments.clone();
        let mut nullifiers = self.nullifiers.clone();
        for n in &body.nullifiers {
            nullifiers.insert(*n).map_err(|_| ScanError::NullifierRejected)?;
        }
        for o in &body.outputs {
            commitments.append(o.commitment).map_err(|_| ScanError::CommitmentRejected)?;
        }
        let mut anchors = tip.anchors.clone();
        anchors.push(AnchorEntry {
            batch_number: body.batch_number,
            commitment_root: commitments.root(),
            commitment_count: commitments.count(),
        });
        let state = RollupState {
            rollup_id: tip.state.rollup_id,
            protocol_version: tip.state.protocol_version,
            batch_number: body.batch_number,
            commitment_root: commitments.root(),
            commitment_count: commitments.count(),
            nullifier_root: nullifiers.root(),
            nullifier_next_index: nullifiers.next_index(),
            anchor_history_commitment: anchors.commitment(),
            data_history_commitment: next_data_history(
                &tip.state.data_history_commitment,
                body.batch_number,
                &body.digest(),
            ),
            backing_sats: rollup_value,
            parent: tip.utxo,
        };
        if state.root() != annex.new_state_root {
            return Err(ScanError::NewRootMismatch);
        }
        self.commitments = commitments;
        self.nullifiers = nullifiers;
        self.history.push(Checkpoint { state, anchors, utxo, creating_tx: tx.clone() });
        Ok(())
    }

    /// Replays raw annex bytes (as read from input zero's witness).
    pub fn accept_annex_bytes(&mut self, annex: &[u8], tx: &PlainTx) -> Result<(), ScanError> {
        let annex = Annex::decode(annex).map_err(|_| ScanError::BadAnnex)?;
        self.accept_annex(&annex, tx)
    }

    /// Reorg: forget the most recent settlement and restore the trees.
    pub fn rollback(&mut self) -> Result<(), ScanError> {
        if self.history.len() < 2 {
            return Err(ScanError::NothingToRollBack);
        }
        self.history.pop();
        let s = self.tip().state;
        self.commitments.truncate(s.commitment_count);
        self.nullifiers.truncate(s.nullifier_next_index);
        Ok(())
    }

    /// Leaf index of a commitment, for wallets.
    pub fn position(&self, commitment: &Fe) -> Option<u64> {
        (0..self.commitments.count()).find(|i| self.commitments.leaf(*i) == *commitment)
    }

    pub fn spent(&self, nullifier: &Fe) -> bool {
        self.nullifiers.contains(nullifier)
    }
}
