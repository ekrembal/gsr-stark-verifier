//! A native end-to-end harness: wallets build join-splits against the scanner's anchors, the
//! mempool admits them, the operator assembles the settlement, the full transition applies it and
//! wallets recover their notes by trial decryption. Proofs are out of scope here (the ProveKit
//! adapter and the guest test them); `submit` passes an always-accepting verifier.
use pr_bitcoin_adapter::SettlementTx;
use pr_mempool::{assemble_settlement, batch_transactions, Entry, FundingCoin, Mempool, MempoolError};
use pr_protocol_types::{
    DepositDeclaration, Fe, Outpoint, RollupDescriptor, RollupTransaction, TxOut, COMMITMENT_TREE_DEPTH,
};
use pr_scanner::{Replica, ScanError};
use pr_state_transition::{BatchEffects, BatchWitness};
use pr_wallet_core::{scan_outputs, BuiltJoinSplit, JoinSplitBuilder, Keys, OutputSpec, OwnedNote, SpendInput};
use rand_core::OsRng;

pub const ROLLUP_SPK: [u8; 34] = [
    0x51, 0x20, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
];

pub fn descriptor() -> RollupDescriptor {
    RollupDescriptor {
        protocol_version: 1,
        genesis_nonce: Outpoint { txid: [7; 32], vout: 0 },
        image_id: [9; 32],
        internal_key: [2; 32],
        seed_sats: 10_000,
    }
}

pub struct Wallet {
    pub keys: Keys,
    pub notes: Vec<OwnedNote>,
}

impl Wallet {
    pub fn new(seed: u8) -> Wallet {
        Wallet { keys: Keys::from_seed(&[seed; 32]), notes: Vec::new() }
    }
    pub fn balance(&self, replica: &Replica) -> u64 {
        self.notes.iter().filter(|n| !replica.spent(&n.nullifier)).map(|n| n.note.value).sum()
    }
    pub fn scan(&mut self, replica: &Replica, effects: &BatchEffects) {
        let outs = &effects.annex.body.outputs;
        let first = effects.new_state.commitment_count - outs.len() as u64;
        self.notes.extend(
            scan_outputs(&self.keys, &replica.descriptor.rollup_id(), outs, first)
                .into_iter()
                .filter(|n| n.note.value > 0),
        );
    }
    pub fn spend(&self, replica: &Replica, note: &OwnedNote) -> SpendInput {
        SpendInput::Real {
            note: note.clone(),
            secret: self.keys.spending_secret,
            siblings: replica.commitments.path(note.leaf_index),
        }
    }
    pub fn pay(&self, value: u64) -> OutputSpec {
        OutputSpec { value, recipient: self.keys.address(), memo: [0; 32] }
    }
}

pub struct Harness {
    pub replica: Replica,
    pub mempool: Mempool,
    pub last_witness: Option<BatchWitness>,
}

impl Default for Harness {
    fn default() -> Self {
        Harness::new()
    }
}

impl Harness {
    pub fn new() -> Harness {
        Harness {
            replica: Replica::new(descriptor(), Outpoint { txid: [1; 32], vout: 0 }),
            mempool: Mempool::new(),
            last_witness: None,
        }
    }

    /// A builder anchored at the tip, valid for the next ten batches.
    pub fn builder(&self, fee: u64) -> JoinSplitBuilder {
        let tip = self.replica.tip();
        let a = tip.anchors.0.last().expect("anchor");
        JoinSplitBuilder {
            rollup_id: self.replica.descriptor.rollup_id(),
            anchor_root: a.commitment_root,
            anchor_commitment_count: a.commitment_count,
            anchor_batch_number: a.batch_number,
            expiry_batch_number: tip.state.batch_number + 10,
            deposit: None,
            withdrawal: None,
            fee_sats: fee,
        }
    }

    pub fn deposit_builder(
        &self,
        fee: u64,
        funding: &[FundingCoin],
        deposit: u64,
        change: Option<TxOut>,
    ) -> JoinSplitBuilder {
        let mut b = self.builder(fee);
        b.deposit =
            Some((DepositDeclaration { funding: funding.iter().map(|f| f.outpoint).collect(), change }, deposit));
        b
    }

    pub fn build(&self, b: &JoinSplitBuilder, inputs: [SpendInput; 2], outputs: [OutputSpec; 2]) -> BuiltJoinSplit {
        b.build(&mut OsRng, inputs, outputs).expect("valid join-split")
    }

    pub fn submit(&mut self, built: &BuiltJoinSplit, funding: Vec<FundingCoin>) -> Result<(), MempoolError> {
        let tx =
            RollupTransaction { public: built.witness.public, external: built.external.clone(), receipt: Vec::new() };
        self.mempool.submit(tx, funding, &self.replica, |_| true)
    }

    pub fn settlement(&self, selected: &[Entry], reward: Option<TxOut>) -> SettlementTx {
        assemble_settlement(&self.replica, ROLLUP_SPK.to_vec(), ROLLUP_SPK.to_vec(), selected, reward)
            .expect("assemble")
    }

    /// Settles the mempool's selection and applies it to the replica.
    pub fn settle(&mut self, reward: Option<TxOut>) -> Result<BatchEffects, ScanError> {
        let selected = self.mempool.select();
        let settlement = self.settlement(&selected, reward);
        let utxo = Outpoint { txid: settlement.txid(), vout: 0 };
        let w = self.replica.witness(batch_transactions(&selected), settlement);
        let effects = self.replica.apply_witness(&w, utxo)?;
        self.last_witness = Some(w);
        self.mempool.remove_settled(&selected);
        self.mempool.revalidate(&self.replica);
        Ok(effects)
    }
}

pub fn coin(tag: u8, amount: u64) -> FundingCoin {
    FundingCoin { outpoint: Outpoint { txid: [tag; 32], vout: 1 }, amount, script_pubkey: vec![0x51, 0x20, tag] }
}

pub fn fe(v: u64) -> Fe {
    let mut b = [0u8; 32];
    b[24..].copy_from_slice(&v.to_be_bytes());
    Fe(b)
}

pub const DEPTH: usize = COMMITMENT_TREE_DEPTH;
