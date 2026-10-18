//! User SDK of the privacy rollup: keys, note scanning, join-split building, zero-knowledge
//! proving and the batcher API.
//!
//! The private `JoinSplitWitness` (input notes, secrets, Merkle paths) is built and proven on the
//! user's device; only the `RollupTransaction` (public statement, external data, zero-knowledge
//! receipt) is sent to the batcher.
//!
//! ```text
//! let wallet = Wallet::from_seed(seed);
//! let built = wallet.deposit(&mut OsRng, &client.status()?, &[coin], fee, 10)?;
//! let (tx, stats) = pr_sdk::prove(&built.witness, &built.external, None)?;  // feature "prove"
//! client.submit(&pr_sdk::submission(&tx, funding))?;        // feature "client"
//! ```
pub mod api;
#[cfg(feature = "client")]
pub mod client;

use anyhow::{bail, ensure, Context, Result};
use pr_commitment_tree::root_from_path;
use pr_mempool::FundingCoin;
use pr_protocol_types::{
    Canonical, DepositDeclaration, ExternalData, Fe, RollupTransaction, TxOut, COMMITMENT_TREE_DEPTH, MAX_RECEIPT_BYTES,
};
use rand_core::{CryptoRng, RngCore};

pub use pr_joinsplit::JoinSplitWitness;
pub use pr_mempool;
pub use pr_protocol_types;
#[cfg(feature = "prove")]
pub use pr_prover::user::{
    decode_receipt, profile_joinsplit, prove_joinsplit, verify_joinsplit_receipt, UserProofStats,
};
#[cfg(feature = "prove")]
pub use pr_prover::JOINSPLIT_ID;
pub use pr_state_transition;
pub use pr_wallet_core::{
    key_tail, scan_outputs, withdrawal, Address, BuiltJoinSplit, Keys, NotePlaintext, OutputSpec, OwnedNote, SpendInput,
};

use api::{EscrowTerms, FundingInput, MerklePath, Notes, Status, Submission};
use pr_state_transition::escrow::{self, EscrowDeposit};

/// Bound on a hex-encoded canonical transaction: twice the receipt bound plus the statement and
/// external data.
pub const MAX_TRANSACTION_HEX: usize = 2 * (MAX_RECEIPT_BYTES + (64 << 10));

pub fn fe_from_hex(s: &str) -> Result<Fe> {
    Ok(Fe(hex::decode(s)?.try_into().map_err(|_| anyhow::anyhow!("field element is not 32 bytes"))?))
}

/// `spend_authority || encapsulation_key`, hex: what a sender needs to pay a wallet.
pub fn encode_address(a: &Address) -> String {
    hex::encode([a.spend_authority.0.as_slice(), &a.encapsulation_key].concat())
}

pub fn decode_address(s: &str) -> Result<Address> {
    let b = hex::decode(s)?;
    ensure!(b.len() == 32 + pr_wallet_core::keys::ENCAPSULATION_KEY_LEN, "address is {} bytes", b.len());
    Ok(Address { spend_authority: Fe(b[..32].try_into()?), encapsulation_key: b[32..].to_vec() })
}

/// Canonical transaction encoding, hex (the `transaction` of a `Submission`).
pub fn encode_transaction(tx: &RollupTransaction) -> String {
    hex::encode(tx.encode())
}

/// Inverse of `encode_transaction`; rejects oversized and non-canonical encodings.
pub fn decode_transaction(s: &str) -> Result<RollupTransaction> {
    ensure!(s.len() <= MAX_TRANSACTION_HEX, "transaction hex is {} characters", s.len());
    RollupTransaction::decode(&hex::decode(s)?).map_err(|e| anyhow::anyhow!("transaction encoding: {e:?}"))
}

/// The transaction sent to the batcher: the witness's public statement, the external data and
/// the user's receipt.
pub fn transaction(built: &BuiltJoinSplit, receipt: Vec<u8>) -> RollupTransaction {
    RollupTransaction {
        public: built.witness.public,
        external: built.external.clone(),
        receipt,
        withdrawal_leaves: built.withdrawal_leaves.clone(),
    }
}

pub fn submission(tx: &RollupTransaction, funding: Vec<FundingInput>) -> Submission {
    Submission { transaction: encode_transaction(tx), funding }
}

/// Proves a join-split on this device and returns the transaction to submit with its stage
/// timings. `external` is the `BuiltJoinSplit::external` the witness was built with; set the
/// returned transaction's `withdrawal_leaves` from `BuiltJoinSplit::withdrawal_leaves`.
#[cfg(feature = "prove")]
pub fn prove(
    witness: &JoinSplitWitness,
    external: &ExternalData,
    segment_po2: Option<u32>,
) -> Result<(RollupTransaction, UserProofStats)> {
    let (receipt, stats) = prove_joinsplit(witness, segment_po2)?;
    Ok((
        RollupTransaction {
            public: witness.public,
            external: external.clone(),
            receipt,
            withdrawal_leaves: Vec::new(),
        },
        stats,
    ))
}

/// Checks a transaction's receipt as the batcher does before admitting it.
#[cfg(feature = "prove")]
pub fn verify_transaction(tx: &RollupTransaction) -> Result<()> {
    verify_joinsplit_receipt(&decode_receipt(&tx.receipt)?, &tx.public)
}

/// A non-interactive deposit address: pay exactly `amount_sats` to `script_pubkey` from any wallet,
/// then register `opening` with the batcher. After `refund_delay` blocks the payer can take the coin
/// back with `refund_leaf` (version `0xc0`) and their key if it was not swept.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DepositAddress {
    pub script_pubkey: String,
    pub amount_sats: u64,
    pub opening: EscrowDeposit,
    pub refund_leaf: String,
    pub refund_delay: u16,
    pub note: NotePlaintext,
}

/// A wallet: keys derived from a 32-byte seed.
pub struct Wallet {
    pub keys: Keys,
}

impl Wallet {
    pub fn from_seed(seed: &[u8; 32]) -> Wallet {
        Wallet { keys: Keys::from_seed(seed) }
    }

    pub fn address(&self) -> Address {
        self.keys.address()
    }

    fn builder(status: &Status, expiry_batches: u64, fee_sats: u64) -> Result<pr_wallet_core::JoinSplitBuilder> {
        Ok(pr_wallet_core::JoinSplitBuilder {
            rollup_id: fe_from_hex(&status.rollup_id)?,
            anchor_root: fe_from_hex(&status.anchor.root)?,
            anchor_commitment_count: status.anchor.commitment_count,
            anchor_batch_number: status.anchor.batch_number,
            expiry_batch_number: status.batch_number + expiry_batches,
            deposit: None,
            withdrawals: Vec::new(),
            withdrawal_leaves: Vec::new(),
            fee_sats,
        })
    }

    fn change(&self, value: u64) -> OutputSpec {
        OutputSpec { value, recipient: self.address(), memo: [0; 32], self_key: Some(self.keys.outgoing_key) }
    }

    /// A deposit of every `funding` coin, paying `sum - fee` to this wallet. The witness is checked
    /// against the circuit's constraints before it is returned.
    pub fn deposit<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        status: &Status,
        funding: &[FundingCoin],
        fee_sats: u64,
        expiry_batches: u64,
    ) -> Result<BuiltJoinSplit> {
        ensure!(!funding.is_empty(), "a deposit needs at least one funding coin");
        let amount = funding.iter().try_fold(0u64, |s, c| s.checked_add(c.amount)).context("funding overflows")?;
        ensure!(amount > fee_sats, "deposit of {amount} sats does not cover the {fee_sats} sat fee");
        let mut b = Self::builder(status, expiry_batches, fee_sats)?;
        let declaration = DepositDeclaration { funding: funding.iter().map(|c| c.outpoint).collect(), change: None };
        b.deposit = Some((declaration, amount));
        let built = b
            .build(rng, [SpendInput::Dummy, SpendInput::Dummy], [self.change(amount - fee_sats), self.change(0)])
            .map_err(|e| anyhow::anyhow!("join-split: {e}"))?;
        built.witness.check().map_err(|e| anyhow::anyhow!("witness: {e}"))?;
        Ok(built)
    }

    /// A deposit address minting a `value` note to this wallet; `fee_sats` goes to the batch fee pool.
    pub fn deposit_address<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        terms: &EscrowTerms,
        value: u64,
        fee_sats: u64,
        refund_xonly: &[u8; 32],
        refund_delay: u16,
    ) -> Result<DepositAddress> {
        ensure!(
            refund_delay >= terms.min_refund_delay,
            "refund delay is below the batcher's {}",
            terms.min_refund_delay
        );
        ensure!(refund_delay < 1 << 15, "refund delay must be a BIP68 block count");
        ensure!(value >= pr_protocol_types::DUST_LIMIT, "deposit of {value} sats is dust");
        let amount_sats = value.checked_add(fee_sats).context("amount overflows")?;
        let rollup_id = fe_from_hex(&terms.rollup_id)?;
        let refund = escrow::refund_leaf(refund_xonly, refund_delay);
        let sibling = escrow::tapleaf_hash(escrow::REFUND_LEAF_VERSION, &refund);
        let (opening, note) = pr_wallet_core::escrow_deposit(
            rng,
            &rollup_id,
            &self.address(),
            value,
            fee_sats,
            &hex::decode(&terms.body)?,
            sibling,
        );
        let spk = escrow::escrow_script_pubkey(&opening.sweep_leaf, &sibling).context("invalid taproot tweak")?;
        ensure!(escrow::check_escrow(&rollup_id, &opening, &spk), "escrow does not open its address");
        Ok(DepositAddress {
            script_pubkey: hex::encode(spk),
            amount_sats,
            opening,
            refund_leaf: hex::encode(refund),
            refund_delay,
            note,
        })
    }

    /// Spends up to two owned notes (each with its path against `status.anchor`) into up to two
    /// outputs and an optional withdrawal; the rest of the input value, less the fee, is change to
    /// this wallet in a free output slot.
    #[allow(clippy::too_many_arguments)]
    pub fn transfer<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        status: &Status,
        spends: &[(OwnedNote, MerklePath)],
        payments: Vec<OutputSpec>,
        withdrawals: Vec<(TxOut, Vec<u8>)>,
        fee_sats: u64,
        expiry_batches: u64,
    ) -> Result<BuiltJoinSplit> {
        ensure!(!spends.is_empty() && spends.len() <= 2, "a join-split spends one or two notes");
        let anchor_root = fe_from_hex(&status.anchor.root)?;
        let rollup_id = fe_from_hex(&status.rollup_id)?;
        let mut inputs = [SpendInput::Dummy, SpendInput::Dummy];
        let mut in_value = 0u64;
        for (i, (note, path)) in spends.iter().enumerate() {
            ensure!(path.anchor == status.anchor, "path {i} is not against the status anchor");
            ensure!(path.leaf == note.leaf_index && path.commitment == note.commitment, "path {i} is of another leaf");
            ensure!(note.note.authority == self.keys.spend_authority, "note {i} is not this wallet's");
            ensure!(note.note.commitment(&rollup_id) == note.commitment, "note {i} does not open its commitment");
            let siblings: [Fe; COMMITMENT_TREE_DEPTH] =
                path.siblings.clone().try_into().map_err(|_| anyhow::anyhow!("path {i} has the wrong depth"))?;
            ensure!(
                root_from_path(&note.commitment, note.leaf_index, &siblings) == anchor_root,
                "path {i} is not in the anchor"
            );
            in_value = in_value.checked_add(note.note.value).context("input value overflows")?;
            inputs[i] = SpendInput::Real { note: note.clone(), secret: self.keys.spending_secret, siblings };
        }
        ensure!(payments.len() <= 2, "a join-split has two output slots");
        let paid = payments.iter().try_fold(0u64, |s, o| s.checked_add(o.value)).context("outputs overflow")?;
        let out = paid
            .checked_add(
                withdrawals
                    .iter()
                    .try_fold(0u64, |a, (o, _)| a.checked_add(o.value))
                    .context("withdrawals overflow")?,
            )
            .and_then(|v| v.checked_add(fee_sats))
            .context("outputs overflow")?;
        let Some(change) = in_value.checked_sub(out) else { bail!("inputs of {in_value} sats do not cover {out}") };
        let mut outputs = payments;
        if change > 0 {
            ensure!(outputs.len() < 2, "no free output slot for {change} sats of change");
            outputs.push(self.change(change));
        }
        while outputs.len() < 2 {
            outputs.push(self.change(0));
        }
        let mut b = Self::builder(status, expiry_batches, fee_sats)?;
        b.set_withdrawals(withdrawals);
        let outputs: [OutputSpec; 2] = outputs.try_into().map_err(|_| anyhow::anyhow!("two outputs"))?;
        let built = b.build(rng, inputs, outputs).map_err(|e| anyhow::anyhow!("join-split: {e}"))?;
        built.witness.check().map_err(|e| anyhow::anyhow!("witness: {e}"))?;
        Ok(built)
    }

    /// Trial-decrypts every settled output and returns this wallet's notes.
    pub fn scan(&self, rollup_id: &Fe, notes: &Notes) -> Vec<OwnedNote> {
        notes.batches.iter().flat_map(|b| scan_outputs(&self.keys, rollup_id, &b.outputs, b.first_leaf)).collect()
    }
}

#[cfg(test)]
mod tests;
