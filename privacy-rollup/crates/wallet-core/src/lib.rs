//! Wallet primitives: keys, notes, ML-KEM-768 note encryption, and join-split witness building.
pub mod encryption;
pub mod joinsplit;
pub mod keys;

pub use encryption::{decrypt_any, decrypt_note, encrypt_note, encrypt_self, NotePlaintext};
pub use joinsplit::{
    key_tail, withdrawal, BuiltJoinSplit, JoinSplitBuilder, JoinSplitWitness, OutputSpec, ProverToml, SpendInput,
};
pub use keys::{Address, Keys};

use pr_protocol_types::Fe;
use serde::{Deserialize, Serialize};

/// A note as known to its owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Note {
    pub value: u64,
    pub authority: Fe,
    pub randomness: Fe,
}

impl Note {
    pub fn commitment(&self, rollup_id: &Fe) -> Fe {
        pr_crypto::note_commitment(rollup_id, self.value, &self.authority, &self.randomness)
    }
}

/// A received note located in the commitment tree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnedNote {
    pub note: Note,
    pub leaf_index: u64,
    pub commitment: Fe,
    pub nullifier: Fe,
}

/// Trial-decrypts a settled batch's outputs. `first_leaf` is the old commitment count: output `k`
/// of the batch is leaf `first_leaf + k`.
pub fn scan_outputs(
    keys: &Keys,
    rollup_id: &Fe,
    outputs: &[pr_protocol_types::NoteOutput],
    first_leaf: u64,
) -> Vec<OwnedNote> {
    outputs
        .iter()
        .enumerate()
        .filter_map(|(k, o)| {
            let pt = decrypt_any(keys, rollup_id, &o.commitment, &o.ciphertext)?;
            let note = pt.note();
            if note.authority != keys.spend_authority || note.commitment(rollup_id) != o.commitment {
                return None;
            }
            let leaf_index = first_leaf + k as u64;
            let nullifier = pr_crypto::nullifier(&keys.nullifier_key, &o.commitment, u32::try_from(leaf_index).ok()?);
            Some(OwnedNote { note, leaf_index, commitment: o.commitment, nullifier })
        })
        .collect()
}

/// A non-interactive deposit to `recipient`: the escrow opening (without its sweep leaf yet) and the
/// minted note's plaintext. The caller derives the address with
/// [`pr_state_transition::escrow::sweep_leaf`] and pays `value + fee_sats` to it.
pub fn escrow_deposit<R: rand_core::RngCore + rand_core::CryptoRng>(
    rng: &mut R,
    rollup_id: &Fe,
    recipient: &Address,
    value: u64,
    fee_sats: u64,
    sweep_body: &[u8],
    sibling: [u8; 32],
) -> (pr_state_transition::escrow::EscrowDeposit, NotePlaintext) {
    let pt = NotePlaintext {
        value,
        randomness: joinsplit::random_fe(rng),
        authority: recipient.spend_authority,
        memo: [0; 32],
    };
    let ciphertext = encrypt_note(rng, &recipient.encapsulation_key, rollup_id, &pt);
    let mut e = pr_state_transition::escrow::EscrowDeposit {
        authority: pt.authority,
        randomness: pt.randomness,
        value,
        fee_sats,
        sweep_leaf: Vec::new(),
        sibling,
        ciphertext,
    };
    e.sweep_leaf = pr_state_transition::escrow::sweep_leaf(&e.digest(rollup_id), sweep_body);
    (e, pt)
}
