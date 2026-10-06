//! Wallet primitives: keys, notes, ML-KEM-768 note encryption, and join-split witness building.
pub mod encryption;
pub mod joinsplit;
pub mod keys;

pub use encryption::{decrypt_note, encrypt_note, NotePlaintext};
pub use joinsplit::{BuiltJoinSplit, JoinSplitBuilder, JoinSplitWitness, OutputSpec, ProverToml, SpendInput};
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
            let pt = decrypt_note(keys, rollup_id, &o.commitment, &o.ciphertext)?;
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
