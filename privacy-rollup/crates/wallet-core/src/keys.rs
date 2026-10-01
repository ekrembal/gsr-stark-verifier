use ml_kem::kem::{DecapsulationKey, EncapsulationKey};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768, MlKem768Params, B32};
use pr_protocol_types::hash::{tagged, tags};
use pr_protocol_types::Fe;

pub const ENCAPSULATION_KEY_LEN: usize = 1184;

/// Wallet keys, all derived from a 32-byte seed.
pub struct Keys {
    pub spending_secret: Fe,
    pub spend_authority: Fe,
    pub nullifier_key: Fe,
    pub decapsulation_key: DecapsulationKey<MlKem768Params>,
    pub encapsulation_key: EncapsulationKey<MlKem768Params>,
}

/// What a sender needs to pay this wallet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Address {
    pub spend_authority: Fe,
    pub encapsulation_key: Vec<u8>,
}

impl Keys {
    pub fn from_seed(seed: &[u8; 32]) -> Keys {
        let spending_secret = Fe::from_digest(tagged(tags::NOTE_KEY, &[b"spend", seed]));
        let d = B32::from(tagged(tags::NOTE_KEY, &[b"ml-kem-d", seed]));
        let z = B32::from(tagged(tags::NOTE_KEY, &[b"ml-kem-z", seed]));
        let (decapsulation_key, encapsulation_key) = MlKem768::generate_deterministic(&d, &z);
        Keys {
            spending_secret,
            spend_authority: pr_crypto::spend_authority(&spending_secret),
            nullifier_key: pr_crypto::nullifier_key(&spending_secret),
            decapsulation_key,
            encapsulation_key,
        }
    }

    pub fn address(&self) -> Address {
        Address { spend_authority: self.spend_authority, encapsulation_key: self.encapsulation_key.as_bytes().to_vec() }
    }
}
