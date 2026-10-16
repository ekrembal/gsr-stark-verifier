//! CPFP children spending the operator's reward output, a BIP86 key-path P2TR output.
use anyhow::{anyhow, Context, Result};
use k256::elliptic_curve::PrimeField;
use k256::schnorr::SigningKey;
use k256::{NonZeroScalar, Scalar};
use pr_protocol_types::hash::{sha256, tagged};

const SEQUENCE: u32 = 0xffff_fffd;

/// The output (BIP86-tweaked) key of a reward output.
pub struct RewardKey {
    key: SigningKey,
}

impl RewardKey {
    pub fn from_secret(secret: &[u8]) -> Result<RewardKey> {
        let internal = SigningKey::from_bytes(secret).map_err(|_| anyhow!("reward key is not a valid secret key"))?;
        let p = internal.verifying_key().to_bytes();
        let t = Option::<Scalar>::from(Scalar::from_repr(tagged("TapTweak", &[&p]).into())).context("tweak")?;
        let d = Option::<NonZeroScalar>::from(NonZeroScalar::new(*internal.as_nonzero_scalar().as_ref() + t))
            .context("tweaked reward key is zero")?;
        Ok(RewardKey { key: SigningKey::from(d) })
    }

    pub fn script_pubkey(&self) -> Vec<u8> {
        [&[0x51u8, 0x20][..], &self.key.verifying_key().to_bytes()].concat()
    }

    /// BIP341 `SIGHASH_DEFAULT` digest of the one-input, one-output child paying back to the key.
    fn sighash(&self, outpoint: &[u8], value: u64, out_value: u64) -> [u8; 32] {
        let spk = self.script_pubkey();
        let mut msg = vec![0u8, 0];
        msg.extend(2u32.to_le_bytes());
        msg.extend(0u32.to_le_bytes());
        msg.extend(sha256(outpoint));
        msg.extend(sha256(&value.to_le_bytes()));
        msg.extend(sha256(&[&[spk.len() as u8][..], &spk].concat()));
        msg.extend(sha256(&SEQUENCE.to_le_bytes()));
        msg.extend(sha256(&[&out_value.to_le_bytes()[..], &[spk.len() as u8], &spk].concat()));
        msg.push(0);
        msg.extend(0u32.to_le_bytes());
        tagged("TapSighash", &[&msg])
    }

    /// Raw hex of a child spending `parent_txid:vout` (display-order txid, `value` sats) back to
    /// the key, paying `fee`.
    pub fn child(&self, parent_txid: &str, vout: u32, value: u64, fee: u64) -> Result<String> {
        let out_value = value.checked_sub(fee).context("fee exceeds the reward output")?;
        let mut txid = hex::decode(parent_txid)?;
        txid.reverse();
        let outpoint = [&txid[..], &vout.to_le_bytes()].concat();
        let digest = self.sighash(&outpoint, value, out_value);
        let sig = self.key.sign_raw(&digest, &sha256(&digest)).map_err(|_| anyhow!("schnorr signing failed"))?;
        let spk = self.script_pubkey();
        let mut tx = Vec::new();
        tx.extend(2u32.to_le_bytes());
        tx.extend([0, 1, 1]);
        tx.extend(&outpoint);
        tx.push(0);
        tx.extend(SEQUENCE.to_le_bytes());
        tx.push(1);
        tx.extend(out_value.to_le_bytes());
        tx.push(spk.len() as u8);
        tx.extend(&spk);
        tx.extend([1, 64]);
        tx.extend(sig.to_bytes());
        tx.extend(0u32.to_le_bytes());
        Ok(hex::encode(tx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_is_a_signed_key_path_spend() {
        let k = RewardKey::from_secret(&[7; 32]).unwrap();
        let raw = hex::decode(k.child(&"11".repeat(32), 3, 5_000, 600).unwrap()).unwrap();
        assert_eq!(raw.len(), 4 + 2 + 1 + 36 + 1 + 4 + 1 + 8 + 1 + 34 + 2 + 64 + 4);
        let sig = k256::schnorr::Signature::try_from(&raw[raw.len() - 68..raw.len() - 4]).unwrap();
        let digest = k.sighash(&[&[0x11; 32][..], &3u32.to_le_bytes()].concat(), 5_000, 4_400);
        k.key.verifying_key().verify_raw(&digest, &sig).unwrap();
        assert_ne!(k.script_pubkey()[2..], SigningKey::from_bytes(&[7; 32]).unwrap().verifying_key().to_bytes()[..]);
    }
}
