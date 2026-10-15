//! Note encryption: ML-KEM-768 encapsulation, then XChaCha20-Poly1305 under the shared secret with
//! `rollup_id || commitment` as associated data.
//!
//! Ciphertext layout (1,232 bytes): `kem_ciphertext[1088] || nonce[24] || sealed[104 + 16]`.
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use kem::{Decapsulate, Encapsulate};
use ml_kem::kem::EncapsulationKey;
use ml_kem::{EncodedSizeUser, MlKem768Params};
use pr_protocol_types::{Fe, NOTE_CIPHERTEXT_LEN, NOTE_PLAINTEXT_LEN};
use rand_core::{CryptoRng, RngCore};

use crate::keys::{Keys, ENCAPSULATION_KEY_LEN};
use crate::Note;

const KEM_CT_LEN: usize = 1088;
const NONCE_LEN: usize = 24;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotePlaintext {
    pub value: u64,
    pub randomness: Fe,
    pub authority: Fe,
    pub memo: [u8; 32],
}

impl NotePlaintext {
    fn encode(&self) -> [u8; NOTE_PLAINTEXT_LEN] {
        let mut b = [0u8; NOTE_PLAINTEXT_LEN];
        b[..8].copy_from_slice(&self.value.to_le_bytes());
        b[8..40].copy_from_slice(&self.randomness.0);
        b[40..72].copy_from_slice(&self.authority.0);
        b[72..].copy_from_slice(&self.memo);
        b
    }
    fn decode(b: &[u8]) -> Option<NotePlaintext> {
        if b.len() != NOTE_PLAINTEXT_LEN {
            return None;
        }
        Some(NotePlaintext {
            value: u64::from_le_bytes(b[..8].try_into().ok()?),
            randomness: Fe::from_canonical(b[8..40].try_into().ok()?)?,
            authority: Fe::from_canonical(b[40..72].try_into().ok()?)?,
            memo: b[72..].try_into().ok()?,
        })
    }
    pub fn note(&self) -> Note {
        Note { value: self.value, authority: self.authority, randomness: self.randomness }
    }
}

fn aad(rollup_id: &Fe, commitment: &Fe) -> [u8; 64] {
    let mut a = [0u8; 64];
    a[..32].copy_from_slice(&rollup_id.0);
    a[32..].copy_from_slice(&commitment.0);
    a
}

pub fn encrypt_note<R: RngCore + CryptoRng>(
    rng: &mut R,
    encapsulation_key: &[u8],
    rollup_id: &Fe,
    plaintext: &NotePlaintext,
) -> Vec<u8> {
    assert_eq!(encapsulation_key.len(), ENCAPSULATION_KEY_LEN);
    let ek = EncapsulationKey::<MlKem768Params>::from_bytes(encapsulation_key.try_into().expect("length checked"));
    let (kem_ct, shared) = ek.encapsulate(rng).expect("ML-KEM encapsulation is infallible");
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let commitment = plaintext.note().commitment(rollup_id);
    let sealed = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(shared.as_slice()))
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: &plaintext.encode(), aad: &aad(rollup_id, &commitment) })
        .expect("encryption");
    let mut out = Vec::with_capacity(NOTE_CIPHERTEXT_LEN);
    out.extend_from_slice(&kem_ct);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    debug_assert_eq!(out.len(), NOTE_CIPHERTEXT_LEN);
    out
}

/// Trial-decrypts an output; returns the note only if it decrypts and opens `commitment`.
pub fn decrypt_note(keys: &Keys, rollup_id: &Fe, commitment: &Fe, ciphertext: &[u8]) -> Option<NotePlaintext> {
    if ciphertext.len() != NOTE_CIPHERTEXT_LEN {
        return None;
    }
    let kem_ct = ciphertext[..KEM_CT_LEN].try_into().ok()?;
    let shared = keys.decapsulation_key.decapsulate(kem_ct).ok()?;
    let nonce = &ciphertext[KEM_CT_LEN..KEM_CT_LEN + NONCE_LEN];
    let opened = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(shared.as_slice()))
        .decrypt(
            XNonce::from_slice(nonce),
            Payload { msg: &ciphertext[KEM_CT_LEN + NONCE_LEN..], aad: &aad(rollup_id, commitment) },
        )
        .ok()?;
    let p = NotePlaintext::decode(&opened)?;
    (p.note().commitment(rollup_id) == *commitment).then_some(p)
}
