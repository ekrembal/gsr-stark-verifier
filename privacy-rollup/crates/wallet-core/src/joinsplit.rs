//! Builds the private witness and public statement of one 2x2 join-split.
use std::fmt::Write as _;

use pr_protocol_types::{
    DepositDeclaration, ExternalData, Fe, JoinSplitPublic, COMMITMENT_TREE_DEPTH, PROTOCOL_VERSION,
};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::encryption::{encrypt_note, NotePlaintext};
use crate::keys::Address;
use crate::{Note, OwnedNote};

pub fn random_fe<R: RngCore + CryptoRng>(rng: &mut R) -> Fe {
    let mut b = [0u8; 32];
    rng.fill_bytes(&mut b);
    Fe::from_digest(b)
}

/// One input slot.
#[allow(clippy::large_enum_variant)]
pub enum SpendInput {
    /// A note owned by `secret`, at `note.leaf_index` with membership path `siblings` in the anchor.
    Real { note: OwnedNote, secret: Fe, siblings: [Fe; COMMITMENT_TREE_DEPTH] },
    /// A zero-valued note with fresh random secret and randomness.
    Dummy,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinSplitWitness {
    pub public: JoinSplitPublic,
    pub in_value: [u64; 2],
    pub in_secret: [Fe; 2],
    pub in_randomness: [Fe; 2],
    pub in_index: [u32; 2],
    pub in_siblings: [Vec<Fe>; 2],
    pub out_value: [u64; 2],
    pub out_auth: [Fe; 2],
    pub out_randomness: [Fe; 2],
}

fn hex_fe(f: &Fe) -> String {
    let mut s = String::from("\"0x");
    for b in f.0 {
        write!(s, "{b:02x}").unwrap();
    }
    s.push('"');
    s
}

fn list<T>(items: &[T], f: impl Fn(&T) -> String) -> String {
    format!("[{}]", items.iter().map(f).collect::<Vec<_>>().join(", "))
}

impl JoinSplitWitness {
    /// Noir `Prover.toml` input file for `circuits/joinsplit-2x2`.
    pub fn prover_toml(&self) -> String {
        let p = &self.public;
        let (hi, lo) = (
            u128::from_be_bytes(p.external_data_commitment[..16].try_into().unwrap()),
            u128::from_be_bytes(p.external_data_commitment[16..].try_into().unwrap()),
        );
        let q = |v: &dyn std::fmt::Display| format!("\"{v}\"");
        let mut s = String::new();
        writeln!(s, "rollup_id = {}", hex_fe(&p.rollup_id)).unwrap();
        writeln!(s, "protocol_version = {}", q(&p.protocol_version)).unwrap();
        writeln!(s, "anchor_root = {}", hex_fe(&p.anchor_root)).unwrap();
        writeln!(s, "anchor_commitment_count = {}", q(&p.anchor_commitment_count)).unwrap();
        writeln!(s, "anchor_batch_number = {}", q(&p.anchor_batch_number)).unwrap();
        writeln!(s, "nullifier = {}", list(&p.nullifiers, hex_fe)).unwrap();
        writeln!(s, "output_commitment = {}", list(&p.output_commitments, hex_fe)).unwrap();
        writeln!(s, "deposit_sats = {}", q(&p.deposit_sats)).unwrap();
        writeln!(s, "withdrawal_sats = {}", q(&p.withdrawal_sats)).unwrap();
        writeln!(s, "fee_sats = {}", q(&p.fee_sats)).unwrap();
        writeln!(s, "external_data_hi = {}", q(&hi)).unwrap();
        writeln!(s, "external_data_lo = {}", q(&lo)).unwrap();
        writeln!(s, "expiry_batch_number = {}", q(&p.expiry_batch_number)).unwrap();
        writeln!(s, "in_value = {}", list(&self.in_value, |v| q(v))).unwrap();
        writeln!(s, "in_secret = {}", list(&self.in_secret, hex_fe)).unwrap();
        writeln!(s, "in_randomness = {}", list(&self.in_randomness, hex_fe)).unwrap();
        writeln!(s, "in_index = {}", list(&self.in_index, |v| q(v))).unwrap();
        writeln!(s, "in_siblings = {}", list(&self.in_siblings, |p| list(p, hex_fe))).unwrap();
        writeln!(s, "out_value = {}", list(&self.out_value, |v| q(v))).unwrap();
        writeln!(s, "out_auth = {}", list(&self.out_auth, hex_fe)).unwrap();
        writeln!(s, "out_randomness = {}", list(&self.out_randomness, hex_fe)).unwrap();
        s
    }

    /// Native evaluation of every circuit constraint (used to reject bad witnesses before proving).
    pub fn check(&self) -> Result<(), &'static str> {
        let p = &self.public;
        if p.protocol_version != PROTOCOL_VERSION {
            return Err("protocol version");
        }
        if p.anchor_batch_number > p.expiry_batch_number {
            return Err("expired");
        }
        let money = |v: u64| v <= pr_protocol_types::MAX_MONEY;
        if ![p.deposit_sats, p.withdrawal_sats, p.fee_sats]
            .into_iter()
            .chain(self.in_value)
            .chain(self.out_value)
            .all(money)
        {
            return Err("amount range");
        }
        for i in 0..2 {
            let auth = pr_crypto::spend_authority(&self.in_secret[i]);
            let nk = pr_crypto::nullifier_key(&self.in_secret[i]);
            let cm = pr_crypto::note_commitment(&p.rollup_id, self.in_value[i], &auth, &self.in_randomness[i]);
            if self.in_value[i] != 0 {
                if self.in_index[i] as u64 >= p.anchor_commitment_count {
                    return Err("input index beyond anchor");
                }
                let sib: [Fe; COMMITMENT_TREE_DEPTH] =
                    self.in_siblings[i].clone().try_into().map_err(|_| "path length")?;
                if pr_commitment_tree::root_from_path(&cm, self.in_index[i] as u64, &sib) != p.anchor_root {
                    return Err("input not in anchor");
                }
            }
            let nf = pr_crypto::nullifier(&nk, &cm, self.in_index[i]);
            if nf.is_zero() || nf != p.nullifiers[i] {
                return Err("nullifier");
            }
        }
        if p.nullifiers[0] == p.nullifiers[1] {
            return Err("duplicate nullifier");
        }
        for j in 0..2 {
            if pr_crypto::note_commitment(&p.rollup_id, self.out_value[j], &self.out_auth[j], &self.out_randomness[j])
                != p.output_commitments[j]
            {
                return Err("output commitment");
            }
        }
        if p.output_commitments[0] == p.output_commitments[1] {
            return Err("duplicate output");
        }
        let lhs = self.in_value[0] as u128 + self.in_value[1] as u128 + p.deposit_sats as u128;
        let rhs =
            self.out_value[0] as u128 + self.out_value[1] as u128 + p.withdrawal_sats as u128 + p.fee_sats as u128;
        if lhs != rhs {
            return Err("unbalanced");
        }
        Ok(())
    }
}

/// An output slot: `None` is a zero-valued dummy output to a fresh throwaway key.
pub struct OutputSpec {
    pub value: u64,
    pub recipient: Address,
    pub memo: [u8; 32],
}

pub struct JoinSplitBuilder {
    pub rollup_id: Fe,
    pub anchor_root: Fe,
    pub anchor_commitment_count: u64,
    pub anchor_batch_number: u64,
    pub expiry_batch_number: u64,
    pub deposit: Option<(DepositDeclaration, u64)>,
    pub withdrawal: Option<(Vec<u8>, u64)>,
    pub fee_sats: u64,
}

pub struct BuiltJoinSplit {
    pub witness: JoinSplitWitness,
    pub external: ExternalData,
    pub output_notes: [Note; 2],
}

impl JoinSplitBuilder {
    pub fn build<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        inputs: [SpendInput; 2],
        outputs: [OutputSpec; 2],
    ) -> Result<BuiltJoinSplit, &'static str> {
        let mut in_value = [0u64; 2];
        let mut in_secret = [Fe::ZERO; 2];
        let mut in_randomness = [Fe::ZERO; 2];
        let mut in_index = [0u32; 2];
        let mut in_siblings = [vec![Fe::ZERO; COMMITMENT_TREE_DEPTH], vec![Fe::ZERO; COMMITMENT_TREE_DEPTH]];
        let mut nullifiers = [Fe::ZERO; 2];
        for (i, input) in inputs.into_iter().enumerate() {
            match input {
                SpendInput::Real { note, secret, siblings } => {
                    in_value[i] = note.note.value;
                    in_secret[i] = secret;
                    in_randomness[i] = note.note.randomness;
                    in_index[i] = u32::try_from(note.leaf_index).map_err(|_| "leaf index")?;
                    in_siblings[i] = siblings.to_vec();
                }
                SpendInput::Dummy => {
                    in_secret[i] = random_fe(rng);
                    in_randomness[i] = random_fe(rng);
                }
            }
            let cm = pr_crypto::note_commitment(
                &self.rollup_id,
                in_value[i],
                &pr_crypto::spend_authority(&in_secret[i]),
                &in_randomness[i],
            );
            nullifiers[i] = pr_crypto::nullifier(&pr_crypto::nullifier_key(&in_secret[i]), &cm, in_index[i]);
        }
        let mut out_value = [0u64; 2];
        let mut out_auth = [Fe::ZERO; 2];
        let mut out_randomness = [Fe::ZERO; 2];
        let mut commitments = [Fe::ZERO; 2];
        let mut ciphertexts = [Vec::new(), Vec::new()];
        let mut output_notes = [
            Note { value: 0, authority: Fe::ZERO, randomness: Fe::ZERO },
            Note { value: 0, authority: Fe::ZERO, randomness: Fe::ZERO },
        ];
        for (j, o) in outputs.into_iter().enumerate() {
            let pt = NotePlaintext {
                value: o.value,
                randomness: random_fe(rng),
                authority: o.recipient.spend_authority,
                memo: o.memo,
            };
            out_value[j] = o.value;
            out_auth[j] = pt.authority;
            out_randomness[j] = pt.randomness;
            commitments[j] = pt.note().commitment(&self.rollup_id);
            ciphertexts[j] = encrypt_note(rng, &o.recipient.encapsulation_key, &self.rollup_id, &pt);
            output_notes[j] = pt.note();
        }
        let external = ExternalData {
            deposit: self.deposit.as_ref().map(|d| d.0.clone()),
            withdrawal_script: self.withdrawal.as_ref().map(|w| w.0.clone()),
            ciphertexts,
        };
        let public = JoinSplitPublic {
            rollup_id: self.rollup_id,
            protocol_version: PROTOCOL_VERSION,
            anchor_root: self.anchor_root,
            anchor_commitment_count: self.anchor_commitment_count,
            anchor_batch_number: self.anchor_batch_number,
            nullifiers,
            output_commitments: commitments,
            deposit_sats: self.deposit.as_ref().map_or(0, |d| d.1),
            withdrawal_sats: self.withdrawal.as_ref().map_or(0, |w| w.1),
            fee_sats: self.fee_sats,
            external_data_commitment: external.commitment(),
            expiry_batch_number: self.expiry_batch_number,
        };
        let witness = JoinSplitWitness {
            public,
            in_value,
            in_secret,
            in_randomness,
            in_index,
            in_siblings,
            out_value,
            out_auth,
            out_randomness,
        };
        witness.check()?;
        Ok(BuiltJoinSplit { witness, external, output_notes })
    }
}
