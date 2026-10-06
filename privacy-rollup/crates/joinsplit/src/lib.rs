//! The private witness of one 2x2 join-split and the native evaluation of every constraint of
//! `circuits/joinsplit-2x2`. Used by the wallet (to reject bad witnesses before proving) and by
//! the `joinsplit` RISC Zero guest, whose journal is the canonical `JoinSplitPublic` encoding.
use pr_protocol_types::{Fe, JoinSplitPublic, COMMITMENT_TREE_DEPTH, PROTOCOL_VERSION};
use serde::{Deserialize, Serialize};

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

impl JoinSplitWitness {
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
