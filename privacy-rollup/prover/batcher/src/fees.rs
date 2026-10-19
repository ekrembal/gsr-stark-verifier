//! Fee policy. A settlement's miner fee is fixed when it is proven (`fee_sats` of every
//! join-split and escrow, all paid to the miner), so the batcher prices it up front:
//!
//! * a transaction pays at least its own weight at the current feerate (admission floor);
//! * a settlement is only proven when the selected fees cover the whole transaction's upper-bound
//!   weight, including the fixed verifier spend (`EMPTY_SETTLEMENT_WEIGHT`), at that feerate;
//! * there is no reward or anchor output: any surplus is miner fee, and users raise fees by re-proving.
use pr_protocol_types::{EMPTY_SETTLEMENT_WEIGHT, MAX_SETTLEMENT_WEIGHT};
use serde::{Deserialize, Serialize};

/// Outputs below this are not created (P2TR / P2WSH dust limit at the default dust relay fee).
pub const DUST_SATS: u64 = 330;

/// Sats for `weight` WU at `sat_per_vb`, rounded up.
pub fn fee_for_weight(weight: u64, sat_per_vb: f64) -> u64 {
    (weight as f64 * sat_per_vb / 4.0).ceil() as u64
}

/// Weight of one output with `script_pubkey`.
pub fn output_weight(script_pubkey: &[u8]) -> u64 {
    4 * (8 + 1 + script_pubkey.len() as u64)
}

/// `GET /v1/fee-quote`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FeeQuote {
    pub sat_per_vb: f64,
    /// Transactions the fixed verifier spend is shared over.
    pub target_transactions: usize,
    pub empty_settlement_weight: u64,
    /// The fixed spend's share per transaction at `target_transactions`.
    pub shared_sats: u64,
    /// Minimum `fee_sats` for a transaction of `weight` WU: its own weight only.
    pub floor_sat_per_kwu: u64,
    /// Suggested `fee_sats` for typical transactions (own weight plus the shared part).
    pub deposit_sats: u64,
    pub transfer_sats: u64,
    pub withdrawal_sats: u64,
}

/// Upper-bound weights of typical transactions (`pr_mempool::entry_weight` of a one-input deposit
/// with self ciphertexts, a transfer with one ML-KEM recipient, a one-output withdrawal).
pub const TYPICAL_DEPOSIT_WEIGHT: u64 = 1_000;
pub const TYPICAL_TRANSFER_WEIGHT: u64 = 1_650;
pub const TYPICAL_WITHDRAWAL_WEIGHT: u64 = 900;

pub fn quote(sat_per_vb: f64, target_transactions: usize) -> FeeQuote {
    let target = target_transactions.max(1);
    let shared = fee_for_weight(EMPTY_SETTLEMENT_WEIGHT, sat_per_vb).div_ceil(target as u64);
    let price = |w| shared + fee_for_weight(w, sat_per_vb);
    FeeQuote {
        sat_per_vb,
        target_transactions: target,
        empty_settlement_weight: EMPTY_SETTLEMENT_WEIGHT,
        shared_sats: shared,
        floor_sat_per_kwu: fee_for_weight(1_000, sat_per_vb),
        deposit_sats: price(TYPICAL_DEPOSIT_WEIGHT),
        transfer_sats: price(TYPICAL_TRANSFER_WEIGHT),
        withdrawal_sats: price(TYPICAL_WITHDRAWAL_WEIGHT),
    }
}

/// The admission floor: a transaction must at least pay for its own weight.
pub fn admission_floor(entry_weight: u64, sat_per_vb: f64) -> u64 {
    fee_for_weight(entry_weight, sat_per_vb)
}

/// How a proven settlement splits its fees.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeePlan {
    /// Upper bound on the settlement's weight.
    pub weight: u64,
    pub fees: u64,
    pub miner_fee: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shortfall {
    pub fees: u64,
    pub required: u64,
}

/// Prices a settlement whose selected transactions and escrows weigh `content_weight` (upper
/// bounds) and pay `fees`. Fails if `fees` do not cover the whole settlement at `sat_per_vb`.
pub fn plan(content_weight: u64, fees: u64, sat_per_vb: f64) -> Result<FeePlan, Shortfall> {
    let weight = EMPTY_SETTLEMENT_WEIGHT + content_weight;
    let required = fee_for_weight(weight, sat_per_vb);
    if fees < required {
        return Err(Shortfall { fees, required });
    }
    Ok(FeePlan { weight, fees, miner_fee: fees })
}

/// When to start proving: never with nothing to settle unless `min_transactions == 0`, only when
/// the fees cover the settlement, and then once the batch is full (count or weight) or its oldest
/// transaction has waited `max_wait_secs`.
#[derive(Clone, Debug)]
pub struct SettlePolicy {
    pub min_transactions: usize,
    pub target_transactions: usize,
    pub max_wait_secs: u64,
}

impl SettlePolicy {
    pub fn ready(&self, pending: usize, content_weight: u64, covered: bool, oldest_age_secs: u64) -> bool {
        if pending < self.min_transactions.max(1) && !(self.min_transactions == 0 && covered) {
            return false;
        }
        let full = pending >= self.target_transactions
            || content_weight + TYPICAL_TRANSFER_WEIGHT > MAX_SETTLEMENT_WEIGHT - EMPTY_SETTLEMENT_WEIGHT;
        covered && (full || oldest_age_secs >= self.max_wait_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fees_round_up_and_scale_with_feerate() {
        assert_eq!(fee_for_weight(4, 1.0), 1);
        assert_eq!(fee_for_weight(5, 1.0), 2);
        assert_eq!(fee_for_weight(EMPTY_SETTLEMENT_WEIGHT, 10.0), 830_000);
        assert_eq!(fee_for_weight(1_000, 2.5), 625);
    }

    #[test]
    fn quote_shares_the_verifier_spend() {
        let q = quote(10.0, 16);
        assert_eq!(q.shared_sats, 830_000 / 16);
        assert_eq!(quote(10.0, 3).shared_sats, 276_667);
        assert_eq!(q.deposit_sats, q.shared_sats + 2_500);
        assert!(q.transfer_sats > q.deposit_sats);
        assert_eq!(quote(10.0, 0).target_transactions, 1);
    }

    #[test]
    fn shortfall_surplus_and_dust() {
        let required = fee_for_weight(EMPTY_SETTLEMENT_WEIGHT + 2_000, 2.0);
        assert_eq!(plan(2_000, required - 1, 2.0), Err(Shortfall { fees: required - 1, required }));
        assert_eq!(plan(2_000, required, 2.0).unwrap().miner_fee, required);
        assert_eq!(plan(2_000, required + 10_000, 2.0).unwrap().miner_fee, required + 10_000);
    }

    #[test]
    fn settle_policy() {
        let p = SettlePolicy { min_transactions: 1, target_transactions: 4, max_wait_secs: 600 };
        assert!(!p.ready(0, 0, true, 10_000), "never empty");
        assert!(!p.ready(4, 4_000, false, 10_000), "never under-paid");
        assert!(!p.ready(2, 2_000, true, 10), "waits for more");
        assert!(p.ready(4, 4_000, true, 10), "full by count");
        assert!(p.ready(2, 67_000, true, 10), "full by weight");
        assert!(p.ready(1, 1_000, true, 600), "oldest waited long enough");
        let empty_ok = SettlePolicy { min_transactions: 0, ..p };
        assert!(empty_ok.ready(0, 0, true, 600));
    }
}
