//! JSON types of the `pr-batcher` HTTP API (`/v1/...`). Hex strings are in serialization byte
//! order; field elements are 32-byte big-endian hex.
use pr_mempool::FundingCoin;
use pr_protocol_types::{Fe, NoteOutput};
use pr_state_transition::escrow::EscrowDeposit;
use serde::{Deserialize, Serialize};

/// The anchor new join-splits prove membership against.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Anchor {
    pub root: String,
    pub commitment_count: u64,
    pub batch_number: u64,
}

/// `GET /v1/status`: the settled tip and the pool size.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub anchor: Anchor,
    pub rollup_id: String,
    pub batch_number: u64,
    pub state_root: String,
    pub commitment_count: u64,
    pub nullifier_next_index: u64,
    pub backing_sats: u64,
    /// Rollup outpoint: (txid, vout).
    pub utxo: (String, u32),
    pub pending: usize,
}

/// A coin a deposit spends, with the witness stack (hex items) that unlocks it. The batcher
/// places it unchanged in the settlement, so it must not sign the settlement's sighash; it is
/// meant for anyone-can-spend-to-the-batcher scripts such as `P2WSH(OP_TRUE)` on regtest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FundingInput {
    pub coin: FundingCoin,
    pub witness: Vec<String>,
}

/// `POST /v1/transactions`: a proven transaction. It carries no private witness data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Submission {
    /// Canonical `RollupTransaction` encoding (statement, external data, receipt), hex.
    pub transaction: String,
    #[serde(default)]
    pub funding: Vec<FundingInput>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitResponse {
    pub pending: usize,
}

/// One settled batch's outputs as wallets scan them: output `k` is leaf `first_leaf + k`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteBatch {
    pub batch_number: u64,
    pub first_leaf: u64,
    pub outputs: Vec<NoteOutput>,
}

/// `GET /v1/notes?from=<batch>`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notes {
    pub batches: Vec<NoteBatch>,
}

/// `GET /v1/paths/<leaf>`: membership path of a leaf against the current anchor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerklePath {
    pub leaf: u64,
    pub commitment: Fe,
    pub anchor: Anchor,
    pub siblings: Vec<Fe>,
}

/// Stage of a settlement attempt, in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Proving,
    Witness,
    Broadcast,
    Confirmed,
    Failed,
}

/// `GET /v1/batches/<n>`: a settlement attempt.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BatchReport {
    pub batch_number: u64,
    pub stage: Stage,
    pub transactions: usize,
    pub txid: Option<String>,
    pub block_hash: Option<String>,
    pub error: Option<String>,
    /// `pr_prover::settle::SettlementStats` once proven.
    pub prove: Option<serde_json::Value>,
    pub weight: Option<u64>,
    /// `pr_batcher::fees::FeePlan` of the proven settlement.
    #[serde(default)]
    pub fees: Option<serde_json::Value>,
    pub started_unix: u64,
    pub finished_unix: Option<u64>,
}

/// `POST /v1/batches`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettleResponse {
    pub batch_number: u64,
}

/// Error body of every non-2xx response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
}

/// `GET /v1/escrow`: how to build a deposit address for this rollup. `body` is the sweep body
/// (`tools/covenant_cli.py escrow-body`); the batcher sweeps an escrow once it has `confirmations`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscrowTerms {
    pub rollup_id: String,
    pub body: String,
    pub confirmations: u64,
    /// Smallest refund delay (blocks) the batcher accepts, so it has time to sweep.
    pub min_refund_delay: u16,
}

/// `POST /v1/escrows`: a paid deposit address and its opening. The opening reveals the minted
/// note's authority, randomness and value to the batcher, as a deposit's amount is public anyway.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscrowRegistration {
    /// Funding outpoint: (txid, vout).
    pub outpoint: (String, u32),
    pub opening: EscrowDeposit,
    /// The address's refund leaf (hex), whose leaf hash is `opening.sibling`.
    pub refund_leaf: String,
}

/// One registered escrow as the batcher sees it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscrowState {
    pub outpoint: (String, u32),
    pub amount: u64,
    pub confirmations: u64,
    /// Batch whose in-flight settlement sweeps it.
    pub reserved_by: Option<u64>,
}
