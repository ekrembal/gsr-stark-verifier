//! JSON types of the `pr-batcher` HTTP API (`/v1/...`). Hex strings are in serialization byte
//! order; field elements are 32-byte big-endian hex.
use pr_mempool::FundingCoin;
use pr_protocol_types::{Fe, NoteOutput};
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
