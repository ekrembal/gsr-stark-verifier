//! The settlement guest: checks every join-split of a batch, the predecessor settlement, applies
//! the state transition, and commits the 196-byte `BatchJournal` that the GSR covenant rebuilds
//! from `OP_TX`.
//!
//! Input frames: `postcard(BatchWitness)`, then the predecessor proof mode.
//!
//! Join-splits are not re-proven here: the user proved each with the `joinsplit` guest, and this
//! guest requires that receipt as an assumption (`env::verify` on the statement's canonical
//! encoding). The operator supplies the receipts with `ExecutorEnv::add_assumption`, and recursion
//! (`resolve_zk`) discharges them, so the final receipt is unconditional. The join-split image ID
//! is compiled in.
//!
//! Lineage: unless the old state is the descriptor's genesis, `apply_batch` returns the journal the
//! previous settlement must have committed, and this guest requires an `apply_batch` receipt for it
//! (under `descriptor.image_id`, which `rollup_id` and so the covenant fix). The second frame picks
//! how: empty, as an assumption (discharged on the host with the previous settlement's poseidon2
//! receipt via `resolve`); or `0x01 || postcard(SuccinctReceipt)`, the previous settlement's
//! on-chain `sha-256-padded` receipt verified inline, which anyone can rebuild from the chain.
use pr_protocol_types::Canonical;
use pr_state_transition::{apply_batch, BatchWitness};
use risc0_zkvm::{
    digest, guest::env, sha::Digest, sha::Digestible, ReceiptClaim, SuccinctReceipt,
    SuccinctReceiptVerifierParameters, VerifierContext,
};

const JOINSPLIT_ID: [u32; 8] = include!("../joinsplit_id.rs");

/// Recursion programs allowed in an on-chain settlement receipt (the padded-SHA control root).
const SETTLEMENT_CONTROL_ROOT: Digest =
    digest!("ad38413aec70f8b75cb9eddffe2185168a942fa0883c4da459a81208b18bffe4");
const SETTLEMENT_INNER_CONTROL_ROOT: Digest =
    digest!("5edc9538daecff76cae54c2228303261edeeb93ecb9a5547b250fa2c550a5b01");
const SEAL_MODE: u8 = 1;

fn main() {
    let witness: BatchWitness = postcard::from_bytes(&env::read_frame()).expect("batch witness");
    let mode = env::read_frame();
    for t in &witness.transactions {
        env::verify(JOINSPLIT_ID, &t.public.encode()).expect("join-split receipt");
    }
    let effects = apply_batch(&witness).expect("state transition");
    if let Some(l) = &effects.lineage {
        let image = Digest::from_bytes(l.image_id);
        let journal = l.journal.encode();
        match mode.split_first() {
            None => env::verify(image, &journal).expect("predecessor receipt"),
            Some((&SEAL_MODE, rest)) => {
                let r: SuccinctReceipt<ReceiptClaim> = postcard::from_bytes(rest).expect("predecessor seal");
                assert_eq!(r.hashfn, "sha-256-padded", "predecessor seal hash");
                let mut params = SuccinctReceiptVerifierParameters::default();
                params.control_root = SETTLEMENT_CONTROL_ROOT;
                params.inner_control_root = Some(SETTLEMENT_INNER_CONTROL_ROOT);
                let ctx = VerifierContext::empty()
                    .with_suites(VerifierContext::default_hash_suites())
                    .with_succinct_verifier_parameters(params);
                r.verify_integrity_with_context(&ctx).expect("predecessor seal");
                assert_eq!(r.claim.digest(), ReceiptClaim::ok(image, journal).digest(), "predecessor claim");
            }
            _ => panic!("predecessor proof mode"),
        }
    }
    env::commit_slice(&effects.journal.encode());
}
