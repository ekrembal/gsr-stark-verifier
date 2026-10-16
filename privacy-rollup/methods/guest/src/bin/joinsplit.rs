//! The user-side join-split guest: checks every constraint of `circuits/joinsplit-2x2` on the
//! private witness and commits only the canonical `JoinSplitPublic` encoding as its journal.
//!
//! Input frame: `postcard(JoinSplitWitness)`. The rollup's `apply_batch` guest consumes the
//! resulting receipt as an assumption via `env::verify(JOINSPLIT_ID, &public.encode())`.
use pr_joinsplit::JoinSplitWitness;
use pr_protocol_types::Canonical;
use risc0_zkvm::guest::env;

fn main() {
    let witness: JoinSplitWitness = postcard::from_bytes(&env::read_frame()).expect("join-split witness");
    witness.check().expect("join-split constraints");
    env::commit_slice(&witness.public.encode());
}
