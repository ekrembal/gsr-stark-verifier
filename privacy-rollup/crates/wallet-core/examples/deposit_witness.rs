//! Writes a Prover.toml for a deposit join-split into an empty tree (argv[1]).
use pr_commitment_tree::Tree;
use pr_protocol_types::{DepositDeclaration, Fe, Outpoint};
use pr_wallet_core::{JoinSplitBuilder, Keys, OutputSpec, ProverToml, SpendInput};

fn main() {
    let mut rng = rand_core::OsRng;
    let alice = Keys::from_seed(&[1; 32]);
    let tree = Tree::new();
    let b = JoinSplitBuilder {
        rollup_id: Fe::from_u64(42),
        anchor_root: tree.root(),
        anchor_commitment_count: 0,
        anchor_batch_number: 0,
        expiry_batch_number: 10,
        deposit: Some((
            DepositDeclaration { funding: vec![Outpoint { txid: [7; 32], vout: 0 }], change: None },
            100_000,
        )),
        withdrawal: None,
        fee_sats: 500,
    };
    let built = b
        .build(
            &mut rng,
            [SpendInput::Dummy, SpendInput::Dummy],
            [
                OutputSpec { value: 99_500, recipient: alice.address(), memo: [0; 32] },
                OutputSpec { value: 0, recipient: alice.address(), memo: [0; 32] },
            ],
        )
        .unwrap();
    std::fs::write(std::env::args().nth(1).unwrap(), built.witness.prover_toml()).unwrap();
}
