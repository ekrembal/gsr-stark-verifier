//! Minimal wallet CLI for the regtest demo.
//!
//! `pr-wallet deposit <status.json> <txid-hex> <vout> <amount> <spk-hex> <fee-sats> <seed-byte> <out-dir>`
//!
//! Builds a deposit join-split anchored at the tip in `status.json` (`pr-operator status`), funded
//! by one coin (txid hex in serialization order) whose whole `amount` is deposited, paying
//! `amount - fee` to the wallet derived from `seed-byte`. Writes `witness.json` (the private
//! `JoinSplitWitness`, input of `joinsplit prove`; it never leaves the wallet), `external.json`
//! (the transaction's `ExternalData`) and `funding.json` (for `pr-operator submit`).
//!
//! `pr-wallet tx <dir>` assembles `<dir>/tx.json` (the `RollupTransaction` sent to the operator)
//! from `witness.json`'s public statement, `external.json` and the `receipt.bin` written by
//! `joinsplit prove`.
use std::{fs, path::Path};

use pr_joinsplit::JoinSplitWitness;
use pr_protocol_types::{DepositDeclaration, ExternalData, Fe, Outpoint, RollupTransaction};
use pr_wallet_core::{JoinSplitBuilder, Keys, OutputSpec, SpendInput};

fn fe(hex_str: &str) -> Fe {
    Fe(hex::decode(hex_str).expect("hex").try_into().expect("32 bytes"))
}

fn tx(dir: &Path) {
    let witness: JoinSplitWitness =
        serde_json::from_slice(&fs::read(dir.join("witness.json")).expect("witness")).expect("witness json");
    let external: ExternalData =
        serde_json::from_slice(&fs::read(dir.join("external.json")).expect("external")).expect("external json");
    let receipt = fs::read(dir.join("receipt.bin")).expect("receipt.bin");
    let tx = RollupTransaction { public: witness.public, external, receipt };
    fs::write(dir.join("tx.json"), serde_json::to_vec(&tx).expect("tx")).expect("write");
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() == 3 && a[1] == "tx" {
        return tx(Path::new(&a[2]));
    }
    assert!(
        a.len() == 10 && a[1] == "deposit",
        "usage: pr-wallet deposit <status.json> <txid> <vout> <amount> <spk> <fee> <seed> <out-dir> | tx <dir>"
    );
    let status: serde_json::Value = serde_json::from_slice(&fs::read(&a[2]).expect("status")).expect("status json");
    let txid: [u8; 32] = hex::decode(&a[3]).expect("txid hex").try_into().expect("txid length");
    let vout: u32 = a[4].parse().expect("vout");
    let (deposit, fee): (u64, u64) = (a[5].parse().expect("amount"), a[7].parse().expect("fee"));
    let keys = Keys::from_seed(&[a[8].parse::<u8>().expect("seed byte"); 32]);
    let anchor = &status["anchor"];
    let batch = status["batch_number"].as_u64().expect("batch_number");
    let b = JoinSplitBuilder {
        rollup_id: fe(status["rollup_id"].as_str().expect("rollup_id")),
        anchor_root: fe(anchor["root"].as_str().expect("anchor root")),
        anchor_commitment_count: anchor["commitment_count"].as_u64().expect("anchor count"),
        anchor_batch_number: anchor["batch_number"].as_u64().expect("anchor batch"),
        expiry_batch_number: batch + 10,
        deposit: Some((DepositDeclaration { funding: vec![Outpoint { txid, vout }], change: None }, deposit)),
        withdrawal: None,
        fee_sats: fee,
    };
    let built = b
        .build(
            &mut rand_core::OsRng,
            [SpendInput::Dummy, SpendInput::Dummy],
            [
                OutputSpec { value: deposit - fee, recipient: keys.address(), memo: [0; 32] },
                OutputSpec { value: 0, recipient: keys.address(), memo: [0; 32] },
            ],
        )
        .expect("valid join-split");
    let out = Path::new(&a[9]);
    fs::create_dir_all(out).expect("out dir");
    fs::write(out.join("witness.json"), serde_json::to_vec(&built.witness).expect("witness")).expect("write");
    fs::write(out.join("external.json"), serde_json::to_vec(&built.external).expect("external")).expect("write");
    let funding = serde_json::json!([{
        "outpoint": Outpoint { txid, vout },
        "amount": deposit,
        "script_pubkey": hex::decode(&a[6]).expect("spk hex"),
    }]);
    fs::write(out.join("funding.json"), serde_json::to_vec(&funding).expect("funding")).expect("write");
}
