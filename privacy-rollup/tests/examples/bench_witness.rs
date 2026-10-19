//! `bench_witness <out-dir> [n..]` writes settlement witnesses for proving benchmarks: for each `n`,
//! `deposit-<n>.json` (n deposits, 2 notes each) and `transfer-<n>.json` (n shielded transfers that
//! each spend two notes, so 2n nullifiers and 2n commitments).
use pr_protocol_types::TxOut;
use pr_tests::{coin, Harness, Wallet};
use pr_wallet_core::SpendInput;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let out = std::path::Path::new(a.get(1).expect("usage: bench_witness <out-dir> [n..]"));
    std::fs::create_dir_all(out).expect("out dir");
    let sizes: Vec<usize> = if a.len() > 2 {
        a[2..].iter().map(|s| s.parse().expect("batch size")).collect()
    } else {
        vec![1, 2, 4, 8, 16]
    };
    for n in sizes {
        let mut h = Harness::new();
        let mut wallets: Vec<Wallet> = (0..n).map(|i| Wallet::new(10 + i as u8)).collect();
        for (i, w) in wallets.iter().enumerate() {
            let tag = 0x40 + i as u8;
            let funding = vec![coin(tag, 61_000)];
            let change = TxOut { value: 1_000, script_pubkey: vec![0x51, 0x20, tag] };
            let b = h.deposit_builder(1_000, &funding, 60_000, Some(change));
            let js = h.build(&b, [SpendInput::Dummy, SpendInput::Dummy], [w.pay(30_000), w.pay(29_000)]);
            h.submit(&js, funding).expect("deposit admitted");
        }
        let e = h.settle().expect("deposit batch");
        let w = h.last_witness.clone().expect("witness");
        assert_eq!(w.transactions.len(), n, "deposit batch size");
        std::fs::write(out.join(format!("deposit-{n}.json")), serde_json::to_string(&w).expect("json")).expect("write");
        for w in &mut wallets {
            w.scan(&h.replica, &e);
        }
        for (i, w) in wallets.iter().enumerate() {
            let to = Wallet::new(200 + i as u8);
            let b = h.builder(1_000);
            let (n0, n1) = (w.notes[0].clone(), w.notes[1].clone());
            let js = h.build(&b, [w.spend(&h.replica, &n0), w.spend(&h.replica, &n1)], [to.pay(40_000), w.pay(18_000)]);
            h.submit(&js, vec![]).expect("transfer admitted");
        }
        h.settle().expect("transfer batch");
        let w = h.last_witness.clone().expect("witness");
        assert_eq!(w.transactions.len(), n, "transfer batch size");
        std::fs::write(out.join(format!("transfer-{n}.json")), serde_json::to_string(&w).expect("json"))
            .expect("write");
        println!("n={n}: deposit and transfer witnesses written");
    }
}
