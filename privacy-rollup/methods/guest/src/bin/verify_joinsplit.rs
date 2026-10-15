//! Verifies one ProveKit join-split proof and commits its public inputs.
use std::{collections::BTreeMap, sync::Mutex};

use provekit_common::{NoirProof, Verifier};
use provekit_verifier::Verify;
use risc0_zkvm::guest::env;
use tracing::{span, Event, Id, Metadata, Subscriber};

#[derive(Default)]
struct Profile {
    names: Vec<&'static str>,
    stack: Vec<(usize, u64)>,
    totals: BTreeMap<&'static str, (u64, u64)>,
}

struct CycleSub(&'static Mutex<Profile>);

impl Subscriber for CycleSub {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, a: &span::Attributes<'_>) -> Id {
        let mut p = self.0.lock().unwrap();
        p.names.push(a.metadata().name());
        Id::from_u64(p.names.len() as u64)
    }
    fn record(&self, _: &Id, _: &span::Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, _: &Event<'_>) {}
    fn enter(&self, id: &Id) {
        self.0.lock().unwrap().stack.push((id.into_u64() as usize, env::cycle_count()));
    }
    fn exit(&self, _: &Id) {
        let now = env::cycle_count();
        let mut p = self.0.lock().unwrap();
        let (i, t) = p.stack.pop().unwrap();
        let name = p.names[i - 1];
        let e = p.totals.entry(name).or_default();
        e.0 += now - t;
        e.1 += 1;
    }
}

static PROFILE: Mutex<Profile> = Mutex::new(Profile { names: Vec::new(), stack: Vec::new(), totals: BTreeMap::new() });

fn bench() {
    use ark_ff::Field;
    let mut a = ark_bn254::Fr::from(123456789u64);
    let b = a.square().square();
    let t = env::cycle_count();
    for _ in 0..1000 {
        a *= b;
    }
    eprintln!("ark mul: {} cycles", (env::cycle_count() - t) / 1000);
    let t = env::cycle_count();
    for _ in 0..1000 {
        a += b;
    }
    eprintln!("ark add: {} cycles", (env::cycle_count() - t) / 1000);
    let m = [0xf0000001u32, 0x43e1f593, 0x79b97091, 0x2833e848, 0x8181585d, 0xb85045b6, 0xe131a029, 0x30644e72];
    let mut x = [5u32; 8];
    let y = [7u32; 8];
    let mut r = [0u32; 8];
    let t = env::cycle_count();
    for _ in 0..1000 {
        risc0_bigint2::field::modmul_256(&x, &y, &m, &mut r);
        x = r;
    }
    eprintln!("bigint2 modmul: {} cycles", (env::cycle_count() - t) / 1000);
    core::hint::black_box(a);
    use ark_ff::fields::MontConfig;
    let mut x = ark_bn254::Fr::from(0xdead_beef_u64).square().square().square();
    let mut y = -ark_bn254::Fr::from(7u64).inverse().unwrap();
    for _ in 0..200 {
        let mut s = x;
        <ark_bn254::FrConfig as MontConfig<4>>::mul_assign(&mut s, &y);
        let mut sq = x;
        <ark_bn254::FrConfig as MontConfig<4>>::square_in_place(&mut sq);
        assert_eq!(x * y, s);
        assert_eq!(x.square(), sq);
        y = x;
        x = s + sq;
    }
    eprintln!("accelerated mul matches software CIOS");
}

fn main() {
    bench();
    tracing::subscriber::set_global_default(CycleSub(&PROFILE)).unwrap();
    let t0 = env::cycle_count();
    let vk = env::read_frame();
    let proof = env::read_frame();
    let t1 = env::cycle_count();
    let mut verifier: Verifier = postcard::from_bytes(&vk).expect("verifier key");
    let proof: NoirProof = postcard::from_bytes(&proof).expect("proof");
    let t2 = env::cycle_count();
    eprintln!("read {} deserialize {}", t1 - t0, t2 - t1);
    verifier.verify(&proof).expect("join-split proof");
    eprintln!("verify cycles: {}", env::cycle_count() - t2);
    for (n, (c, k)) in &PROFILE.lock().unwrap().totals {
        eprintln!("span {n}: {c} cycles over {k} entries");
    }
    env::commit(&proof.public_inputs.0.len());
}
