//! Profile-independent extension-field function bodies.
use super::{cm31::CM31Bar, m31::M31Bar, qm31::QM31Bar, table::TableBar};
use recursive_stwo_bitcoin_dsl::{bar::AllocBar, compiler::Compiler, gsr, treepp::Script};
use std::sync::OnceLock;
use stwo_prover::core::fields::{cm31::CM31, m31::M31, qm31::QM31};
macro_rules! routine {
    ($name:ident,$build:expr) => {
        pub fn $name() -> Script {
            static BODY: OnceLock<Script> = OnceLock::new();
            BODY.get_or_init(|| {
                gsr::local(|cs| {
                    let result = ($build)(&cs);
                    cs.set_program_output(&result).unwrap();
                    Compiler::compile(cs).unwrap().script
                })
            })
            .clone()
        }
    };
}
fn q(cs: &recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef) -> QM31Bar {
    QM31Bar::new_program_input(cs, QM31::from_u32_unchecked(1, 2, 3, 4)).unwrap()
}
fn c(cs: &recursive_stwo_bitcoin_dsl::bitcoin_system::BitcoinSystemRef) -> CM31Bar {
    CM31Bar::new_program_input(cs, CM31::from_u32_unchecked(1, 2)).unwrap()
}
routine!(qadd, |cs| {
    let a = q(cs);
    let b = q(cs);
    &a + &b
});
routine!(qsub, |cs| {
    let a = q(cs);
    let b = q(cs);
    &a - &b
});
routine!(qmul, |cs| {
    let a = q(cs);
    let b = q(cs);
    &a * &b
});
routine!(qneg, |cs| {
    let a = q(cs);
    -&a
});
routine!(cadd, |cs| {
    let a = c(cs);
    let b = c(cs);
    &a + &b
});
routine!(csub, |cs| {
    let a = c(cs);
    let b = c(cs);
    &a - &b
});
routine!(cmul, |cs| {
    let a = c(cs);
    let b = c(cs);
    &a * &b
});
routine!(qscalar, |cs| {
    let a = q(cs);
    let b = M31Bar::new_program_input(cs, M31(2)).unwrap();
    let table = TableBar::new_constant(cs, ()).unwrap();
    &a * (&table, &b)
});
