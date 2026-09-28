//! GSR adaptations. The upstream verifier constructs the relation; this module
//! supplies unsigned arithmetic and a shared compilation session.
use crate::{
    bitcoin_system::{BitcoinSystem, BitcoinSystemRef},
    treepp::*,
};
use std::{cell::RefCell, rc::Rc};

thread_local! { static SESSION: RefCell<Option<BitcoinSystemRef>> = const { RefCell::new(None) }; }
pub fn current() -> Option<BitcoinSystemRef> {
    SESSION.with(|s| s.borrow().clone())
}
pub fn enabled() -> bool {
    current().is_some()
}
pub fn capture<T>(f: impl FnOnce() -> anyhow::Result<T>) -> anyhow::Result<(BitcoinSystemRef, T)> {
    assert!(!enabled(), "nested GSR compilation");
    reset_metrics();
    let cs = BitcoinSystemRef(Rc::new(RefCell::new(BitcoinSystem::new())));
    SESSION.with(|s| *s.borrow_mut() = Some(cs.clone()));
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            SESSION.with(|s| *s.borrow_mut() = None);
        }
    }
    let _reset = Reset;
    Ok((cs, f()?))
}
pub const P: u32 = 0x7fff_ffff;
pub fn add() -> Script {
    script! { OP_ADD {P} OP_MOD }
}
pub fn sub() -> Script {
    script! { OP_SWAP {P} OP_ADD OP_SWAP OP_SUB {P} OP_MOD }
}
pub fn mul() -> Script {
    script! { OP_MUL {P} OP_MOD }
}
pub fn neg() -> Script {
    script! { {P} OP_SWAP OP_SUB {P} OP_MOD }
}
/// Input is a canonical unsigned M31. Bitcoin's legacy signed-magnitude
/// encoding appends a sign byte iff the most significant byte has bit 7 set.
pub fn encode_hash_field() -> Script {
    script! { OP_DUP 1 OP_RIGHT {128u32} OP_GREATERTHANOREQUAL
    OP_IF {vec![0u8]} OP_CAT OP_ENDIF }
}
pub fn unsigned_bytes(value: u32) -> Vec<u8> {
    let mut bytes = value.to_le_bytes().to_vec();
    while bytes.last() == Some(&0) {
        bytes.pop();
    }
    bytes
}

pub fn trace_len(cs: &BitcoinSystemRef) -> usize {
    cs.0.borrow().trace.len()
}
thread_local! { static LOCAL_DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }
pub fn compact() -> bool {
    enabled() && LOCAL_DEPTH.with(|d| d.get() == 0)
}
/// Lower a small arithmetic routine in a local symbolic frame. Its inputs are
/// runtime stack values; dummy host values only determine output types.
pub fn local<T>(f: impl FnOnce(BitcoinSystemRef) -> T) -> T {
    let cs = BitcoinSystemRef(Rc::new(RefCell::new(BitcoinSystem::new())));
    let old = SESSION.with(|s| s.replace(Some(cs.clone())));
    LOCAL_DEPTH.with(|d| d.set(d.get() + 1));
    struct Restore(Option<BitcoinSystemRef>);
    impl Drop for Restore {
        fn drop(&mut self) {
            SESSION.with(|s| s.replace(self.0.take()));
            LOCAL_DEPTH.with(|d| d.set(d.get() - 1));
        }
    }
    let _restore = Restore(old);
    f(cs)
}
thread_local! {
    static COUNTS: RefCell<std::collections::BTreeMap<String,u64>> = RefCell::new(std::collections::BTreeMap::new());
    static SECTIONS: RefCell<Vec<(usize,String)>> = const { RefCell::new(Vec::new()) };
    static STAGES: RefCell<Vec<std::collections::BTreeMap<String,u64>>> = const { RefCell::new(Vec::new()) };
}
pub fn count(name: &str) {
    if compact() {
        COUNTS.with(|c| *c.borrow_mut().entry(name.into()).or_default() += 1);
    }
}
pub fn counts() -> std::collections::BTreeMap<String, u64> {
    COUNTS.with(|c| c.borrow().clone())
}
pub fn section(name: impl Into<String>) {
    SECTIONS.with(|s| {
        s.borrow_mut()
            .push((trace_len(&current().unwrap()), name.into()))
    });
}
pub fn sections() -> Vec<(usize, String)> {
    SECTIONS.with(|s| s.borrow().clone())
}
pub fn stage() {
    STAGES.with(|s| s.borrow_mut().push(counts()));
}
pub fn stages() -> Vec<std::collections::BTreeMap<String, u64>> {
    STAGES.with(|s| s.borrow().clone())
}
fn reset_metrics() {
    LABELS.with(|l| l.borrow_mut().clear());
    COUNTS.with(|c| c.borrow_mut().clear());
    SECTIONS.with(|s| s.borrow_mut().clear());
    STAGES.with(|s| s.borrow_mut().clear());
}
thread_local! {static LABELS: RefCell<std::collections::BTreeMap<usize,Vec<String>>> = RefCell::new(std::collections::BTreeMap::new());}
pub fn label(ids: impl IntoIterator<Item = usize>, name: impl Into<String>) {
    if !compact() {
        return;
    }
    let name = name.into();
    LABELS.with(|l| {
        let mut l = l.borrow_mut();
        for id in ids {
            l.entry(id).or_default().push(name.clone());
        }
    });
}
pub fn labels(id: usize) -> Vec<String> {
    LABELS.with(|l| l.borrow().get(&id).cloned().unwrap_or_default())
}
