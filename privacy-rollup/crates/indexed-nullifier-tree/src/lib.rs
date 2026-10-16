//! Depth-32 indexed (sorted linked-list) SHA-256 Merkle tree of spent nullifiers.
//!
//! Leaf `i` is `(value, next_index, next_value)`; the leaves form a list sorted by `value`, with
//! `next_value = 0` meaning "no successor". Leaf 0 is the zero sentinel, so nullifier 0 is reserved.
//! Insertion of `v` is authenticated by the predecessor ("low") leaf, which proves `v` is absent.
use std::collections::{BTreeMap, HashMap};
use std::sync::OnceLock;

use pr_protocol_types::hash::{tagged, tags};
use pr_protocol_types::{Fe, NULLIFIER_TREE_DEPTH as DEPTH};
use serde::{Deserialize, Serialize};

pub type Hash = [u8; 32];
pub const CAPACITY: u64 = 1 << DEPTH;
pub const EMPTY: Hash = [0; 32];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Leaf {
    pub value: Fe,
    pub next_index: u64,
    pub next_value: Fe,
}

impl Leaf {
    pub fn hash(&self) -> Hash {
        tagged(tags::NULLIFIER_LEAF, &[&self.value.0, &self.next_index.to_le_bytes(), &self.next_value.0])
    }
    /// `v` lies strictly inside this leaf's interval, so it is not in the tree.
    pub fn brackets(&self, v: &Fe) -> bool {
        self.value < *v && (self.next_value.is_zero() || *v < self.next_value)
    }
}

pub fn node(l: &Hash, r: &Hash) -> Hash {
    tagged(tags::NULLIFIER_NODE, &[l, r])
}

pub fn empty_hashes() -> &'static [Hash; DEPTH + 1] {
    static E: OnceLock<[Hash; DEPTH + 1]> = OnceLock::new();
    E.get_or_init(|| {
        let mut e = [EMPTY; DEPTH + 1];
        for i in 0..DEPTH {
            e[i + 1] = node(&e[i], &e[i]);
        }
        e
    })
}

pub fn root_from_path(leaf: &Hash, index: u64, siblings: &[Hash]) -> Hash {
    let mut n = *leaf;
    for (i, s) in siblings.iter().enumerate() {
        n = if (index >> i) & 1 == 1 { node(s, &n) } else { node(&n, s) };
    }
    n
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NullifierError {
    ZeroNullifier,
    NotBracketed,
    LowLeafMismatch,
    SlotNotEmpty,
    BadIndex,
    BadPath,
    Full,
    Duplicate,
    /// The low-leaf runs of a batch witness do not cover the batch exactly.
    Coverage,
}

/// Witness for inserting one value into the tree with root `root` and `next_index` leaves.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InsertionWitness {
    pub low_index: u64,
    pub low_leaf: Leaf,
    pub low_path: Vec<Hash>,
    /// Path of the empty slot `next_index`, against the root after the low leaf is updated.
    pub new_path: Vec<Hash>,
}

/// Verifies an insertion and returns the new root. This is the only logic the batch guest trusts.
pub fn verify_insertion(
    root: &Hash,
    next_index: u64,
    value: &Fe,
    w: &InsertionWitness,
) -> Result<Hash, NullifierError> {
    if value.is_zero() {
        return Err(NullifierError::ZeroNullifier);
    }
    if next_index >= CAPACITY {
        return Err(NullifierError::Full);
    }
    if w.low_index >= next_index {
        return Err(NullifierError::BadIndex);
    }
    if w.low_path.len() != DEPTH || w.new_path.len() != DEPTH {
        return Err(NullifierError::BadPath);
    }
    if !w.low_leaf.brackets(value) {
        return Err(if w.low_leaf.value == *value || w.low_leaf.next_value == *value {
            NullifierError::Duplicate
        } else {
            NullifierError::NotBracketed
        });
    }
    if root_from_path(&w.low_leaf.hash(), w.low_index, &w.low_path) != *root {
        return Err(NullifierError::LowLeafMismatch);
    }
    let updated = Leaf { value: w.low_leaf.value, next_index, next_value: *value };
    let mid = root_from_path(&updated.hash(), w.low_index, &w.low_path);
    if root_from_path(&EMPTY, next_index, &w.new_path) != mid {
        return Err(NullifierError::SlotNotEmpty);
    }
    let new_leaf = Leaf { value: *value, next_index: w.low_leaf.next_index, next_value: w.low_leaf.next_value };
    Ok(root_from_path(&new_leaf.hash(), next_index, &w.new_path))
}

/// One pre-existing leaf whose gap receives the next `count` values of a sorted batch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowUpdate {
    pub low_index: u64,
    pub low_leaf: Leaf,
    /// Path of `low_index` against the root after the previous low updates.
    pub path: Vec<Hash>,
    pub count: u32,
}

/// Witness for inserting a sorted batch of values: one path per distinct low leaf, plus the left
/// siblings of slot `next_index` after those updates. The new leaves occupy consecutive slots, so
/// they are appended like a frontier (about two node hashes each) instead of one 32-level path
/// verification and one recomputation per value.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchInsertionWitness {
    pub lows: Vec<LowUpdate>,
    /// Sibling of the slot-`next_index` path at each level; levels where the slot is a left child
    /// must hold the empty-subtree hash.
    pub frontier: Vec<Hash>,
}

/// Root of a tree whose leaves at `count..` are empty, from the left siblings `left[l]` of slot
/// `count` (read only where bit `l` of `count` is set).
fn root_from_left(left: &[Hash], count: u64) -> Hash {
    let e = empty_hashes();
    let mut n = EMPTY;
    let mut empty = true;
    for l in 0..DEPTH {
        if (count >> l) & 1 == 1 {
            n = node(&left[l], &n);
            empty = false;
        } else if empty {
            n = e[l + 1];
        } else {
            n = node(&n, &e[l]);
        }
    }
    n
}

/// Verifies insertion of `values` (strictly increasing) and returns the new root. The resulting
/// tree equals inserting the values one by one in increasing order with [`verify_insertion`].
pub fn verify_batch_insertion(
    root: &Hash,
    next_index: u64,
    values: &[Fe],
    w: &BatchInsertionWitness,
) -> Result<Hash, NullifierError> {
    if values.is_empty() {
        return if w.lows.is_empty() && w.frontier.is_empty() { Ok(*root) } else { Err(NullifierError::Coverage) };
    }
    if values[0].is_zero() {
        return Err(NullifierError::ZeroNullifier);
    }
    if values.windows(2).any(|p| p[0] >= p[1]) {
        return Err(NullifierError::Duplicate);
    }
    let k = values.len() as u64;
    if next_index.checked_add(k).is_none_or(|end| end > CAPACITY) {
        return Err(NullifierError::Full);
    }
    let mut root = *root;
    let mut new_leaves = Vec::with_capacity(values.len());
    let mut j = 0usize;
    for u in &w.lows {
        let end = j.checked_add(u.count as usize).filter(|&e| u.count > 0 && e <= values.len());
        let Some(end) = end else { return Err(NullifierError::Coverage) };
        let run = &values[j..end];
        if u.low_index >= next_index {
            return Err(NullifierError::BadIndex);
        }
        if u.path.len() != DEPTH {
            return Err(NullifierError::BadPath);
        }
        let l = &u.low_leaf;
        if !(l.brackets(&run[0]) && l.brackets(&run[run.len() - 1])) {
            return Err(if run.iter().any(|v| *v == l.value || *v == l.next_value) {
                NullifierError::Duplicate
            } else {
                NullifierError::NotBracketed
            });
        }
        if root_from_path(&l.hash(), u.low_index, &u.path) != root {
            return Err(NullifierError::LowLeafMismatch);
        }
        let updated = Leaf { value: l.value, next_index: next_index + j as u64, next_value: run[0] };
        root = root_from_path(&updated.hash(), u.low_index, &u.path);
        for (i, v) in run.iter().enumerate() {
            let (next_index, next_value) = match run.get(i + 1) {
                Some(n) => (next_index + (j + i + 1) as u64, *n),
                None => (l.next_index, l.next_value),
            };
            new_leaves.push(Leaf { value: *v, next_index, next_value }.hash());
        }
        j = end;
    }
    if j != values.len() {
        return Err(NullifierError::Coverage);
    }
    if w.frontier.len() != DEPTH {
        return Err(NullifierError::BadPath);
    }
    let e = empty_hashes();
    if (0..DEPTH).any(|l| (next_index >> l) & 1 == 0 && w.frontier[l] != e[l]) {
        return Err(NullifierError::SlotNotEmpty);
    }
    if root_from_left(&w.frontier, next_index) != root {
        return Err(NullifierError::SlotNotEmpty);
    }
    let mut left = w.frontier.clone();
    let mut count = next_index;
    for h in new_leaves {
        let mut n = h;
        let mut l = 0;
        while (count >> l) & 1 == 1 {
            n = node(&left[l], &n);
            l += 1;
        }
        left[l] = n;
        count += 1;
    }
    Ok(root_from_left(&left, count))
}

/// Non-membership proof: the low leaf bracketing `value`, with its path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbsenceProof {
    pub low_index: u64,
    pub low_leaf: Leaf,
    pub path: Vec<Hash>,
}

pub fn verify_absence(root: &Hash, value: &Fe, p: &AbsenceProof) -> bool {
    !value.is_zero()
        && p.low_leaf.brackets(value)
        && p.path.len() == DEPTH
        && root_from_path(&p.low_leaf.hash(), p.low_index, &p.path) == *root
}

#[derive(Clone, Debug)]
pub struct IndexedTree {
    nodes: HashMap<(u8, u64), Hash>,
    leaves: Vec<Leaf>,
    by_value: BTreeMap<Fe, u64>,
}

impl Default for IndexedTree {
    fn default() -> Self {
        Self::new()
    }
}

impl IndexedTree {
    /// Genesis tree: the zero sentinel at index 0.
    pub fn new() -> Self {
        let mut t = IndexedTree { nodes: HashMap::new(), leaves: Vec::new(), by_value: BTreeMap::new() };
        t.leaves.push(Leaf::default());
        t.by_value.insert(Fe::ZERO, 0);
        t.write(0, Leaf::default().hash());
        t
    }
    pub fn root(&self) -> Hash {
        self.get(DEPTH, 0)
    }
    pub fn next_index(&self) -> u64 {
        self.leaves.len() as u64
    }
    pub fn contains(&self, v: &Fe) -> bool {
        self.by_value.contains_key(v)
    }
    fn get(&self, level: usize, index: u64) -> Hash {
        self.nodes.get(&(level as u8, index)).copied().unwrap_or(empty_hashes()[level])
    }
    fn write(&mut self, index: u64, leaf_hash: Hash) {
        let mut n = leaf_hash;
        let mut idx = index;
        self.nodes.insert((0, idx), n);
        for level in 0..DEPTH {
            let s = self.get(level, idx ^ 1);
            n = if idx & 1 == 1 { node(&s, &n) } else { node(&n, &s) };
            idx >>= 1;
            self.nodes.insert((level as u8 + 1, idx), n);
        }
    }
    pub fn path(&self, index: u64) -> Vec<Hash> {
        (0..DEPTH).map(|l| self.get(l, (index >> l) ^ 1)).collect()
    }
    fn low_index(&self, v: &Fe) -> u64 {
        *self.by_value.range(..*v).next_back().expect("sentinel").1
    }
    pub fn prove_absence(&self, v: &Fe) -> Option<AbsenceProof> {
        if v.is_zero() || self.contains(v) {
            return None;
        }
        let low_index = self.low_index(v);
        Some(AbsenceProof { low_index, low_leaf: self.leaves[low_index as usize], path: self.path(low_index) })
    }
    pub fn insert(&mut self, v: Fe) -> Result<InsertionWitness, NullifierError> {
        if v.is_zero() {
            return Err(NullifierError::ZeroNullifier);
        }
        if self.contains(&v) {
            return Err(NullifierError::Duplicate);
        }
        let next_index = self.next_index();
        if next_index >= CAPACITY {
            return Err(NullifierError::Full);
        }
        let low_index = self.low_index(&v);
        let low_leaf = self.leaves[low_index as usize];
        let low_path = self.path(low_index);
        let updated = Leaf { value: low_leaf.value, next_index, next_value: v };
        self.leaves[low_index as usize] = updated;
        self.write(low_index, updated.hash());
        let new_path = self.path(next_index);
        let new_leaf = Leaf { value: v, next_index: low_leaf.next_index, next_value: low_leaf.next_value };
        self.leaves.push(new_leaf);
        self.by_value.insert(v, next_index);
        self.write(next_index, new_leaf.hash());
        Ok(InsertionWitness { low_index, low_leaf, low_path, new_path })
    }
    /// Inserts strictly increasing `values` and returns the [`BatchInsertionWitness`] for them.
    pub fn insert_batch(&mut self, values: &[Fe]) -> Result<BatchInsertionWitness, NullifierError> {
        if values.is_empty() {
            return Ok(BatchInsertionWitness::default());
        }
        if values.iter().any(Fe::is_zero) {
            return Err(NullifierError::ZeroNullifier);
        }
        if values.windows(2).any(|p| p[0] >= p[1]) || values.iter().any(|v| self.contains(v)) {
            return Err(NullifierError::Duplicate);
        }
        let start = self.next_index();
        if start + values.len() as u64 > CAPACITY {
            return Err(NullifierError::Full);
        }
        let mut lows = Vec::new();
        let mut new_leaves = Vec::with_capacity(values.len());
        let mut j = 0;
        while j < values.len() {
            let low_index = self.low_index(&values[j]);
            let low_leaf = self.leaves[low_index as usize];
            let count = values[j..].iter().take_while(|v| low_leaf.brackets(v)).count();
            lows.push(LowUpdate { low_index, low_leaf, path: self.path(low_index), count: count as u32 });
            let updated = Leaf { value: low_leaf.value, next_index: start + j as u64, next_value: values[j] };
            self.leaves[low_index as usize] = updated;
            self.write(low_index, updated.hash());
            for i in j..j + count {
                let (next_index, next_value) = if i + 1 < j + count {
                    (start + i as u64 + 1, values[i + 1])
                } else {
                    (low_leaf.next_index, low_leaf.next_value)
                };
                new_leaves.push(Leaf { value: values[i], next_index, next_value });
            }
            j += count;
        }
        let frontier = self.path(start);
        for (i, leaf) in new_leaves.into_iter().enumerate() {
            self.leaves.push(leaf);
            self.by_value.insert(leaf.value, start + i as u64);
            self.write(start + i as u64, leaf.hash());
        }
        Ok(BatchInsertionWitness { lows, frontier })
    }
    /// Rebuilds the tree with only the first `next_index` leaves' insertions (reorg rollback).
    pub fn truncate(&mut self, next_index: u64) {
        let values: Vec<Fe> = self.leaves[1..next_index.max(1) as usize].iter().map(|l| l.value).collect();
        *self = IndexedTree::new();
        for v in values {
            self.insert(v).expect("previously inserted");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insertion_witnesses_verify_in_any_order() {
        let mut t = IndexedTree::new();
        for v in [50u64, 10, 90, 30, 70, 11, 89] {
            let root = t.root();
            let next = t.next_index();
            let w = t.insert(Fe::from_u64(v)).unwrap();
            assert_eq!(verify_insertion(&root, next, &Fe::from_u64(v), &w).unwrap(), t.root());
        }
        for v in [1u64, 20, 95] {
            let p = t.prove_absence(&Fe::from_u64(v)).unwrap();
            assert!(verify_absence(&t.root(), &Fe::from_u64(v), &p));
        }
        assert!(t.prove_absence(&Fe::from_u64(30)).is_none());
    }

    #[test]
    fn rejects_duplicates_and_forgeries() {
        let mut t = IndexedTree::new();
        t.insert(Fe::from_u64(10)).unwrap();
        t.insert(Fe::from_u64(20)).unwrap();
        assert_eq!(t.insert(Fe::from_u64(10)), Err(NullifierError::Duplicate));
        assert_eq!(t.insert(Fe::ZERO), Err(NullifierError::ZeroNullifier));

        let root = t.root();
        let next = t.next_index();
        // Witness that 10 is absent via the sentinel's stale pre-insertion leaf.
        let mut fresh = IndexedTree::new();
        let stale = fresh.insert(Fe::from_u64(10)).unwrap();
        assert!(verify_insertion(&root, next, &Fe::from_u64(10), &stale).is_err());

        // Honest witness for 15, then tamper with each component.
        let mut c = t.clone();
        let w = c.insert(Fe::from_u64(15)).unwrap();
        assert!(verify_insertion(&root, next, &Fe::from_u64(15), &w).is_ok());
        assert_eq!(verify_insertion(&root, next, &Fe::from_u64(25), &w), Err(NullifierError::NotBracketed));
        assert_eq!(verify_insertion(&root, next, &Fe::from_u64(20), &w), Err(NullifierError::Duplicate));
        assert_eq!(verify_insertion(&root, next + 1, &Fe::from_u64(15), &w), Err(NullifierError::SlotNotEmpty));
        assert_eq!(verify_insertion(&root, 1, &Fe::from_u64(15), &w), Err(NullifierError::BadIndex));
        let mut bad = w.clone();
        bad.low_leaf.next_value = Fe::from_u64(30);
        assert_eq!(verify_insertion(&root, next, &Fe::from_u64(15), &bad), Err(NullifierError::LowLeafMismatch));
        let mut bad = w.clone();
        bad.new_path[3] = [7; 32];
        assert_eq!(verify_insertion(&root, next, &Fe::from_u64(15), &bad), Err(NullifierError::SlotNotEmpty));
        // Overwriting the occupied slot 1 is rejected.
        let mut bad = w.clone();
        bad.new_path = t.path(1);
        assert!(verify_insertion(&root, 1, &Fe::from_u64(15), &bad).is_err());
    }

    fn values(v: &[u64]) -> Vec<Fe> {
        let mut v: Vec<Fe> = v.iter().map(|x| Fe::from_u64(*x)).collect();
        v.sort();
        v
    }

    #[test]
    fn batch_insertion_matches_sequential_insertion() {
        let mut seq = IndexedTree::new();
        let mut bat = IndexedTree::new();
        for batch in [&[50u64][..], &[10, 90, 30], &[11, 12, 13, 89, 91, 1000], &[2, 3, 4, 5, 6, 7, 8, 9, 14], &[]] {
            let vs = values(batch);
            let (root, next) = (bat.root(), bat.next_index());
            let w = bat.insert_batch(&vs).unwrap();
            for v in &vs {
                seq.insert(*v).unwrap();
            }
            assert_eq!(bat.root(), seq.root());
            assert_eq!(verify_batch_insertion(&root, next, &vs, &w), Ok(bat.root()));
        }
        assert_eq!(bat.leaves, seq.leaves);
    }

    #[test]
    fn batch_insertion_rejects_tampering() {
        let mut t = IndexedTree::new();
        t.insert_batch(&values(&[10, 20, 30])).unwrap();
        let (root, next) = (t.root(), t.next_index());
        let vs = values(&[15, 16, 25]);
        let w = t.clone().insert_batch(&vs).unwrap();
        assert_eq!(w.lows.len(), 2);
        assert!(verify_batch_insertion(&root, next, &vs, &w).is_ok());
        assert_eq!(t.clone().insert_batch(&values(&[15, 20])), Err(NullifierError::Duplicate));
        assert_eq!(verify_batch_insertion(&root, next, &values(&[15, 16, 20]), &w), Err(NullifierError::Duplicate));
        assert_eq!(verify_batch_insertion(&root, next, &values(&[15, 16, 35]), &w), Err(NullifierError::NotBracketed));
        assert_eq!(verify_batch_insertion(&root, next, &values(&[15, 16]), &w), Err(NullifierError::Coverage));
        assert_eq!(verify_batch_insertion(&root, next, &[vs[1], vs[0], vs[2]], &w), Err(NullifierError::Duplicate));
        assert_eq!(verify_batch_insertion(&root, next + 1, &vs, &w), Err(NullifierError::LowLeafMismatch));
        assert_eq!(verify_batch_insertion(&root, next, &[], &w), Err(NullifierError::Coverage));
        let mut bad = w.clone();
        bad.lows.swap(0, 1);
        assert!(verify_batch_insertion(&root, next, &vs, &bad).is_err());
        let mut bad = w.clone();
        bad.lows[0].count = 1;
        bad.lows[1].count = 2;
        assert!(verify_batch_insertion(&root, next, &vs, &bad).is_err());
        let mut bad = w.clone();
        bad.lows.pop();
        assert_eq!(verify_batch_insertion(&root, next, &vs, &bad), Err(NullifierError::Coverage));
        let mut bad = w.clone();
        bad.lows[1].low_leaf.next_value = Fe::from_u64(26);
        assert_eq!(verify_batch_insertion(&root, next, &vs, &bad), Err(NullifierError::LowLeafMismatch));
        let mut bad = w.clone();
        bad.frontier[0] = [7; 32];
        assert_eq!(verify_batch_insertion(&root, next, &vs, &bad), Err(NullifierError::SlotNotEmpty));
        // The same low leaf supplied twice (to split a run) fails: its first update changes its hash.
        let mut bad = w.clone();
        bad.lows[0].count = 1;
        let mut again = bad.lows[0].clone();
        again.count = 1;
        bad.lows.insert(1, again);
        assert_eq!(verify_batch_insertion(&root, next, &vs, &bad), Err(NullifierError::LowLeafMismatch));
    }

    #[test]
    fn truncate_restores_root() {
        let mut t = IndexedTree::new();
        t.insert(Fe::from_u64(5)).unwrap();
        let r = t.root();
        t.insert(Fe::from_u64(3)).unwrap();
        t.truncate(2);
        assert_eq!(t.root(), r);
    }
}
