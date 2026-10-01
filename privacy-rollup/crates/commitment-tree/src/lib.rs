//! Depth-32 append-only Poseidon2 note-commitment tree (empty leaf = 0).
//!
//! [`Frontier`] is the O(depth) state the batch guest needs: it is authenticated against the
//! committed `(root, count)` and then extended by appending. [`Tree`] keeps every node and serves
//! wallets and operators with membership paths.
#![allow(clippy::needless_range_loop)]
use std::collections::HashMap;
use std::sync::OnceLock;

use pr_crypto::merkle_node;
use pr_protocol_types::{Fe, COMMITMENT_TREE_DEPTH as DEPTH};
use serde::{Deserialize, Serialize};

pub const CAPACITY: u64 = 1 << DEPTH;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeError {
    Full,
    FrontierMismatch,
    NonCanonicalFrontier,
}

pub fn zero_hashes() -> &'static [Fe; DEPTH + 1] {
    static Z: OnceLock<[Fe; DEPTH + 1]> = OnceLock::new();
    Z.get_or_init(|| {
        let mut z = [Fe::ZERO; DEPTH + 1];
        for i in 0..DEPTH {
            z[i + 1] = merkle_node(&z[i], &z[i]);
        }
        z
    })
}

pub fn root_from_path(leaf: &Fe, index: u64, siblings: &[Fe; DEPTH]) -> Fe {
    let mut node = *leaf;
    for (i, s) in siblings.iter().enumerate() {
        node = if (index >> i) & 1 == 1 { merkle_node(s, &node) } else { merkle_node(&node, s) };
    }
    node
}

/// Left-sibling frontier: `nodes[i]` is the root of the completed level-`i` subtree immediately
/// left of position `count`, when bit `i` of `count` is set; zero otherwise.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Frontier {
    pub count: u64,
    pub nodes: Vec<Fe>,
}

impl Default for Frontier {
    fn default() -> Self {
        Frontier { count: 0, nodes: vec![Fe::ZERO; DEPTH] }
    }
}

impl Frontier {
    pub fn root(&self) -> Fe {
        let z = zero_hashes();
        let mut node = z[0];
        for i in 0..DEPTH {
            node =
                if (self.count >> i) & 1 == 1 { merkle_node(&self.nodes[i], &node) } else { merkle_node(&node, &z[i]) };
        }
        node
    }

    /// Checks the frontier is the unique canonical frontier for `(root, count)`.
    pub fn authenticate(&self, root: &Fe, count: u64) -> Result<(), TreeError> {
        if self.nodes.len() != DEPTH || self.count != count || count > CAPACITY {
            return Err(TreeError::NonCanonicalFrontier);
        }
        for i in 0..DEPTH {
            if (count >> i) & 1 == 0 && !self.nodes[i].is_zero() {
                return Err(TreeError::NonCanonicalFrontier);
            }
        }
        if self.root() != *root {
            return Err(TreeError::FrontierMismatch);
        }
        Ok(())
    }

    pub fn append(&mut self, leaf: Fe) -> Result<u64, TreeError> {
        if self.count >= CAPACITY {
            return Err(TreeError::Full);
        }
        let index = self.count;
        let mut node = leaf;
        for i in 0..DEPTH {
            if (index >> i) & 1 == 0 {
                self.nodes[i] = node;
                break;
            }
            node = merkle_node(&self.nodes[i], &node);
            self.nodes[i] = Fe::ZERO;
        }
        self.count += 1;
        Ok(index)
    }
}

/// Full tree with every non-empty node, for path queries.
#[derive(Clone, Debug, Default)]
pub struct Tree {
    nodes: HashMap<(u8, u64), Fe>,
    count: u64,
}

impl Tree {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn count(&self) -> u64 {
        self.count
    }
    fn get(&self, level: usize, index: u64) -> Fe {
        self.nodes.get(&(level as u8, index)).copied().unwrap_or(zero_hashes()[level])
    }
    pub fn root(&self) -> Fe {
        self.get(DEPTH, 0)
    }
    pub fn leaf(&self, index: u64) -> Fe {
        self.get(0, index)
    }
    pub fn append(&mut self, leaf: Fe) -> Result<u64, TreeError> {
        if self.count >= CAPACITY {
            return Err(TreeError::Full);
        }
        let index = self.count;
        let mut node = leaf;
        let mut idx = index;
        self.nodes.insert((0, idx), node);
        for level in 0..DEPTH {
            let sibling = self.get(level, idx ^ 1);
            node = if idx & 1 == 1 { merkle_node(&sibling, &node) } else { merkle_node(&node, &sibling) };
            idx >>= 1;
            self.nodes.insert((level as u8 + 1, idx), node);
        }
        self.count += 1;
        Ok(index)
    }
    pub fn path(&self, index: u64) -> [Fe; DEPTH] {
        let mut out = [Fe::ZERO; DEPTH];
        for (level, o) in out.iter_mut().enumerate() {
            *o = self.get(level, (index >> level) ^ 1);
        }
        out
    }
    pub fn frontier(&self) -> Frontier {
        let mut f = Frontier { count: self.count, nodes: vec![Fe::ZERO; DEPTH] };
        for i in 0..DEPTH {
            if (self.count >> i) & 1 == 1 {
                f.nodes[i] = self.get(i, (self.count >> i) - 1);
            }
        }
        f
    }
    /// Removes the most recent leaves (reorg rollback), restoring the tree to `count` leaves.
    pub fn truncate(&mut self, count: u64) {
        let leaves: Vec<Fe> = (0..count.min(self.count)).map(|i| self.leaf(i)).collect();
        *self = Tree::new();
        for l in leaves {
            self.append(l).expect("capacity");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frontier_matches_full_tree() {
        let mut t = Tree::new();
        let mut f = Frontier::default();
        assert_eq!(f.root(), t.root());
        assert_eq!(t.root(), zero_hashes()[DEPTH]);
        for i in 0..37u64 {
            let leaf = Fe::from_u64(1000 + i);
            assert_eq!(t.append(leaf).unwrap(), i);
            assert_eq!(f.append(leaf).unwrap(), i);
            assert_eq!(f, t.frontier());
            assert_eq!(f.root(), t.root());
            f.authenticate(&t.root(), t.count()).unwrap();
            for j in [0, i / 2, i] {
                assert_eq!(root_from_path(&t.leaf(j), j, &t.path(j)), t.root());
            }
        }
    }

    #[test]
    fn rejects_wrong_frontier() {
        let mut t = Tree::new();
        for i in 0..5 {
            t.append(Fe::from_u64(i + 1)).unwrap();
        }
        let f = t.frontier();
        assert_eq!(f.authenticate(&t.root(), 4), Err(TreeError::NonCanonicalFrontier));
        let mut g = f.clone();
        g.nodes[1] = Fe::from_u64(9);
        assert_eq!(g.authenticate(&t.root(), 5), Err(TreeError::NonCanonicalFrontier));
        let mut g = f.clone();
        g.nodes[0] = Fe::from_u64(9);
        assert_eq!(g.authenticate(&t.root(), 5), Err(TreeError::FrontierMismatch));
        assert_eq!(f.authenticate(&Fe::from_u64(3), 5), Err(TreeError::FrontierMismatch));
        assert!(root_from_path(&t.leaf(2), 3, &t.path(2)) != t.root());
    }

    #[test]
    fn truncate_rolls_back() {
        let mut t = Tree::new();
        for i in 0..6 {
            t.append(Fe::from_u64(i + 1)).unwrap();
        }
        let mut u = Tree::new();
        for i in 0..4 {
            u.append(Fe::from_u64(i + 1)).unwrap();
        }
        t.truncate(4);
        assert_eq!(t.root(), u.root());
        assert_eq!(t.count(), 4);
    }
}
