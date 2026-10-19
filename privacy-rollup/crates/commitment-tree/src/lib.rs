//! Depth-32 append-only note-commitment tree over `pr_crypto::merkle_node` (empty leaf = 0).
//!
//! [`Frontier`] is the O(depth) state the batch guest needs: it is authenticated against the
//! committed `(root, count)` and then extended by appending. [`Tree`] keeps every node and serves
//! wallets and operators with membership paths.
#![allow(clippy::needless_range_loop)]
use std::collections::HashMap;

use pr_crypto::merkle_node;
use pr_protocol_types::hash::{tagged_hasher, tags};
use pr_protocol_types::{Fe, COMMITMENT_TREE_DEPTH as DEPTH};
use serde::{Deserialize, Serialize};
use sha2::Digest;

pub const CAPACITY: u64 = 1 << DEPTH;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeError {
    Full,
    FrontierMismatch,
    NonCanonicalFrontier,
}

/// `ZERO_HASHES[i]` is the root of an empty level-`i` subtree: `z[0] = 0`, `z[i + 1] = merkle_node(z[i], z[i])`.
/// Precomputed so the batch guest does not spend 32 hashes deriving them;
/// `tests::zero_hashes_match_merkle_node` checks the table.
pub const ZERO_HASHES: [Fe; DEPTH + 1] = [
    Fe([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
    Fe([
        25, 139, 125, 157, 61, 111, 238, 82, 85, 213, 247, 208, 28, 19, 215, 10, 131, 119, 26, 237, 222, 113, 132, 47,
        241, 130, 128, 71, 3, 192, 178, 204,
    ]),
    Fe([
        23, 107, 207, 63, 95, 12, 12, 199, 138, 133, 196, 206, 51, 12, 26, 51, 52, 167, 162, 183, 254, 179, 124, 9, 3,
        129, 189, 11, 66, 89, 73, 13,
    ]),
    Fe([
        30, 7, 183, 43, 135, 124, 138, 193, 15, 19, 195, 103, 185, 14, 163, 74, 149, 93, 172, 169, 56, 7, 108, 30, 235,
        4, 113, 106, 209, 161, 181, 132,
    ]),
    Fe([
        20, 176, 70, 239, 247, 35, 57, 78, 220, 29, 186, 129, 8, 120, 195, 95, 245, 188, 101, 62, 178, 193, 212, 171,
        141, 13, 25, 135, 227, 86, 4, 21,
    ]),
    Fe([
        6, 78, 65, 150, 123, 191, 201, 87, 86, 73, 34, 66, 249, 44, 191, 7, 61, 218, 19, 72, 170, 244, 34, 46, 200,
        178, 101, 144, 155, 204, 25, 102,
    ]),
    Fe([
        6, 197, 98, 137, 42, 134, 72, 43, 80, 157, 208, 244, 75, 249, 212, 127, 46, 120, 231, 192, 124, 148, 84, 227,
        199, 7, 212, 31, 26, 113, 94, 41,
    ]),
    Fe([
        1, 232, 107, 119, 138, 250, 220, 192, 212, 84, 100, 103, 81, 122, 238, 241, 182, 82, 253, 209, 8, 72, 81, 87,
        216, 152, 57, 177, 245, 120, 80, 39,
    ]),
    Fe([
        13, 114, 178, 16, 19, 221, 75, 84, 196, 97, 244, 179, 95, 17, 227, 47, 63, 62, 168, 155, 43, 3, 58, 47, 67,
        204, 195, 66, 249, 72, 221, 226,
    ]),
    Fe([
        17, 85, 126, 40, 90, 206, 178, 145, 152, 200, 220, 217, 22, 20, 139, 44, 143, 110, 9, 238, 153, 92, 57, 230,
        126, 87, 198, 225, 247, 206, 130, 207,
    ]),
    Fe([
        6, 223, 186, 204, 204, 11, 140, 2, 22, 201, 220, 100, 71, 82, 95, 219, 24, 150, 219, 115, 112, 42, 177, 210,
        190, 24, 143, 80, 102, 78, 229, 235,
    ]),
    Fe([
        20, 140, 198, 243, 143, 149, 67, 203, 233, 205, 8, 149, 21, 211, 86, 38, 115, 2, 87, 14, 237, 223, 92, 200,
        244, 56, 91, 59, 57, 163, 238, 233,
    ]),
    Fe([
        11, 18, 124, 132, 116, 100, 185, 107, 75, 127, 119, 22, 38, 14, 79, 117, 166, 117, 145, 197, 52, 29, 3, 48,
        119, 161, 173, 103, 35, 207, 215, 82,
    ]),
    Fe([
        27, 142, 254, 221, 114, 238, 4, 140, 194, 118, 178, 227, 13, 26, 194, 244, 117, 119, 224, 63, 151, 27, 181, 20,
        175, 14, 86, 10, 22, 99, 85, 195,
    ]),
    Fe([
        15, 125, 105, 69, 119, 24, 21, 156, 169, 52, 98, 62, 77, 161, 244, 215, 255, 76, 242, 90, 41, 172, 133, 140,
        242, 226, 79, 29, 95, 121, 102, 112,
    ]),
    Fe([
        25, 6, 252, 217, 181, 163, 210, 97, 194, 42, 255, 172, 187, 221, 213, 158, 109, 14, 99, 254, 148, 70, 112, 175,
        128, 177, 241, 242, 247, 11, 97, 88,
    ]),
    Fe([
        1, 236, 54, 103, 154, 104, 202, 55, 62, 175, 67, 31, 20, 49, 14, 8, 96, 166, 74, 20, 185, 66, 212, 227, 6, 241,
        101, 169, 145, 17, 184, 179,
    ]),
    Fe([
        1, 52, 32, 47, 136, 40, 196, 217, 164, 62, 240, 129, 7, 64, 204, 14, 75, 173, 197, 228, 251, 97, 58, 169, 16,
        236, 40, 228, 132, 209, 233, 30,
    ]),
    Fe([
        4, 111, 151, 51, 226, 139, 101, 214, 132, 237, 5, 104, 196, 196, 39, 97, 152, 127, 194, 134, 66, 189, 242, 54,
        142, 54, 74, 112, 126, 216, 166, 50,
    ]),
    Fe([
        24, 249, 34, 1, 232, 237, 146, 193, 198, 79, 163, 47, 13, 68, 92, 33, 158, 52, 43, 67, 33, 164, 8, 26, 231, 1,
        176, 190, 6, 66, 170, 47,
    ]),
    Fe([
        12, 36, 119, 92, 129, 128, 234, 111, 179, 81, 190, 115, 205, 181, 10, 194, 70, 199, 253, 219, 177, 81, 131,
        229, 177, 21, 161, 99, 101, 65, 10, 249,
    ]),
    Fe([
        19, 133, 150, 233, 201, 46, 232, 47, 137, 155, 101, 13, 27, 62, 156, 160, 179, 53, 162, 248, 110, 18, 248, 51,
        235, 201, 10, 145, 186, 220, 206, 250,
    ]),
    Fe([
        25, 57, 235, 57, 164, 212, 16, 13, 38, 53, 56, 241, 223, 116, 153, 67, 137, 146, 138, 28, 8, 169, 207, 94, 21,
        40, 148, 150, 181, 31, 131, 132,
    ]),
    Fe([
        25, 208, 191, 98, 3, 40, 68, 155, 59, 18, 102, 241, 22, 146, 142, 202, 51, 6, 204, 75, 108, 230, 243, 207, 215,
        2, 122, 198, 183, 220, 17, 60,
    ]),
    Fe([
        22, 109, 42, 104, 124, 183, 164, 29, 21, 18, 161, 15, 229, 217, 56, 16, 113, 80, 247, 81, 9, 64, 49, 206, 113,
        18, 92, 247, 86, 46, 200, 173,
    ]),
    Fe([
        15, 194, 23, 168, 12, 77, 121, 139, 35, 87, 93, 205, 173, 153, 55, 165, 83, 145, 233, 44, 131, 19, 200, 71,
        129, 217, 167, 121, 72, 133, 190, 37,
    ]),
    Fe([
        10, 211, 31, 195, 247, 147, 129, 26, 173, 232, 64, 158, 121, 74, 39, 177, 213, 47, 238, 37, 119, 197, 231, 15,
        177, 8, 137, 63, 232, 77, 72, 47,
    ]),
    Fe([
        9, 80, 11, 152, 42, 23, 189, 41, 218, 195, 245, 40, 249, 21, 70, 105, 49, 19, 44, 142, 241, 134, 73, 12, 177,
        133, 142, 234, 194, 28, 144, 193,
    ]),
    Fe([
        15, 6, 192, 95, 183, 56, 73, 164, 91, 50, 199, 49, 66, 228, 199, 136, 57, 185, 59, 147, 97, 171, 222, 60, 62,
        212, 124, 105, 1, 38, 86, 145,
    ]),
    Fe([
        1, 18, 202, 35, 166, 133, 182, 41, 200, 158, 45, 136, 169, 17, 109, 191, 22, 12, 19, 5, 91, 11, 68, 39, 4, 94,
        255, 247, 230, 43, 74, 133,
    ]),
    Fe([
        19, 241, 217, 49, 141, 162, 77, 71, 83, 189, 2, 96, 238, 210, 6, 109, 83, 56, 31, 157, 169, 144, 93, 20, 134,
        228, 64, 135, 246, 212, 82, 26,
    ]),
    Fe([
        30, 89, 17, 224, 38, 57, 57, 54, 248, 191, 128, 71, 223, 161, 59, 24, 20, 1, 190, 170, 145, 128, 224, 12, 37,
        207, 43, 24, 53, 156, 4, 98,
    ]),
    Fe([
        22, 255, 7, 187, 68, 31, 41, 99, 79, 66, 229, 170, 184, 41, 76, 85, 125, 37, 241, 143, 70, 59, 5, 12, 10, 234,
        143, 255, 198, 65, 238, 208,
    ]),
];

pub fn zero_hashes() -> &'static [Fe; DEPTH + 1] {
    &ZERO_HASHES
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
        if self.count == 0 {
            return z[DEPTH];
        }
        let mut node = z[0];
        for i in 0..DEPTH {
            node =
                if (self.count >> i) & 1 == 1 { merkle_node(&self.nodes[i], &node) } else { merkle_node(&node, &z[i]) };
        }
        node
    }

    /// SHA-256 commitment to `(count, nodes)`, stored in the rollup state next to the root.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = tagged_hasher(tags::COMMITMENT_FRONTIER);
        h.update(self.count.to_le_bytes());
        for n in &self.nodes {
            h.update(n.0);
        }
        h.finalize().into()
    }

    fn check_canonical(&self, count: u64) -> Result<(), TreeError> {
        if self.nodes.len() != DEPTH || self.count != count || count > CAPACITY {
            return Err(TreeError::NonCanonicalFrontier);
        }
        for i in 0..DEPTH {
            if (count >> i) & 1 == 0 && !self.nodes[i].is_zero() {
                return Err(TreeError::NonCanonicalFrontier);
            }
        }
        Ok(())
    }

    /// Checks the frontier is canonical for `count` and matches `digest`. Sound when `digest` was
    /// produced by [`Frontier::digest`] of the frontier whose root is the state's `commitment_root`
    /// (an invariant every accepted state transition maintains), and costs no tree hashes.
    pub fn authenticate_digest(&self, digest: &[u8; 32], count: u64) -> Result<(), TreeError> {
        self.check_canonical(count)?;
        if self.digest() != *digest {
            return Err(TreeError::FrontierMismatch);
        }
        Ok(())
    }

    /// Checks the frontier is the unique canonical frontier for `(root, count)`.
    pub fn authenticate(&self, root: &Fe, count: u64) -> Result<(), TreeError> {
        self.check_canonical(count)?;
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
    fn zero_hashes_match_merkle_node() {
        let mut z = Fe::ZERO;
        for (i, expected) in ZERO_HASHES.iter().enumerate() {
            assert_eq!(&z, expected, "level {i}");
            z = merkle_node(&z, &z);
        }
    }

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
        let d = f.digest();
        f.authenticate_digest(&d, 5).unwrap();
        assert_eq!(f.authenticate_digest(&d, 4), Err(TreeError::NonCanonicalFrontier));
        let mut g = f.clone();
        g.nodes[0] = Fe::from_u64(9);
        assert_eq!(g.authenticate_digest(&d, 5), Err(TreeError::FrontierMismatch));
        let mut g = f.clone();
        g.nodes[1] = Fe::from_u64(9);
        assert_eq!(g.authenticate_digest(&d, 5), Err(TreeError::NonCanonicalFrontier));
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
