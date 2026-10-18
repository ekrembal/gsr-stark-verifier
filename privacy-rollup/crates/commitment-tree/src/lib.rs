//! Depth-32 append-only Poseidon2 note-commitment tree (empty leaf = 0).
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
/// Precomputed so the batch guest does not spend 32 Poseidon2 calls deriving them;
/// `tests::zero_hashes_match_merkle_node` checks the table.
pub const ZERO_HASHES: [Fe; DEPTH + 1] = [
    Fe([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
    Fe([
        27, 157, 19, 169, 79, 43, 71, 105, 124, 37, 23, 48, 72, 200, 90, 248, 30, 183, 18, 81, 21, 215, 197, 185, 198,
        61, 162, 152, 27, 81, 79, 3,
    ]),
    Fe([
        48, 4, 29, 18, 98, 239, 121, 92, 125, 167, 79, 7, 30, 32, 109, 197, 27, 147, 184, 35, 108, 170, 140, 222, 147,
        167, 65, 48, 19, 173, 110, 161,
    ]),
    Fe([
        4, 253, 118, 233, 227, 203, 169, 53, 142, 102, 40, 196, 99, 55, 123, 115, 21, 214, 27, 91, 7, 71, 22, 254, 69,
        28, 241, 75, 81, 109, 49, 22,
    ]),
    Fe([
        30, 203, 74, 185, 43, 131, 127, 116, 186, 43, 46, 142, 157, 222, 24, 173, 36, 246, 37, 9, 106, 198, 17, 72, 59,
        235, 75, 98, 96, 189, 204, 34,
    ]),
    Fe([
        13, 1, 164, 136, 134, 214, 137, 255, 46, 231, 12, 154, 60, 181, 203, 221, 229, 239, 135, 28, 88, 23, 208, 164,
        209, 48, 53, 240, 62, 82, 156, 232,
    ]),
    Fe([
        44, 103, 245, 169, 233, 242, 50, 69, 140, 99, 27, 78, 255, 93, 66, 255, 172, 217, 210, 159, 90, 205, 87, 144,
        165, 100, 149, 250, 93, 242, 75, 221,
    ]),
    Fe([
        9, 1, 28, 102, 25, 252, 141, 134, 118, 175, 237, 57, 183, 174, 44, 183, 21, 9, 92, 171, 236, 98, 208, 145, 87,
        15, 236, 172, 26, 182, 118, 213,
    ]),
    Fe([
        43, 122, 239, 212, 8, 220, 42, 71, 241, 68, 77, 88, 5, 191, 6, 39, 38, 236, 209, 248, 58, 169, 79, 133, 44, 35,
        163, 93, 15, 120, 42, 222,
    ]),
    Fe([
        11, 133, 228, 22, 242, 230, 186, 73, 237, 240, 31, 121, 207, 189, 37, 107, 111, 238, 147, 109, 145, 119, 21,
        220, 21, 176, 190, 68, 156, 106, 98, 32,
    ]),
    Fe([
        8, 165, 98, 202, 135, 26, 42, 45, 34, 74, 94, 207, 72, 87, 200, 28, 208, 163, 148, 66, 71, 213, 213, 43, 34,
        88, 101, 92, 27, 208, 251, 116,
    ]),
    Fe([
        5, 253, 36, 156, 78, 195, 250, 164, 21, 35, 70, 238, 70, 126, 153, 139, 106, 223, 190, 165, 66, 207, 129, 108,
        52, 228, 35, 127, 160, 43, 112, 65,
    ]),
    Fe([
        38, 246, 209, 242, 238, 194, 225, 28, 64, 77, 23, 205, 106, 186, 249, 61, 226, 86, 122, 196, 106, 154, 214, 60,
        70, 192, 111, 68, 204, 71, 202, 131,
    ]),
    Fe([
        19, 151, 107, 31, 99, 55, 103, 246, 71, 33, 182, 125, 73, 212, 213, 50, 189, 79, 194, 165, 154, 68, 118, 106,
        128, 3, 253, 88, 146, 93, 249, 207,
    ]),
    Fe([
        24, 5, 74, 250, 23, 97, 57, 152, 200, 95, 87, 69, 20, 32, 48, 159, 169, 225, 128, 207, 37, 100, 173, 195, 247,
        27, 181, 243, 191, 19, 239, 1,
    ]),
    Fe([
        32, 4, 126, 118, 18, 40, 94, 183, 45, 28, 3, 128, 135, 179, 229, 66, 43, 222, 180, 34, 197, 112, 216, 63, 208,
        41, 11, 34, 85, 245, 62, 204,
    ]),
    Fe([
        18, 39, 83, 135, 248, 98, 219, 212, 11, 142, 100, 104, 161, 41, 70, 218, 178, 21, 112, 51, 227, 242, 181, 55,
        12, 171, 21, 115, 123, 65, 174, 14,
    ]),
    Fe([
        43, 155, 176, 217, 49, 66, 5, 249, 224, 216, 187, 10, 144, 41, 211, 0, 212, 240, 213, 30, 89, 95, 252, 227, 34,
        59, 230, 66, 185, 207, 40, 40,
    ]),
    Fe([
        8, 205, 186, 14, 214, 150, 140, 218, 184, 5, 153, 203, 103, 159, 89, 52, 102, 13, 177, 26, 196, 250, 142, 30,
        34, 135, 191, 48, 246, 172, 185, 113,
    ]),
    Fe([
        1, 199, 85, 113, 246, 248, 140, 37, 148, 223, 213, 161, 245, 120, 102, 203, 76, 48, 131, 121, 54, 120, 192, 5,
        12, 254, 168, 78, 136, 4, 88, 110,
    ]),
    Fe([
        37, 168, 203, 58, 163, 149, 85, 238, 145, 84, 176, 119, 34, 231, 229, 215, 242, 10, 90, 170, 29, 239, 230, 128,
        179, 113, 248, 175, 65, 49, 246, 199,
    ]),
    Fe([
        3, 64, 199, 59, 93, 230, 151, 83, 241, 6, 142, 202, 39, 59, 128, 234, 24, 156, 11, 240, 70, 100, 85, 111, 249,
        93, 192, 177, 119, 171, 111, 241,
    ]),
    Fe([
        27, 128, 185, 135, 77, 252, 8, 11, 104, 143, 205, 10, 198, 143, 47, 40, 60, 221, 4, 164, 236, 255, 91, 159,
        200, 179, 20, 143, 113, 248, 102, 226,
    ]),
    Fe([
        35, 47, 7, 37, 50, 131, 59, 199, 114, 19, 199, 255, 61, 134, 185, 188, 144, 13, 97, 233, 237, 43, 133, 236,
        209, 149, 174, 169, 217, 27, 116, 142,
    ]),
    Fe([
        28, 195, 226, 193, 76, 228, 126, 105, 191, 204, 141, 247, 58, 160, 100, 165, 168, 89, 170, 119, 56, 17, 195,
        222, 3, 168, 213, 131, 79, 145, 47, 249,
    ]),
    Fe([
        31, 133, 105, 208, 129, 4, 191, 158, 16, 18, 51, 48, 254, 169, 106, 221, 20, 254, 214, 211, 15, 114, 124, 89,
        151, 176, 71, 22, 91, 62, 68, 115,
    ]),
    Fe([
        19, 207, 251, 109, 118, 26, 210, 235, 37, 176, 124, 90, 41, 148, 186, 14, 46, 190, 94, 129, 226, 230, 106, 36,
        17, 47, 77, 10, 88, 90, 18, 207,
    ]),
    Fe([
        47, 61, 255, 21, 244, 23, 189, 18, 68, 224, 194, 161, 72, 146, 106, 216, 149, 166, 160, 3, 142, 68, 26, 157,
        131, 116, 105, 74, 62, 91, 212, 204,
    ]),
    Fe([
        12, 200, 173, 163, 195, 208, 53, 187, 3, 126, 221, 219, 27, 86, 121, 18, 56, 66, 37, 146, 2, 48, 210, 26, 34,
        63, 166, 180, 171, 59, 156, 186,
    ]),
    Fe([
        8, 153, 44, 130, 83, 51, 176, 50, 234, 162, 115, 199, 75, 241, 58, 3, 95, 188, 180, 176, 45, 201, 11, 36, 155,
        199, 133, 231, 26, 160, 123, 65,
    ]),
    Fe([
        14, 64, 77, 245, 153, 79, 92, 75, 72, 13, 55, 104, 100, 129, 167, 140, 123, 226, 216, 139, 207, 253, 72, 35,
        169, 204, 126, 18, 134, 146, 79, 203,
    ]),
    Fe([
        16, 248, 186, 80, 82, 177, 114, 166, 80, 59, 112, 235, 34, 13, 136, 225, 214, 172, 60, 11, 234, 178, 161, 229,
        121, 69, 36, 147, 187, 38, 239, 197,
    ]),
    Fe([
        36, 227, 228, 104, 205, 135, 208, 34, 2, 63, 112, 1, 67, 23, 60, 152, 188, 193, 223, 49, 134, 8, 198, 55, 53,
        116, 168, 55, 18, 154, 232, 198,
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
    /// (an invariant every accepted state transition maintains), and costs no Poseidon2 calls.
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
