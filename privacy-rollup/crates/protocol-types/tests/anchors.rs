use pr_protocol_types::*;

fn entry(i: u64) -> AnchorEntry {
    AnchorEntry { batch_number: i, commitment_root: Fe::from_u64(1000 + i), commitment_count: 2 * i }
}

fn history(n: u64) -> AnchorHistory {
    AnchorHistory((0..n).map(entry).collect())
}

#[test]
fn every_member_and_the_next_slot_authenticate() {
    for n in 1..=17u64 {
        let h = history(n);
        let root = h.commitment();
        for i in 0..n {
            let p = AnchorProof { entry: entry(i), path: h.path(i) };
            assert_eq!(p.verify(&root), Some(&entry(i)), "n={n} i={i}");
            assert_eq!(h.find(i), Some(&entry(i)));
        }
        assert_eq!(h.find(n), None);
        let slot = h.path(n);
        assert_eq!(anchor_root_from_path(&[0; 32], n, &slot), Some(root), "empty slot n={n}");
        let mut next = h.clone();
        next.push(entry(n));
        assert_eq!(anchor_root_from_path(&anchor_leaf(&entry(n)), n, &slot), Some(next.commitment()), "append n={n}");
    }
}

#[test]
fn malformed_proofs_are_rejected() {
    let h = history(6);
    let root = h.commitment();
    let good = AnchorProof { entry: entry(3), path: h.path(3) };
    assert!(good.verify(&root).is_some());

    let mut p = good.clone();
    p.entry.commitment_root = Fe::from_u64(7);
    assert!(p.verify(&root).is_none(), "tampered root");
    let mut p = good.clone();
    p.entry.commitment_count += 1;
    assert!(p.verify(&root).is_none(), "tampered count");
    let mut p = good.clone();
    p.entry.batch_number = 2;
    assert!(p.verify(&root).is_none(), "entry moved to another index");
    let mut p = good.clone();
    p.path[0][0] ^= 1;
    assert!(p.verify(&root).is_none(), "tampered sibling");
    let mut p = good.clone();
    p.path.pop();
    assert!(p.verify(&root).is_none(), "short path");
    let mut p = good.clone();
    p.path.push([0; 32]);
    assert!(p.verify(&root).is_none(), "long path");
    assert!(AnchorProof { entry: entry(4), path: h.path(4) }.verify(&history(5).commitment()).is_none(), "stale root");
    assert_eq!(anchor_root_from_path(&[0; 32], 1 << ANCHOR_TREE_DEPTH, &h.path(0)), None, "index beyond the tree");
    assert_ne!(anchor_root_from_path(&[0; 32], 5, &h.path(5)), Some(root), "occupied slot is not empty");
}

#[test]
fn history_decodes_only_in_batch_order() {
    let h = history(4);
    assert_eq!(AnchorHistory::decode(&h.encode()).unwrap(), h);
    let mut swapped = h.clone();
    swapped.0.swap(1, 2);
    assert!(AnchorHistory::decode(&swapped.encode()).is_err());
    assert!(AnchorHistory::decode(&AnchorHistory(Vec::new()).encode()).is_err());
}
