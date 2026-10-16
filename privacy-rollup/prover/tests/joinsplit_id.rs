//! `apply_batch` compiles the join-split image ID in from `methods/guest/src/joinsplit_id.rs`; it
//! must be the ID of the `joinsplit` guest built alongside it.
#[test]
fn joinsplit_id_matches() {
    let src = include_str!("../../methods/guest/src/joinsplit_id.rs");
    let array = src.lines().find(|l| l.starts_with('[')).expect("array literal");
    let words: Vec<u32> =
        array.trim_matches(|c| c == '[' || c == ']').split(',').map(|w| w.trim().parse().unwrap()).collect();
    assert_eq!(words, pr_methods::JOINSPLIT_ID, "regenerate joinsplit_id.rs with `joinsplit id`");
}
