#!/usr/bin/env bash
# Rewrites methods/guest/src/joinsplit_id.rs from the freshly built joinsplit guest, then rebuilds
# so apply_batch compiles the new ID in. Run from privacy-rollup/prover.
set -euo pipefail
cargo build -q --release --bin joinsplit
id=$(./target/release/joinsplit id)
f=../methods/guest/src/joinsplit_id.rs
head -n 3 "$f" > "$f.tmp" && echo "$id" >> "$f.tmp" && mv "$f.tmp" "$f"
cargo build -q --release --bin joinsplit
test "$(./target/release/joinsplit id)" = "$id"
echo "joinsplit id $id"
