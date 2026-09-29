#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo test --locked
cargo run --locked -- verify-native
cargo run --locked -- freeze-profile build/regenerated-profile.json
cmp profiles/bws-v1.json build/regenerated-profile.json
cargo run --locked -- compile
cargo run --locked -- prepare-witness
cargo run --locked -- differential-reference
build/harness/gsr-meter build/differential.json > build/differential-result.json
python3 tools/test-negative.py
cargo run --locked -- measure
