#!/usr/bin/env bash
set -euo pipefail

tools_dir="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$tools_dir/.." && pwd)"
python_bin="${PYTHON:-python3}"

"$python_bin" "$tools_dir/reference_test.py"
"$python_bin" "$tools_dir/subgroup_test.py"
"$python_bin" "$tools_dir/field_test.py"
"$python_bin" "$tools_dir/pairing_test.py"
"$python_bin" "$tools_dir/verifier_test.py"
cargo run --release --locked --manifest-path "$tools_dir/native/Cargo.toml" -- verify "$root/fixtures"
