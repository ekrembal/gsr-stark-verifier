#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
cargo run --release --locked --manifest-path "$script_dir/native/Cargo.toml" -- generate "$script_dir/../fixtures"
