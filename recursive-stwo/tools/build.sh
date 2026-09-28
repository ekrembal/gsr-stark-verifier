#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
expected=d2799052604eb138c5a79acf88514a0c8b07f4ef
[[ "$(git -C ../bitcoin rev-parse HEAD)" == "$expected" ]] || { echo 'Wrong Bitcoin revision' >&2; exit 1; }
git -C ../bitcoin diff --exit-code -- src/script src/policy src/consensus
cmake -S ../bitcoin -B ../build/bitcoin -DBUILD_GUI=OFF -DBUILD_TESTS=OFF -DBUILD_BENCH=OFF -DBUILD_FUZZ_BINARY=OFF -DENABLE_WALLET=OFF -DWITH_ZMQ=OFF
cmake --build ../build/bitcoin --target bitcoind bitcoin-cli --parallel "${GSR_BUILD_JOBS:-6}"
python3 tools/build-harness.py
cargo build --locked
