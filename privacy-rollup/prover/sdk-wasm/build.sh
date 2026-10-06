#!/bin/bash
# Builds pr-sdk-wasm.wasm (wasm32-wasip1) into ../web/ with the WASI SDK at $WASI_SDK.
set -euo pipefail
W=${WASI_SDK:-$HOME/wasi-sdk-25.0-x86_64-linux}
S=$W/share/wasi-sysroot
export CC_wasm32_wasip1=$W/bin/clang CXX_wasm32_wasip1=$W/bin/clang++ AR_wasm32_wasip1=$W/bin/llvm-ar
export CFLAGS_wasm32_wasip1="--sysroot=$S" CXXFLAGS_wasm32_wasip1="--sysroot=$S -fno-exceptions"
# Only libc++/libc++abi come from the WASI SDK; libc stays Rust's self-contained copy.
CXXLIB=$(cd "$(dirname "$0")/.." && pwd)/target/wasi-cxxlib
mkdir -p "$CXXLIB"
cp "$S/lib/wasm32-wasip1/libc++.a" "$S/lib/wasm32-wasip1/libc++abi.a" "$CXXLIB/"
export CARGO_TARGET_WASM32_WASIP1_RUSTFLAGS="-L native=$CXXLIB -l static=c++abi -C link-arg=--max-memory=4294967296"
cd "$(dirname "$0")/.."
cargo build --release --target wasm32-wasip1 -p pr-sdk-wasm
mkdir -p web
cp target/wasm32-wasip1/release/pr-sdk-wasm.wasm web/pr-sdk-wasm.wasm
ls -l web/pr-sdk-wasm.wasm
