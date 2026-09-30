#!/usr/bin/env bash
# Regenerate the verifier, measure the complete transaction, and run the native/reference/Script differential suite.
set -euo pipefail
cd "$(dirname "$0")"
python3 generate.py
python3 measure.py
python3 differential.py "$@"
