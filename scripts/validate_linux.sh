#!/usr/bin/env bash
set -euo pipefail
if [[ "$(uname -s)" != Linux ]]; then
  echo "This validation script requires Linux" >&2
  exit 1
fi
rustc --version
cargo --version
uname -a
cargo test --workspace --all-features --all-targets --locked
cargo clippy --workspace --all-features --all-targets --locked --no-deps -- -D warnings
bao_binary="$(python3 scripts/fetch_openbao.py)"
KASUMI_OPENBAO_BIN="$bao_binary" cargo test -p kasumi-store --test openbao_live --locked -- --ignored
