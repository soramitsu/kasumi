#!/usr/bin/env bash
set -euo pipefail
if [[ "$(uname -s)" != Linux ]]; then
  echo "This validation script requires Linux" >&2
  exit 1
fi
if [[ "$(rustc --version)" != "rustc 1.97.1 "* ]]; then
  echo "The release gate requires the pinned Rust 1.97.1 toolchain" >&2
  exit 1
fi
rustc -Vv
cargo --version
uname -a
cargo fmt --all -- --check
python3 -m unittest discover -s scripts -p 'test_*.py' -v
python3 scripts/check_dependency_patches.py
cargo test --manifest-path vendor/bitmaps-3.2.1/Cargo.toml --locked -j 2
cargo test --manifest-path vendor/lru-0.16.4/Cargo.toml --locked -j 2
cargo test --workspace --all-features --all-targets --locked -j 2
cargo clippy --workspace --all-features --all-targets --locked --no-deps -j 2 -- -D warnings
# Resolve the production dependency graph separately from test/bench feature
# unification. A fixture capability must never enter a distributed executable.
production_graph="$(cargo tree -p kasumi-server --edges normal,build --format '{p} {f}' --no-default-features --locked)"
if printf '%s\n' "$production_graph" | rg 'kasumi-(store|serving).*test-utils'; then
  echo "Production dependency graph includes fixture capabilities" >&2
  exit 1
fi
cargo build --release -p kasumi-server --bins --no-default-features --locked -j 2
bao_binary="$(python3 scripts/fetch_openbao.py)"
KASUMI_OPENBAO_BIN="$bao_binary" cargo test -p kasumi-store --test openbao_live --features test-utils --locked -j 2 -- --ignored
