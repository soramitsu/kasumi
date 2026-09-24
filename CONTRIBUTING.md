# Contributing to Kasumi

Kasumi is an open-source key-value database written in Rust
and licensed under Apache-2.0. Contributions are submitted under the same license.
Preserve third-party license and attribution notices when importing code or assets.

Run the [public repository checks](docs/public-repository.md) before submitting
new fixtures, configuration or retained logs. Keep credentials and unrelated
project material out of both files and commit messages.

Install the toolchain selected by `rust-toolchain.toml`. Use a separate worktree
and Cargo target directory for each independently changing checkout; generated
Protobuf from a shared target can otherwise outlive its source checkout.

Run focused tests while developing, then the complete gate:

```sh
cargo test --workspace --all-features --all-targets --locked
cargo clippy --workspace --all-features --all-targets --locked --no-deps -- -D warnings
cargo fmt --all --check
python3 -m unittest discover -s scripts -p 'test_*.py'
```

Changes to durability, authorization, recovery or ownership require meaningful
failure and restart tests. Do not replace an unknown outcome with a claimed
rollback, revive expired handles, silently reduce membership, or weaken current
authorization to recover a historical receipt.

Before the first release, update the canonical APIs, required configuration and
formats directly. Do not introduce compatibility aliases or old-format decoders.
Update native clients, examples, documentation and rejection tests together.

Pull requests should state the concrete behavior changed, relevant limits, and
which checks actually ran. Preserve failed evidence; never present old-source
results as validation of a changed executable. The release acceptance ledger is
in `docs/production-release.md`.

Report vulnerabilities using `SECURITY.md`, without posting secrets or exploit
details in a public issue.
