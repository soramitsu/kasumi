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

The Python tooling requires Python 3.11 or newer (including the standard-library
`tomllib` module). Check `python3 --version` before running the gate; macOS's
Xcode-provided Python may be older. Use an installed `python3.12` or newer
explicitly when necessary.

Run focused tests while developing, then the complete gate:

```sh
cargo test --workspace --all-features --all-targets --locked
cargo clippy --workspace --all-features --all-targets --locked --no-deps -- -D warnings
cargo fmt --all --check
python3 -m unittest discover -s scripts -p 'test_*.py'
```

To try a change against a running database, `scripts/dev_standalone.py start`
creates and supervises a disposable loopback installation from the binaries in
`target/debug`, and `stop --remove` deletes it. The
[README](README.md#one-command-for-a-development-database) has an example.
After building the server binaries, run
`python3 scripts/smoke_dev_standalone.py --bin-dir target/debug` to exercise
initialization, collection defaults, authenticated writes and idempotent replay,
stop/resume persistence, and cleanup against a disposable database.

On a shared or heavily loaded machine, append `-- --test-threads=2` to the
test command and keep durable-store tests separate from benchmark runs. Some
tests start several Raft nodes; concurrent fixtures can contend for full
device flushes and trigger leader changes or deadlines. Preserve failed runs
and check failures in isolation before attributing them to a code change.

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
