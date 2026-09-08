# Frozen functional release gates

Run the functional checks from a committed checkout with Python 3.11 or newer and
the pinned Rust toolchain installed. Use a new output directory outside the checkout:

```sh
python3 scripts/release_gate.py \
  --output /absolute/evidence/kasumi-functional-run-001 \
  --execution-description 'macOS ARM64 native execution' \
  --jobs 2
```

The runner archives the exact commit and extracts only regular files and
directories into an exclusive source directory. Builds use a new target directory.
It checks formatting, Python tests, vendored dependency patches and upstream
tests, the complete workspace (all targets and a separate documentation-test
gate), strict Clippy, the production dependency feature
graph and production binaries. Production graphs containing Kasumi fixture
features fail. The production gate must report all three executable targets.

`evidence.json` records individual exit codes, raw log hashes and the executable
hashes reported by Cargo immediately after each gate. Failed checks remain in the
record and later independent checks still run. A crash or interruption leaves a
running or interrupted record, which cannot be interpreted as a pass. Source
content, added files and executable permission changes invalidate the run. The
archive, its file inventory, Cargo.lock hash, raw logs, target files and earlier
failed runs are retained. Never reuse or manually edit an evidence directory.

This runner establishes functional results for its recorded inputs and host
execution description. It does not establish a hermetic or bit-for-bit reproducible
compiler environment; the installed compiler, system linker, dependency cache and
host still require the release workflow's pinned platform provenance. It does not
run the live OpenBao/MinIO gates, real 3 GiB capacity workloads, recovery drills,
performance matrix, or the 24-hour HA soak. A functional pass does not complete
production acceptance. Bind those separate results and their actual configurations
to the same final source and executable hashes before publishing release artifacts.
