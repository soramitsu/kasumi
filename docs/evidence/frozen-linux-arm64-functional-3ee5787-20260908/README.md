# Frozen Linux ARM64 functional attempt — failed

Exact source `3ee5787eca56e29e1170975e57a400702fd1baac`, Rust 1.97.1,
native Linux ARM64 in the dedicated Debian 13 VZ VM (2 CPUs, 8 GiB RAM).
The runner froze its source archive, retained input inventories and executable
hashes, and continued independent gates after failures. This attempt is **failed**.

The workspace reported 479 passes, three failures and two ignored tests:

- Authority voter replacement checked the successor before resolving the original
  ambiguous operation. The exact-outcome fixture fix is integrated separately.
- The restore expiry fixture saw an unavailable `Weak` before the final resource
  destructor had drained. The test now also waits for actual governor counters.
- Replicated `PrepareRestore` exhausted its work admission budget. Running that
  exact frozen test binary in isolation also failed; its raw log is retained.
  Inspection found overlapping verification/materialization reservations. The
  handoff fix is separate ongoing work, with the default budget unchanged.

Formatting, Python checks, dependency patch/upstream checks, strict workspace
Clippy, fixture-free production feature verification and all three production
binaries passed. The production build took 834.681 seconds. Their exact hashes
and commands are in `evidence.json`. Every gate log and the source inventory were
hash-checked when copied here.

Production binaries were hash-verified and copied out of the reusable target
directory into `/opt/kasumi-acceptance/3ee5787-binaries` in the validation VM. The
frozen source/archive and original output remain under
`/opt/kasumi-acceptance/3ee5787-functional-arm64/run`. These intermediate binaries
predate later storage/configuration changes. They do not close final-source,
3 GiB, endurance, cross-platform or release-artifact acceptance.
