# Dependency inventory gate development checkpoint

The format-2 dependency verifier runs only the current manifest contract. It
checks six root Cargo patches and seven local packages, including OpenRaft's
sibling macros crate, against complete source-tree file hashes, sizes and modes.
Symlinks and special files fail; ordinary empty directories do not affect a
fresh Git checkout. The ignored upstream OpenRaft Cargo.lock is included.

All 282 original dependency input hashes and published archive checksums were
preserved. The 97 canonical redb inputs match their frozen provenance; all 600
OpenRaft inputs match the final attempt-49 byte/mode inventory. The manifest
also binds those review records so stale or different provenance fails.

Eighteen focused Python counterexample tests and the actual read-only
`cargo metadata --locked` selection check passed in
`/Users/mtakemiya/dev/kasumi` on `master`. Receipts identify Python 3.12.14,
Rust 1.97.1, input hashes and the unchanged metadata-check inputs. The root
owned Python regression attempt 16 additionally passed all 84 tooling tests,
including these eighteen; its result is retained with the installed-storage
development diagnostics. These are scoped development checks, not native
release qualification or a completed release acceptance manifest.
