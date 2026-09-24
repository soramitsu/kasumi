# Admitted synthetic backend fixture

Target-only follow-up after store metadata revision2 (10ebc1c6). The only file is
store test_utils.rs; actual/intermediate/proposed hashes are in manifest.json.
The intermediate hash is the frozen metadata proposal's test_utils.rs, so this
must not be applied directly to the pre-metadata source.

NodeStore::open_fixture_backend_on_disk(backend, redb_admission, persistent,
scratch) requires exact persistent/scratch memory-core identity before invoking
redb's builder and retains that persistent owner alongside the synthetic backend.
It makes no claim that synthetic backend bytes are real filesystem bytes. Existing
pure-redb open_with_backend remains a distinct fixture purpose without an engine
installed-owner capability. Production constructors and guards are unchanged.

The new regression rejects foreign memory with a backend that panics on every
I/O/acquisition method; no backend access, new lease or file creation is allowed.
A matching core initializes real FaultBackend storage, returns the exact supplied
owners, and explicitly shuts the node down. The test is prepared but not run.

Target formatting and the follow-up patch check against its exact intermediate
baseline pass. No actual source changes, Cargo check, or test execution occurred.
