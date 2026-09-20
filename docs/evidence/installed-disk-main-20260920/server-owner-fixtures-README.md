# Gate65 serving and signer fixture correction — proposed, unapplied

This is a narrow correction against the actual current server API in the main
`/Users/mtakemiya/dev/kasumi` checkout on `master`. It is independent of the held
future installed-memory caller stack. No Rust source was edited, no Rust build
or test was run, and no branch, worktree, or commit was created.

Gate65 finished normally with 37 passed and 9 failed tests; its source inventory
was unchanged and its process group drained. This proposal covers five serving
owner tests and two signer tests. The other two MCP failures belong to root's
separate fix. The exact gate artifacts remain under
`target/installed-disk-validation/65-*`.

Revision 1, SHA `bb880123d826c9fd8e68a64939a4c9c00583be87b84aef71b66b700e87553ce1`,
is preserved byte-exact under `revision-1/`. Root found that it called store's
private `NodeDisk::binding` method from server tests. Revision 2 keeps the exact
public `NodeDiskConfig` in the serving fixture, passes that policy to its lock
helpers, and uses the signer's existing configured policy to resolve its empty
inode. No store API visibility changed. The current patch SHA is
`b8ff6eeb8f1312cc435f8f787b5c10ade76da2957e9a531139d52c24ea9fba54`.

## Findings and direct replacements

1. The serving failures occur at physical reopen, after the fixture has already
   acquired its raw `ExclusiveLock`. `NodeStore::open_existing_fixture` calls
   `NodeDisk::fixture_for_path`, which automatically reconciles when no managed
   descriptors remain. That census finds the fixture's own held installation
   lock and correctly reports `persistent storage ownership unavailable`
   (`EWOULDBLOCK`). This is a fixture census/lock collision, not evidence that
   redb Drop retains its descriptor: the vendored destructor calls the backend
   abandon/close path. The proposal installs one explicit fixture NodeDisk and
   ScratchDisk, creates the installation lock as a managed `NodeDiskFile`, and
   reuses these owners through canonical `NodeStore::open_existing`.

2. `PhysicalOwner::close` previously joined its real worker but then reported
   Complete without an explicit node close. It now awaits `NodeStore::shutdown`
   after the worker joins, merges its original typed failure, and propagates
   Retained when completion is unproven. The existing paused-worker and
   cancelled-drain assertions still prove that both physical file and lock are
   unavailable before actual completion. Successful physical reopens explicitly
   shut their temporary node down too.

3. The intentionally panicking destructor fixture now actually closes its node
   before its destructor panics. The existing test still checks an unavailable
   outer census, the same original issues, no replacement task, and repeat
   pending drains. Only the independently proven physical resources reopen;
   there is no assertion that the unknown destructor census completed.

4. The signer empty-file case previously inserted an inode using raw filesystem
   creation after the NodeDisk census. Its rejected open correctly fenced that
   unexpected binding; raw unlink did not authorize subsequent initialization.
   The test now creates and deletes the exact deliberately empty inode through
   NodeDisk. It checks that rejection of the invalid node envelope leaves the
   physical owner Open, then performs managed unlink plus parent sync before
   explicit fresh initialization. No absence retry or policy reset is added.

5. The stale signer test expected an old facade Arc to hold the physical file
   after `InstalledSignerVerifier::shutdown` succeeded. The current shutdown
   actually joins trust workers, seals store access, and closes the node. The
   replacement test retains both old verifier and signer Arcs while opening a
   fresh verifier; old signer access stays rejected, repeating old shutdown
   leaves the fresh signer usable, and fresh shutdown invalidates the fresh
   signer. Existing real retained-worker tests remain unchanged.

## Validation boundary

`manifest.json` records the patch hash and exact base/proposed bytes for the two
test files. Rust 1.97.1 rustfmt stdin parsing and `git apply --check` passed;
actual file hashes were checked unchanged. These are preparation checks only.
Root must coordinate execution of the seven failed tests, the unchanged signer
retained-worker tests, and the relevant strict lint gate before claiming a pass.

The patch is a first-release direct replacement. It introduces no compatibility
branch, alternate production owner, relaxed census fence, or fallback reopen.
