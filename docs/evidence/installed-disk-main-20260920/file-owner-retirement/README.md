# File-owner retirement — target-only correction

Prepared against current actual master source, independently of the unmerged directory draft. No actual source edits, Cargo, tests or production compilation occurred. Only node_disk/file.rs and node_disk/tests.rs change. A separate root node_disk.rs lint fix does not overlap.

The previous destructor closed the data FD and decremented open_files before the parent FD, paths, native mutex and Arc backing were destroyed. The live map also pruned strong_count==0 entries, allowing a same-inode reopen while its predecessor still retained resources. Repeated overlap could reuse a metadata allowance before its old allocation was gone.

This patch:

- Keeps every private strong Arc behind OwnedFileArc. Normal and concurrent final drops use Arc::into_inner; failed exclusive unwrap returns that same wrapper. The moved FileOwner is retired outside the original Arc allocation.
- Retains the exact live-map Weak through retirement. Its stable allocation address is copied into FileOwner and transferred only under the publication state guard. No Weak is pruned on strong_count==0; retiring same-inode opens return WouldBlock without poisoning the owner.
- Closes both actual descriptors, destroys root/relative/component/name allocations and the native budget mutex, then drops the exact last registered Weak, then decrements open_files. This keeps actual FD drain and metadata-slot reuse behind complete destruction. No public raw Arc/Weak escape is added.
- Makes exclusive reclaim retire all resources and Weak backing under serialization before publishing byte/promise/handle credit; failure retains the original io::Error and prior bytes/promises.
- Declares PreparedFile's state guard last, so its unregistered Arc/path/FD/native-lock preparation storage is destroyed before another preparation can use the H+1 allowance.
- Keeps publication's replacement Arc uninitialized and separate from its moved registered owner. Uninitialized Arc and staged paths/FDs drop before state unlock; the registered owner drops after unlock. Successful rename initializes the already-prepared allocation and transfers the exact Weak registration without allocating. Destructured local declaration order also puts the guard before registered retirement during unwind.
- Preserves existing file quotas and required_metadata_bytes' actual size-based formula. The owner gains only inline retirement state; no new independent governor or increased operating cap is introduced.

Tests added (unrun): gated data-close versus all-resources-close credit denial; concurrent final clone retirement; gated reclaim success/failure retaining device promises; zero-allocation publication abandonment then successful publication; actual prepared target descriptor retirement before later preparation. The existing predecessor test is tightened: data-FD close alone no longer permits a replacement owner; after complete retirement a replacement retains its own exact registration. Existing post-publication allocation assertions remain exactly zero.

Target-only checks: rustfmt and git apply --check; manifest contains every actual-before/proposed hash. No behavioral/lint success is claimed until root's coordinated compile and store cohort run. Directory accounting, namespace growth limits, and async worker custody remain separate work.
