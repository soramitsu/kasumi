# Gate 77 store follow-up

Target-only proposal against the now-applied source observed during gate 77.
Actual source and the running check were not changed. Exact before/proposed
hashes are in manifest.json. No build or runtime test was run.

- Remove only the mechanically inserted third scratch argument from two
  AtomicBool::store calls in the historical audit verification test.
- Prepare the symlink ScratchDiskConfig and one explicit TestDiskMemory before
  entering the FnMut retry closure. Every retry borrows the same config and
  clones the exact same admitted memory owner. Byte and reservation caps remain
  1 MiB and 32, and only RegistryBusy is retried by the existing helper.
- Keep one mutable NodeDisk state guard at the existing preallocation
  serialization point in prepare_publication. Remove the second lock acquisition,
  which otherwise self-deadlocks while the first shadowed guard is still live.
  The same guard survives path validation into PreparedPublication; physical
  parent failures still call fail_locked and preparation failure still drops
  the guard before the descriptor owner.
- Scope DeviceDisk::memory to cfg(test), matching both actual caller sites
  (DeviceSelection::Existing and ScratchDisk::test_with_device).

All four target files format; git apply --check passes against their exact
current hashes. Existing publication/allocation tests should validate the single
lock boundary in the coordinated successor run. No quotas, assertions, deadlines,
production fencing, or registered-owner drop behavior are relaxed.
