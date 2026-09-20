# Frozen 3b932ee compiler failure

The exact prepared cohort ran on unchanged source
`3b932ee0a2de86b76655b5bef6dd4cc4fff82fab`, tree
`4f696e370e184ea36e5f3314feeb064679b6d3ba`, from
2026-09-09 15:38:14.303097 UTC through 15:39:20.295181 UTC.
This is a failed integration diagnostic, not release acceptance.

| Gate | Original deadline | Actual outcome |
| --- | --- | --- |
| Locked offline workspace, all targets/features check | 900 seconds | FAIL; exit 101; 65.581 seconds; PG 15838 drained |
| Workspace formatting | 300 seconds | UNRUN |
| Complete store library with 44 mandatory regressions | 900 seconds | UNRUN |
| Strict store lint, all targets/features | 600 seconds | UNRUN |

The compiler reported three E0599 diagnostics: `get` and `range` in
`single_catalog.rs`, and `iter` in `single_catalog/tests.rs`. The new module
omitted the `redb::ReadableTable` import. No test executed. The original
stop-on-first-failure rule withheld every subsequent gate; no deadline was changed.
The process group had no remaining processes, signals, drain errors or timeout.
Source comparison passed. The wrapper reports 65.581 seconds including drain;
the inner process record reports 65.580 seconds.

Root development commit `198bb6ca8986073ecdeebb2a749b16f4ebd75027` adds that trait
import; the child test module imports the parent's names. Only direct formatting
and whitespace checks ran on the correction. It still requires actual compilation
and all withheld gates. The frozen failed source and its evidence are unchanged.

The five original files are copied byte for byte. `copied-files.json` contains
their SHA-256 values; original evidence SHA-256 is
`0ee67276c68486835e481e4d35563660c8c60aad859c696ab932c071a5d3b614`.
Source, lockfile, toolchain, commands, runner/helper hashes and compiled dependency
inventory are retained in the raw manifests and log. This cohort excludes the
later typed drain, polling-panic and explicit Control genesis changes, all of
which remain unvalidated. Full platform, native, provider, capacity and endurance
gates remain open.
