# Recovery fixture stack diagnosis

The frozen `f4a472ffa510cead0a5383a5a199a7e5f47560ef` exact activation-recovery test aborted with a stack overflow. The original runner retained its failed output and executable. No new Kasumi process or compiler ran for this diagnosis.

The selected macOS crash frames bind to PID 65795 and executable SHA-256 `26d58319400fb6ee4fddcfe8b0b1aa2cb116d8f084c72f843c4027eb1e42fd88`; the executable's Mach-O UUID also matches the crash image. `analysis.json` records the original report, runner evidence, source manifest and full raw-output hashes. Only selected symbols and source positions were extracted; host inventory, register contents and memory maps were omitted. The original executable is not copied into this directory.

The test had finished activation and every-voter confirmation. Its poll chain entered `exercise_route_publication` at `recovery_control.rs:1076`, then `ControlPlane::initialize`, collections and a real Raft linearizable barrier. No recursive application call loop appears in the 45-frame report.

The retained ARM64 debug prologues reserve these fixed stack frames:

| Poll function | Bytes |
| --- | ---: |
| `exercise_completed_recovery` | 1,365,616 |
| `exercise_route_publication` | 372,016 |
| `ControlPlane::initialize` | 30,320 |
| `Database::collections` | 13,184 |
| `Database::collections_inner` | 31,904 |
| `Database::barrier` | 8,544 |

These are manual sums of prologue allocation instructions, including saved registers. `prologues.txt` preserves the exact instructions. They are not future-object sizes or a complete measurement of dynamic stack usage. The evidence supports excessive composition of two large fixture poll frames, rather than recursive recovery dispatch.

The proposed fixture change returns an owned `{Fixture, database, RecoveryStart}` handoff after the original completion/activation assertions. A small wrapper heap-owns each phase future in sequence; the first future returns and is dropped before route publication is polled. No detached task, stack-size increase, changed assertion, new authorization, deadline reset, storage reopen or owner clone is added at this boundary. Existing route checks and explicit fixture closure remain in the route phase.

The source change is uncompiled and unexecuted. It is a fixture composition fix; it does not establish production API stack bounds or release readiness. Required validation starts with the exact failed test at normal stack settings, then all five `exercise_completed_recovery` callers, followed by the scheduled strict checks. Preserve this failure even if the successor passes.

`extract.py --report ORIGINAL.ips --binary RETAINED_EXECUTABLE --output OUTPUT_DIRECTORY` reproduces selected frames and disassembly using macOS `nm`, `dwarfdump`, and the installed `llvm-objdump`. It verifies the binary hash, PID and image UUID before extraction. The three parent evidence hashes were added separately from the frozen runner files; raw source and failure artifacts remain with that runner.
