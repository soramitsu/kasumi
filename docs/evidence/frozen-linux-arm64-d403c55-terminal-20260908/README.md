# Failed frozen Linux ARM64 functional run

Source `d403c55225d372fa09d6e9eb1f9472cb571af685` failed the workspace gate during linking: the7GiB container triggered a confirmed OOM kill. No full workspace test result or candidate is inferred. The original kernel/cgroup evidence and launch configuration remain in `../frozen-linux-arm64-d403c55-launch-20260908`.

Every other gate passed, including strict Clippy and the fixture-free production build (834.847s). `evidence.json` binds all logs, frozen input hashes and exact3 production executable hashes. The original detached source, full target and binaries remain in the owned Linux VM. The conditional package steps did not run.

The subsequent VM memory expansion is a separate environment change; it does not amend this attempt. Final-source native platform, capacity, recovery, performance and24-hour endurance gates remain open.
