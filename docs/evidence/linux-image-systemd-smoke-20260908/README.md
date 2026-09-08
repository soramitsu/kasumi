# Native Linux build image and deployment recipe smoke

Recipe source 42bf607 built the pinned Rust validation image and an ARM64 runtime
image. This smoke uses the retained production binaries from 8e90ff2, whose full
workspace test gate failed. It does not approve those binaries for release.

The runtime image initialized an offline private standalone installation and
served authenticated native audit, renewal and encrypted backup requests with a
read-only root filesystem, UID/GID 65532, no capabilities and no external network.
The first backup hit work admission under a 2 GiB cgroup. After a clean restart
under 4 GiB, the exact saved session succeeded and its backup verified. Both
attempts remain in the raw logs. Both container stops drained and exited zero.

Both systemd units passed static verification. The exact data service unit also
ran as its dedicated static user, passed authenticated operations, reloaded all
three TLS listeners through SIGHUP, restarted the same installation and drained
twice. The authority service was not installed or run. Both smoke daemons are
stopped. Private installation keys remain only in the isolated VM.

Image identities, executable hashes, build logs, OS package inventories and
service results are retained here. These are recipe checks, not end-to-end
candidate assembly, a full OCI/SPDX artifact, independent recompilation or final
cross-platform, capacity, recovery and endurance acceptance.
