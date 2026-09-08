# Shared scratch disk core evidence

This records core constructor changes through `9f870cd` on macOS ARM64.
The final store suite passed 79 tests with one external-service test ignored;
strict store Clippy and fixture-free library checks passed. Earlier private
directory fixture failures are retained. Executable hashes were captured when
each run closed; later reuse of the build directory does not establish a new
historical hash.

The governor accounts encrypted allocated extents and pending filesystem
promises, shares installed owners, and releases charges only after actual file
drain or successful truncation. Production caller integration was separately
validated at `cc7fbeb`. This does not reserve persistent database/index/WAL
capacity or satisfy native durable reservations, 3 GiB or endurance gates.
