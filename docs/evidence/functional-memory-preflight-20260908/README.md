# Effective functional build memory

A kernel-confirmed linker OOM in d403c55 showed that the former 7 GiB container
allocation was insufficient for the full debug workspace. Source 4f5550f now
requires 15 GiB effective memory and provisions a 16 GiB reference VM, allowing
kernel reservations. Linux preflight checks the current cgroup and visible
ancestor ceilings as well as physical memory.

All 18 Python tests pass. Actual macOS preflight passes at 64 GiB, and the still
running 7 GiB Linux container is rejected with its exact effective limit recorded.
The current failed run remains frozen at its original allocation until all
remaining gates close. It is not retroactively repaired by changing the template.
This is a build-host requirement; workload deployment capacity needs measurement.
