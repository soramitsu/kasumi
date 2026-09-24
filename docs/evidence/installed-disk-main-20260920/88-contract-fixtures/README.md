# Contracts fixture successors

Combined target-only candidate for both observed run88 contracts failures. Includes the exact previously prepared private crash installation change (00892529), whose standalone package remains preserved and must not also be applied.

The forced audit backend failure correctly withholds the read, then exposes original background-write and OpenRaft core storage failures through complete drain. The old test incorrectly required clean success after injecting that permanent I/O failure. The corrected assertion requires exactly the two observed components, original typed Store/Write core failure and exact diagnostic, no other runtime child failures, Complete on both drains, and identical original DrainIssue Arcs. It also verifies the actual Raft/read owners remain fenced. No production error or drain behavior changes; audit shutdown still must pass its unchanged assertion.

Original crash/deadline/workloads and strict data-withholding assertions are retained. Formatting and apply-check pass, no actual source edit/build/test. Validate both exact contracts cases and later complete successor before claiming success. Any new failure remains evidence; do not widen this expected inventory speculatively.
