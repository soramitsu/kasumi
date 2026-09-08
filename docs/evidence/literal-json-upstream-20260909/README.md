# Literal JSON dependency: retained upstream and baseline failures

These are dependency-only checks on macOS ARM64 using Rust 1.97.1. No Kasumi
workspace compilation, listener, provider, native API or release acceptance ran.
Sources and dependency locks stayed unchanged; all owned process groups drained.

Prepared patch `8f4cf744248f54ca416c965e708ad9d0b6074930`:

| Gate | Actual outcome |
|---|---|
| Root dependency resolution and exact patch inputs | Passed, 0.803 s |
| Default upstream serde_json suite and documentation | 239 passed, 1 upstream test ignored; 79.638 s |
| Number-only upstream suite | Failed in the new large-number regression after 49 passing tests |
| Raw-only and combined feature suites | Not started |

Session 27813 exited after the first failed gate. In
`genuine_numbers_survive_direct_owned_borrowed_and_tagged_paths`, an owned
`from_value` conversion into a tagged enum failed at `literal_keys.rs:112`.
The integer `18446744073709551616000000000000001` was dispatched through a
128-bit visitor callback that the locked serde 1.0.229 content buffer does not
support. The failure occurred after the direct and ordinary Value conversions
in that regression. Its expected behavior was not weakened or removed.

An isolated pristine serde_json 1.0.151 copy, verified against the published
archive, reproduced the **same failure** in the same exact test. Only the test
target and regression source were added; production decoder files remained
unmodified. Session 68901 exited 101 after 26.509 s. This establishes that this
particular numeric failure predates the literal-key patch, but does not make
the patched behavior acceptable. A corrected patch must still pass the test.

Per-attempt evidence contains exact source inventories, published/root lock
hashes, compiler and executable hashes, commands, raw failures and child-drain
records. Earlier independent source review is retained with its stated limits;
it did not substitute for these execution gates. Both prepared patch and its
numeric correction remain outside the release implementation pending validation.
