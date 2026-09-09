# Literal JSON dependency: upstream validation and retained failures

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
it did not substitute for these execution gates. The failure remains unchanged in this historical attempt. Its separately frozen
numeric correction and complete upstream results follow below.


Corrected source `13fbbc162d2a428bde502a334beb3ebab9aa59d9` keeps generic
arbitrary integers above 64 bits on the exact-number map path through Serde
content buffering; explicit signed/unsigned 128-bit decoding remains available.
The exact original failing case and additional boundary cases remain required.

| Corrected gate | Actual outcome |
|---|---|
| Resolver and all vendored input hashes | Passed, 1.067 s |
| Complete default upstream suite | 239 passed, 1 ignored; 65.836 s |
| Complete number-only upstream suite | 245 passed, 1 ignored; 68.876 s |
| Complete raw-only upstream suite | 257 passed, 1 ignored; 76.108 s |
| Complete combined upstream suite | 265 passed, 1 ignored; 78.180 s |

Counts include documentation tests. Each suite retains the unchanged upstream
UI test ignored because it requires nightly. All eight combined literal-key
regressions passed. Session 51013 exited successfully; all five owned process
groups drained. Source inventories before/after are identical and all recorded
artifact hashes were rechecked. The preserved-executables manifest identifies
the original local artifact copies; executable bytes are not checked into this
evidence directory.

`13fbbc1/evidence.json` SHA-256 is
`2c0eb93be7c7d7fc325dc03313feff5b8c8b4cfcf2854ee99dad1f3a30d6953d`.
The patch is now combined with SDK snapshot and corrected shutdown ownership
work only in validation branch `eb1f31e`. No combined Kasumi compilation, native
boundary test or final production gate has yet run against that integration.
