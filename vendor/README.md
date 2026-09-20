# Reviewed dependency patches

These directories contain the published crates with minimal security changes.
The upstream versions are unchanged: scanners must continue to show the original
advisory when one exists, and the release gate must verify the exact patched
sources. Registry extraction markers and VCS directories are omitted; published
`.cargo_vcs_info.json` provenance remains. Original licenses and notices remain.
`patch-manifest.json` records the published archive checksums and every vendored
input, including separate lockfiles used by the upstream regression suites.

## bitmaps 3.2.1

[RUSTSEC-2025-0167](https://rustsec.org/advisories/RUSTSEC-2025-0167.html)
describes invalid boolean representations accepted through two byte APIs. The
patch rejects every byte above one when decoding `Bitmap<1>` and removes the
`AsMut<[u8]>` implementation. Bit operations and checked byte construction remain.
The regression exercises all 256 byte values, malformed lengths, and a full
eight-bit bitmap; a compile-fail doctest checks that mutable byte access is absent.
The changed `src/bitmap.rs` and `src/lib.rs` remain under MPL-2.0 or later. Their
source and the original `LICENCE.md` must accompany release source distributions.

## lru 0.16.4

[RUSTSEC-2026-0253](https://rustsec.org/advisories/RUSTSEC-2026-0253.html)
is fixed by unlinking the entry before its allocation is released and before the
key destructor runs. This backports the ordering change from
[upstream pull request 238](https://github.com/jeromefroe/lru-rs/pull/238), whose
released fix is 0.18.2. Tantivy's current dependency accepts 0.16, so the backport
keeps its API without replacing unrelated search dependencies. The regression
catches a key destructor panic, checks both list directions, then exercises
eviction, lookup, removal and destruction. The upstream MIT license applies.

## serde_json 1.0.151

The serde_json 1.0.151 patch preserves literal JSON object keys that spell its
private number and raw-value tokens. Only synthesized deserializer keys use the
Serde byte channel; JSON string keys remain strings. This corrects native,
durable, and MCP `Value` decoding without banning document keys or changing
JSON output. See [the patch disposition](serde-json-literal-keys.md) for the
published checksum, reviewed consumers, exact scope, and pending validation.
The generic number deserializer also retains larger integers on that exact map
path through Serde enum buffering; explicit typed 128-bit requests stay exact.
Both upstream MIT and Apache-2.0 licenses remain in the vendored directory.

## rmcp 3.2.0

The terminal stateless HTTP constructor executes the handler inside its calling
HTTP future, preserving SDK validation while avoiding detached service, handler
and response-send tasks. Unsupported asynchronous peer traffic fails explicitly;
Kasumi preserves uncertain mutation outcomes when the transport withholds a
response. See [the ownership review](rmcp-terminal-ownership.md) for provenance,
the exact ownership graph and required regression commands. The upstream
Apache-2.0 license is retained.

## Verification

```sh
python3 scripts/check_dependency_patches.py
cargo test --manifest-path vendor/bitmaps-3.2.1/Cargo.toml --locked
cargo test --manifest-path vendor/lru-0.16.4/Cargo.toml --locked
cargo test --manifest-path vendor/serde_json-1.0.151/Cargo.toml --locked
cargo test --manifest-path vendor/serde_json-1.0.151/Cargo.toml --locked --features arbitrary_precision
cargo test --manifest-path vendor/serde_json-1.0.151/Cargo.toml --locked --features raw_value
cargo test --manifest-path vendor/serde_json-1.0.151/Cargo.toml --locked --features arbitrary_precision,raw_value,float_roundtrip,preserve_order
```

The release workflow must run every upstream suite above in addition to the workspace
tests. Miri regression checks are supplementary evidence; they do not replace
the production toolchain gates. Changing an input requires reviewing the diff
and deliberately updating its hash. Do not regenerate the manifest in CI.
