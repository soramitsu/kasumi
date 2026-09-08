# Dependency dispositions

This register records source decisions, not a waiver of final release checks.
Every release must retain the raw current advisory report, dependency lockfile,
patch verification output and regression logs. A new advisory fails acceptance
until reviewed. No version-only ignore is sufficient for a source patch.

| Advisory or source defect | Disposition |
| --- | --- |
| RUSTSEC-2025-0167, bitmaps unsound byte access | Vendored validation and removal of mutable byte access. Verify exact input hashes and run both runtime and compile-fail regressions. |
| RUSTSEC-2026-0253, lru panic safety | Minimal upstream ordering backport to the compatible 0.16.4 API. Verify exact input hashes and panic/eviction regression. |
| RUSTSEC-2026-0247, bitmaps unmaintained | Kasumi owns the small vendored patch and review surface. Retain MPL source/license and monitor replacement options. This maintenance advisory remains visible. |
| RUSTSEC-2023-0089, atomic-polyfill unmaintained | Disabled postcard's unused default heapless-cas feature. Kasumi uses its allocated encoding API; removing heapless also removes atomic-polyfill from the lockfile. Final platform graphs must confirm continued absence. |
| RUSTSEC-2025-0134, rustls-pemfile unmaintained | Replaced direct transport use with rustls-pki-types PEM APIs; removed from the integration lockfile. Final platform graphs must confirm its continued absence. |
| serde_json 1.0.151 literal private-marker object keys | Vendored decoder separates synthesized byte keys from literal string keys, preserving arbitrary document keys and genuine arbitrary-precision numbers. No advisory ID is asserted. Source-only disposition; resolver, upstream feature suites and Kasumi regressions remain required. See the [review](../vendor/serde-json-literal-keys.md). |

Patch provenance, original license obligations, and commands are in
[`vendor/README.md`](../vendor/README.md). These patches keep the published version
number so that security tools cannot mistake a local version suffix for an
upstream fix. Release evidence must show the resolved path and content hashes.
