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
| GHSA-2mjx-qc3c-rqvc (RUSTSEC-2026-0285), GHSA-c8m5-c952-6cm4 (RUSTSEC-2026-0346), GHSA-h2v8-394m-p7vv (RUSTSEC-2026-0348), GHSA-w44r-93j7-qv28 (RUSTSEC-2026-0349), rustls | Updated the workspace lockfile from 0.23.43 to 0.23.46, which fixes all four advisories. Only rustls's version and checksum change; persisted formats and the remaining dependency graph are unchanged. Retain TLS listener, client, cluster transport and affected-crate test evidence with the release. |
| [GHSA-h395-gr6q-cpjc](https://github.com/Keats/jsonwebtoken/security/advisories/GHSA-h395-gr6q-cpjc) (CVE-2026-25537), jsonwebtoken 9.3.1 claim type confusion | Not applicable to the current authentication path; retained 9.3.1. `Authenticator::verify`, Kasumi's only JWT decode, disables the library's wall-clock `exp`/`nbf` checks, requires `exp`, `iss`, `aud` and `sub`, and decodes `exp: u64` and `nbf: Option<u64>`. Malformed non-null time claims therefore fail typed decoding before Kasumi checks expiry and not-before against its trusted epoch clock. `auth::tests::signed_claim_times_use_only_trusted_native_epoch_with_exact_boundaries` covers wrong types, overflow and exact time boundaries. GitHub reports this advisory against three dependency manifests; all use this path. Re-review if another decode path is added, claim types change or validation settings change. This disposition does not dismiss the GitHub alerts. |
| serde_json 1.0.151 literal private-marker object keys and generic 128-bit enum buffering | Vendored decoder separates synthesized byte keys from literal string keys and keeps larger generic integers on the exact synthetic map path. Explicit typed 128-bit requests remain exact. The generic owned-tagged failure was reproduced against pristine upstream. No advisory ID is asserted. This corrected source has not been tested; upstream feature suites and Kasumi regressions remain required. See the [review](../vendor/serde-json-literal-keys.md). |

Patch provenance, original license obligations, and commands are in
[`vendor/README.md`](../vendor/README.md). These patches keep the published version
number so that security tools cannot mistake a local version suffix for an
upstream fix. Release evidence must show the resolved path and content hashes.
