# Complete upstream source preparation for the capacity prototype

This is source preparation and review, with no dependency resolution, build,
functional, lint or fuzz result. It does not approve a production redb patch.

Frozen upstream verification overlay `bdde7978ddac88db4851cbf0c1f77f75f5778b47`
(tree `16deeaf1fadc3f169e69e960457042296fe8b3ed`) combines exact redb 4.2.0
upstream Git commit `23b6ba05473b13e69ed4db82f4b5bc07f0c33be9` with reviewed
Kasumi prototype source `4f628637f35439a51c0b63faf98534800c5a5f85`. Its 124
tracked file hashes and exact overlay patch are retained here. The separate
upstream checkout is `/tmp/kasumi-redb-4f62863-upstream`.

Only the prototype source/CHANGELOG changes and its explicit feature declaration
were overlaid. The original workspace manifest, derive/Python workspace members,
examples, upstream tests and fuzz inputs remain. The normalized published crate
manifest and its lockfile were not substituted. This matters because the
published crate omits inputs required by the upstream verification recipes.

Both upstream workspace and fuzz dependency graphs still require resolution and
freezing; the pinned Rust 1.97.1 harness and tools remain to be prepared. Complete
`just test` scope and bounded transaction fuzzing are required before declaring
the vendored change done. The previous narrow prototype tests cannot substitute
for those gates. The source review also leaves production owner admission and
response-release fences open; existing issued memory views are not revoked by
the prototype itself.

Preservation hashes cover the byte-exact source inventory, patch and root review.
