# Literal JSON object keys in serde_json 1.0.151

This follow-up is a source-only patch disposition. On the preceding `8f4cf74`
checkpoint, dependency resolution and the complete default upstream suite passed;
the number-only suite failed an owned tagged-enum regression. The exact failure
was then reproduced on the pristine published crate with only the test added.
No Rust tests, resolver check or production build have run on this corrected
source. Raw-only and combined feature suites remain unrun. This is not release
acceptance evidence.

## Published base and exact change

The base is the published `serde_json` 1.0.151 crate, archive SHA-256
`c841b55ecdae098c80dcae9cf767f6f8a0c2cdb3416bbef72181df4d0fe73f14`.
Its published `.cargo_vcs_info.json` names upstream commit
`de8500740cdcabffb9734f503e4889def823cf10`. The archive was verified before
extraction. Both MIT and Apache-2.0 license files remain unchanged.
`patch-manifest.json` records every extracted or added input. The separate
`serde_json-1.0.151-literal-keys.patch` records the complete diff from the archive,
including the new regression target; unmodified upstream inputs stay byte exact.
It is a zero-context unified diff (`git apply --unidiff-zero -p1` from an
extracted package), avoiding whitespace-only context lines in the source tree.

Production edits are confined to `src/number.rs`, `src/raw.rs`, and
`src/value/de.rs`. The package manifest adds one regression target because
upstream disables automatic test discovery. The root manifest selects the local
crate; the root lockfile removes only its registry source and checksum. The
root lock edit is unverified until `cargo metadata --locked` succeeds. The
published upstream suite lockfile remains unchanged and is independently hashed.

## Counterexamples and correction

With `arbitrary_precision`, stock `Value::deserialize` can interpret the object
`{"$serde_json::private::Number":"7"}` as the number `7`. With `raw_value`, the
object `{"$serde_json::private::RawValue":"[1,2]"}` can become an array, and
`{"$serde_json::private::RawValue":"not JSON"}` can fail instead of preserving
the string. Unicode escapes in the key spelling take the same path. A raw-marker
string starts a second JSON parser after the outer parse; its brackets are not
part of the outer nesting count. These are source-derived counterexamples, not
executed results at this checkpoint.

The stock `Value` first-key classifier compares ordinary strings with private
tokens. Real JSON keys and the internal synthetic number/raw maps consequently
share the same representation. Removing marker recognition alone would turn
genuine large numbers into maps, including numbers buffered by tagged enums.

The correction gives synthesized keys the Serde **byte** channel:

- `NumberFieldDeserializer` and `RawKeyDeserializer` emit borrowed token bytes.
- Their internal `NumberKey` and `RawKey` visitors require the exact bytes.
- `Value::KeyClassifier` treats every string as a literal object key and recognizes
  private markers only in `visit_bytes`. No string-marker fallback remains.

The JSON lexer emits string keys, including escaped keys. Serde preserves strings
and bytes separately through `Content`, its owned/ref deserializers, and visitor
defaults. Therefore neither tagged enum buffering nor `from_value` can transform
a literal JSON string key into an internal byte marker. This is a distinction
inside the Serde protocol; JSON does not acquire byte keys. Non-JSON custom
deserializers can intentionally synthesize bytes and are not an authentication
boundary. Serializers, numeric lexemes, `RawValue` capture, and JSON wire bytes
are unchanged. Literal keys are not rejected or renamed.

## Generic 128-bit number dispatch

The owned/ref `Number::deserialize_any` implementation tried `visit_u128` and
`visit_i128` after its 64-bit cases. Serde 1.0.229's `Content` has no 128-bit
variants. Thus a genuine number can succeed through direct JSON parsing but fail
when a typed tagged enum is decoded from an already parsed `Value`. The retained
test fails with `18446744073709551616000000000000001` at its owned tagged
`from_value` assertion. Both the marker-patched source and verified pristine
1.0.151 reproduce that same failure; it is not a reason to remove the assertion.

The correction leaves the 64-bit cases intact and sends every larger integer to
the exact synthetic-number map. Only decimal/exponent lexemes may take the
existing round-tripping `f64` shortcut. This restriction matters for integers
such as `100000000000000000000`: dropping only the 128-bit callbacks would let
that integer fall through to `f64` and change its stored numeric lexeme. Explicit
`deserialize_u128` and `deserialize_i128` still parse the exact number string,
including their original sign and overflow rejection.

The new source tests retain the original failure and add both sides of the
64-bit and signed/unsigned 128-bit boundaries, larger arbitrary integers, and
integer values representable as floating point. They compare direct, owned,
borrowed, tagged, and untagged decoding, and exercise explicit typed 128-bit
success and overflow. Those additional checks have not run on this follow-up.

## Exact consumer review

The root and published upstream test lockfiles both select `serde`/`serde_core`
1.0.229. Source locations below refer to that exact version or the named locked
package, not an assertion about other releases.

| Consumer | Source behavior and disposition |
| --- | --- |
| serde_json JSON lexer | `src/de.rs`, `MapKey::deserialize_any`, emits `visit_str` or `visit_borrowed_str` after parsing key escapes. No input byte key exists. |
| serde 1.0.229 enum buffering | `src/private/de.rs`, `ContentVisitor`, `ContentDeserializer`, `ContentRefDeserializer`, and `TagOrContentVisitor` preserve byte/string variants. `deserialize_str` and `deserialize_identifier` do not coerce stored bytes to strings. No serde patch is needed. |
| serde_core 1.0.229 visitor defaults | Borrowed/owned byte visitors delegate to `visit_bytes`. `String` and borrowed `str` visitors accept valid UTF-8 bytes; ordinary map-key consumers remain usable with synthetic internal maps. |
| serde_json `Value` owned and borrowed deserializers | Literal map keys use their string deserializers. Genuine large integers use the corrected synthetic number path rather than unsupported 128-bit `Content` callbacks. `RawValue`'s explicit newtype request creates the raw capture map. All three use the patched discriminator. |
| serde_path_to_error 0.1.20 | `src/de.rs` visitor and key wrappers preserve byte callbacks; no private-token comparison was found. |
| rmcp 3.2.0 | `transport/common/server_side_http.rs::expect_json` parses the body into `ClientJsonRpcMessage` before Kasumi tool dispatch. Generic arguments contain `Value`; patching the common dependency reaches this earliest parse. |
| jsonschema 0.52.1 | Its private-number token use is a `SerializeStruct` helper, not a decode visitor; the serializer path is unchanged. |
| bigdecimal 0.4.10 | Its optional serde visitor reads the number marker using `next_key::<&str>()`, which accepts borrowed UTF-8 bytes. That serde feature was absent from the recorded production build; this is a source observation, not a tested enabled-feature claim. |
| rust_decimal 1.43.0 | Its optional `serde-with-arbitrary-precision` `DecimalKey` only accepts strings and would require a byte-visitor adaptation before enabling that feature. The recorded production build enables only `std`; this unused feature is explicitly outside the patch's validated scope. |
| Kasumi SDK literal builder | The separately reviewed bounded parser constructs maps/arrays directly and parses admitted numeric lexemes as `Number`; it does not depend on private map markers. Keep its admission work: this semantic dependency fix does not add native preallocation budgets. |

The frozen Linux ARM64 `3a8d512` production compilation already included
`serde_json` 1.0.151 with `arbitrary_precision` and `raw_value`; its network driver
used `arbitrary_precision`. The marker behavior predates the SDK parser changes.
That checkpoint failed a workspace restart test; the feature inventory is not
evidence of an accepted release. Final feature graphs must be checked again,
particularly if numeric dependency features change.

This internal protocol correction is coherent only when the decoder and `Value`
come from the same corrected crate. A stock serde_json decoder can emit a
synthetic string-marker map to a separately patched `Value` visitor, which then
correctly treats that string as a literal key. Cargo root patches are not
inherited by applications consuming published SDK crates. Consequently the
global server correction does not replace the SDK-owned bounded literal parser,
and it is not a claim of universal compatibility with external Serde decoders.

## Kasumi boundary coverage and pending gates

Regression sources cover private and escaped keys, first/last key order, invalid
and deeply nested inner text remaining strings, genuine large integers and exact
decimals, owned/borrowed `Value`, internally tagged and untagged enum buffering,
typed `Number`, and real borrowed/owned `RawValue` round trips. Kasumi tests cover
native `MutationBatch` and staged chunks, tagged `Predicate`, canonical `Command`,
rmcp's actual earliest message type and typed arguments, MCP structured output,
history document digests, canonical snapshot verification and indexed reread.
These are parser tests, not live native/MCP acceptance or persistence crash tests.

`scripts/release_gate.py` schedules the complete upstream suite under default,
number-only, raw-only, and combined number/raw/float-roundtrip/preserve-order
features. The normal workspace gate includes the representative Kasumi tests.
Run `scripts/check_dependency_patches.py` to verify the actual Cargo resolution
and every reviewed input; a hash-only source audit does not replace that check.
Record failures and executable hashes before accepting this patch. This change
does not repair already-corrupted data or add legacy decoding paths, and does
not close the separate bounded parsing or capacity release gates.
