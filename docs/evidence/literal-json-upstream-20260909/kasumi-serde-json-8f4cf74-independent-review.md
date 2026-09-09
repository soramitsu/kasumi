# Independent source review: literal JSON discriminator

Reviewed clean source `8f4cf744248f54ca416c965e708ad9d0b6074930`, tree `b2f6f0506a05e52bbbda432c5d0cbe8a83180b3b`, in `/tmp/kasumi-literal-json-markers`. Root Cargo.lock SHA-256: `dd3c9d643a2fcb270147fc6bde72e2c6a5afab505d8f61a7525f0e5ba1fecaa5`.

No actionable defect was found in the three decoder changes. This is a source review, not compiler, runtime, feature-resolution, upstream-suite, or release acceptance evidence. I did not edit the reviewed worktree or run Cargo/native processes.

## Exact reviewed production inputs

- `vendor/serde_json-1.0.151/src/number.rs`: SHA-256 `8a834e29189a76772a2cd8a37fd7b259ad3bac4aa0912ea3d6156a1c22db3d96`
- `vendor/serde_json-1.0.151/src/raw.rs`: SHA-256 `82c5bb1b6e39d9c2e1620bb8e1ef826af97731e2c122e3b359a1c14a8d7b6cfc`
- `vendor/serde_json-1.0.151/src/value/de.rs`: SHA-256 `2c27c2c59649c59044dbaedb389c6c7e2dc93efe9de983fd4e79df879eb9bf58`
- Complete package diff `vendor/serde_json-1.0.151-literal-keys.patch`: SHA-256 `df9fde63228c4629faf8cbe3affb2d4284dbc498fbc881cb987106f786fcf97f`

I compared the three files with the installed published 1.0.151 sources. Production changes are the synthesized-byte-key emitters, exact byte-key consumers, and Value classifier. Serializer and numeric lexical parsing code remains unchanged.

## Causal behavior checked

1. JSON object keys reach the classifier as strings, including decoded escape spellings. Both string visitor methods now return ordinary map keys. Neither a first marker key, a later marker key, an invalid inner JSON string, nor a deeply bracketed inner string selects the synthetic Value path.
2. Genuine numeric and explicit RawValue capture maps use borrowed byte keys. Their typed NumberKey/RawKey consumers accept exact bytes. The default borrowed-byte and owned-byte visitor methods in locked serde_core 1.0.229 delegate to visit_bytes.
3. Locked serde 1.0.229 ContentVisitor records Bytes and ByteBuf separately from String and Str. ContentDeserializer and ContentRefDeserializer preserve this distinction through deserialize_str and deserialize_identifier. Therefore the internally tagged/untagged buffering path does not convert a literal string into a synthetic byte discriminator.
4. Owned and borrowed Value map readers use string key deserializers for literal objects. Genuine Value::Number delegates to Number's numeric or synthetic map reader. Explicit RawValue newtype reads create the raw capture map. These paths remain distinguishable through from_value and borrowed Deserialize.
5. The SDK literal builder in frozen 2b9061d/fb172be constructs maps and arrays directly. It parses an already-admitted numeric lexeme with Number::from_str, whose implementation directly invokes parse_any_signed_number. It does not depend on a private map key. Thus the dependency patch complements the SDK parser without replacing its depth/node/string/wire/ownership admission.
6. Bytes are an internal Serde protocol discriminator, not a security credential. A custom non-JSON deserializer can deliberately emit bytes; the patch makes no authentication claim about such a caller.
7. The published upstream Cargo.toml disables automatic tests. The patch explicitly registers literal_keys, and its retained published suite lockfile selects the same serde/serde_core 1.0.229 reviewed here.

## Regression sources reviewed

The new vendor target covers literal and escaped markers, marker ordering, inner JSON remaining string data, owned/borrowed Value and from_value, internally tagged buffering, typed-number rejection through untagged buffering, genuine large integer/exact decimal values, and explicit borrowed/owned RawValue capture and serialization. The Kasumi parser tests cover typed native mutation/staged chunks and predicates, canonical commands, rmcp's actual earliest message type, MCP output/typed arguments, history hashes, canonical snapshots, and indexed rereads.

All those Rust regressions are unrun at the reviewed checkpoint. They must execute on the resolved vendored graph. The combined SDK plus vendored graph must also rerun the snapshot tests; success on the earlier stock-dependency SDK graph does not establish combined integration correctness.

## Limits and consumer dispositions

The independent source review does not add an allocation or RSS guarantee. Correctly preserving literal strings prevents their reinterpretation as hidden raw JSON; bounded response/request admission remains separate SDK work.

The disposition correctly records that production 3a8d512 already compiled raw_value plus arbitrary_precision, so this production hazard predates the SDK feature addition. Small client-only feature graphs can differ and still require exact feature evidence.

The disposition identifies the optional rust_decimal serde-with-arbitrary-precision string-only key visitor as incompatible until adapted; its feature was absent from the recorded production graph. Final graph verification must keep this explicit and must not silently enable it. Upstream feature-matrix tests and root locked metadata checks remain required.

The vendor patch and its staged evidence do not repair old corrupted data, accept a legacy format, or bypass canonical snapshot/hash validation.
