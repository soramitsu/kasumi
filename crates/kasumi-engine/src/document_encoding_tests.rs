use super::*;
use serde_json::json;
use std::collections::HashMap;

fn limits() -> BodyLimits {
    BodyLimits {
        canonical_bytes: 4 << 20,
        manifest_bytes: 8 << 20,
        fragments: 16_384,
        blobs: 16_384,
        depth: 128,
    }
}

fn encode(body: &Value, blobs: &mut HashMap<[u8; 32], Vec<u8>>) -> BodyManifest {
    let (manifest, wire) = encode_body(body, limits(), |object| {
        let bytes = object.bytes();
        assert_eq!(object.digest(), <[u8; 32]>::from(Sha256::digest(bytes)));
        if let Some(existing) = blobs.get(&object.digest()) {
            ensure!(existing == bytes, "immutable blob collision");
        } else {
            blobs.insert(object.digest(), bytes.to_vec());
        }
        Ok(())
    })
    .unwrap();
    assert_eq!(wire, serde_json::to_vec(&manifest).unwrap());
    manifest
}

fn reconstruct(manifest: &BodyManifest, blobs: &HashMap<[u8; 32], Vec<u8>>) -> Vec<u8> {
    reconstruct_body(manifest, limits(), |reference| {
        blobs.get(&reference.sha256).context("missing blob")
    })
    .unwrap()
    .into_owned()
}

#[test]
fn staged_manifest_fits_its_exact_wire_limit() {
    let body = json!({"nested": [true, "雪\n", "a".repeat(STRING_THRESHOLD * 2)]});
    let (_, original) = encode_body(&body, limits(), |_| Ok(())).unwrap();
    let exact = BodyLimits {
        manifest_bytes: original.len(),
        ..limits()
    };
    let (manifest, wire) = encode_body(&body, exact, |_| Ok(())).unwrap();
    assert_eq!(wire, original);
    assert_eq!(wire, serde_json::to_vec(&manifest).unwrap());
    assert!(
        encode_body(
            &body,
            BodyLimits {
                manifest_bytes: original.len() - 1,
                ..exact
            },
            |_| Ok(())
        )
        .is_err()
    );
}

#[test]
fn single_literal_lends_its_authenticated_bytes_before_decode() {
    let body = json!({"values": vec![0u8; 500]});
    let mut manifest = encode(&body, &mut HashMap::new());
    let [Fragment::Literal(text)] = manifest.fragments.as_slice() else {
        panic!("expected one inline document");
    };
    let data = reconstruct_body::<Vec<u8>>(&manifest, limits(), |_| bail!("unexpected blob read"))
        .unwrap();
    assert!(matches!(data, Cow::Borrowed(_)));
    assert_eq!(data.as_ptr(), text.as_ptr());
    assert_eq!(serde_json::from_slice::<Value>(&data).unwrap(), body);
    drop(data);
    manifest.canonical_sha256[0] ^= 1;
    assert!(
        reconstruct_body::<Vec<u8>>(&manifest, limits(), |_| bail!("unexpected blob read"))
            .is_err()
    );
}

#[test]
fn action_scoped_proofs_share_binary_chunks_without_changing_documents() {
    let raw: Vec<u8> = (0..BLOB_CHUNK_BYTES * 3 + 37)
        .map(|n| (n * 73 % 251) as u8)
        .collect();
    let mut blobs = HashMap::new();
    let first = json!({"actionId": "first", "bytesBase64": STANDARD.encode(&raw), "index": 0});
    let second = json!({"actionId": "second", "bytesBase64": STANDARD.encode(&raw), "index": 0});
    let third = json!({"actionId": "third", "hex": hex::encode(&raw)});
    let fourth = json!({"actionId": "fourth", "hex": hex::encode_upper(&raw)});
    let mut identities = None;
    for body in [first, second, third, fourth] {
        let manifest = encode(&body, &mut blobs);
        let refs = manifest.blob_references().cloned().collect::<Vec<_>>();
        if let Some(expected) = &identities {
            assert_eq!(&refs, expected);
        } else {
            identities = Some(refs);
        }
        assert_eq!(
            reconstruct(&manifest, &blobs),
            serde_json::to_vec(&kasumi_types::CanonicalJsonValue(&body)).unwrap()
        );
        assert_eq!(
            decode_body(&manifest, limits(), |reference| blobs
                .get(&reference.sha256)
                .context("missing"))
            .unwrap(),
            body
        );
    }
    assert_eq!(blobs.len(), 4);
    assert_eq!(blobs.values().map(Vec::len).sum::<usize>(), raw.len());
}

#[test]
fn opaque_unicode_escaping_and_literal_markers_round_trip_exactly() {
    let number: Value =
        serde_json::from_str("1.23456789012345678901234567890123456789e+123").unwrap();
    let body = json!({
        "z": "雪\"\\\n\u{0000}".repeat(20_000),
        "n": number,
        "marker": {"$serde_json::private::Number": "123", "$serde_json::private::RawValue": "null"},
        "array": [null, false, {}, [], "ordinary"]
    });
    let mut blobs = HashMap::new();
    let manifest = encode(&body, &mut blobs);
    let encoded = manifest.to_bytes(limits()).unwrap();
    let reparsed = BodyManifest::from_bytes(&encoded, limits()).unwrap();
    let actual = decode_body(&reparsed, limits(), |reference| {
        blobs.get(&reference.sha256).context("missing")
    })
    .unwrap();
    assert_eq!(actual, body);
    assert_eq!(
        reconstruct(&reparsed, &blobs),
        serde_json::to_vec(&kasumi_types::CanonicalJsonValue(&body)).unwrap()
    );
    assert!(blobs.values().all(|blob| blob.len() <= BLOB_CHUNK_BYTES));
}

#[test]
fn opaque_strings_use_the_exact_canonical_chunk_boundary_before_calling_the_sink() {
    for (prefix, tail) in [
        (BLOB_CHUNK_BYTES - 3, "!"),
        (BLOB_CHUNK_BYTES - 3, "\n"),
        (BLOB_CHUNK_BYTES - 3, "\u{0001}"),
        (BLOB_CHUNK_BYTES - 3, "雪"),
        (STRING_THRESHOLD, "雪"),
        (STRING_THRESHOLD, "\"\\"),
    ] {
        let value = Value::String(format!("{}{tail}", "!".repeat(prefix)));
        let canonical = serde_json::to_vec(&value).unwrap();
        let mut chunks = Vec::new();
        let (manifest, _) = encode_body(&value, limits(), |object| {
            chunks.push(object.bytes().to_vec());
            Ok(())
        })
        .unwrap();
        assert_eq!(
            manifest.canonical_sha256,
            <[u8; 32]>::from(Sha256::digest(&canonical))
        );
        assert_eq!(
            chunks,
            canonical.chunks(BLOB_CHUNK_BYTES).collect::<Vec<_>>()
        );
        let mut calls = 0;
        let refused = encode_body(
            &value,
            BodyLimits {
                canonical_bytes: canonical.len() - 1,
                ..limits()
            },
            |_| {
                calls += 1;
                Ok(())
            },
        );
        assert!(refused.is_err());
        assert_eq!(calls, 0);
    }
}

#[test]
fn alternate_binary_spellings_are_preserved_as_opaque_json() {
    // A mixed-case hex-looking value must not have its spelling normalized.
    let mixed = "aAbBcCdDeEfF".repeat(1000);
    let noncanonical_base64 = format!("{}Zh==", "AAAA".repeat(1100));
    for string in [mixed, noncanonical_base64, "=?".repeat(3000)] {
        let mut blobs = HashMap::new();
        let body = json!({"data": string});
        let manifest = encode(&body, &mut blobs);
        assert_eq!(
            reconstruct(&manifest, &blobs),
            serde_json::to_vec(&body).unwrap()
        );
    }
    assert_eq!(
        classify(&format!("{}Zh==", "AAAA".repeat(1100))),
        Encoding::Json
    );
}

#[test]
fn base64_physical_selection_matches_the_exact_logical_spelling() {
    // Cross a physical chunk boundary. A padding symbol is valid only in the
    // last quartet, and any unused low bits in that quartet must be zero.
    let prefix = "++//".repeat(BLOB_CHUNK_BYTES / 3 + 1);
    for byte in 0u8..=127 {
        let ch = char::from(byte);
        for s in [
            format!("{prefix}A{ch}=="),
            format!("{prefix}AA{ch}="),
            format!("{prefix}A/+{ch}"),
            format!("AA{ch}A{prefix}AAAA"),
        ] {
            let canonical = STANDARD
                .decode(&s)
                .is_ok_and(|raw| STANDARD.encode(raw) == s);
            assert_eq!(classify(&s) == Encoding::Base64, canonical);
        }
    }
}

#[test]
fn byte_fragment_blob_and_depth_limits_fail_closed() {
    let body = json!({"proof": "a".repeat(STRING_THRESHOLD * 3)});
    let mut called = 0;
    assert!(
        encode_body(
            &body,
            BodyLimits {
                canonical_bytes: 50,
                ..limits()
            },
            |_| {
                called += 1;
                Ok(())
            }
        )
        .is_err()
    );
    assert_eq!(called, 0);
    assert!(
        encode_body(
            &body,
            BodyLimits {
                fragments: 1,
                ..limits()
            },
            |_| Ok(())
        )
        .is_err()
    );
    assert!(
        encode_body(
            &body,
            BodyLimits {
                blobs: 0,
                ..limits()
            },
            |_| Ok(())
        )
        .is_err()
    );
    assert!(
        encode_body(
            &json!([[[true]]]),
            BodyLimits {
                depth: 1,
                ..limits()
            },
            |_| Ok(())
        )
        .is_err()
    );
    assert!(
        encode_body(
            &body,
            BodyLimits {
                manifest_bytes: 10,
                ..limits()
            },
            |_| Ok(())
        )
        .is_err()
    );
}

#[test]
fn decode_limits_are_checked_before_allocation_and_blob_reads() {
    let mut blobs = HashMap::new();
    let manifest = encode(&json!({"proof": "a".repeat(30_000)}), &mut blobs);
    let mut reads = 0;
    assert!(
        reconstruct_body(
            &manifest,
            BodyLimits {
                canonical_bytes: 12,
                ..limits()
            },
            |_| {
                reads += 1;
                Ok(Vec::<u8>::new())
            }
        )
        .is_err()
    );
    assert_eq!(reads, 0);
    let mut oversized = manifest.clone();
    oversized.canonical_bytes = u64::MAX;
    assert!(
        reconstruct_body(&oversized, limits(), |_| {
            reads += 1;
            Ok(Vec::<u8>::new())
        })
        .is_err()
    );
    assert_eq!(reads, 0);
    let encoded = manifest.to_bytes(limits()).unwrap();
    assert!(
        BodyManifest::from_bytes(
            &encoded,
            BodyLimits {
                manifest_bytes: encoded.len() - 1,
                ..limits()
            }
        )
        .is_err()
    );
    let nested = encode(&json!([[[false]]]), &mut blobs);
    assert!(
        decode_body::<Vec<u8>>(
            &nested,
            BodyLimits {
                depth: 1,
                ..limits()
            },
            |_| bail!("unexpected read")
        )
        .is_err()
    );
}

#[test]
fn missing_corrupt_truncated_and_reordered_chunks_are_rejected() {
    let raw: Vec<u8> = (0..BLOB_CHUNK_BYTES * 2 + 97)
        .map(|n| (n * 53 % 251) as u8)
        .collect();
    let mut blobs = HashMap::new();
    let manifest = encode(&json!({"proof": hex::encode(&raw)}), &mut blobs);
    assert!(reconstruct_body::<Vec<u8>>(&manifest, limits(), |_| bail!("missing")).is_err());
    assert!(
        reconstruct_body(&manifest, limits(), |reference| {
            let mut bytes = blobs[&reference.sha256].clone();
            bytes[0] ^= 1;
            Ok(bytes)
        })
        .is_err()
    );
    assert!(
        reconstruct_body(&manifest, limits(), |reference| {
            let mut bytes = blobs[&reference.sha256].clone();
            bytes.pop();
            Ok(bytes)
        })
        .is_err()
    );
    let mut reordered = manifest.clone();
    let string = reordered
        .fragments
        .iter_mut()
        .find_map(|part| match part {
            Fragment::String(s) => Some(s),
            _ => None,
        })
        .unwrap();
    string.chunks.swap(0, 1);
    assert!(
        reconstruct_body(&reordered, limits(), |reference| blobs
            .get(&reference.sha256)
            .context("missing"))
        .is_err()
    );
}

#[test]
fn publication_is_impossible_when_blob_sink_fails() {
    let body = json!({"proof": hex::encode(vec![19; BLOB_CHUNK_BYTES * 3])});
    let mut puts = 0;
    let result = encode_body(&body, limits(), |_| {
        puts += 1;
        if puts == 2 {
            bail!("injected native write failure");
        }
        Ok(())
    });
    assert!(result.is_err());
    assert_eq!(puts, 2);
}

#[test]
fn decode_rejects_noncanonical_literal_even_with_matching_self_digest() {
    let bytes = b"{\"z\":1,\"a\":2}";
    let manifest = BodyManifest {
        format: FORMAT,
        canonical_bytes: bytes.len() as u64,
        canonical_sha256: Sha256::digest(bytes).into(),
        fragments: vec![Fragment::Literal(
            String::from_utf8(bytes.to_vec()).unwrap(),
        )],
    };
    assert!(decode_body::<Vec<u8>>(&manifest, limits(), |_| bail!("unexpected read")).is_err());
}
