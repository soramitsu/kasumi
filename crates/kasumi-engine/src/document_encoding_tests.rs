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
    encode_body(body, limits(), |reference, bytes| {
        if let Some(existing) = blobs.get(&reference.sha256) {
            ensure!(existing == bytes, "immutable blob collision");
        } else {
            blobs.insert(reference.sha256, bytes.to_vec());
        }
        Ok(())
    })
    .unwrap()
}

fn reconstruct(manifest: &BodyManifest, blobs: &HashMap<[u8; 32], Vec<u8>>) -> Vec<u8> {
    reconstruct_body(manifest, limits(), |reference| {
        blobs.get(&reference.sha256).context("missing blob")
    })
    .unwrap()
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
            |_, _| {
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
            |_, _| Ok(())
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
            |_, _| Ok(())
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
            |_, _| Ok(())
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
            |_, _| Ok(())
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
    let result = encode_body(&body, limits(), |_, _| {
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
