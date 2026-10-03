use super::*;
use std::cell::Cell;

thread_local! {
    static ALLOCATIONS: Cell<Option<usize>> = const { Cell::new(None) };
}
// Forwarded by the existing Engine test allocator; no recursive allocation or
// second global allocator. Disabled on every thread outside this local guard.
pub(crate) fn note_allocation() {
    let _ = ALLOCATIONS.try_with(|count| {
        if let Some(n) = count.get() {
            count.set(Some(n + 1));
        }
    });
}
struct AllocationGuard;
impl AllocationGuard {
    fn begin() -> Self {
        ALLOCATIONS.with(|count| {
            assert!(count.get().is_none());
            count.set(Some(0));
        });
        Self
    }
    fn finish(self) -> usize {
        let count = ALLOCATIONS.with(|count| count.replace(None).unwrap());
        drop(self);
        count
    }
}
impl Drop for AllocationGuard {
    fn drop(&mut self) {
        ALLOCATIONS.with(|count| count.set(None));
    }
}
fn object(n: u64) -> ObjectId {
    ObjectId {
        attempt: [3; 16],
        ordinal: n,
    }
}
fn spec(n: u64, level: u8) -> PageSpec {
    PageSpec {
        tree_id: [7; 16],
        id: object(n),
        generation: 20,
        level,
    }
}
fn live(id: &str, n: u64) -> Entry<'_> {
    Entry {
        id,
        value: Value::Leaf(Leaf {
            version: 13,
            kind: RecordKind::Live,
            object: OverflowRef {
                id: object(n),
                encoded_bytes: 100,
                sha256: [n as u8; 32],
            },
            semantic_bytes: 7,
        }),
    }
}
fn archived(id: &str, n: u64, bytes: u64) -> Entry<'_> {
    Entry {
        id,
        value: Value::Leaf(Leaf {
            version: 11,
            kind: RecordKind::Archived,
            object: OverflowRef {
                id: object(n),
                encoded_bytes: bytes,
                sha256: [n as u8; 32],
            },
            semantic_bytes: archived_metadata_bytes(id, bytes).unwrap(),
        }),
    }
}
fn expected<'a>(spec: PageSpec, encoded: EncodedPage, range: KeyRange<'a>) -> ExpectedPage<'a> {
    ExpectedPage {
        tree_id: spec.tree_id,
        reference: encoded.reference,
        generation_ceiling: spec.generation,
        level: spec.level,
        totals: encoded.totals,
        range,
    }
}
fn reseal<'a>(bytes: &[u8], mut expected: ExpectedPage<'a>) -> ExpectedPage<'a> {
    expected.reference.sha256 = Sha256::digest(bytes).into();
    expected
}
fn child(id: &str, encoded: EncodedPage) -> Entry<'_> {
    Entry {
        id,
        value: Value::Child(Child {
            reference: encoded.reference,
            totals: encoded.totals,
        }),
    }
}
fn no_write(spec: PageSpec, entries: &[Entry<'_>], error: CodecError) {
    let mut page = [0xa7; PAGE_BYTES];
    assert_eq!(encode(&mut page, spec, entries), Err(error));
    assert!(page.iter().all(|byte| *byte == 0xa7));
}

#[test]
fn logical_page_codec_preserves_distinct_quota_metrics_and_canonical_archive_ids() {
    use kasumi_types::{ArchivedDocument, Document};
    let document = Document {
        id: "live".into(),
        version: 13,
        body: serde_json::json!({"body": [true, 12, "内容"]}),
    };
    let body_bytes = crate::accounting::encoded_len(&document.body).unwrap() as u64;
    let object_bytes = crate::accounting::encoded_len(&document).unwrap() as u64;
    assert!(body_bytes < object_bytes);
    let reference = ArchivedDocument {
        version: 11,
        archive_id: "archive".into(),
        chunk_index: 0,
        document_sha256: "ab".repeat(32),
        document_bytes: object_bytes as usize,
        indexed_fields: [(
            "nested".into(),
            serde_json::json!({"x": "projection".repeat(1024)}),
        )]
        .into_iter()
        .collect(),
    };
    let archived_object_bytes = crate::accounting::encoded_len(&reference).unwrap() as u64;
    for id in [
        "plain",
        "quote\"",
        "back\\slash",
        "é日本語",
        "line\u{2028}separator",
    ] {
        assert_eq!(
            archived_metadata_bytes(id, archived_object_bytes).unwrap(),
            crate::state::history::metadata_entry(id, &reference).unwrap() as u64
        );
    }
    let mut entry = live("live", 2);
    let Value::Leaf(ref mut leaf) = entry.value else {
        unreachable!()
    };
    leaf.object.encoded_bytes = object_bytes;
    leaf.semantic_bytes = body_bytes;
    let archive = archived("old\"\\é", 3, archived_object_bytes);
    let mut bytes = [0; PAGE_BYTES];
    let encoded = encode(&mut bytes, spec(1, 0), &[entry, archive]).unwrap();
    assert_eq!(
        encoded.totals,
        Totals {
            live_count: 1,
            archived_count: 1,
            live_body_bytes: body_bytes,
            archived_metadata_bytes: crate::state::history::metadata_entry(archive.id, &reference)
                .unwrap() as u64
        }
    );
    let page = validate(&bytes, expected(spec(1, 0), encoded, KeyRange::default())).unwrap();
    assert_eq!(page.totals(), encoded.totals);
    assert_eq!(page.spec(), spec(1, 0));
    assert_eq!(
        page.lookup("live").unwrap().unwrap().object.encoded_bytes,
        object_bytes
    );
    assert_eq!(
        page.lookup(archive.id).unwrap().unwrap().semantic_bytes,
        encoded.totals.archived_metadata_bytes
    );
    assert_eq!(page.entries().collect::<Vec<_>>(), vec![entry, archive]);
    assert_eq!(page.lookup("missing").unwrap(), None);
    assert_eq!(page.successor("live", true).unwrap().unwrap(), archive);
    assert_eq!(page.successor("z", false).unwrap(), None);
    assert_eq!(
        archived_metadata_bytes("x", u64::MAX),
        Err(CodecError::Overflow)
    );
    // Archived projections have no new live-body byte ceiling in this codec.
    let huge = archived("archive", 4, (1 << 30) + 123);
    encode(&mut bytes, spec(5, 0), &[huge]).unwrap();
}

#[test]
fn logical_page_codec_three_level_parent_bounds_and_totals_bind_each_descent() {
    let mut left = [0; PAGE_BYTES];
    let mut middle = [0; PAGE_BYTES];
    let mut right = [0; PAGE_BYTES];
    let a = encode(
        &mut left,
        spec(10, 0),
        &[live("ant", 101), live("bee", 102)],
    )
    .unwrap();
    let b = encode(
        &mut middle,
        spec(11, 0),
        &[archived("cat", 103, 80), live("dog", 104)],
    )
    .unwrap();
    let c = encode(&mut right, spec(12, 0), &[live("yak", 105)]).unwrap();
    let mut lower = [0; PAGE_BYTES];
    let lower_encoded =
        encode(&mut lower, spec(20, 1), &[child("ant", a), child("cat", b)]).unwrap();
    let mut upper = [0; PAGE_BYTES];
    let upper_encoded = encode(&mut upper, spec(21, 1), &[child("yak", c)]).unwrap();
    let mut root = [0; PAGE_BYTES];
    let root_encoded = encode(
        &mut root,
        spec(30, 2),
        &[child("ant", lower_encoded), child("yak", upper_encoded)],
    )
    .unwrap();
    let root_page = validate(
        &root,
        expected(spec(30, 2), root_encoded, KeyRange::default()),
    )
    .unwrap();
    assert_eq!(root_page.totals().live_count, 4);
    assert_eq!(root_page.totals().archived_count, 1);
    assert_eq!(root_page.lookup("ant"), Err(CodecError::Kind));
    let left_expected = root_page.route("aardvark").unwrap();
    assert_eq!(
        left_expected.range,
        KeyRange {
            lower: Some("ant"),
            upper: Some("yak")
        }
    );
    let lower_page = validate(&lower, left_expected).unwrap();
    let first = lower_page.route("bee").unwrap();
    assert_eq!(first.range.upper, Some("cat"));
    assert_eq!(
        validate(&left, first).unwrap().lookup("bee").unwrap(),
        match live("bee", 102).value {
            Value::Leaf(leaf) => Some(leaf),
            _ => unreachable!(),
        }
    );
    let last = lower_page.route("fox").unwrap();
    assert_eq!(
        last.range,
        KeyRange {
            lower: Some("cat"),
            upper: Some("yak")
        }
    );
    let middle_page = validate(&middle, last).unwrap();
    assert_eq!(
        middle_page.successor("car", false).unwrap().unwrap().id,
        "cat"
    );
    assert_eq!(middle_page.route("cat"), Err(CodecError::Kind));
    assert_eq!(validate(&right, last).unwrap_err(), CodecError::Identity);
    // Rebind only the physical reference: the original parent range/counts
    // still reject a different canonical page instead of trusting its hash.
    let mut substituted = last;
    substituted.reference = c.reference;
    assert_eq!(
        validate(&right, substituted).unwrap_err(),
        CodecError::Totals
    );
    substituted.totals = c.totals;
    assert_eq!(
        validate(&right, substituted).unwrap_err(),
        CodecError::Range
    );
    let mut stale = last;
    stale.generation_ceiling = 19;
    assert_eq!(validate(&middle, stale).unwrap_err(), CodecError::Version);
    let mut wrong_level = last;
    wrong_level.level = 1;
    assert_eq!(
        validate(&middle, wrong_level).unwrap_err(),
        CodecError::Level
    );
    let mut wrong_tree = last;
    wrong_tree.tree_id = [8; 16];
    assert_eq!(
        validate(&middle, wrong_tree).unwrap_err(),
        CodecError::Identity
    );
    let mut narrow = last;
    narrow.range.upper = Some("dog");
    assert_eq!(validate(&middle, narrow).unwrap_err(), CodecError::Range);
    let upper_page = validate(&upper, root_page.route("zz").unwrap()).unwrap();
    assert_eq!(upper_page.route("zz").unwrap().range.upper, None);
}

#[test]
fn logical_page_codec_refuses_bad_inputs_before_output_mutation() {
    let valid = live("a", 2);
    no_write(spec(1, 0), &[], CodecError::Capacity);
    no_write(spec(1, 0), &[valid, valid], CodecError::Order);
    no_write(spec(1, 0), &[live("z", 3), valid], CodecError::Order);
    for id in ["", "control\n", "delete\u{7f}", "c1\u{85}"] {
        no_write(spec(1, 0), &[live(id, 2)], CodecError::Name);
        assert!(kasumi_types::validate_name(id).is_err());
    }
    let too_long = "x".repeat(257);
    no_write(spec(1, 0), &[live(&too_long, 2)], CodecError::Name);
    let mut invalid_spec = spec(1, 0);
    invalid_spec.id.attempt = [0; 16];
    no_write(invalid_spec, &[valid], CodecError::Identity);
    invalid_spec = spec(1, 0);
    invalid_spec.tree_id = [0; 16];
    no_write(invalid_spec, &[valid], CodecError::Identity);
    invalid_spec = spec(1, 64);
    no_write(invalid_spec, &[valid], CodecError::Level);
    let Value::Leaf(mut leaf) = valid.value else {
        unreachable!()
    };
    leaf.version = 21;
    no_write(
        spec(1, 0),
        &[Entry {
            id: "a",
            value: Value::Leaf(leaf),
        }],
        CodecError::Version,
    );
    leaf.version = 20;
    leaf.semantic_bytes = 101;
    no_write(
        spec(1, 0),
        &[Entry {
            id: "a",
            value: Value::Leaf(leaf),
        }],
        CodecError::Totals,
    );
    leaf.semantic_bytes = 0;
    no_write(
        spec(1, 0),
        &[Entry {
            id: "a",
            value: Value::Leaf(leaf),
        }],
        CodecError::Totals,
    );
    leaf.semantic_bytes = 7;
    leaf.object.encoded_bytes = 0;
    no_write(
        spec(1, 0),
        &[Entry {
            id: "a",
            value: Value::Leaf(leaf),
        }],
        CodecError::Totals,
    );
    let mut archive = archived("a", 2, 300);
    let Value::Leaf(ref mut leaf) = archive.value else {
        unreachable!()
    };
    leaf.semantic_bytes += 1;
    no_write(spec(1, 0), &[archive], CodecError::Totals);
    let overflow = Entry {
        id: "archive",
        value: Value::Leaf(Leaf {
            version: 1,
            kind: RecordKind::Archived,
            object: OverflowRef {
                id: object(9),
                encoded_bytes: u64::MAX,
                sha256: [0; 32],
            },
            semantic_bytes: 1,
        }),
    };
    no_write(spec(1, 0), &[overflow], CodecError::Overflow);
    no_write(spec(1, 1), &[valid], CodecError::Kind);
    let self_child = Entry {
        id: "a",
        value: Value::Child(Child {
            reference: PageRef {
                id: object(1),
                sha256: [0; 32],
            },
            totals: Totals {
                live_count: 1,
                live_body_bytes: 1,
                ..Totals::default()
            },
        }),
    };
    no_write(spec(1, 1), &[self_child], CodecError::Identity);
    no_write(spec(1, 0), &[self_child], CodecError::Kind);
    // Preserve the existing accepted upper-bound-only version semantics.
    let zero = Entry {
        id: "zero",
        value: Value::Leaf(Leaf {
            version: 0,
            kind: RecordKind::Live,
            object: OverflowRef {
                id: object(9),
                encoded_bytes: 100,
                sha256: [0; 32],
            },
            semantic_bytes: 1,
        }),
    };
    let mut page = [0; PAGE_BYTES];
    encode(
        &mut page,
        PageSpec {
            generation: 0,
            ..spec(1, 0)
        },
        &[zero],
    )
    .unwrap();
}

#[test]
fn logical_page_codec_exact_fanout_and_checked_aggregate_overflow() {
    let ids: Vec<_> = (0..48)
        .map(|n| format!("{n:03}{}", "x".repeat(253)))
        .collect();
    let entries: Vec<_> = ids
        .iter()
        .enumerate()
        .map(|(n, id)| live(id, 100 + n as u64))
        .collect();
    assert_eq!(
        (PAGE_BYTES - HEADER_BYTES) / (2 + 256 + DESCRIPTOR_BYTES),
        47
    );
    let mut page = [0; PAGE_BYTES];
    let encoded = encode(&mut page, spec(1, 0), &entries[..47]).unwrap();
    let borrowed = validate(&page, expected(spec(1, 0), encoded, KeyRange::default())).unwrap();
    assert_eq!(borrowed.entries().len(), 47);
    no_write(spec(1, 0), &entries, CodecError::Capacity);
    let metric = |id, n, count, bytes| Entry {
        id,
        value: Value::Child(Child {
            reference: PageRef {
                id: object(n),
                sha256: [0; 32],
            },
            totals: Totals {
                live_count: count,
                live_body_bytes: bytes,
                ..Totals::default()
            },
        }),
    };
    no_write(
        spec(1, 1),
        &[metric("a", 2, 1, u64::MAX), metric("b", 3, 1, 1)],
        CodecError::Overflow,
    );
    no_write(
        spec(1, 1),
        &[metric("a", 2, u64::MAX, u64::MAX), metric("b", 3, 1, 1)],
        CodecError::Overflow,
    );
    no_write(spec(1, 1), &[metric("a", 2, 0, 1)], CodecError::Totals);
    let both = Entry {
        id: "a",
        value: Value::Child(Child {
            reference: PageRef {
                id: object(2),
                sha256: [0; 32],
            },
            totals: Totals {
                live_count: u64::MAX,
                archived_count: 1,
                live_body_bytes: u64::MAX,
                archived_metadata_bytes: 1,
            },
        }),
    };
    no_write(spec(1, 1), &[both], CodecError::Overflow);
}

#[test]
fn logical_page_codec_rejects_rehashed_noncanonical_pages_and_unchecked_lengths() {
    let mut original = [0; PAGE_BYTES];
    let encoded = encode(
        &mut original,
        spec(1, 0),
        &[live("a", 2), archived("b", 3, 100)],
    )
    .unwrap();
    let expected = expected(spec(1, 0), encoded, KeyRange::default());
    for len in 0..PAGE_BYTES {
        assert_eq!(
            validate(&original[..len], expected).unwrap_err(),
            CodecError::Length
        );
    }
    let mut oversized = original.to_vec();
    oversized.push(0);
    assert_eq!(
        validate(&oversized, expected).unwrap_err(),
        CodecError::Length
    );
    let descriptor = HEADER_BYTES + 3;
    let second = descriptor + DESCRIPTOR_BYTES;
    let cases = [
        (0, 0, CodecError::Format),
        (16, 2, CodecError::Format),
        (18, 2, CodecError::Kind),
        (19, 64, CodecError::Level),
        (20, 9, CodecError::Identity),
        (44, 9, CodecError::Identity),
        (36, 21, CodecError::Version),
        (68, 0, CodecError::Length),
        // Clearing the low byte makes 286 become 256: an in-range boundary
        // with nonzero record bytes beyond it. Clearing the high byte makes
        // it 30, which is shorter than the header itself.
        (70, 0, CodecError::Padding),
        (71, 0, CodecError::Length),
        (71, 255, CodecError::Length),
        (72, 99, CodecError::Totals),
        (PAGE_BYTES - 1, 1, CodecError::Padding),
        (HEADER_BYTES, 255, CodecError::Length),
        (HEADER_BYTES + 2, 0xff, CodecError::Name),
        (HEADER_BYTES + 2, b'\n', CodecError::Name),
        (descriptor + 8, 2, CodecError::Kind),
        (descriptor + 9, 1, CodecError::Padding),
        (descriptor, 21, CodecError::Version),
        (descriptor + 80, 101, CodecError::Totals),
        (second + 2, b'a', CodecError::Order),
    ];
    for (at, byte, error) in cases {
        let mut damaged = original;
        damaged[at] = byte;
        assert_eq!(
            validate(&damaged, reseal(&damaged, expected)).unwrap_err(),
            error,
            "offset {at}"
        );
    }
    let mut digest_mismatch = original;
    digest_mismatch[descriptor + 48] ^= 1;
    assert_eq!(
        validate(&digest_mismatch, expected).unwrap_err(),
        CodecError::Digest
    );
    // Every possible header used/count/key-length value is bounded before slice
    // access; rejection type may vary, but malformed framing never panics.
    for value in [0u16, 1, 2, 103, 104, 105, 16383, 16384, 16385, u16::MAX] {
        for at in [68, 70, HEADER_BYTES] {
            let mut damaged = original;
            damaged[at..at + 2].copy_from_slice(&value.to_le_bytes());
            let _ = validate(&damaged, reseal(&damaged, expected));
        }
    }
}

#[test]
fn logical_page_codec_borrowed_encode_validate_lookup_and_refusals_allocate_nothing() {
    let entries = [live("a", 2), archived("é\"\\", 3, 200)];
    let mut bytes = [0; PAGE_BYTES];
    // Warm platform SHA dispatch outside the measured codec calls.
    let _ = Sha256::digest([0]);
    let guard = AllocationGuard::begin();
    let encoded = encode(&mut bytes, spec(1, 0), &entries).unwrap();
    let e = expected(spec(1, 0), encoded, KeyRange::default());
    let page = validate(&bytes, e).unwrap();
    assert!(page.lookup("a").unwrap().is_some());
    assert_eq!(
        page.successor("a", true).unwrap().unwrap().id,
        entries[1].id
    );
    assert_eq!(page.entries().count(), 2);
    let mut branch = [0; PAGE_BYTES];
    let parent_encoded = encode(&mut branch, spec(9, 1), &[child("a", encoded)]).unwrap();
    let parent = validate(
        &branch,
        expected(spec(9, 1), parent_encoded, KeyRange::default()),
    )
    .unwrap();
    let next = parent.route("a").unwrap();
    assert_eq!(validate(&bytes, next).unwrap().totals(), encoded.totals);

    assert_eq!(page.lookup("bad\n"), Err(CodecError::Name));
    assert_eq!(validate(&bytes[..100], e).unwrap_err(), CodecError::Length);
    let mut rejected = [0x55; PAGE_BYTES];
    assert_eq!(
        encode(&mut rejected, spec(1, 0), &[entries[0], entries[0]]),
        Err(CodecError::Order)
    );
    assert_eq!(guard.finish(), 0);
    // An unwind must disable measurement, rather than contaminate later tests.
    let _ = std::panic::catch_unwind(|| {
        let _guard = AllocationGuard::begin();
        panic!("test counter guard cleanup");
    });
    let guard = AllocationGuard::begin();
    assert_eq!(guard.finish(), 0);
}

#[path = "primary_records_tests.rs"]
mod record_tests;
