use super::*;
use crate::ReadFailure;
use crate::source_test_utils::pending;
use crate::source_test_utils::{FixtureQueries, ResidentSource, query_memory};
use serde_json::json;

/// 20,010 rows in two scopes under a unique (scope, at, literalId) index.
fn setup() -> (BTreeMap<String, CollectionState>, QueryIndexes) {
    let definition = CollectionDefinition {
        name: "ordered".into(),
        schema: json!({"type":"object"}),
        indexes: vec![IndexDefinition {
            name: "scope_time_id".into(),
            fields: ["/scope", "/at", "/literalId"]
                .into_iter()
                .map(|path| IndexField {
                    path: path.into(),
                    kind: ScalarType::String,
                })
                .collect(),
            unique: true,
            text: None,
        }],
        write_mode: CollectionWriteMode::Mutable,
        retention_class: CollectionRetentionClass::Operational,
        strict_read_audit: true,
    };
    let documents = (0..20_010)
        .map(|n| {
            let id = format!("row-{n:05}");
            let body = json!({
                "scope": if n < 10_005 { "a" } else { "b" },
                "at": format!("{:020}", n % 10_005),
                "literalId": format!("literal-{n:05}"),
                "note": "x".repeat(64),
            });
            (
                id.clone(),
                pending(Document {
                    id,
                    version: 10,
                    body,
                }),
            )
        })
        .collect();
    let collections = BTreeMap::from([(
        "ordered".into(),
        CollectionState {
            definition: definition.into(),
            documents,
            archived_documents: Default::default(),
            archived_document_bytes: 0,
            data_epoch: 20,
        },
    )]);
    let indexes = QueryIndexes::build_fixture(&collections).unwrap();
    (collections, indexes)
}

fn seek(
    (collections, indexes): &(BTreeMap<String, CollectionState>, QueryIndexes),
    request: &QueryRequest,
    after: Option<&[Value]>,
    limits: &Limits,
    cancellation: &QueryCancellation,
) -> Result<SeekPage> {
    indexes
        .seek_page(
            &ResidentSource {
                collection: &collections["ordered"],
                indexes,
            },
            request,
            after,
            limits,
            &|_| Ok(36),
            cancellation,
            &mut query_memory(),
        )
        .map_err(ReadFailure::into_query_error)
}

fn scope_a() -> QueryRequest {
    QueryRequest::new("ordered")
        .filter(Filter::new().eq("/scope", "a"))
        .sort_desc("/at")
        .sort_desc("/literalId")
        .limit(2)
        .paging(Paging::Seek)
}

fn at(page: &SeekPage) -> Vec<&str> {
    page.rows
        .iter()
        .map(|row| row.body["at"].as_str().unwrap())
        .collect()
}

#[test]
fn seek_pages_read_only_their_rows_and_one_lookahead_at_volume() {
    let fixture = setup();
    let request = scope_a();
    // Each body loan checks cancellation six times across the source and
    // lending boundary and each visited index entry once more, including the
    // lookahead; entry and exit add two. This depends on the page size alone,
    // never on the 10,005 rows in the scope.
    let budget = || QueryCancellation::after_checks(2 * (6 + 1) + 1 + 2);
    let limits = Limits::default();
    let page = seek(&fixture, &request, None, &limits, &budget()).unwrap();
    assert_eq!(at(&page), ["00000000000000010004", "00000000000000010003"]);
    let after = page.last_key.unwrap();
    assert_eq!(
        after,
        [
            json!("a"),
            json!("00000000000000010003"),
            json!("literal-10003")
        ]
    );
    let next = seek(&fixture, &request, Some(&after), &limits, &budget()).unwrap();
    assert_eq!(at(&next), ["00000000000000010002", "00000000000000010001"]);

    // Ascending order, and a range on the field after the fixed prefix.
    let ascending = QueryRequest::new("ordered")
        .filter(Filter::new().eq("/scope", "a"))
        .sort_asc("/at")
        .sort_asc("/literalId")
        .limit(2)
        .paging(Paging::Seek);
    let first = seek(&fixture, &ascending, None, &limits, &budget()).unwrap();
    assert_eq!(at(&first), ["00000000000000000000", "00000000000000000001"]);
    let ranged = ascending
        .clone()
        .filter(Filter::new().gte("/at", "00000000000000010003"));
    let last = seek(&fixture, &ranged, None, &limits, &budget()).unwrap();
    assert_eq!(at(&last), ["00000000000000010003", "00000000000000010004"]);
    assert!(last.last_key.is_none());
    let below = ascending
        .clone()
        .filter(Filter::new().lt("/at", "00000000000000000001"));
    let only = seek(&fixture, &below, None, &limits, &budget()).unwrap();
    assert_eq!(at(&only), ["00000000000000000000"]);
    assert!(only.last_key.is_none());

    // The sort may list the fixed fields too; select trims rows but the
    // cursor keeps the full index key.
    let whole = QueryRequest::new("ordered")
        .filter(Filter::new().eq("/scope", "b"))
        .sort_asc("/scope")
        .sort_asc("/at")
        .sort_asc("/literalId")
        .select(["/literalId"])
        .limit(1)
        .paging(Paging::Seek);
    let page = seek(&fixture, &whole, None, &limits, &budget()).unwrap();
    assert_eq!(page.rows[0].body, json!({"literalId": "literal-10005"}));
    assert_eq!(page.last_key.unwrap()[2], json!("literal-10005"));

    // A page also ends at max_result_bytes, and continues from its last row.
    let small = Limits {
        max_result_bytes: 350,
        ..Limits::default()
    };
    let page = seek(
        &fixture,
        &request.clone().limit(10),
        None,
        &small,
        &budget(),
    )
    .unwrap();
    assert_eq!(page.rows.len(), 1);
    assert_eq!(page.last_key.unwrap()[1], json!("00000000000000010004"));
}

#[test]
fn seek_shapes_and_cursors_are_checked_before_reading() {
    let fixture = setup();
    let limits = Limits::default();
    let unread = || QueryCancellation::after_checks(4);
    let error = |request: &QueryRequest, after: Option<&[Value]>| {
        seek(
            &fixture,
            request,
            after,
            &limits,
            &QueryCancellation::default(),
        )
        .unwrap_err()
    };

    // A prefix with no rows reads nothing.
    let absent = QueryRequest::new("ordered")
        .filter(Filter::new().eq("/scope", "absent"))
        .sort_desc("/at")
        .sort_desc("/literalId")
        .paging(Paging::Seek);
    let page = seek(&fixture, &absent, None, &limits, &unread()).unwrap();
    assert!(page.rows.is_empty() && page.last_key.is_none());

    for (request, code) in [
        // Fields outside the index, gaps in the prefix, or a sort that does
        // not continue it, name no unique index.
        (
            scope_a().filter(Filter::new().eq("/note", "x")),
            ErrorCode::IndexRequired,
        ),
        (
            QueryRequest::new("ordered")
                .filter(Filter::new().eq("/at", "0"))
                .sort_asc("/literalId")
                .paging(Paging::Seek),
            ErrorCode::IndexRequired,
        ),
        (
            QueryRequest::new("ordered")
                .filter(Filter::new().eq("/scope", "a"))
                .sort_asc("/literalId")
                .paging(Paging::Seek),
            ErrorCode::IndexRequired,
        ),
        (
            QueryRequest::new("ordered")
                .filter(Filter::new().eq("/scope", "a"))
                .sort_asc("/at")
                .sort_desc("/literalId")
                .paging(Paging::Seek),
            ErrorCode::IndexRequired,
        ),
        (
            QueryRequest::new("ordered")
                .filter(Filter::new().eq("/scope", "a"))
                .paging(Paging::Seek),
            ErrorCode::IndexRequired,
        ),
        // A range must be on the field right after the fixed prefix.
        (
            QueryRequest::new("ordered")
                .filter(Filter::new().eq("/scope", "a").gt("/literalId", "x"))
                .sort_asc("/at")
                .sort_asc("/literalId")
                .paging(Paging::Seek),
            ErrorCode::IndexRequired,
        ),
        // Only equality and range conditions can be walked.
        (
            scope_a().filter(Filter::or([
                Filter::new().eq("/at", "1"),
                Filter::new().eq("/at", "2"),
            ])),
            ErrorCode::InvalidArgument,
        ),
        (
            scope_a().filter(Filter::new().is_in("/at", ["1"])),
            ErrorCode::InvalidArgument,
        ),
        (
            QueryRequest::new("ordered")
                .filter(Filter::new().eq("/scope", 42))
                .sort_desc("/at")
                .sort_desc("/literalId")
                .paging(Paging::Seek),
            ErrorCode::InvalidArgument,
        ),
        (
            scope_a().search(TextSearch::new("body", "x")),
            ErrorCode::InvalidArgument,
        ),
    ] {
        assert_eq!(error(&request, None).code, code, "{request:?}");
    }

    // A cursor from another prefix or index shape belongs to another query.
    for after in [
        vec![json!("b"), json!("0"), json!("id")],
        vec![json!("a"), json!("0")],
        vec![json!("a"), json!(1), json!("id")],
    ] {
        assert_eq!(
            error(&scope_a(), Some(&after)).code,
            ErrorCode::InvalidArgument
        );
    }
}

fn small_fixture(
    fields: &[(&str, ScalarType)],
    bodies: impl IntoIterator<Item = Value>,
) -> (BTreeMap<String, CollectionState>, QueryIndexes) {
    let collection = CollectionState {
        definition: CollectionDefinition {
            name: "ordered".into(),
            schema: json!({"type": "object"}),
            indexes: vec![IndexDefinition {
                name: "ordered_key".into(),
                fields: fields
                    .iter()
                    .map(|(path, kind)| IndexField {
                        path: (*path).into(),
                        kind: *kind,
                    })
                    .collect(),
                unique: true,
                text: None,
            }],
            write_mode: CollectionWriteMode::Mutable,
            retention_class: CollectionRetentionClass::Operational,
            strict_read_audit: false,
        }
        .into(),
        documents: bodies
            .into_iter()
            .enumerate()
            .map(|(n, body)| {
                let id = format!("row-{n}");
                (
                    id.clone(),
                    pending(Document {
                        id,
                        version: 1,
                        body,
                    }),
                )
            })
            .collect(),
        archived_documents: Default::default(),
        archived_document_bytes: 0,
        data_epoch: 1,
    };
    let collections = BTreeMap::from([("ordered".into(), collection)]);
    let indexes = QueryIndexes::build_fixture(&collections).unwrap();
    (collections, indexes)
}

#[test]
fn seek_continues_long_keys_and_admits_their_copies() {
    let prefix = "scope".repeat(400);
    let key = "key".repeat(700);
    let fixture = small_fixture(
        &[("/scope", ScalarType::String), ("/key", ScalarType::String)],
        [
            json!({"scope": prefix, "key": key}),
            json!({"scope": prefix, "key": format!("{key}z")}),
        ],
    );
    let request = QueryRequest::new("ordered")
        .filter(Filter::new().eq("/scope", prefix.as_str()))
        .sort_asc("/key")
        .select(["/scope"])
        .limit(1)
        .paging(Paging::Seek);
    let first = seek(
        &fixture,
        &request,
        None,
        &Limits::default(),
        &QueryCancellation::default(),
    )
    .unwrap();
    assert_eq!(first.rows[0].id, "row-0");
    let after = first.last_key.unwrap();
    assert_eq!(after, [json!(prefix), json!(key)]);
    let last = seek(
        &fixture,
        &request,
        Some(&after),
        &Limits::default(),
        &QueryCancellation::default(),
    )
    .unwrap();
    assert_eq!(last.rows[0].id, "row-1");
    assert!(last.last_key.is_none());

    struct Bounded;
    impl QueryWorkspace for Bounded {
        fn ensure_peak(&mut self, bytes: u64) -> Result<()> {
            if bytes > 1024 {
                return Err(Error::new(
                    ErrorCode::ResourceExhausted,
                    "seek fixture allowance",
                ));
            }
            Ok(())
        }
    }
    let mut memory = QueryMemory::new(Bounded, 0).unwrap();
    let error = fixture
        .1
        .seek_page(
            &ResidentSource {
                collection: &fixture.0["ordered"],
                indexes: &fixture.1,
            },
            &request,
            None,
            &Limits::default(),
            &|_| Ok(36),
            &QueryCancellation::default(),
            &mut memory,
        )
        .unwrap_err()
        .into_query_error();
    assert_eq!(error.code, ErrorCode::ResourceExhausted);
    assert_eq!(
        memory.live_bytes(),
        0,
        "failed key admission releases its scratch"
    );
}

#[test]
fn seek_ranges_keep_compound_boundary_rows_and_exclude_nulls() {
    let fixture = small_fixture(
        &[("/at", ScalarType::Number), ("/tie", ScalarType::String)],
        [
            json!({"at": null, "tie": "null"}),
            json!({"at": 1, "tie": "a"}),
            json!({"at": 1, "tie": "b"}),
            json!({"at": 2, "tie": "a"}),
            json!({"at": 2, "tie": "b"}),
            json!({"at": 3, "tie": "a"}),
        ],
    );
    for (filter, expected) in [
        (
            Filter::new().gte("/at", 1).lte("/at", 2),
            vec!["row-1", "row-2", "row-3", "row-4"],
        ),
        (
            Filter::new().gt("/at", 1).lt("/at", 3),
            vec!["row-3", "row-4"],
        ),
        (Filter::new().lt("/at", 2), vec!["row-1", "row-2"]),
        (
            Filter::new().gte("/at", 2).lte("/at", 2),
            vec!["row-3", "row-4"],
        ),
        (Filter::new().gt("/at", 2).lte("/at", 2), vec![]),
        (Filter::new().gt("/at", 3).lt("/at", 1), vec![]),
    ] {
        for descending in [false, true] {
            let mut request = QueryRequest::new("ordered")
                .filter(filter.clone())
                .limit(1)
                .paging(Paging::Seek);
            request = if descending {
                request.sort_desc("/at").sort_desc("/tie")
            } else {
                request.sort_asc("/at").sort_asc("/tie")
            };
            let mut actual = Vec::new();
            let mut after = None;
            loop {
                let page = seek(
                    &fixture,
                    &request,
                    after.as_deref(),
                    &Limits::default(),
                    &QueryCancellation::default(),
                )
                .unwrap();
                actual.extend(page.rows.into_iter().map(|row| row.id));
                after = page.last_key;
                if after.is_none() {
                    break;
                }
            }
            let mut expected = expected.clone();
            if descending {
                expected.reverse();
            }
            assert_eq!(actual, expected, "{request:?}");
        }
    }
}

#[test]
fn seek_walks_sparse_unique_entries_and_keeps_explicit_nulls() {
    let fixture = small_fixture(
        &[("/at", ScalarType::String), ("/tie", ScalarType::String)],
        [
            json!({"at": "missing tie"}),
            json!({"tie": "missing at"}),
            json!({"at": null, "tie": "explicit null"}),
            json!({"at": "a", "tie": "complete"}),
        ],
    );
    let request = QueryRequest::new("ordered")
        .sort_asc("/at")
        .sort_asc("/tie")
        .paging(Paging::Seek);
    let page = seek(
        &fixture,
        &request,
        None,
        &Limits::default(),
        &QueryCancellation::default(),
    )
    .unwrap();
    assert_eq!(
        page.rows
            .iter()
            .map(|row| row.id.as_str())
            .collect::<Vec<_>>(),
        ["row-2", "row-3"]
    );
    assert!(page.last_key.is_none());
}

#[test]
fn single_unique_postings_keep_sparse_seek_order_and_every_cursor_bound() {
    let fixture = small_fixture(
        &[("/at", ScalarType::Number)],
        [
            json!({}),
            json!({"at":null}),
            json!({"at":1}),
            json!({"at":2}),
            json!({"at":3}),
        ],
    );
    let limits = Limits::default();
    let cancellation = QueryCancellation::default();
    for (request, expected) in [
        (
            QueryRequest::new("ordered").sort_asc("/at"),
            vec![1, 2, 3, 4],
        ),
        (
            QueryRequest::new("ordered").sort_desc("/at"),
            vec![4, 3, 2, 1],
        ),
        (
            QueryRequest::new("ordered")
                .filter(Filter::new().gte("/at", 1).lt("/at", 3))
                .sort_asc("/at"),
            vec![2, 3],
        ),
        (
            QueryRequest::new("ordered")
                .filter(Filter::new().gt("/at", 1).lte("/at", 3))
                .sort_desc("/at"),
            vec![4, 3],
        ),
        (
            QueryRequest::new("ordered")
                .filter(Filter::new().eq("/at", 2))
                .sort_desc("/at"),
            vec![3],
        ),
    ] {
        let request = request.limit(1).paging(Paging::Seek);
        let mut after = None;
        let mut ids = Vec::new();
        loop {
            let page = seek(&fixture, &request, after.as_deref(), &limits, &cancellation).unwrap();
            ids.extend(page.rows.into_iter().map(|row| row.id));
            after = page.last_key;
            if after.is_none() {
                break;
            }
            assert!(ids.len() <= expected.len());
        }
        assert_eq!(
            ids,
            expected
                .iter()
                .map(|n| format!("row-{n}"))
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn native_pages_merge_oversized_rows_across_cursors_in_both_directions() {
    use crate::{CollectionRecords, Header, Record, SourceIdentity};
    use std::ops::RangeBounds;
    struct Mixed<'a> {
        source: ResidentSource<'a>,
        compact: BTreeMap<Vec<u8>, String>,
        reads: std::cell::Cell<usize>,
        ranked: Option<&'a [([u8; 32], String)]>,
        damage: bool,
        rank_reads: std::cell::Cell<usize>,
    }
    impl CollectionRecords for Mixed<'_> {
        type Failure = std::convert::Infallible;
        fn identity(&self) -> SourceIdentity<'_> {
            self.source.identity()
        }
        fn definition(&self) -> &CollectionDefinition {
            self.source.definition()
        }
        fn visit_records(
            &self,
            lend: impl for<'a> FnMut(&'a str, Record<'a>) -> Result<()>,
        ) -> ReadResult<(), Self::Failure> {
            self.source.visit_records(lend)
        }
    }
    impl DocumentSource for Mixed<'_> {
        fn indexes(&self) -> &QueryIndexes {
            self.source.indexes
        }
        fn has_ordered_unique_source(&self) -> bool {
            true
        }
        fn ranked_compound_count(
            &self,
            ordinal: usize,
            _: &QueryCancellation,
        ) -> ReadResult<Option<u64>, Self::Failure> {
            assert_eq!(ordinal, 0);
            Ok(self.ranked.map(|r| r.len() as u64))
        }
        fn ranked_compound_window(
            &self,
            _: usize,
            start: u64,
            end: u64,
            descending: bool,
            _: &QueryCancellation,
        ) -> ReadResult<Option<Vec<crate::RankedOwner>>, Self::Failure> {
            let Some(rows) = self.ranked else {
                return Ok(None);
            };
            self.rank_reads.set(self.rank_reads.get() + 1);
            let mut range = start..end;
            Ok(Some(
                (0..crate::ORDERED_TUPLE_WINDOW)
                    .map_while(|_| directed_next(&mut range, descending))
                    .map(|rank| {
                        let (mut digest, id) = rows[rank as usize].clone();
                        if self.damage {
                            digest[0] ^= 1;
                        }
                        crate::RankedOwner { rank, digest, id }
                    })
                    .collect(),
            ))
        }
        fn ordered_unique_window(
            &self,
            index: usize,
            lower: Bound<&[u8]>,
            upper: Bound<&[u8]>,
            descending: bool,
            cancellation: &QueryCancellation,
        ) -> ReadResult<Option<crate::OrderedTupleWindow>, Self::Failure> {
            assert_eq!(index, 0);
            cancellation.check()?;
            self.reads.set(self.reads.get() + 1);
            let mut rows = self
                .compact
                .iter()
                .filter(|(k, _)| RangeBounds::<[u8]>::contains(&(lower, upper), k.as_slice()));
            Ok(Some(
                (0..crate::ORDERED_TUPLE_WINDOW)
                    .map_while(|_| directed_next(&mut rows, descending))
                    .map(|(k, id)| (k.clone(), id.clone()))
                    .collect(),
            ))
        }
        fn with_record<T>(
            &self,
            id: &str,
            version: Option<u64>,
            cancellation: &QueryCancellation,
            lend: impl for<'a> FnOnce(Option<Record<'a>>) -> Result<T>,
        ) -> ReadResult<T, Self::Failure> {
            self.source.with_record(id, version, cancellation, lend)
        }
        fn header_after<T>(
            &self,
            after: Option<&str>,
            cancel: &QueryCancellation,
            lend: impl for<'a> FnOnce(Option<Header<'a>>) -> Result<T>,
        ) -> ReadResult<T, Self::Failure> {
            self.source.header_after(after, cancel, lend)
        }
    }

    let mut expected: Vec<_> = (0..48).map(|n| format!("{n:02}")).collect();
    for n in [0, 7, 15, 16, 17, 31, 32, 47] {
        expected.push(format!("{n:02}{}", "x".repeat(2048)));
    }
    expected.sort();
    let rows = expected
        .iter()
        .map(|v| json!({"scope":"g","key":v}))
        .collect::<Vec<_>>();
    let (collections, indexes) = small_fixture(
        &[("/scope", ScalarType::String), ("/key", ScalarType::String)],
        rows,
    );
    let mut compact = BTreeMap::new();
    indexes
        .visit_compound_rows(|_, _, key, id| {
            compact.insert(key.to_vec(), id.to_owned());
            Ok::<_, ()>(true)
        })
        .unwrap();
    assert_eq!(compact.len(), 48);
    let original = indexes;
    let indexes = original.published_seek_projection("ordered").unwrap();
    let capture = indexes.seek_projection.as_ref().unwrap();
    assert_eq!(
        capture.fallback.lock().unwrap().as_ref().unwrap()[0].len(),
        48
    );
    let fallback = ResidentSource {
        collection: &collections["ordered"],
        indexes: &indexes,
    };
    let plain = QueryRequest::new("ordered")
        .filter(Filter::new().eq("/scope", "g"))
        .sort_asc("/key")
        .limit(7)
        .paging(Paging::Seek);
    let page = indexes
        .seek_page(
            &fallback,
            &plain,
            None,
            &Limits::default(),
            &|_| Ok(32),
            &Default::default(),
            &mut query_memory(),
        )
        .unwrap();
    assert_eq!(page.rows.len(), 7);
    assert!(capture.fallback.lock().unwrap().is_some());
    let source = Mixed {
        source: ResidentSource {
            collection: &collections["ordered"],
            indexes: &indexes,
        },
        compact,
        reads: Default::default(),
        ranked: None,
        damage: false,
        rank_reads: Default::default(),
    };
    for desc in [false, true] {
        let mut seen = Vec::new();
        let mut cursor = None;
        let req = QueryRequest::new("ordered")
            .filter(Filter::new().eq("/scope", "g"))
            .limit(7)
            .paging(Paging::Seek);
        let req = if desc {
            req.sort_desc("/key")
        } else {
            req.sort_asc("/key")
        };
        loop {
            let previous = source.reads.get();
            let page = indexes
                .seek_page(
                    &source,
                    &req,
                    cursor.as_deref(),
                    &Limits::default(),
                    &|_| Ok(32),
                    &Default::default(),
                    &mut query_memory(),
                )
                .unwrap();
            assert!(source.reads.get() > previous);
            for row in page.rows {
                seen.push(row.body["key"].as_str().unwrap().to_owned());
            }
            cursor = page.last_key;
            if cursor.is_none() {
                break;
            }
        }
        if desc {
            seen.reverse();
        }
        assert_eq!(seen, expected);
    }
    assert!(capture.fallback.lock().unwrap().is_none());
    assert_eq!(
        indexes.collections["ordered"]
            .structured
            .unique
            .values()
            .next()
            .unwrap()
            .overflow
            .len(),
        8
    );
    // Each production page has its own registered worker. Verify an actual
    // continuation after a bounded wide slice in both traversal directions.
    for descending in [false, true] {
        let req = QueryRequest::new("ordered")
            .filter(Filter::new().eq("/scope", "g"))
            .limit(3)
            .paging(Paging::Seek);
        let req = if descending {
            req.sort_desc("/key")
        } else {
            req.sort_asc("/key")
        };
        let mut seen = Vec::new();
        let mut cursor = None;
        loop {
            let worker = original
                .published_seek_worker_projection("ordered")
                .unwrap();
            let root = worker
                .seek_projection
                .as_ref()
                .unwrap()
                .worker_wide
                .as_ref()
                .unwrap();
            assert_eq!(root.lock().unwrap().as_ref().unwrap()[0].len(), 8);
            let registered = Mixed {
                source: ResidentSource {
                    collection: &collections["ordered"],
                    indexes: &worker,
                },
                compact: source.compact.clone(),
                reads: Default::default(),
                ranked: None,
                damage: false,
                rank_reads: Default::default(),
            };
            let page = worker
                .seek_page(
                    &registered,
                    &req,
                    cursor.as_deref(),
                    &Limits::default(),
                    &|_| Ok(32),
                    &Default::default(),
                    &mut query_memory(),
                )
                .unwrap();
            assert!(root.lock().unwrap().is_none());
            seen.extend(
                page.rows
                    .into_iter()
                    .map(|row| row.body["key"].as_str().unwrap().to_owned()),
            );
            cursor = page.last_key;
            if cursor.is_none() {
                break;
            }
        }
        if descending {
            seen.reverse();
        }
        assert_eq!(seen, expected);
    }
    let mut ranked_rows = Vec::new();
    original
        .visit_ranked_compounds(|_, _, row| {
            match row {
                crate::RankedCompound::Count(count) => assert_eq!(count as usize, expected.len()),
                crate::RankedCompound::Owner { rank, digest, id } => {
                    assert_eq!(rank as usize, ranked_rows.len());
                    ranked_rows.push((digest, id.to_owned()));
                }
            }
            Ok::<_, ()>(())
        })
        .unwrap();
    for descending in [false, true] {
        let mut seen = Vec::new();
        let mut cursor = None;
        let req = QueryRequest::new("ordered")
            .filter(
                Filter::new()
                    .eq("/scope", "g")
                    .gte("/key", expected[8].clone())
                    .lt("/key", expected[45].clone()),
            )
            .limit(5)
            .paging(Paging::Seek);
        let req = if descending {
            req.sort_desc("/key")
        } else {
            req.sort_asc("/key")
        };
        loop {
            let worker = original
                .published_seek_worker_projection("ordered")
                .unwrap();
            let registered = Mixed {
                source: ResidentSource {
                    collection: &collections["ordered"],
                    indexes: &worker,
                },
                compact: BTreeMap::new(),
                reads: Default::default(),
                ranked: Some(&ranked_rows),
                damage: false,
                rank_reads: Default::default(),
            };
            let page = worker
                .seek_page(
                    &registered,
                    &req,
                    cursor.as_deref(),
                    &Limits::default(),
                    &|_| Ok(32),
                    &Default::default(),
                    &mut query_memory(),
                )
                .unwrap();
            assert_eq!(registered.reads.get(), 0);
            assert!(registered.rank_reads.get() > 0);
            seen.extend(
                page.rows
                    .into_iter()
                    .map(|r| r.body["key"].as_str().unwrap().to_owned()),
            );
            cursor = page.last_key;
            if cursor.is_none() {
                break;
            }
            assert!(seen.len() < expected.len());
        }
        if descending {
            seen.reverse();
        }
        assert_eq!(seen, expected[8..45]);
    }
    let damaged = Mixed {
        source: ResidentSource {
            collection: &collections["ordered"],
            indexes: &original,
        },
        compact: BTreeMap::new(),
        reads: Default::default(),
        ranked: Some(&ranked_rows),
        damage: true,
        rank_reads: Default::default(),
    };
    let all = QueryRequest::new("ordered")
        .sort_asc("/scope")
        .sort_asc("/key")
        .limit(2)
        .paging(Paging::Seek);
    let failure = original
        .seek_page(
            &damaged,
            &all,
            None,
            &Limits::default(),
            &|_| Ok(32),
            &Default::default(),
            &mut query_memory(),
        )
        .unwrap_err();
    assert!(matches!(failure,crate::ReadFailure::Query(ref e) if e.code==ErrorCode::Corruption));
    assert_eq!(damaged.rank_reads.get(), 1);
}

#[test]
fn compound_keys_share_field_strings_across_build_swaps_and_new_values() {
    use crate::scalar::IndexString;
    use std::collections::BTreeSet;
    use std::sync::Arc;
    fn check(indexes: &QueryIndexes) {
        let structured = &indexes.collections["ordered"].structured;
        let unique = structured.unique.values().next().unwrap();
        let mut count = 0;
        for (tuple, _) in unique
            .entries
            .as_ref()
            .unwrap()
            .iter()
            .chain(unique.overflow.iter())
        {
            for (key, field) in tuple.iter().zip(&unique.fields) {
                let Some((Scalar::String(IndexString::Shared(posting)), _)) =
                    structured.fields[&field.path].entries.get_key_value(key)
                else {
                    panic!("field did not own a shared string")
                };
                let Scalar::String(IndexString::Shared(component)) = key else {
                    panic!("tuple copied a field string")
                };
                assert!(Arc::ptr_eq(component, posting));
            }
            count += 1;
        }
        assert_eq!(count, 3);
    }
    let wide = "q".repeat(4096);
    let (base, indexes) = small_fixture(
        &[("/scope", ScalarType::String), ("/key", ScalarType::String)],
        [
            json!({"scope":"g","key":"small"}),
            json!({"scope":"g","key":wide}),
            json!({"scope":"g","key":"untouched"}),
        ],
    );
    check(&indexes);
    let mut next = base.clone();
    let coll = next.get_mut("ordered").unwrap();
    coll.data_epoch += 1;
    for (id, key) in [("row-0", wide.as_str()), ("row-1", "small")] {
        coll.documents.insert(
            id.into(),
            pending(Document {
                id: id.into(),
                version: 2,
                body: json!({"scope":"fresh","key":key}),
            }),
        );
    }
    let changed = BTreeMap::from([(
        "ordered".to_owned(),
        BTreeSet::from(["row-0".to_owned(), "row-1".to_owned()]),
    )]);
    let updated = indexes.update_fixture(&base, &next, &changed).unwrap();
    check(&updated);
    check(&indexes);
    let rebuilt = QueryIndexes::build_fixture(&next).unwrap();
    check(&rebuilt);
}
