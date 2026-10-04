use super::*;
use crate::ReadFailure;
use crate::source_test_utils::{FixtureQueries, ResidentSource, query_memory};
use serde_json::json;
use std::sync::Arc;

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
                Arc::new(Document {
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
            definition,
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
        },
        documents: bodies
            .into_iter()
            .enumerate()
            .map(|(n, body)| {
                let id = format!("row-{n}");
                (
                    id.clone(),
                    Arc::new(Document {
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
