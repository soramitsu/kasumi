use super::*;
use serde_json::json;

fn definition(fields: &[(&str, ScalarType)]) -> CollectionDefinition {
    CollectionDefinition {
        name: "docs".into(),
        schema: json!({"type":"object"}),
        strict_read_audit: false,
        indexes: fields
            .iter()
            .enumerate()
            .map(|(i, (path, kind))| IndexDefinition {
                name: format!("i{i}"),
                fields: vec![IndexField {
                    path: (*path).into(),
                    kind: *kind,
                }],
                unique: false,
                text: None,
            })
            .collect(),
    }
}

fn collection(
    definition: CollectionDefinition,
    bodies: Vec<Value>,
) -> BTreeMap<String, CollectionState> {
    let documents = bodies
        .into_iter()
        .enumerate()
        .map(|(i, body)| {
            let id = format!("{i:03}");
            (
                id.clone(),
                Arc::new(Document {
                    id,
                    version: 7,
                    body,
                }),
            )
        })
        .collect();
    BTreeMap::from([(
        "docs".into(),
        CollectionState {
            definition,
            documents,
        },
    )])
}

fn request() -> QueryRequest {
    serde_json::from_value(json!({"collection":"docs"})).unwrap()
}
fn ids(response: QueryResponse) -> Vec<String> {
    response.rows.into_iter().map(|row| row.id).collect()
}
fn run(
    collections: &BTreeMap<String, CollectionState>,
    request: &QueryRequest,
) -> Result<QueryResponse> {
    QueryIndexes::build(collections)?.execute(collections, request, &Limits::default())
}
fn aggregate(
    alias: &str,
    function: AggregateFunction,
    field: Option<&str>,
    scale: Option<i64>,
) -> Aggregation {
    Aggregation {
        alias: alias.into(),
        function,
        field: field.map(str::to_owned),
        scale,
    }
}

#[test]
fn indexed_boolean_filters_match_independent_reference_evaluator() {
    let collections = collection(definition(&[("/n", ScalarType::Number), ("/tag", ScalarType::String), ("/tags", ScalarType::StringArray)]),
        (0..180).map(|i| json!({"n":i % 37, "tag":if i % 3 == 0 { "a" } else { "b" }, "tags":[format!("{}",i % 4)]})).collect());
    let indexes = QueryIndexes::build(&collections).unwrap();
    // Reference uses native integers directly and does not invoke query internals.
    for low in [0, 7, 23, 36] {
        for high in [3, 17, 36, 50] {
            let mut query = request();
            query.filter = Predicate::And {
                predicates: vec![
                    Predicate::Compare {
                        field: "/n".into(),
                        comparison: Comparison::Gte,
                        value: json!(low),
                    },
                    Predicate::Or {
                        predicates: vec![
                            Predicate::Compare {
                                field: "/n".into(),
                                comparison: Comparison::Lt,
                                value: json!(high),
                            },
                            Predicate::Contains {
                                field: "/tags".into(),
                                value: json!("2"),
                            },
                        ],
                    },
                    Predicate::Not {
                        predicate: Box::new(Predicate::Eq {
                            field: "/tag".into(),
                            value: json!("a"),
                        }),
                    },
                ],
            };
            let expected: Vec<String> = (0..180)
                .filter(|i| i % 37 >= low && (i % 37 < high || i % 4 == 2) && i % 3 != 0)
                .map(|i| format!("{i:03}"))
                .collect();
            assert_eq!(
                ids(indexes
                    .execute(&collections, &query, &Limits::default())
                    .unwrap()),
                expected
            );
        }
    }
}

#[test]
fn decimal_sort_range_and_sum_preserve_more_than_f64_precision() {
    let collections = collection(
        definition(&[("/n", ScalarType::Number), ("/d", ScalarType::Decimal)]),
        vec![
            serde_json::from_str(
                r#"{"n":900719925474099312345678901.3,"d":"900719925474099312345678901.3"}"#,
            )
            .unwrap(),
            serde_json::from_str(
                r#"{"n":900719925474099312345678901.2,"d":"900719925474099312345678901.2"}"#,
            )
            .unwrap(),
        ],
    );
    let mut query = request();
    query.sort = vec![Sort {
        field: "/n".into(),
        direction: Direction::Asc,
    }];
    query.aggregates = vec![aggregate("sum", AggregateFunction::Sum, Some("/d"), None)];
    let result = run(&collections, &query).unwrap();
    assert_eq!(
        result.rows.iter().map(|row| &row.id).collect::<Vec<_>>(),
        vec!["001", "000"]
    );
    assert_eq!(
        result.aggregates,
        vec![json!({"group":{},"values":{"sum":"1801439850948198624691357802.5"}})]
    );
    query.filter = Predicate::Compare {
        field: "/d".into(),
        comparison: Comparison::Gt,
        value: json!("900719925474099312345678901.2"),
    };
    assert_eq!(ids(run(&collections, &query).unwrap()), vec!["000"]);
    query.filter = Predicate::Eq {
        field: "/d".into(),
        value: json!(1),
    };
    assert_eq!(
        run(&collections, &query).unwrap_err().code,
        ErrorCode::InvalidArgument
    );
}

#[test]
fn missing_null_empty_array_and_projection_remain_distinct() {
    let collections = collection(
        definition(&[
            ("/value", ScalarType::String),
            ("/tags", ScalarType::StringArray),
        ]),
        vec![
            json!({}),
            json!({"value":null,"tags":null}),
            json!({"value":"a","tags":[]}),
            json!({"value":"b","tags":["x"]}),
        ],
    );
    let mut query = request();
    query.filter = Predicate::Eq {
        field: "/value".into(),
        value: Value::Null,
    };
    assert_eq!(ids(run(&collections, &query).unwrap()), vec!["001"]);
    query.filter = Predicate::Exists {
        field: "/tags".into(),
        exists: false,
    };
    assert_eq!(ids(run(&collections, &query).unwrap()), vec!["000"]);
    query.filter = Predicate::Exists {
        field: "/tags".into(),
        exists: true,
    };
    assert_eq!(
        ids(run(&collections, &query).unwrap()),
        vec!["001", "002", "003"]
    );
    query.filter = Predicate::Contains {
        field: "/tags".into(),
        value: json!("x"),
    };
    assert_eq!(ids(run(&collections, &query).unwrap()), vec!["003"]);
    query.filter = Predicate::All;
    query.projection = vec!["/value".into(), "/absent".into()];
    let result = run(&collections, &query).unwrap();
    assert_eq!(result.rows[0].body, json!({}));
    assert_eq!(result.rows[1].body, json!({"/value":null}));
}

#[test]
fn groups_distinguish_absent_and_null_and_skip_empty_numeric_inputs() {
    let collections = collection(
        definition(&[("/group", ScalarType::String), ("/n", ScalarType::Number)]),
        vec![
            json!({"n":3}),
            json!({"group":null,"n":null}),
            json!({"group":"a","n":4}),
            json!({"group":"a","n":5}),
            json!({"group":"a"}),
        ],
    );
    let mut query = request();
    query.group_by = vec!["/group".into()];
    query.aggregates = vec![
        aggregate("rows", AggregateFunction::Count, None, None),
        aggregate("numbers", AggregateFunction::Count, Some("/n"), None),
        aggregate("sum", AggregateFunction::Sum, Some("/n"), None),
        aggregate("min", AggregateFunction::Min, Some("/n"), None),
        aggregate("max", AggregateFunction::Max, Some("/n"), None),
        aggregate("avg", AggregateFunction::Avg, Some("/n"), Some(0)),
    ];
    let result = run(&collections, &query).unwrap();
    assert_eq!(
        result.aggregates,
        vec![
            json!({"group":{},"values":{"rows":1,"numbers":1,"sum":"3","min":"3","max":"3","avg":"3"}}),
            json!({"group":{"/group":null},"values":{"rows":1,"numbers":0,"sum":"0","min":null,"max":null,"avg":null}}),
            json!({"group":{"/group":"a"},"values":{"rows":3,"numbers":2,"sum":"9","min":"4","max":"5","avg":"4"}}),
        ]
    );
}

#[test]
fn average_is_half_even_at_requested_scale_including_negative_ties() {
    use std::str::FromStr;
    for (sum, count, scale, expected) in [
        ("5", 2, 0, "2"),
        ("7", 2, 0, "4"),
        ("-5", 2, 0, "-2"),
        ("-7", 2, 0, "-4"),
        ("0.01", 2, 2, "0"),
        ("0.03", 2, 2, "0.02"),
        ("1", 3, 4, "0.3333"),
    ] {
        assert_eq!(
            exact_average(&BigDecimal::from_str(sum).unwrap(), count, scale),
            BigDecimal::from_str(expected).unwrap()
        );
    }
    let long = exact_average(&BigDecimal::from(1), 3, 1000);
    assert_eq!(long.to_string(), format!("0.{}", "3".repeat(1000)));
    let huge = format!("{}5", "9".repeat(100));
    let exact = exact_average(&BigDecimal::from_str(&huge).unwrap(), 2, 2);
    assert_eq!(&exact * 2, BigDecimal::from_str(&huge).unwrap());
}

#[test]
fn aggregate_validation_and_empty_collection_are_data_independent() {
    let collections = collection(definition(&[("/n", ScalarType::Number)]), vec![]);
    let mut query = request();
    query.filter = Predicate::Eq {
        field: "/n".into(),
        value: json!("wrong type"),
    };
    assert_eq!(
        run(&collections, &query).unwrap_err().code,
        ErrorCode::InvalidArgument
    );
    query.filter = Predicate::All;
    query.aggregates = vec![aggregate("avg", AggregateFunction::Avg, Some("/n"), None)];
    assert_eq!(
        run(&collections, &query).unwrap_err().code,
        ErrorCode::InvalidArgument
    );
    query.aggregates = vec![
        aggregate("sum", AggregateFunction::Sum, Some("/n"), None),
        aggregate("count", AggregateFunction::Count, None, None),
    ];
    assert_eq!(
        run(&collections, &query).unwrap().aggregates,
        vec![json!({"group":{},"values":{"sum":"0","count":0}})]
    );
}

#[test]
fn declared_indexes_and_explicit_scan_admission_are_enforced() {
    let collections = collection(definition(&[]), vec![json!({"n":2}), json!({"n":1})]);
    let mut query = request();
    query.filter = Predicate::Eq {
        field: "/n".into(),
        value: json!(1),
    };
    assert_eq!(
        run(&collections, &query).unwrap_err().code,
        ErrorCode::IndexRequired
    );
    query.allow_scan = true;
    assert_eq!(ids(run(&collections, &query).unwrap()), vec!["001"]);
    query.filter = Predicate::All;
    query.sort = vec![Sort {
        field: "/n".into(),
        direction: Direction::Asc,
    }];
    assert_eq!(ids(run(&collections, &query).unwrap()), vec!["001", "000"]);
    query.allow_scan = false;
    assert_eq!(
        run(&collections, &query).unwrap_err().code,
        ErrorCode::IndexRequired
    );
}

#[test]
fn candidate_group_and_response_budgets_fail_closed() {
    let collections = collection(
        definition(&[("/n", ScalarType::Number)]),
        (0..8).map(|i| json!({"n":i})).collect(),
    );
    let indexes = QueryIndexes::build(&collections).unwrap();
    let mut query = request();
    let mut limits = Limits {
        max_query_candidates: 4,
        ..Limits::default()
    };
    assert_eq!(
        indexes
            .execute(&collections, &query, &limits)
            .unwrap_err()
            .code,
        ErrorCode::ResourceExhausted
    );
    query.filter = Predicate::Eq {
        field: "/n".into(),
        value: json!(1),
    };
    assert_eq!(
        ids(indexes.execute(&collections, &query, &limits).unwrap()),
        vec!["001"]
    );
    query.filter = Predicate::All;
    limits.max_query_candidates = 10;
    limits.max_query_groups = 2;
    query.group_by = vec!["/n".into()];
    query.aggregates = vec![aggregate("count", AggregateFunction::Count, None, None)];
    assert_eq!(
        indexes
            .execute(&collections, &query, &limits)
            .unwrap_err()
            .code,
        ErrorCode::ResourceExhausted
    );
    query.group_by.clear();
    query.aggregates.clear();
    limits.max_result_bytes = 10;
    assert_eq!(
        indexes
            .execute(&collections, &query, &limits)
            .unwrap_err()
            .code,
        ErrorCode::ResourceExhausted
    );
}

#[test]
fn engine_owns_pagination_and_query_does_not_truncate_snapshot() {
    let collections = collection(definition(&[]), vec![json!({}), json!({}), json!({})]);
    let mut query = request();
    query.limit = 1;
    let result = run(&collections, &query).unwrap();
    assert_eq!(result.rows.len(), 3);
    assert!(result.cursor.is_none());
    query.cursor = Some("untrusted-token".into());
    assert_eq!(
        run(&collections, &query).unwrap_err().code,
        ErrorCode::InvalidArgument
    );
}

#[test]
fn json_pointer_escapes_and_invalid_pointers() {
    let collections = collection(
        definition(&[("/a~1b/~0key", ScalarType::Number)]),
        vec![json!({"a/b":{"~key":42}})],
    );
    let mut query = request();
    query.filter = Predicate::Eq {
        field: "/a~1b/~0key".into(),
        value: json!(42),
    };
    query.projection = vec!["/a~1b/~0key".into()];
    assert_eq!(
        run(&collections, &query).unwrap().rows[0].body,
        json!({"/a~1b/~0key":42})
    );
    query.projection = vec!["/bad~2escape".into()];
    assert_eq!(
        run(&collections, &query).unwrap_err().code,
        ErrorCode::InvalidArgument
    );
}

#[test]
fn schema_202012_local_refs_and_exact_numeric_constraints() {
    let mut definition = definition(&[]);
    definition.schema = serde_json::from_str(r##"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","$defs":{"n":{"type":"number","minimum":9007199254740993.01,"multipleOf":0.01}},"properties":{"n":{"$ref":"#/$defs/n"}},"required":["n"],"unevaluatedProperties":false}"##).unwrap();
    assert!(
        validate_document(
            &definition,
            &serde_json::from_str(r#"{"n":9007199254740993.02}"#).unwrap()
        )
        .is_ok()
    );
    assert_eq!(
        validate_document(
            &definition,
            &serde_json::from_str(r#"{"n":9007199254740993.00}"#).unwrap()
        )
        .unwrap_err()
        .code,
        ErrorCode::SchemaViolation
    );
    assert_eq!(
        validate_document(&definition, &json!({"n":1,"extra":true}))
            .unwrap_err()
            .code,
        ErrorCode::SchemaViolation
    );
}

#[test]
fn schemas_never_resolve_remote_or_file_resources_or_rebase_fragments() {
    for schema in [
        json!({"$ref":"https://example.invalid/secret"}),
        json!({"$ref":"file:///etc/passwd"}),
        json!({"$defs":{"hidden":{"$ref":"https://example.invalid/unused"}}}),
        json!({"$id":"https://example.invalid/rebase","$ref":"#/local"}),
        json!({"$schema":"http://json-schema.org/draft-07/schema#"}),
    ] {
        let mut definition = definition(&[]);
        definition.schema = schema;
        assert_eq!(
            validate_collection(&definition, &imbl::HashMap::new())
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
    }
    let mut definition = definition(&[]);
    definition.schema = json!({"type":"object","properties":{"$ref":{"type":"string"},"$id":{"type":"string"}},"default":{"$ref":"literal data"}});
    validate_document(&definition, &json!({"$ref":"literal","$id":"literal"})).unwrap();
}

#[test]
fn unique_indexes_are_compound_exact_and_sparse_only_for_missing() {
    let mut definition = definition(&[("/group", ScalarType::String), ("/n", ScalarType::Decimal)]);
    definition.indexes = vec![IndexDefinition {
        name: "unique_pair".into(),
        fields: vec![
            IndexField {
                path: "/group".into(),
                kind: ScalarType::String,
            },
            IndexField {
                path: "/n".into(),
                kind: ScalarType::Decimal,
            },
        ],
        unique: true,
        text: None,
    }];
    let mut collections = collection(
        definition,
        vec![
            json!({}),
            json!({}),
            json!({"group":"a","n":"1.00"}),
            json!({"group":"b","n":"1"}),
        ],
    );
    QueryIndexes::build(&collections).unwrap();
    collections.get_mut("docs").unwrap().documents.insert(
        "dup".into(),
        Arc::new(Document {
            id: "dup".into(),
            version: 8,
            body: json!({"group":"a","n":"1"}),
        }),
    );
    assert_eq!(
        QueryIndexes::build(&collections).unwrap_err().code,
        ErrorCode::Conflict
    );
}

fn text_collection(analyzer: Analyzer, values: &[&str]) -> BTreeMap<String, CollectionState> {
    let mut definition = definition(&[("/text", ScalarType::String)]);
    definition.indexes[0].text = Some(TextIndex { analyzer });
    definition.indexes[0].name = "text".into();
    collection(
        definition,
        values.iter().map(|text| json!({"text":text})).collect(),
    )
}
fn text_query(query: &str, mode: TextMode) -> QueryRequest {
    let mut request = request();
    request.text = Some(TextSearch {
        index: "text".into(),
        query: query.into(),
        mode,
        distance: 1,
    });
    request
}

#[test]
fn english_terms_stem_but_prefix_uses_surface_tokens_and_phrase_has_positions() {
    let collections = text_collection(
        Analyzer::EnglishV1,
        &[
            "The runners are running swiftly",
            "swiftly running across hills",
            "We run around valleys",
            "shipping shipped ships",
        ],
    );
    let indexes = QueryIndexes::build(&collections).unwrap();
    let query = |text, mode| {
        ids(indexes
            .execute(&collections, &text_query(text, mode), &Limits::default())
            .unwrap())
        .into_iter()
        .collect::<BTreeSet<_>>()
    };
    assert_eq!(
        query("run", TextMode::Terms),
        BTreeSet::from(["000".into(), "001".into(), "002".into()])
    );
    assert_eq!(
        query("running swiftly", TextMode::Phrase),
        BTreeSet::from(["000".into()])
    );
    assert_eq!(
        query("shippi", TextMode::Prefix),
        BTreeSet::from(["003".into()])
    );
    assert!(query("swiftly runners", TextMode::Phrase).is_empty());
}

#[test]
fn unicode_nfkc_and_case_normalization_and_ranked_results() {
    let collections = text_collection(
        Analyzer::UnicodeV1,
        &[
            "ＣＡＦＥ",
            "cafe cafe cafe",
            "cafe with many unrelated ordinary words",
            "unrelated",
        ],
    );
    let indexes = QueryIndexes::build(&collections).unwrap();
    let result = indexes
        .execute(
            &collections,
            &text_query("CAFE", TextMode::Terms),
            &Limits::default(),
        )
        .unwrap();
    assert_eq!(result.rows.len(), 3);
    assert!(
        result
            .rows
            .iter()
            .all(|row| row.score.is_some_and(|score| score > 0.0))
    );
    assert!(
        result
            .rows
            .windows(2)
            .all(|pair| pair[0].score >= pair[1].score)
    );
    assert!(result.rows.iter().any(|row| row.id == "000"));
}

#[test]
fn japanese_lindera_terms_phrases_and_fuzzy_typos() {
    let collections = text_collection(
        Analyzer::JapaneseV1,
        &[
            "東京都で日本語を検索します",
            "大阪で図書館へ行きます",
            "日本語のデータベース",
        ],
    );
    let indexes = QueryIndexes::build(&collections).unwrap();
    let query = |text, mode| {
        ids(indexes
            .execute(&collections, &text_query(text, mode), &Limits::default())
            .unwrap())
        .into_iter()
        .collect::<BTreeSet<_>>()
    };
    assert_eq!(
        query("日本語", TextMode::Terms),
        BTreeSet::from(["000".into(), "002".into()])
    );
    assert_eq!(
        query("日本語を検索", TextMode::Phrase),
        BTreeSet::from(["000".into()])
    );
    assert_eq!(
        query("図書官", TextMode::Fuzzy),
        BTreeSet::from(["001".into()])
    );
}

#[test]
fn fuzzy_distance_and_expansion_limits_are_enforced() {
    let collections = text_collection(
        Analyzer::UnicodeV1,
        &["kitten", "sitten", "kitchen", "puppy"],
    );
    let indexes = QueryIndexes::build(&collections).unwrap();
    assert_eq!(
        ids(indexes
            .execute(
                &collections,
                &text_query("kitten", TextMode::Fuzzy),
                &Limits::default()
            )
            .unwrap()),
        vec!["000", "001"]
    );
    let mut query = text_query("kitten", TextMode::Fuzzy);
    query.text.as_mut().unwrap().distance = 3;
    assert_eq!(
        indexes
            .execute(&collections, &query, &Limits::default())
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
    query.text.as_mut().unwrap().distance = 0;
    assert_eq!(
        ids(indexes
            .execute(&collections, &query, &Limits::default())
            .unwrap()),
        vec!["000"]
    );
    let values: Vec<String> = (0..65).map(|i| format!("prefix{i:03}")).collect();
    let collections = text_collection(
        Analyzer::UnicodeV1,
        &values.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    assert_eq!(
        run(&collections, &text_query("prefix", TextMode::Prefix))
            .unwrap_err()
            .code,
        ErrorCode::ResourceExhausted
    );
}

#[test]
fn text_generation_is_immutable_and_reader_is_ready_when_published() {
    let mut collections = text_collection(Analyzer::EnglishV1, &["old contents"]);
    let old = QueryIndexes::build(&collections).unwrap();
    let old_collections = collections.clone();
    change_document(&mut collections, "000").body = json!({"text":"new contents"});
    let new = QueryIndexes::build(&collections).unwrap();
    let query = text_query("new", TextMode::Terms);
    assert!(
        old.execute(&old_collections, &query, &Limits::default())
            .unwrap()
            .rows
            .is_empty()
    );
    assert_eq!(
        ids(new
            .execute(&collections, &query, &Limits::default())
            .unwrap()),
        vec!["000"]
    );
}

#[test]
fn oversized_text_is_rejected_during_document_validation() {
    let collections = text_collection(Analyzer::EnglishV1, &[]);
    let definition = &collections["docs"].definition;
    assert_eq!(
        validate_document(definition, &json!({"text":"x".repeat(241)}))
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
}

#[test]
fn text_planned_postings_are_bounded_even_when_intersection_has_no_hits() {
    let collections = text_collection(
        Analyzer::UnicodeV1,
        &[
            "common", "common", "common", "common", "common", "common", "common", "common",
            "common",
        ],
    );
    let indexes = QueryIndexes::build(&collections).unwrap();
    let limits = Limits {
        max_query_candidates: 1,
        ..Limits::default()
    };
    assert_eq!(
        indexes
            .execute(
                &collections,
                &text_query("common missing", TextMode::Terms),
                &limits
            )
            .unwrap_err()
            .code,
        ErrorCode::ResourceExhausted
    );
}

#[test]
fn invalid_queries_fail_without_hits_and_json_recursion_is_bounded() {
    let collections = collection(
        definition(&[
            ("/tags", ScalarType::StringArray),
            ("/n", ScalarType::Number),
        ]),
        vec![],
    );
    for predicate in [
        Predicate::In {
            field: "/tags".into(),
            values: vec![],
        },
        Predicate::Compare {
            field: "/n".into(),
            comparison: Comparison::Gt,
            value: Value::Null,
        },
        Predicate::Contains {
            field: "/tags".into(),
            value: Value::Null,
        },
    ] {
        let mut query = request();
        query.filter = predicate;
        assert_eq!(
            run(&collections, &query).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
    }
    let mut query = request();
    for _ in 0..17 {
        query.filter = Predicate::Not {
            predicate: Box::new(query.filter),
        };
    }
    assert_eq!(
        run(&collections, &query).unwrap_err().code,
        ErrorCode::InvalidArgument
    );
    let mut body = json!({});
    for _ in 0..50 {
        body = json!({"next":body});
    }
    assert_eq!(
        validate_document(&definition(&[]), &body).unwrap_err().code,
        ErrorCode::InvalidArgument
    );
}

#[test]
fn validator_cache_does_not_retain_tenant_plaintext_after_generation_drop() {
    let mut definition = definition(&[]);
    definition.schema =
        json!({"properties":{"secret":{"const":"only-this-test-schema-contains-this-secret"}}});
    let collections = collection(definition, vec![]);
    let indexes = QueryIndexes::build(&collections).unwrap();
    let validator = validation::compile(&collections["docs"].definition.schema).unwrap();
    let weak = std::sync::Arc::downgrade(&validator);
    drop(validator);
    assert!(weak.upgrade().is_some()); // Published generation owns the validator.
    drop(indexes);
    assert!(weak.upgrade().is_none()); // Global cache contains only a digest/Weak.
}

#[test]
fn incremental_postings_match_rebuild_and_share_unchanged_roots() {
    let mut previous = collection(
        definition(&[("/n", ScalarType::Number), ("/tag", ScalarType::String)]),
        (0..10_000).map(|i| json!({"n":i,"tag":"common"})).collect(),
    );
    let mut unrelated = previous["docs"].clone();
    unrelated.definition.name = "untouched".into();
    previous.insert("untouched".into(), unrelated);
    let old = QueryIndexes::build(&previous).unwrap();
    let mut next = previous.clone();
    let documents = &mut next.get_mut("docs").unwrap().documents;
    Arc::make_mut(documents.get_mut("001").unwrap()).body["n"] = json!(10001);
    documents.remove("002");
    documents.insert(
        "new".into(),
        Arc::new(Document {
            id: "new".into(),
            version: 8,
            body: json!({"n":-1,"tag":"common"}),
        }),
    );
    let changed = BTreeMap::from([(
        "docs".into(),
        BTreeSet::from(["001".into(), "002".into(), "new".into()]),
    )]);
    let updated = old.update(&previous, &next, &changed).unwrap();
    assert!(Arc::ptr_eq(
        &old.collections["untouched"],
        &updated.collections["untouched"]
    ));
    let rebuilt = QueryIndexes::build(&next).unwrap();
    for n in [-1, 1, 2, 9999, 10001] {
        let mut query = request();
        query.filter = Predicate::Eq {
            field: "/n".into(),
            value: json!(n),
        };
        assert_eq!(
            updated.execute(&next, &query, &Limits::default()).unwrap(),
            rebuilt.execute(&next, &query, &Limits::default()).unwrap()
        );
    }
    let mut query = request();
    query.filter = Predicate::Eq {
        field: "/n".into(),
        value: json!(1),
    };
    assert_eq!(
        ids(old.execute(&previous, &query, &Limits::default()).unwrap()),
        vec!["001"]
    );

    let mut fields_only = previous.clone();
    change_document(&mut fields_only, "001").body["n"] = json!(12345);
    let changed = BTreeMap::from([("docs".into(), BTreeSet::from(["001".into()]))]);
    let fields_only = old.update(&previous, &fields_only, &changed).unwrap();
    assert!(
        old.collections["docs"]
            .structured
            .ids
            .ptr_eq(&fields_only.collections["docs"].structured.ids)
    );
    assert!(
        old.collections["docs"].structured.fields["/tag"]
            .entries
            .ptr_eq(&fields_only.collections["docs"].structured.fields["/tag"].entries)
    );
}

#[test]
fn incremental_text_updates_reuse_index_and_preserve_every_old_snapshot() {
    let mut previous = text_collection(
        Analyzer::EnglishV1,
        &["first apple", "second pear", "third peach"],
    );
    let old = QueryIndexes::build(&previous).unwrap();
    let mut next = previous.clone();
    change_document(&mut next, "000").body = json!({"text":"fresh banana"});
    next.get_mut("docs").unwrap().documents.remove("001");
    next.get_mut("docs").unwrap().documents.insert(
        "added".into(),
        Arc::new(Document {
            id: "added".into(),
            version: 8,
            body: json!({"text":"ripe banana"}),
        }),
    );
    let changed = BTreeMap::from([(
        "docs".into(),
        BTreeSet::from(["000".into(), "001".into(), "added".into()]),
    )]);
    let mut updated = old.update(&previous, &next, &changed).unwrap();
    let rebuilt = QueryIndexes::build(&next).unwrap();
    for text in ["apple", "pear", "peach", "banana"] {
        let query = text_query(text, TextMode::Terms);
        let normalize = |result: QueryResponse| ids(result).into_iter().collect::<BTreeSet<_>>();
        assert_eq!(
            normalize(updated.execute(&next, &query, &Limits::default()).unwrap()),
            normalize(rebuilt.execute(&next, &query, &Limits::default()).unwrap())
        );
    }
    assert_eq!(
        ids(old
            .execute(
                &previous,
                &text_query("apple", TextMode::Terms),
                &Limits::default()
            )
            .unwrap()),
        vec!["000"]
    );
    assert_eq!(
        ids(old
            .execute(
                &previous,
                &text_query("pear", TextMode::Terms),
                &Limits::default()
            )
            .unwrap()),
        vec!["001"]
    );
    assert!(
        old.execute(
            &previous,
            &text_query("banana", TextMode::Terms),
            &Limits::default()
        )
        .unwrap()
        .rows
        .is_empty()
    );

    // Successive commits/merges keep old readers usable and don't accumulate a
    // logical document for every update of the same external id.
    let mut retained = Vec::new();
    previous = next;
    for i in 0..12 {
        let mut next = previous.clone();
        change_document(&mut next, "000").body = json!({"text":format!("replacement{i} banana")});
        let changed = BTreeMap::from([("docs".into(), BTreeSet::from(["000".into()]))]);
        let current = updated.update(&previous, &next, &changed).unwrap();
        retained.push((updated, previous));
        updated = current;
        previous = next;
    }
    assert_eq!(
        updated
            .execute(
                &previous,
                &text_query("banana", TextMode::Terms),
                &Limits::default()
            )
            .unwrap()
            .rows
            .len(),
        2
    );
    for (i, (snapshot, documents)) in retained.iter().enumerate().skip(1) {
        assert_eq!(
            ids(snapshot
                .execute(
                    documents,
                    &text_query(&format!("replacement{}", i - 1), TextMode::Terms),
                    &Limits::default()
                )
                .unwrap()),
            vec!["000"]
        );
    }
}

#[test]
fn unrelated_document_fields_reuse_text_reader_and_definition_change_rebuilds() {
    let previous = text_collection(Analyzer::EnglishV1, &["first apple"]);
    let old = QueryIndexes::build(&previous).unwrap();
    let mut next = previous.clone();
    change_document(&mut next, "000").body["unindexed"] = json!(123);
    let changed = BTreeMap::from([("docs".into(), BTreeSet::from(["000".into()]))]);
    let updated = old.update(&previous, &next, &changed).unwrap();
    assert!(Arc::ptr_eq(
        old.collections["docs"].text.as_ref().unwrap(),
        updated.collections["docs"].text.as_ref().unwrap()
    ));
    let mut replacement = next.clone();
    replacement.get_mut("docs").unwrap().definition.indexes[0]
        .text
        .as_mut()
        .unwrap()
        .analyzer = Analyzer::UnicodeV1;
    let replaced = updated
        .update(&next, &replacement, &BTreeMap::new())
        .unwrap();
    assert!(!Arc::ptr_eq(
        updated.collections["docs"].text.as_ref().unwrap(),
        replaced.collections["docs"].text.as_ref().unwrap()
    ));
    assert_eq!(
        ids(replaced
            .execute(
                &replacement,
                &text_query("apple", TextMode::Terms),
                &Limits::default()
            )
            .unwrap()),
        vec!["000"]
    );
}

#[test]
fn incremental_unique_indexes_allow_atomic_swaps_and_reject_conflicts() {
    let mut definition = definition(&[("/n", ScalarType::Decimal)]);
    definition.indexes[0].unique = true;
    let previous = collection(
        definition,
        vec![json!({"n":"1"}), json!({"n":"2"}), json!({})],
    );
    let old = QueryIndexes::build(&previous).unwrap();
    let mut next = previous.clone();
    change_document(&mut next, "000").body["n"] = json!("2.00");
    change_document(&mut next, "001").body["n"] = json!("1");
    let changed = BTreeMap::from([("docs".into(), BTreeSet::from(["000".into(), "001".into()]))]);
    old.validate_unique_changes(&previous, &next, &changed)
        .unwrap();
    let updated = old.update(&previous, &next, &changed).unwrap();
    let mut conflict = next.clone();
    change_document(&mut conflict, "002").body = json!({"n":"1.0"});
    let changed = BTreeMap::from([("docs".into(), BTreeSet::from(["002".into()]))]);
    assert_eq!(
        updated
            .validate_unique_changes(&next, &conflict, &changed)
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    assert_eq!(
        updated.update(&next, &conflict, &changed).unwrap_err().code,
        ErrorCode::Conflict
    );
}

#[test]
fn text_writer_rejects_stale_branches_without_damaging_published_reader() {
    let previous = text_collection(Analyzer::UnicodeV1, &["old"]);
    let old = QueryIndexes::build(&previous).unwrap();
    let mut next = previous.clone();
    change_document(&mut next, "000").body = json!({"text":"new"});
    let changed = BTreeMap::from([("docs".into(), BTreeSet::from(["000".into()]))]);
    let updated = old.update(&previous, &next, &changed).unwrap();
    assert_eq!(
        old.update(&previous, &next, &changed).unwrap_err().code,
        ErrorCode::Unavailable
    );
    assert_eq!(
        ids(updated
            .execute(
                &next,
                &text_query("new", TextMode::Terms),
                &Limits::default()
            )
            .unwrap()),
        vec!["000"]
    );
    assert_eq!(
        ids(old
            .execute(
                &previous,
                &text_query("old", TextMode::Terms),
                &Limits::default()
            )
            .unwrap()),
        vec!["000"]
    );
}

#[test]
fn cooperative_cancellation_discards_partial_index_scan_sort_and_projection_results() {
    let collections = collection(
        definition(&[("/n", ScalarType::Number)]),
        (0..512).map(|n| json!({"n":n,"body":"payload"})).collect(),
    );
    let indexes = QueryIndexes::build(&collections).unwrap();
    for filter in [
        Predicate::All,
        Predicate::Exists {
            field: "/missing".into(),
            exists: false,
        },
        Predicate::Compare {
            field: "/n".into(),
            comparison: Comparison::Gte,
            value: json!(0),
        },
    ] {
        let mut query = request();
        query.filter = filter;
        query.allow_scan = true;
        query.sort = vec![Sort {
            field: "/n".into(),
            direction: Direction::Desc,
        }];
        query.projection = vec!["/body".into()];
        for checkpoints in [0, 50, 500, 1000, 2000] {
            let cancellation = QueryCancellation::after_checks(checkpoints);
            let result = indexes.execute_with_cancellation(
                &collections,
                &query,
                &Limits::default(),
                &cancellation,
            );
            assert_eq!(result.unwrap_err().code, ErrorCode::ResourceExhausted);
            assert!(cancellation.is_cancelled());
        }
        assert_eq!(
            indexes
                .execute(&collections, &query, &Limits::default())
                .unwrap()
                .rows
                .len(),
            512
        );
    }
}

#[test]
fn cooperative_cancellation_stops_text_postings_and_term_expansion() {
    let collections = text_collection(Analyzer::UnicodeV1, &vec!["prefix searchable word"; 512]);
    let indexes = QueryIndexes::build(&collections).unwrap();
    for mode in [
        TextMode::Terms,
        TextMode::Phrase,
        TextMode::Prefix,
        TextMode::Fuzzy,
    ] {
        let query = text_query("prefix", mode);
        let cancellation = QueryCancellation::after_checks(100);
        assert_eq!(
            indexes
                .execute_with_cancellation(&collections, &query, &Limits::default(), &cancellation)
                .unwrap_err()
                .code,
            ErrorCode::ResourceExhausted
        );
        assert!(cancellation.is_cancelled());
    }
}

fn change_document<'a>(
    collections: &'a mut BTreeMap<String, CollectionState>,
    id: &str,
) -> &'a mut Document {
    Arc::make_mut(
        collections
            .get_mut("docs")
            .unwrap()
            .documents
            .get_mut(id)
            .unwrap(),
    )
}

#[test]
fn shared_document_representation_preserves_snapshot_bytes_and_historical_values() {
    let body: Value = serde_json::from_str(
        r#"{"exact":123456789012345678901234567890.00001,"nested":[null,{"k":"v"}]}"#,
    )
    .unwrap();
    let old = collection(
        definition(&[]),
        vec![body.clone(), json!({"other":"untouched"})],
    );
    // This matches the previous owned-document snapshot representation. Sorting
    // borrowed entries and Arc serde dereferencing must preserve exact bytes.
    #[derive(serde::Serialize)]
    struct OwnedRepresentation<'a> {
        definition: &'a CollectionDefinition,
        documents: BTreeMap<&'a String, &'a Document>,
    }
    let expected = OwnedRepresentation {
        definition: &old["docs"].definition,
        documents: old["docs"]
            .documents
            .iter()
            .map(|(id, doc)| (id, doc.as_ref()))
            .collect(),
    };
    let encoded = serde_json::to_vec(&old["docs"]).unwrap();
    assert_eq!(encoded, serde_json::to_vec(&expected).unwrap());
    let recovered: CollectionState = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(serde_json::to_vec(&recovered).unwrap(), encoded);
    assert_eq!(recovered.documents["000"].body, body);

    let mut next = old.clone();
    assert!(Arc::ptr_eq(
        &old["docs"].documents["000"],
        &next["docs"].documents["000"]
    ));
    assert!(
        Arc::get_mut(
            next.get_mut("docs")
                .unwrap()
                .documents
                .get_mut("000")
                .unwrap()
        )
        .is_none()
    );
    change_document(&mut next, "000").body = json!({"new":true});
    assert_eq!(old["docs"].documents["000"].body, body);
    assert!(!Arc::ptr_eq(
        &old["docs"].documents["000"],
        &next["docs"].documents["000"]
    ));
    assert!(Arc::ptr_eq(
        &old["docs"].documents["001"],
        &next["docs"].documents["001"]
    ));
}
