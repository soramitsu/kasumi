use super::*;
use crate::source_test_utils::{FixtureQueries, query_memory};
use std::cell::{Cell, RefCell};

#[derive(Debug)]
struct Marker(Arc<()>);
impl std::fmt::Display for Marker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("original source failure")
    }
}
impl std::error::Error for Marker {}

/// Bodies are decoded into one local allocation per loan, never retained in
/// the source or returned behind Arc. The only long-lived body copies are the
/// fixture's encoded input and the query's bounded final output.
struct LoanSource {
    definition: CollectionDefinition,
    indexes: QueryIndexes,
    encoded: BTreeMap<String, String>,
    owners: [Box<u8>; 2],
    owner: Cell<usize>,
    switch_after_first: bool,
    calls: Cell<usize>,
    callbacks: Cell<usize>,
    active: Cell<bool>,
    cancel_after_read: bool,
    cancel_after_loan: bool,
    missing_output: bool,
    fail_at: usize,
    failure: Arc<()>,
    archived: bool,
    expected: RefCell<Vec<Option<u64>>>,
}
impl LoanSource {
    fn new() -> Self {
        let definition: CollectionDefinition = serde_json::from_value(serde_json::json!({
            "name":"docs", "schema":{"type":"object"}, "write_mode":"mutable", "retention_class":"operational", "strict_read_audit":false, "indexes":[]
        })).unwrap();
        let documents: imbl::OrdMap<String, Arc<Document>> = (0..3)
            .map(|n| {
                let id = format!("d{n}");
                (
                    id.clone(),
                    Arc::new(Document {
                        id,
                        version: 7,
                        body: serde_json::json!({"order":2-n,"group":"g","n":n}),
                    }),
                )
            })
            .collect();
        let encoded = documents
            .iter()
            .map(|(id, doc)| (id.clone(), serde_json::to_string(doc).unwrap()))
            .collect();
        let collection = CollectionState {
            definition: definition.clone(),
            data_epoch: 7,
            documents,
            archived_documents: Default::default(),
            archived_document_bytes: 0,
        };
        let indexes =
            QueryIndexes::build_fixture(&BTreeMap::from([("docs".to_owned(), collection)]))
                .unwrap();
        Self {
            definition,
            indexes,
            encoded,
            owners: [Box::new(1), Box::new(2)],
            owner: Cell::new(0),
            switch_after_first: false,
            calls: Cell::new(0),
            callbacks: Cell::new(0),
            active: Cell::new(false),
            cancel_after_read: false,
            cancel_after_loan: false,
            missing_output: false,
            fail_at: usize::MAX,
            failure: Arc::new(()),
            archived: false,
            expected: RefCell::new(vec![]),
        }
    }
    fn query(&self) -> QueryRequest {
        serde_json::from_value(serde_json::json!({"collection":"docs","allow_scan":true,"limit":1}))
            .unwrap()
    }

    fn set_body(&mut self, body: Value) {
        // The fixture has no field indexes. Replacing the encoded bodies keeps
        // its maintained ID root and exact document versions unchanged.
        for encoded in self.encoded.values_mut() {
            let mut document: Document = serde_json::from_str(encoded).unwrap();
            document.body = body.clone();
            *encoded = serde_json::to_string(&document).unwrap();
        }
    }
}
struct Loan<'a>(&'a Cell<bool>);
impl Drop for Loan<'_> {
    fn drop(&mut self) {
        assert!(self.0.replace(false));
    }
}

struct LimitedWorkspace(u64);
impl QueryWorkspace for LimitedWorkspace {
    fn ensure_peak(&mut self, total: u64) -> Result<()> {
        if total > self.0 {
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                "fixture workspace exhausted",
            ));
        }
        Ok(())
    }
}

#[test]
fn workspace_denial_keeps_prior_typed_output_as_the_next_query_baseline() {
    let source = LoanSource::new();
    let query = source.query();
    let limits = Limits::default();
    let mut pilot = query_memory();
    let response = source
        .indexes
        .execute(&source, &query, &limits, &mut pilot)
        .unwrap();
    let allowance = pilot.peak_bytes();
    drop(response);
    let mut memory = QueryMemory::new(LimitedWorkspace(allowance), 0).unwrap();
    let first = source
        .indexes
        .execute(&source, &query, &limits, &mut memory)
        .unwrap();
    let retained = memory.live_bytes();
    assert!(retained > 0);
    assert_eq!(
        retained,
        query_response_clone_bytes(&first, 0..first.rows.len()).unwrap()
    );
    assert_eq!(memory.peak_bytes(), allowance);
    assert!(matches!(
        source
            .indexes
            .execute(&source, &query, &limits, &mut memory),
        Err(ReadFailure::Query(Error {
            code: ErrorCode::ResourceExhausted,
            ..
        }))
    ));
    assert_eq!(
        (memory.live_bytes(), memory.peak_bytes()),
        (retained, allowance)
    );
    assert_eq!(first.rows.len(), 3);
    drop(first);
    memory.release(retained).unwrap();
    assert_eq!(memory.live_bytes(), 0);
}

#[test]
fn long_string_sort_key_is_admitted_even_when_projection_is_tiny() {
    let mut source = LoanSource::new();
    source.set_body(serde_json::json!({ "sort": "x".repeat(64 << 10), "tiny": true }));
    let query: QueryRequest = serde_json::from_value(serde_json::json!({
        "collection": "docs", "allow_scan": true, "limit": 1,
        "sort": ["/sort"], "select": ["/tiny"]
    }))
    .unwrap();
    let limits = Limits {
        max_query_candidates: 3,
        max_query_groups: 0,
        max_result_bytes: 2048,
        ..Limits::default()
    };
    let mut memory = QueryMemory::new(LimitedWorkspace(16 << 10), 0).unwrap();
    assert!(matches!(
        source
            .indexes
            .execute(&source, &query, &limits, &mut memory),
        Err(ReadFailure::Query(Error {
            code: ErrorCode::ResourceExhausted,
            ..
        }))
    ));
    // The first borrowed source loan can decode its own body, but copying its
    // large sort string is denied before any selected row or output is built.
    assert_eq!(source.calls.get(), 1);
    assert_eq!(&*source.expected.borrow(), &[None]);
    assert!(!source.active.get());
    assert_eq!(memory.live_bytes(), 0);
    assert!(memory.peak_bytes() > 0 && memory.peak_bytes() <= 16 << 10);
}

#[test]
fn many_small_json_members_require_owned_nodes_before_the_row_clone() {
    let mut source = LoanSource::new();
    source.set_body(Value::Object(
        (0..200)
            .map(|n| (format!("k{n}"), Value::Bool(true)))
            .collect(),
    ));
    let query = source.query();
    let limits = Limits {
        max_query_candidates: 3,
        max_query_groups: 0,
        max_result_bytes: 16 << 10,
        ..Limits::default()
    };
    let mut memory = QueryMemory::new(LimitedWorkspace(64 << 10), 0).unwrap();
    assert!(matches!(
        source
            .indexes
            .execute(&source, &query, &limits, &mut memory),
        Err(ReadFailure::Query(Error {
            code: ErrorCode::ResourceExhausted,
            ..
        }))
    ));
    // The first loan cannot copy its object, even though every row fits the
    // configured wire-byte budget; no later document is read.
    assert_eq!(&*source.expected.borrow(), &[None]);
    assert!(!source.active.get());
    assert_eq!(memory.live_bytes(), 0);
}

#[test]
fn nested_select_retains_its_complete_owned_clone_and_rejects_overlaps() {
    let mut source = LoanSource::new();
    source.set_body(serde_json::json!({ "nested": { "text": "x".repeat(8192), "other": 1 } }));
    let mut query = source.query();
    query.select = vec!["/nested/text".into()];
    let limits = Limits {
        max_query_candidates: 3,
        max_query_groups: 0,
        ..Limits::default()
    };
    let mut memory = query_memory();
    let response = source
        .indexes
        .execute(&source, &query, &limits, &mut memory)
        .unwrap();
    assert_eq!(
        memory.live_bytes(),
        query_response_clone_bytes(&response, 0..response.rows.len()).unwrap()
    );
    assert!(memory.live_bytes() > 3 * 8192);
    assert_eq!(
        response.rows[0].body,
        serde_json::json!({"nested": {"text": "x".repeat(8192)}})
    );
    drop(response);
    query.select.push("/nested".into());
    let mut denied = query_memory();
    assert!(matches!(
        source
            .indexes
            .execute(&source, &query, &limits, &mut denied),
        Err(ReadFailure::Query(Error {
            code: ErrorCode::InvalidArgument,
            ..
        }))
    ));
    assert_eq!(source.calls.get(), 3);
}

#[test]
fn candidate_id_output_retains_only_its_admitted_vector_and_string_backing() {
    let source = LoanSource::new();
    let query = source.query();
    let limits = Limits {
        max_query_candidates: 100,
        ..Limits::default()
    };
    let mut memory = query_memory();
    let ids = source
        .indexes
        .indexed_candidate_ids(
            &source,
            &query,
            &limits,
            &QueryCancellation::default(),
            &mut memory,
        )
        .unwrap();
    let expected = ids
        .iter()
        .try_fold(
            allocation::vec_bytes::<String>(ids.len()).unwrap(),
            |bytes, id| allocation::add(bytes, allocation::string_clone_bytes(id)?),
        )
        .unwrap();
    assert_eq!(ids, ["d0", "d1", "d2"]);
    assert_eq!(memory.live_bytes(), expected);
    assert!(memory.peak_bytes() > expected + 128 * 100);
    assert_eq!(source.calls.get(), 0);
    drop(ids);
    memory.release(expected).unwrap();
    assert_eq!(memory.live_bytes(), 0);
}

#[test]
fn indexed_planning_requires_explicit_admission_before_candidate_allocation() {
    let source = LoanSource::new();
    let mut query = source.query();
    query.allow_scan = false;
    let limits = Limits::default();
    let mut memory = QueryMemory::new(LimitedWorkspace(0), 0).unwrap();
    assert!(matches!(
        source.indexes.indexed_candidate_ids(
            &source,
            &query,
            &limits,
            &QueryCancellation::default(),
            &mut memory,
        ),
        Err(ReadFailure::Query(Error {
            code: ErrorCode::ResourceExhausted,
            ..
        }))
    ));
    assert_eq!(source.calls.get(), 0);
    assert_eq!((memory.live_bytes(), memory.peak_bytes()), (0, 0));
}
impl CollectionRecords for LoanSource {
    type Failure = Marker;
    fn identity(&self) -> SourceIdentity<'_> {
        // A hostile fixture can change its selected owner; the canonical read
        // must keep the first identity even though both captures share indexes.
        SourceIdentity::new(
            self.owners[self.owner.get()].as_ref(),
            "tenant",
            "incarnation",
            "docs",
        )
    }
    fn definition(&self) -> &CollectionDefinition {
        &self.definition
    }
    fn visit_records(
        &self,
        mut lend: impl for<'a> FnMut(&'a str, Record<'a>) -> Result<()>,
    ) -> ReadResult<(), Self::Failure> {
        for (id, encoded) in &self.encoded {
            assert!(!self.active.replace(true));
            let _loan = Loan(&self.active);
            let document: Document = serde_json::from_str(encoded).unwrap();
            lend(id, Record::Live(&document))?;
        }
        Ok(())
    }
}
impl DocumentSource for LoanSource {
    fn indexes(&self) -> &QueryIndexes {
        &self.indexes
    }
    fn with_record<T>(
        &self,
        id: &str,
        expected_version: Option<u64>,
        cancellation: &QueryCancellation,
        lend: impl for<'a> FnOnce(Option<Record<'a>>) -> Result<T>,
    ) -> ReadResult<T, Marker> {
        cancellation.check()?;
        assert!(!self.active.replace(true), "simultaneous decoded loans");
        let _loan = Loan(&self.active);
        let call = self.calls.get() + 1;
        self.calls.set(call);
        self.expected.borrow_mut().push(expected_version);
        if call == self.fail_at {
            return Err(ReadFailure::Source(Marker(self.failure.clone())));
        }
        let mut document: Option<Document> = self
            .encoded
            .get(id)
            .map(|encoded| serde_json::from_str(encoded).unwrap());
        if self.missing_output {
            document = None;
        }
        if self.cancel_after_read {
            cancellation.cancel();
        }
        cancellation.check()?;
        self.callbacks.set(self.callbacks.get() + 1);
        let archive = ArchivedDocument {
            version: 7,
            archive_id: "archive".to_owned(),
            chunk_index: 0,
            document_sha256: "digest".to_owned(),
            document_bytes: 10,
            indexed_fields: BTreeMap::new(),
        };
        let record = if self.archived {
            Some(Record::Archived(&archive))
        } else {
            document.as_ref().map(Record::Live)
        };
        // Deliberately omit the source's expected-version validation so the
        // query-side defensive validation is independently exercised.
        let result = lend(record)?;
        if self.cancel_after_loan {
            cancellation.cancel();
        }
        if self.switch_after_first && call == 1 {
            self.owner.set(1);
        }
        cancellation.check()?;
        Ok(result)
    }
    fn header_after<T>(
        &self,
        after: Option<&str>,
        cancellation: &QueryCancellation,
        lend: impl for<'a> FnOnce(Option<Header<'a>>) -> Result<T>,
    ) -> ReadResult<T, Marker> {
        cancellation.check()?;
        let id = self
            .encoded
            .keys()
            .find(|id| after.is_none_or(|after| id.as_str() > after));
        let result = lend(id.map(|id| Header {
            id,
            version: 7,
            kind: if self.archived {
                RecordKind::Archived
            } else {
                RecordKind::Live
            },
        }))?;
        cancellation.check()?;
        Ok(result)
    }
}

#[test]
fn lending_scan_sort_select_and_aggregate_read_each_document_once() {
    let source = LoanSource::new();
    let query: QueryRequest = serde_json::from_value(serde_json::json!({
        "collection":"docs","allow_scan":true,"limit":1,
        "filter":{"/group":"g"}, "sort":["/order"], "select":["/n"]
    }))
    .unwrap();
    let (response, remaining) = source
        .indexes
        .execute_page(
            &source,
            &query,
            &Limits::default(),
            crate::PageBound {
                rows: 1,
                bytes: usize::MAX,
            },
            &QueryCancellation::default(),
            &mut query_memory(),
            |remaining, _| {
                Ok((
                    remaining.map(|(id, _)| id.to_owned()).collect::<Vec<_>>(),
                    0,
                ))
            },
        )
        .unwrap();
    assert_eq!(
        response
            .rows
            .iter()
            .map(|row| row.id.as_str())
            .collect::<Vec<_>>(),
        vec!["d2"]
    );
    assert_eq!(remaining, ["d1", "d0"]);
    assert_eq!(response.rows[0].body, serde_json::json!({"n":2}));
    assert!(response.aggregates.is_empty());
    // The scanned filter reads each document, ordering reads each one's sort
    // key, and only the page's row is read again to copy it.
    assert_eq!(source.calls.get(), 7);
    assert!(source.expected.borrow().iter().all(Option::is_none));
    let totals: QueryRequest = serde_json::from_value(serde_json::json!({
        "collection":"docs","allow_scan":true,
        "filter":{"/group":"g"}, "aggregate":{"total":{"sum":"/n"},"n":{"count":"*"}}
    }))
    .unwrap();
    let response = source
        .indexes
        .execute(&source, &totals, &Limits::default(), &mut query_memory())
        .unwrap();
    assert!(response.rows.is_empty());
    assert_eq!(
        response.aggregates,
        vec![serde_json::json!({"group":{},"values":{"n":3,"total":3}})]
    );
    assert!(!source.active.get());
}

#[test]
fn lending_source_error_retains_the_original_owner() {
    let mut source = LoanSource::new();
    source.fail_at = 2;
    let error = source
        .indexes
        .execute(
            &source,
            &source.query(),
            &Limits::default(),
            &mut query_memory(),
        )
        .unwrap_err();
    let ReadFailure::Source(Marker(original)) = error else {
        panic!("source error was flattened")
    };
    assert!(Arc::ptr_eq(&original, &source.failure));
    assert_eq!(source.calls.get(), 2);
    assert!(!source.active.get());
}

#[test]
fn cancellation_after_source_read_prevents_lending_or_next_read() {
    let mut source = LoanSource::new();
    source.cancel_after_read = true;
    let error = source
        .indexes
        .execute(
            &source,
            &source.query(),
            &Limits::default(),
            &mut query_memory(),
        )
        .unwrap_err();
    assert!(
        matches!(error, ReadFailure::Query(error) if error.code == ErrorCode::ResourceExhausted)
    );
    assert_eq!((source.calls.get(), source.callbacks.get()), (1, 0));
    assert!(!source.active.get());
}

#[test]
fn lending_rejects_unhydrated_archive() {
    let mut source = LoanSource::new();
    source.archived = true;
    let error = source
        .indexes
        .execute(
            &source,
            &source.query(),
            &Limits::default(),
            &mut query_memory(),
        )
        .unwrap_err();
    assert!(matches!(error, ReadFailure::Query(error) if error.code == ErrorCode::Unavailable));
    assert!(!source.active.get());
}

#[test]
fn expected_version_is_checked_before_archived_hydration_dispatch() {
    let mut source = LoanSource::new();
    source.archived = true;
    let cancellation = QueryCancellation::default();
    let wrong = document_source::with_live(&source, "d0", Some(8), &cancellation, |_| Ok(()));
    assert!(matches!(wrong, Err(ReadFailure::Query(error)) if error.code == ErrorCode::Corruption));
    let current = document_source::with_live(&source, "d0", Some(7), &cancellation, |_| Ok(()));
    assert!(
        matches!(current, Err(ReadFailure::Query(error)) if error.code == ErrorCode::Unavailable)
    );
}

#[test]
fn lending_rejects_foreign_indexes_before_read_and_owner_switches_across_loans() {
    let one = LoanSource::new();
    let mut two = LoanSource::new();
    let error = one
        .indexes
        .execute(&two, &two.query(), &Limits::default(), &mut query_memory())
        .unwrap_err();
    assert!(matches!(error, ReadFailure::Query(error) if error.code == ErrorCode::Corruption));
    assert_eq!(two.calls.get(), 0);
    two.switch_after_first = true;
    let error = two
        .indexes
        .execute(&two, &two.query(), &Limits::default(), &mut query_memory())
        .unwrap_err();
    assert!(matches!(error, ReadFailure::Query(error) if error.code == ErrorCode::Corruption));
    assert_eq!(two.calls.get(), 1);
}

#[test]
fn borrowed_projection_wire_accounting_matches_owned_rows_before_clone() {
    let document = Document {
        id: "x".to_owned(),
        version: 1,
        body: serde_json::json!({"a":{"b":[null,"escaped\n"]},"none":null}),
    };
    for select in [
        None,
        Some(
            crate::select::Selection::new(
                &["/a/b".to_owned(), "/none".to_owned(), "/absent".to_owned()],
                "select",
            )
            .unwrap(),
        ),
    ] {
        let row = BorrowedRow {
            document: &document,
            selection: select.as_ref(),
            score: Some(0.25),
        };
        let encoded = serde_json::to_vec(&row).unwrap();
        let mut exact = ResultBudget::new(encoded.len());
        exact.account(&row).unwrap();
        assert!(ResultBudget::new(encoded.len() - 1).account(&row).is_err());
        let owned = row.into_owned();
        assert_eq!(encoded.len(), serde_json::to_vec(&owned).unwrap().len());
        assert_eq!(
            serde_json::from_slice::<Value>(&encoded).unwrap(),
            serde_json::to_value(owned).unwrap()
        );
    }
}

#[test]
fn canceled_completed_loan_and_missing_selected_document_discard_partial_results() {
    let mut source = LoanSource::new();
    source.cancel_after_loan = true;
    assert!(
        matches!(source.indexes.execute(&source, &source.query(), &Limits::default(), &mut query_memory()),
        Err(ReadFailure::Query(error)) if error.code == ErrorCode::ResourceExhausted)
    );
    assert_eq!((source.calls.get(), source.callbacks.get()), (1, 1));
    let mut source = LoanSource::new();
    source.missing_output = true;
    assert!(
        matches!(source.indexes.execute(&source, &source.query(), &Limits::default(), &mut query_memory()),
        Err(ReadFailure::Query(error)) if error.code == ErrorCode::Corruption)
    );
    assert_eq!(source.calls.get(), 1);
}

#[test]
fn fixture_headers_are_exclusive_and_deduplicate_verified_hydration() {
    use crate::source_test_utils::ResidentSource;
    let fixture = LoanSource::new();
    let archived = Arc::new(ArchivedDocument {
        version: 7,
        archive_id: "archive".to_owned(),
        chunk_index: 0,
        document_sha256: "digest".to_owned(),
        document_bytes: 10,
        indexed_fields: BTreeMap::new(),
    });
    let collection = CollectionState {
        definition: fixture.definition.clone(),
        data_epoch: 7,
        archived_document_bytes: 0,
        documents: [(
            "b".to_owned(),
            Arc::new(Document {
                id: "b".to_owned(),
                version: 7,
                body: serde_json::json!({}),
            }),
        )]
        .into_iter()
        .collect(),
        archived_documents: [
            ("a".to_owned(), archived.clone()),
            ("b".to_owned(), archived.clone()),
            ("c".to_owned(), archived),
        ]
        .into_iter()
        .collect(),
    };
    let source = ResidentSource {
        collection: &collection,
        indexes: &fixture.indexes,
    };
    let cancellation = QueryCancellation::default();
    let mut after = None;
    let mut headers = vec![];
    loop {
        let next = source
            .header_after(after.as_deref(), &cancellation, |header| {
                Ok(header.map(|header| (header.id.to_owned(), header.version, header.kind)))
            })
            .unwrap();
        let Some((id, version, kind)) = next else {
            break;
        };
        assert!(after.as_ref().is_none_or(|after| after < &id));
        after = Some(id.clone());
        headers.push((id, version, kind));
    }
    assert_eq!(
        headers,
        vec![
            ("a".to_owned(), 7, RecordKind::Archived),
            ("b".to_owned(), 7, RecordKind::Live),
            ("c".to_owned(), 7, RecordKind::Archived)
        ]
    );
}

#[test]
fn source_identity_includes_owner_type_and_all_scope_fields() {
    let first = 1u64;
    let second = 1u64;
    let identity = SourceIdentity::new(&first, "tenant", "incarnation", "docs");
    assert_eq!(
        identity,
        SourceIdentity::new(&first, "tenant", "incarnation", "docs")
    );
    assert_ne!(
        identity,
        SourceIdentity::new(&second, "tenant", "incarnation", "docs")
    );
    assert_ne!(
        identity,
        SourceIdentity::new(&first, "other", "incarnation", "docs")
    );
    assert_ne!(
        identity,
        SourceIdentity::new(&first, "tenant", "other", "docs")
    );
    assert_ne!(
        identity,
        SourceIdentity::new(&first, "tenant", "incarnation", "other")
    );
}
