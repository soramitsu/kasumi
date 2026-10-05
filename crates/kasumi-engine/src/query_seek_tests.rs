use super::super::*;
use crate::admission::AdmissionConfig;
use crate::test_utils::{SnapshotFixture, decode_snapshot_candidate, encode_snapshot_candidate};
use serde_json::json;
use std::collections::BTreeSet;

fn restored_source() -> (TenantEngine, crate::codec_fixture::ScratchScope) {
    restored_source_with_limit(Limits::default().max_result_bytes)
}

fn restored_source_with_limit(
    max_result_bytes: usize,
) -> (TenantEngine, crate::codec_fixture::ScratchScope) {
    restored_source_with_key_suffix(max_result_bytes, "")
}

fn restored_source_with_key_suffix(
    max_result_bytes: usize,
    key_suffix: &str,
) -> (TenantEngine, crate::codec_fixture::ScratchScope) {
    let scratch = crate::codec_fixture::ScratchScope::new(
        kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 64),
    )
    .unwrap();
    let context = RequestContext {
        authorization: RequestAuthorization::service_identity(),
        principal: "owner".into(),
        tenant: "tenant".into(),
        scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin]),
        request_id: "zero-seek".into(),
    };
    let engine = TenantEngine::new(
        "tenant".into(),
        "incarnation".into(),
        Policy {
            grants: vec![Grant {
                principal: "owner".into(),
                collection: None,
                actions: context.scopes.clone(),
            }],
            strict_read_audit: false,
        },
        Limits {
            max_result_bytes,
            max_snapshot_bytes: 2 << 20,
            ..Default::default()
        },
    )
    .unwrap();
    for (revision, operation) in [
        (
            1,
            Operation::CreateCollection(CollectionDefinition {
                name: "rows".into(),
                schema: json!({"type":"object"}),
                indexes: vec![IndexDefinition {
                    name: "at".into(),
                    fields: vec![IndexField {
                        path: "/at".into(),
                        kind: ScalarType::String,
                    }],
                    unique: true,
                    text: None,
                }],
                strict_read_audit: false,
                retention_class: CollectionRetentionClass::Operational,
                write_mode: CollectionWriteMode::Mutable,
            }),
        ),
        (
            2,
            Operation::Mutate(MutationBatch {
                idempotency_key: "seed".into(),
                read_set: vec![],
                operations: ["a", "b", "c"]
                    .into_iter()
                    .map(|id| Mutation::Put {
                        collection: "rows".into(),
                        id: id.into(),
                        body: json!({"at":format!("{id}{key_suffix}")}),
                        expected: Precondition::Absent,
                    })
                    .collect(),
            }),
        ),
    ] {
        engine
            .apply_command(
                &scratch.disk,
                revision,
                Command {
                    context: context.clone(),
                    timestamp_ms: revision,
                    operation,
                },
            )
            .unwrap()
            .unwrap();
    }
    let image = engine.fixture_snapshot(&scratch.disk).unwrap();
    let mut candidate = decode_snapshot_candidate(&image).unwrap();
    for id in ["a", "b"] {
        Arc::make_mut(
            candidate
                .collections
                .get_mut("rows")
                .unwrap()
                .documents
                .get_mut(id)
                .unwrap(),
        )
        .version = 0;
    }
    let image = encode_snapshot_candidate(&scratch.disk, &candidate, 2 << 20).unwrap();
    engine.fixture_restore(&image).unwrap();
    (engine, scratch)
}

fn request() -> QueryRequest {
    QueryRequest::new("rows")
        .sort_asc("/at")
        .limit(1)
        .paging(Paging::Seek)
}

// Invoke the actual worker with its retained Generation, admitted ledger,
// semaphore permit and work registration. No fake query response or extracted
// predicate can bypass source or continuation validation.
fn run(
    generation: Arc<crate::Generation>,
    request: QueryRequest,
    admission: &Arc<NodeAdmission>,
) -> Result<QueryResponse> {
    let cancellation = QueryCancellation::default();
    let fence = Arc::new(WorkFence::default());
    let registration = Arc::new(fence.begin(cancellation.clone())?);
    let workspace = query_workspace(&generation.state.limits, &request)?;
    let memory = QueryMemory::empty(admission.reserve(workspace, None)?);
    let permit = Arc::new(tokio::sync::Semaphore::new(1))
        .try_acquire_owned()
        .unwrap();
    QueryWork {
        generation,
        request,
        cancellation,
        _permit: permit,
        memory,
        registration,
    }
    .run()
    .response
    .map(|(page, pinned)| {
        assert!(pinned.rows.is_empty(), "seek pages pin nothing");
        page
    })
}

fn continue_from(page: &QueryResponse) -> QueryRequest {
    request().cursor(page.cursor.clone().unwrap())
}

#[test]
fn seek_worker_accepts_restored_zero_rows_and_keeps_original_revision_bound() {
    let (engine, _scratch) = restored_source();
    let generation = engine.generation().unwrap();
    let admission =
        NodeAdmission::with_fixed_memory(AdmissionConfig::default(), 2 << 30, 0).unwrap();
    let baseline = admission.snapshot().reserved_bytes;
    let first = run(generation.clone(), request(), &admission).unwrap();
    assert_eq!(first.revision, 2);
    assert_eq!(first.rows.len(), 1);
    assert_eq!((&*first.rows[0].id, first.rows[0].version), ("a", 0));
    let second = run(generation.clone(), continue_from(&first), &admission).unwrap();
    assert_eq!((&*second.rows[0].id, second.rows[0].version), ("b", 0));
    assert_eq!(second.revision, first.revision);
    let last = run(generation.clone(), continue_from(&second), &admission).unwrap();
    assert_eq!((&*last.rows[0].id, last.rows[0].version), ("c", 2));
    assert!(last.cursor.is_none());

    // A valid document at version two still cannot cross an original revision
    // of one. Revision zero is never a first page's revision.
    // Altering the revision also expires a page whose next row has version
    // zero: the revision is part of the continuation's source identity.
    for (page, revision) in [(&second, 1), (&first, 0), (&first, 1)] {
        let mut cursor = query_seek::SeekCursor::decode(page.cursor.as_deref().unwrap()).unwrap();
        cursor.revision = revision;
        assert_eq!(
            run(
                generation.clone(),
                request().cursor(cursor.encode().unwrap()),
                &admission,
            )
            .unwrap_err()
            .code,
            ErrorCode::CursorExpired
        );
    }
    // A cursor belongs to its query: another limit or order cannot resume it.
    assert_eq!(
        run(
            generation.clone(),
            continue_from(&first).limit(2),
            &admission
        )
        .unwrap_err()
        .code,
        ErrorCode::CursorExpired
    );
    assert_eq!(
        run(generation.clone(), request().cursor("not hex"), &admission)
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
    assert_eq!(admission.snapshot().reserved_bytes, baseline);
}

#[test]
fn seek_pages_budget_their_actual_cursor_envelope() {
    let (engine, _scratch) = restored_source_with_limit(350);
    let generation = engine.generation().unwrap();
    let admission =
        NodeAdmission::with_fixed_memory(AdmissionConfig::default(), 2 << 30, 0).unwrap();
    let baseline = admission.snapshot().reserved_bytes;
    let query = request().limit(2);
    let first = run(generation.clone(), query.clone(), &admission).unwrap();
    assert_eq!(
        first.rows.len(),
        1,
        "the full hex cursor must fit alongside the row"
    );
    assert!(serde_json::to_vec(&first).unwrap().len() <= 350);
    let second = run(generation, query.cursor(first.cursor.unwrap()), &admission).unwrap();
    assert_eq!(
        second
            .rows
            .iter()
            .map(|row| row.id.as_str())
            .collect::<Vec<_>>(),
        ["b", "c"]
    );
    assert!(second.cursor.is_none());
    assert!(serde_json::to_vec(&second).unwrap().len() <= 350);
    assert_eq!(admission.snapshot().reserved_bytes, baseline);

    let (engine, _scratch) = restored_source_with_limit(300);
    assert_eq!(
        run(engine.generation().unwrap(), request().limit(2), &admission)
            .unwrap_err()
            .code,
        ErrorCode::ResourceExhausted
    );
    assert_eq!(admission.snapshot().reserved_bytes, baseline);
}

#[test]
fn seek_terminal_projection_fits_even_when_its_intermediate_cursors_do_not() {
    let (engine, _scratch) = restored_source_with_key_suffix(350, &"x".repeat(2048));
    let generation = engine.generation().unwrap();
    let admission =
        NodeAdmission::with_fixed_memory(AdmissionConfig::default(), 2 << 30, 0).unwrap();
    let baseline = admission.snapshot().reserved_bytes;
    let query = request().select(["/not_indexed"]).limit(3);
    let page = run(generation.clone(), query.clone(), &admission).unwrap();
    assert_eq!(
        page.rows
            .iter()
            .map(|row| row.id.as_str())
            .collect::<Vec<_>>(),
        ["a", "b", "c"]
    );
    assert!(page.rows.iter().all(|row| row.body == json!({})));
    assert!(page.cursor.is_none());
    assert!(serde_json::to_vec(&page).unwrap().len() <= 350);
    assert_eq!(admission.snapshot().reserved_bytes, baseline);

    // Stopping before the final row still needs a token, and no nonempty
    // prefix can carry these large index keys under this byte limit.
    assert_eq!(
        run(generation, query.limit(2), &admission)
            .unwrap_err()
            .code,
        ErrorCode::ResourceExhausted
    );
    assert_eq!(admission.snapshot().reserved_bytes, baseline);
}
