use super::*;
use crate::admission::AdmissionConfig;
use crate::test_utils::{SnapshotFixture, decode_snapshot_candidate, encode_snapshot_candidate};
use serde_json::json;
use std::collections::BTreeSet;

fn restored_source() -> (TenantEngine, crate::codec_fixture::ScratchScope) {
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
                        body: json!({"at":id}),
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

fn request() -> OrderedSeekRequest {
    OrderedSeekRequest {
        collection: "rows".into(),
        index: "at".into(),
        prefix: vec![],
        lower: None,
        upper: None,
        direction: Direction::Asc,
        limit: 1,
        continuation: None,
    }
}

// Invoke the actual worker with its retained Generation, installed admission
// reservation, semaphore permit and work registration. No fake query response
// or extracted predicate can bypass source/continuation validation.
fn run(
    generation: Arc<crate::Generation>,
    request: OrderedSeekRequest,
    admission: &Arc<NodeAdmission>,
) -> Result<OrderedSeekResponse> {
    let cancellation = QueryCancellation::default();
    let fence = Arc::new(WorkFence::default());
    let registration = Arc::new(fence.begin(cancellation.clone())?);
    let reservation = admission.reserve(workspace(&generation.state.limits, &request), None)?;
    let permit = Arc::new(tokio::sync::Semaphore::new(1))
        .try_acquire_owned()
        .unwrap();
    OrderedSeekWork {
        generation,
        request,
        cancellation,
        _permit: permit,
        reservation,
        registration,
    }
    .run()
    .response
}

#[test]
fn ordered_seek_worker_accepts_restored_zero_rows_and_keeps_original_revision_bound() {
    let (engine, _scratch) = restored_source();
    let generation = engine.generation().unwrap();
    let admission =
        NodeAdmission::with_fixed_memory(AdmissionConfig::default(), 2 << 30, 0).unwrap();
    let baseline = admission.snapshot().reserved_bytes;
    let first = run(generation.clone(), request(), &admission).unwrap();
    assert_eq!(first.revision, 2);
    assert_eq!(first.rows.len(), 1);
    assert_eq!((&*first.rows[0].id, first.rows[0].version), ("a", 0));
    assert_eq!(first.index_entries_visited, 2);
    let cursor = first.continuation.unwrap();
    let second = run(
        generation.clone(),
        OrderedSeekRequest {
            continuation: Some(cursor.clone()),
            ..request()
        },
        &admission,
    )
    .unwrap();
    assert_eq!((&*second.rows[0].id, second.rows[0].version), ("b", 0));
    assert_eq!(second.revision, first.revision);
    assert_eq!(second.index_entries_visited, 2);

    let last_cursor = second.continuation.unwrap();
    let final_page = run(
        generation.clone(),
        OrderedSeekRequest {
            continuation: Some(last_cursor.clone()),
            ..request()
        },
        &admission,
    )
    .unwrap();
    assert_eq!(
        (&*final_page.rows[0].id, final_page.rows[0].version),
        ("c", 2)
    );
    assert!(final_page.continuation.is_none());

    // A valid document at version two still cannot cross an original revision
    // of one. Cursor revision zero is a separate invalid control value.
    for (mut cursor, revision) in [(last_cursor, 1), (cursor, 0)] {
        cursor.revision = revision;
        assert_eq!(
            run(
                generation.clone(),
                OrderedSeekRequest {
                    continuation: Some(cursor),
                    ..request()
                },
                &admission,
            )
            .unwrap_err()
            .code,
            ErrorCode::Conflict
        );
    }
    assert_eq!(admission.snapshot().reserved_bytes, baseline);
}
