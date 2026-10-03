use super::*;
use crate::codec_fixture::ScratchScope;
use kasumi_types::{
    Action, CollectionDefinition, CollectionRetentionClass, CollectionState, CollectionWriteMode,
    Document, Grant, Limits, Policy, TenantState,
};
use serde_json::json;
use std::sync::Arc;

fn scratch() -> ScratchScope {
    ScratchScope::new(kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 64)).unwrap()
}

fn table(scope: &ScratchScope) -> EncryptedTable {
    EncryptedTable::new(&scope.disk, 64 << 20, scope.disk.native_cache_config()).unwrap()
}

#[test]
fn pending_index_commits_full_prefix_and_final_tail_at_bounded_boundaries() {
    let scope = scratch();
    let index = table(&scope);
    let mut pending = PendingIndex::new(&index);
    for id in 0u64..16 {
        pending
            .insert(&id.to_be_bytes(), &[id as u8], &mut || Ok(()))
            .unwrap();
    }
    // The full batch stays private until more room or an explicit flush is
    // required. A point reader cannot observe any transaction-local prefix.
    for id in 0u64..16 {
        assert!(index.get(&id.to_be_bytes()).unwrap().is_none());
    }
    pending
        .insert(&16u64.to_be_bytes(), &[16], &mut || Ok(()))
        .unwrap();
    for id in 0u64..16 {
        assert_eq!(index.get(&id.to_be_bytes()).unwrap(), Some(vec![id as u8]));
    }
    assert!(index.get(&16u64.to_be_bytes()).unwrap().is_none());
    pending.flush(&mut || Ok(())).unwrap();
    assert_eq!(index.get(&16u64.to_be_bytes()).unwrap(), Some(vec![16]));
    // Finishing an already empty tail is harmless and retains every row.
    pending.flush(&mut || Ok(())).unwrap();
    let mut rows = 0;
    index
        .visit(|_, _| {
            rows += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(rows, 17);
}

#[derive(Debug)]
struct CheckDenied(Arc<()>);
impl std::fmt::Display for CheckDenied {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("original snapshot check denial")
    }
}
impl std::error::Error for CheckDenied {}

#[test]
fn denied_flush_and_duplicate_insert_drop_abort_only_the_pending_batch() {
    let scope = scratch();
    let index = table(&scope);
    index.insert(b"retained", b"committed").unwrap();
    let failure = Arc::new(());
    {
        let mut pending = PendingIndex::new(&index);
        pending.insert(b"first", b"one", &mut || Ok(())).unwrap();
        pending.insert(b"second", b"two", &mut || Ok(())).unwrap();
        let error = pending
            .flush(&mut || Err(CheckDenied(failure.clone()).into()))
            .unwrap_err();
        assert!(Arc::ptr_eq(
            &error.downcast_ref::<CheckDenied>().unwrap().0,
            &failure
        ));
        assert!(index.get(b"first").unwrap().is_none());
        assert!(index.get(b"second").unwrap().is_none());
    }
    assert!(index.get(b"first").unwrap().is_none());
    assert!(index.get(b"second").unwrap().is_none());
    assert_eq!(index.get(b"retained").unwrap(), Some(b"committed".to_vec()));
    {
        let mut pending = PendingIndex::new(&index);
        pending
            .insert(b"unpublished", b"new", &mut || Ok(()))
            .unwrap();
        let error = pending
            .insert(b"retained", b"replacement", &mut || Ok(()))
            .unwrap_err();
        assert!(error.to_string().contains("duplicate staged key"));
    }
    assert!(index.get(b"unpublished").unwrap().is_none());
    assert_eq!(index.get(b"retained").unwrap(), Some(b"committed".to_vec()));
    // Both failures leave a healthy table able to admit an exact retry.
    let mut retry = PendingIndex::new(&index);
    retry
        .insert(b"unpublished", b"accepted", &mut || Ok(()))
        .unwrap();
    retry.flush(&mut || Ok(())).unwrap();
    assert_eq!(
        index.get(b"unpublished").unwrap(),
        Some(b"accepted".to_vec())
    );
}

fn header() -> TenantState {
    crate::TenantEngine::new(
        "tenant".into(),
        "incarnation".into(),
        Policy {
            grants: vec![Grant {
                principal: "owner".into(),
                collection: None,
                actions: [Action::Admin].into_iter().collect(),
            }],
            strict_read_audit: false,
        },
        Limits::default(),
    )
    .unwrap()
    .generation()
    .unwrap()
    .state
    .clone()
}

fn collection(name: &str) -> Record {
    Record::Collection(
        name.into(),
        CollectionState {
            definition: CollectionDefinition {
                name: name.into(),
                schema: json!({"type":"object"}),
                indexes: vec![],
                strict_read_audit: false,
                retention_class: CollectionRetentionClass::Operational,
                write_mode: CollectionWriteMode::Mutable,
            },
            documents: Default::default(),
            archived_documents: Default::default(),
            archived_document_bytes: 0,
            data_epoch: 1,
        },
    )
}

fn document(collection: &str, id: usize) -> Record {
    Record::Document(
        collection.into(),
        Arc::new(Document {
            id: format!("row-{id:02}"),
            version: 1,
            body: json!({"collection": collection, "row": id}),
        }),
    )
}

fn image(scope: &ScratchScope, records: Vec<Record>) -> SnapshotImage {
    SnapshotImage::capture(&scope.disk, 8 << 20, |writer| {
        let mut encoder = crate::snapshot_codec::Encoder::new(writer)?;
        encoder.record(Record::Header(Box::new(header())))?;
        for record in records {
            encoder.record(record)?;
        }
        encoder.finish()
    })
    .unwrap()
}

#[test]
fn staged_index_flushes_parent_kinds_and_retains_group_cursors_across_batches() {
    let scope = scratch();
    let mut records = vec![collection("alpha"), collection("beta")];
    records.extend((0..17).map(|id| document("alpha", id)));
    records.extend((0..2).map(|id| document("beta", id)));
    let staged = StagedSnapshot::new(image(&scope, records), 64 << 20, || Ok(())).unwrap();
    assert_eq!(staged.count(2).unwrap(), 2);
    assert_eq!(staged.count(3).unwrap(), 19);
    for (name, count) in [("alpha", 17), ("beta", 2)] {
        assert!(
            matches!(staged.get(2, name, "").unwrap(), Some(Record::Collection(found, _)) if found == name)
        );
        let ids = staged
            .cursor(3, Some(name))
            .unwrap()
            .map(|record| match record.unwrap() {
                Record::Document(found, document) => {
                    assert_eq!(found, name);
                    document.id.clone()
                }
                _ => panic!("document group returned another record kind"),
            })
            .collect::<Vec<_>>();
        assert_eq!(
            ids,
            (0..count)
                .map(|id| format!("row-{id:02}"))
                .collect::<Vec<_>>()
        );
        let last = format!("row-{:02}", count - 1);
        assert!(
            matches!(staged.get(3, name, &last).unwrap(), Some(Record::Document(found, document)) if found == name && document.id == last)
        );
    }
    assert!(staged.cursor(3, Some("missing")).unwrap().next().is_none());
    assert_eq!(
        staged
            .cursor(3, None)
            .unwrap()
            .collect::<Result<Vec<_>>>()
            .unwrap()
            .len(),
        19
    );
    drop(staged);

    // Flushing earlier kinds must make real parents visible, without allowing
    // an unrelated committed parent to satisfy a missing collection reference.
    let missing = image(&scope, vec![collection("alpha"), document("ghost", 0)]);
    let error = StagedSnapshot::new(missing, 64 << 20, || Ok(()))
        .err()
        .expect("missing collection parent must be rejected");
    assert!(
        error
            .to_string()
            .contains("snapshot structural parent missing")
    );
}

#[test]
fn thirty_two_empty_collections_build_a_complete_structural_index_and_drain() {
    empty_collections_build_a_complete_structural_index_and_drain(32);
}

#[test]
fn two_hundred_fifty_six_collections_build_a_multileaf_structural_index_and_drain() {
    // The point and group keys exceed one native directory leaf. Interleaved
    // staging becomes sorted runs spanning multiple leaves on publication.
    empty_collections_build_a_complete_structural_index_and_drain(256);
}

fn empty_collections_build_a_complete_structural_index_and_drain(collections: usize) {
    use std::time::Instant;

    let trace = std::env::var("KASUMI_TEST_RESTORE_TRACE").is_ok_and(|value| value == "1");
    let scope = scratch();
    let baseline = scope.disk.snapshot();
    let mut names: Vec<_> = (0..collections)
        .map(|id| format!("financial_{id}"))
        .collect();
    names.sort();

    let started = Instant::now();
    let image = image(&scope, names.iter().map(|name| collection(name)).collect());
    let capture_elapsed = started.elapsed();
    let captured = scope.disk.snapshot();
    assert_eq!(captured.live_files, baseline.live_files + 1);
    assert!(captured.charged_bytes > baseline.charged_bytes);

    let started = Instant::now();
    let staged = StagedSnapshot::new(image, 64 << 20, || Ok(())).unwrap();
    let index_elapsed = started.elapsed();

    let started = Instant::now();
    // Every collection and the header have their own primary group, so the
    // index has twice as many rows as the canonical image has records.
    assert_eq!(staged.summary().records, collections as u64 + 1);
    assert_eq!(staged.summary().bytes, staged.image().len());
    for kind in 0..crate::snapshot_codec::RECORD_KINDS {
        assert_eq!(
            staged.count(kind).unwrap(),
            match kind {
                0 => 1,
                2 => collections as u64,
                _ => 0,
            },
        );
    }
    assert!(matches!(
        staged.get(0, "", "").unwrap(),
        Some(Record::Header(_))
    ));
    for name in &names {
        let Some(Record::Collection(found, state)) = staged.get(2, name, "").unwrap() else {
            panic!("indexed collection missing");
        };
        assert_eq!(&found, name);
        assert_eq!(&state.definition.name, name);
        assert!(state.documents.is_empty() && state.archived_documents.is_empty());
        let mut group = staged.cursor(2, Some(name)).unwrap();
        assert!(matches!(
            group.next().unwrap().unwrap(),
            Record::Collection(found, _) if &found == name
        ));
        assert!(group.next().is_none());
    }
    let found = staged
        .cursor(2, None)
        .unwrap()
        .map(|record| match record.unwrap() {
            Record::Collection(name, _) => name,
            _ => panic!("collection span returned another record kind"),
        })
        .collect::<Vec<_>>();
    assert_eq!(found, names);
    assert!(staged.get(2, "missing", "").unwrap().is_none());
    assert!(staged.cursor(2, Some("missing")).unwrap().next().is_none());
    assert!(staged.cursor(3, None).unwrap().next().is_none());
    let indexed = scope.disk.snapshot();
    assert!(indexed.live_files > captured.live_files);
    assert!(indexed.charged_bytes > captured.charged_bytes);
    let verify_elapsed = started.elapsed();

    let started = Instant::now();
    drop(staged);
    let drained = scope.disk.snapshot();
    assert_eq!(drained.live_files, baseline.live_files);
    assert_eq!(drained.charged_bytes, baseline.charged_bytes);
    assert_eq!(
        drained.filesystem_pending_bytes,
        baseline.filesystem_pending_bytes
    );
    let teardown_elapsed = started.elapsed();
    if trace {
        eprintln!(
            "restore_structural_index_{collections} capture_ms={} index_ms={} verify_ms={} teardown_ms={}",
            capture_elapsed.as_millis(),
            index_elapsed.as_millis(),
            verify_elapsed.as_millis(),
            teardown_elapsed.as_millis(),
        );
    }
}

#[test]
fn schema_activation_backup_shape_builds_a_complete_structural_index_and_drain() {
    use kasumi_types::{
        AuditEvent, Command, Operation, RequestAuthorization, RequestContext, SchemaChange,
        SchemaChangeSet,
    };
    use std::{collections::BTreeSet, time::Instant};

    let trace = std::env::var("KASUMI_TEST_RESTORE_TRACE").is_ok_and(|value| value == "1");
    let memory = kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 64);
    let scope = ScratchScope::new(memory.clone()).unwrap();
    let baseline = scope.disk.snapshot();
    let memory_baseline = memory.snapshot();
    let context = RequestContext {
        authorization: RequestAuthorization::service_identity(),
        tenant: "schema".into(),
        principal: "owner".into(),
        scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin]),
        request_id: "schema-test".into(),
    };
    let started = Instant::now();
    let engine = crate::TenantEngine::new(
        context.tenant.clone(),
        uuid::Uuid::from_u128(84).to_string(),
        Policy {
            grants: vec![Grant {
                principal: context.principal.clone(),
                collection: None,
                actions: context.scopes.clone(),
            }],
            strict_read_audit: false,
        },
        Limits::default(),
    )
    .unwrap();
    let install = SchemaChangeSet {
        activation_id: "financial-install".into(),
        expected_incarnation: engine.generation().unwrap().state.incarnation.clone(),
        expected_schema_epoch: 0,
        read_set: vec![],
        changes: (0..32)
            .map(|id| SchemaChange::Create {
                definition: CollectionDefinition {
                    name: format!("financial_{id}"),
                    schema: json!({"type":"object"}),
                    indexes: vec![],
                    strict_read_audit: false,
                    retention_class: CollectionRetentionClass::Operational,
                    write_mode: CollectionWriteMode::Mutable,
                },
            })
            .collect(),
    };
    let names: BTreeSet<_> = (0..32).map(|id| format!("financial_{id}")).collect();
    let receipt = {
        // Schema reads/status always emit strict release audits, including the
        // initial named read of missing collections. Reproduce that command
        // matrix without the integration helper's full-snapshot checks.
        let apply = |operation| {
            let revision = engine.generation().unwrap().state.revision + 1;
            engine
                .apply_command(
                    &scope.disk,
                    revision,
                    Command {
                        context: context.clone(),
                        timestamp_ms: 1_700_000_000_000 + revision,
                        operation,
                    },
                )
                .unwrap()
                .unwrap()
        };
        let release = |action: &str, data_revision| {
            let generation = engine.generation().unwrap();
            assert_eq!(generation.state.revision, data_revision);
            let policy_epoch = generation.state.policy_epoch;
            drop(generation);
            for name in &names {
                engine
                    .authorize(&context, Some(name), Action::Admin)
                    .unwrap();
                engine
                    .authorize_release(&context, Some(name), Action::Admin, policy_epoch)
                    .unwrap();
            }
            for name in &names {
                let revision = engine.generation().unwrap().state.revision + 1;
                apply(Operation::Audit(AuditEvent {
                    event_id: uuid::Uuid::from_u128(10_000 + u128::from(revision)).to_string(),
                    principal: context.principal.clone(),
                    action: action.into(),
                    request_id: context.request_id.clone(),
                    timestamp_ms: 1_700_000_000_000 + revision,
                    data_revision: Some(data_revision),
                    outcome: "authorized_release".into(),
                    collection: Some(name.clone()),
                }));
                engine
                    .authorize_release(&context, Some(name), Action::Admin, policy_epoch)
                    .unwrap();
            }
        };
        assert!(engine.generation().unwrap().state.collections.is_empty());
        release("schema_read", 0);
        let receipt = apply(Operation::ActivateSchema(install.clone()));
        assert_eq!(receipt.revision, 33);
        assert_eq!(engine.generation().unwrap().state.collections.len(), 32);
        release("schema_read", 33); // Named collections after activation.
        release("schema_read", 65); // All collections.
        release("schema_activation_status", 97);
        apply(Operation::Suspend(true));
        assert_eq!(apply(Operation::ActivateSchema(install.clone())), receipt);
        receipt
    };
    let apply_elapsed = started.elapsed();
    let generation = engine.generation().unwrap();
    assert_eq!(generation.state.revision, 131);
    assert_eq!(generation.state.schema_epoch, 1);
    assert!(generation.state.suspended);
    assert_eq!(generation.state.schema_activations.len(), 1);
    assert_eq!(generation.state.audits.len(), 131);
    for (start, action, data_revision) in [
        (0, "schema_read", 0),
        (33, "schema_read", 33),
        (65, "schema_read", 65),
        (97, "schema_activation_status", 97),
    ] {
        for (offset, name) in names.iter().enumerate() {
            let event = &generation.state.audits[start + offset];
            assert_eq!(event.action, action);
            assert_eq!(event.collection.as_ref(), Some(name));
            assert_eq!(event.data_revision, Some(data_revision));
            assert_eq!(event.outcome, "authorized_release");
        }
    }
    for (offset, action) in [(32, "schema"), (129, "suspend"), (130, "schema")] {
        let event = &generation.state.audits[offset];
        assert_eq!(event.action, action);
        assert_eq!(event.collection, None);
        assert_eq!(event.data_revision, Some(offset as u64 + 1));
        assert_eq!(event.outcome, "committed");
    }
    let expected = generation.state.clone();
    let started = Instant::now();
    let image = SnapshotImage::capture(&scope.disk, 8 << 20, |writer| {
        crate::snapshot_codec::write(
            &generation.state,
            &generation.receipts,
            &generation.backup_bindings,
            &generation.terminals,
            &generation.target_resolutions,
            writer,
        )
    })
    .unwrap();
    let capture_elapsed = started.elapsed();
    drop(generation);
    drop(engine);
    let captured = scope.disk.snapshot();
    assert_eq!(captured.live_files, baseline.live_files + 1);

    let started = Instant::now();
    let staged = StagedSnapshot::new(image, 64 << 20, || Ok(())).unwrap();
    let index_elapsed = started.elapsed();
    let started = Instant::now();
    assert_eq!(staged.summary().records, 165);
    assert_eq!(staged.summary().bytes, staged.image().len());
    for kind in 0..crate::snapshot_codec::RECORD_KINDS {
        assert_eq!(
            staged.count(kind).unwrap(),
            match kind {
                0 | 12 => 1,
                2 => 32,
                14 => 131,
                _ => 0,
            },
        );
    }
    let Some(Record::Header(actual)) = staged.get(0, "", "").unwrap() else {
        panic!("schema backup header missing");
    };
    assert_eq!(
        serde_json::to_value(actual).unwrap(),
        serde_json::to_value(crate::snapshot_codec::metadata(&expected)).unwrap()
    );
    for (name, collection) in &expected.collections {
        let Some(Record::Collection(found, actual)) = staged.get(2, name, "").unwrap() else {
            panic!("activated collection missing");
        };
        assert_eq!(&found, name);
        assert_eq!(
            serde_json::to_value(actual).unwrap(),
            serde_json::to_value(collection).unwrap()
        );
    }
    let (key, activation) = expected.schema_activations.iter().next().unwrap();
    assert_eq!(activation.outcome.as_ref().unwrap(), &receipt);
    let Some(Record::Activation(found, actual)) = staged.get(12, key, "").unwrap() else {
        panic!("permanent activation point missing");
    };
    assert_eq!(&found, key);
    assert_eq!(
        serde_json::to_value(actual).unwrap(),
        serde_json::to_value(activation).unwrap()
    );
    let mut group = staged.cursor(12, Some(key)).unwrap();
    let Record::Activation(found, actual) = group.next().unwrap().unwrap() else {
        panic!("permanent activation group missing");
    };
    assert_eq!(&found, key);
    assert_eq!(
        serde_json::to_value(actual).unwrap(),
        serde_json::to_value(activation).unwrap()
    );
    assert!(group.next().is_none());
    drop(group);
    for (offset, event) in expected.audits.iter().enumerate() {
        let sequence = expected.audit_retention.pruned_before + offset as u64;
        let key = format!("{sequence:020}");
        let Some(Record::Audit(found, actual)) = staged.get(14, &key, "").unwrap() else {
            panic!("replicated audit point missing");
        };
        assert_eq!(found, sequence);
        assert_eq!(&actual, event);
        let mut group = staged.cursor(14, Some(&key)).unwrap();
        let Record::Audit(found, actual) = group.next().unwrap().unwrap() else {
            panic!("replicated audit group missing");
        };
        assert_eq!(found, sequence);
        assert_eq!(&actual, event);
        assert!(group.next().is_none());
    }
    let mut index_entries = 0;
    let mut index_key_bytes = 0;
    let mut index_value_bytes = 0;
    staged
        .index
        .visit(|key, value| {
            index_entries += 1;
            index_key_bytes += key.len();
            index_value_bytes += value.len();
            Ok(())
        })
        .unwrap();
    assert_eq!(index_entries, 330);
    let framed_bytes = staged.summary().bytes;
    let verify_elapsed = started.elapsed();

    let started = Instant::now();
    drop(staged);
    let drained = scope.disk.snapshot();
    assert_eq!(drained.live_files, baseline.live_files);
    assert_eq!(drained.charged_bytes, baseline.charged_bytes);
    assert_eq!(
        drained.filesystem_pending_bytes,
        baseline.filesystem_pending_bytes
    );
    let memory_drained = memory.snapshot();
    assert_eq!(memory_drained.used_bytes, memory_baseline.used_bytes);
    assert_eq!(
        memory_drained.live_reservations,
        memory_baseline.live_reservations
    );
    let teardown_elapsed = started.elapsed();
    if trace {
        eprintln!(
            "restore_schema_activation_structural_index records=165 framed_bytes={framed_bytes} index_entries={index_entries} index_key_bytes={index_key_bytes} index_value_bytes={index_value_bytes} apply_ms={} capture_ms={} index_ms={} verify_ms={} teardown_ms={}",
            apply_elapsed.as_millis(),
            capture_elapsed.as_millis(),
            index_elapsed.as_millis(),
            verify_elapsed.as_millis(),
            teardown_elapsed.as_millis(),
        );
    }
}
