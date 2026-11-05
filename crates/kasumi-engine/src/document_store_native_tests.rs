//! Real encrypted native rows and paired application/custody publication.
//! These tests exercise the production document store, not a replacement cache.
use super::completion_tests::{OrdinaryFixture, definition};
use super::*;
use crate::document_store::{BLOBS, BODIES, PreparedDocuments, SelectedDocuments};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use kasumi_store::WriteOp;
use kasumi_types::{Document, Mutation, MutationBatch, Operation, Precondition, WriteReceipt};

const TENANT: &str = "selected-sources";

struct PanickingAccessClock {
    armed: std::sync::atomic::AtomicBool,
    original: Arc<u8>,
}
impl kasumi_clock::LeaseClock for PanickingAccessClock {
    fn now(&self) -> std::time::Duration {
        if self.armed.swap(false, Ordering::SeqCst) {
            std::panic::panic_any(self.original.clone());
        }
        std::time::Duration::ZERO
    }
}

fn incarnation() -> String {
    uuid::Uuid::from_u128(73).to_string()
}

fn document(id: &str, version: u64, proof: String) -> Document {
    Document {
        id: id.into(),
        version,
        body: serde_json::json!({"actionId": id, "proof": proof}),
    }
}

fn proof() -> Vec<u8> {
    (0..70_013).map(|index| (index % 251) as u8).collect()
}

/// Actual Entry sink: the write slice bound by the expectation is exactly the
/// slice committed with the custody applied cursor before source selection.
fn publish(
    fixture: &Fixture,
    previous: Option<&kasumi_raft::AppliedEntryContext>,
    writes: &[WriteOp],
) -> Result<(kasumi_raft::AppliedEntryContext, SelectedApplication)> {
    publish_to(&fixture.roots, &fixture.stores, previous, writes)
}

fn publish_to(
    roots: &SourceRootsRef,
    stores: &TenantStorageSet,
    previous: Option<&kasumi_raft::AppliedEntryContext>,
    writes: &[WriteOp],
) -> Result<(kasumi_raft::AppliedEntryContext, SelectedApplication)> {
    let position = kasumi_raft::AppliedEntryContext {
        log_id: openraft::LogId::new(
            openraft::CommittedLeaderId::new(1, 1),
            previous.map_or(1, |position| position.log_id.index + 1),
        ),
        previous: previous.map(|position| position.log_id),
        membership: Default::default(),
        command_sha256: "0".repeat(64),
        retirement_seed: None,
    };
    let response = kasumi_raft::AppliedResponse::application(Vec::new());
    let expectation = roots.publication_expectation(&position, writes, &response)?;
    let mut preparer = roots.publication_preparation();
    let mut receipt = None;
    kasumi_raft::with_application_publisher_for_test(
        stores,
        &position,
        |publisher| -> Result<()> {
            receipt = Some(publisher.commit_with_selection(
                response,
                writes,
                &mut preparer,
                expectation.challenge()?,
            )?);
            Ok(())
        },
    )?;
    let selected = preparer
        .finish_publication(&expectation, receipt.context("publication receipt absent")?)?
        .capture(ApplicationBoundaryRef::Entry(&position), false)?;
    assert!(matches!(
        selected.cell.position.get().unwrap().applied(),
        Some(kasumi_raft::SelectedAppliedRef::Entry { log_id, .. }) if log_id == position.log_id
    ));
    Ok((position, selected))
}

#[tokio::test]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn document_store_native_control_catalog_uses_bound_document_sources()
-> crate::test_fixture_failure::FixtureResult<()> {
    let fixture = Fixture::new().await?;
    let tenant = crate::control::CONTROL_TENANT;
    let stores = TenantStorageSet::initialize_catalogs(
        fixture.node.clone(),
        tenant.into(),
        Arc::new(LocalKeyProvider::new([121; 32])),
        Arc::new(LocalKeyProvider::new([122; 32])),
        kasumi_store::StorageAccess::node_control(),
    )
    .await?;
    assert_eq!(
        stores.application().storage_access().purpose(),
        &kasumi_store::StoragePurpose::NodeControl
    );
    let engine = TenantEngine::new(tenant.into(), incarnation(), policy(), Limits::default())?;
    let image = engine.logical_snapshot(stores.application().scratch_disk())?;
    crate::bootstrap::persist_fixture_bootstrap(
        &stores,
        &image,
        1,
        &format!("{tenant}/{}", incarnation()),
    )?;
    let (roots, binding) = SourceRoots::new(
        stores.clone(),
        fixture.storage.admission.clone(),
        RaftLimits::default(),
    )?;
    let buffers = fixture.storage.admission.snapshot_buffer_owner()?;
    roots.bind_lifecycle(&buffers, binding)?;
    let bootstrap = roots
        .prepare()?
        .capture(ApplicationBoundaryRef::Bootstrap(&image), false)?;
    let input = document("current", 1, STANDARD.encode(proof()));
    let mut prepared = PreparedDocuments::new(&roots, &bootstrap, tenant, &incarnation())?;
    let descriptor = prepared.stage(&input)?;
    assert!(PreparedDocuments::new(&roots, &bootstrap, TENANT, &incarnation()).is_err());
    let (_, selected) = publish_to(&roots, &stores, None, prepared.writes())?;
    drop(prepared);
    assert!(
        SelectedDocuments::new(
            fixture.roots.clone(),
            selected.clone(),
            TENANT,
            &incarnation(),
        )
        .is_err()
    );
    let reader = SelectedDocuments::new(roots.clone(), selected.clone(), tenant, &incarnation())?;
    assert_eq!(descriptor.load(&reader)?.as_ref(), &input);
    drop(reader);
    drop(selected);
    drop(bootstrap);
    buffers.drain_startup().await?;
    std::future::poll_fn(|cx| roots.poll_drain(cx)).await?;
    stores.shutdown().await?;
    drop(roots);
    drop(stores);
    fixture.close().await
}

fn resolver(fixture: &Fixture, selected: &SelectedApplication) -> Result<SelectedDocuments> {
    SelectedDocuments::new(
        fixture.roots.clone(),
        selected.clone(),
        TENANT,
        &incarnation(),
    )
}

fn blob_count(writes: &[WriteOp]) -> usize {
    writes
        .iter()
        .filter(|write| matches!(write, WriteOp::Put { namespace, .. } if namespace == BLOBS))
        .count()
}

fn assert_canonical_descriptor(
    document: &Document,
    descriptor: &kasumi_types::StoredDocument,
) -> Result<()> {
    let canonical = serde_json::to_vec(&kasumi_types::CanonicalJsonValue(&document.body))?;
    let body_work = crate::snapshot_codec::inspect_external_json_work(&canonical, &mut || Ok(()))?;
    assert_eq!(
        descriptor,
        &kasumi_types::StoredDocument::from_document(
            document,
            descriptor.body_object,
            descriptor.body_object_bytes,
            body_work,
            descriptor.body_manifest_work,
        )?
    );
    Ok(())
}

#[tokio::test]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn document_store_native_capacity_refusal_does_not_poison_selected_source()
-> crate::test_fixture_failure::FixtureResult<()> {
    let fixture = Fixture::new().await?;
    let bootstrap = fixture
        .roots
        .prepare()?
        .capture(ApplicationBoundaryRef::Bootstrap(&fixture.image), false)?;
    let input = document("capacity-retry", 1, STANDARD.encode(proof()));
    let mut prepared = PreparedDocuments::new(&fixture.roots, &bootstrap, TENANT, &incarnation())?;
    let descriptor = prepared.stage(&input)?;
    let (_, selected) = publish(&fixture, None, prepared.writes())?;
    drop(prepared);
    let mut reader = selected.open_document_reader(&fixture.roots)?;
    // The outer operation was admitted before competing native traffic took
    // the remainder. Refusal here must not retire the generation's own view.
    let mut workspace =
        crate::admission::DocumentWorkspace::new(&fixture.storage.admission, 4 << 20)?;
    let admission = &fixture.storage.admission;
    let free = admission.policy().max_inflight_bytes.unwrap() - admission.snapshot().reserved_bytes;
    let mut held = vec![admission.reserve_resident(free)?];
    while let Ok(slot) = admission.reserve_resident(0) {
        held.push(slot);
    }
    let key =
        crate::document_store::Scope::new(TENANT, &incarnation())?.key(descriptor.body_object);
    let original = reader
        .with_record(
            &mut workspace,
            0,
            BODIES,
            &key,
            descriptor.body_object_bytes as usize,
            |wire| Ok(wire.context("native manifest absent")?.len()),
        )
        .expect_err("native read unexpectedly admitted after exhaustion");
    drop(held);
    drop(original);
    drop(reader);
    drop(workspace);
    assert_eq!(
        descriptor.load(&resolver(&fixture, &selected)?)?.as_ref(),
        &input
    );
    drop(selected);
    drop(bootstrap);
    fixture.close().await
}

#[tokio::test]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn document_store_native_access_panic_retains_original_without_poisoning_selected_source()
-> crate::test_fixture_failure::FixtureResult<()> {
    let fixture = Fixture::new().await?;
    let tenant = "document-access-panic";
    let clock = Arc::new(PanickingAccessClock {
        armed: std::sync::atomic::AtomicBool::new(false),
        original: Arc::new(73),
    });
    // The actual encrypted application key lease invokes this clock; this does
    // not substitute a resolver or bypass the selected native access boundary.
    let application = kasumi_store::TenantStore::initialize_catalog_fixture_with_clock(
        fixture.node.clone(),
        tenant.into(),
        Arc::new(LocalKeyProvider::new([123; 32])),
        clock.clone(),
    )
    .await?;
    let stores = kasumi_store::test_utils::initialize_custody_fixture(
        application,
        Arc::new(LocalKeyProvider::new([124; 32])),
    )
    .await?;
    let engine = TenantEngine::new(tenant.into(), incarnation(), policy(), Limits::default())?;
    let image = engine.logical_snapshot(stores.application().scratch_disk())?;
    crate::bootstrap::persist_fixture_bootstrap(
        &stores,
        &image,
        1,
        &format!("{tenant}/{}", incarnation()),
    )?;
    let (roots, binding) = SourceRoots::new(
        stores.clone(),
        fixture.storage.admission.clone(),
        RaftLimits::default(),
    )?;
    let buffers = fixture.storage.admission.snapshot_buffer_owner()?;
    roots.bind_lifecycle(&buffers, binding)?;
    let selected = roots
        .prepare()?
        .capture(ApplicationBoundaryRef::Bootstrap(&image), false)?;
    let committed =
        crate::admission::ApplyEscrow::admit(fixture.storage.admission.memory())?.enter();
    clock.armed.store(true, Ordering::SeqCst);
    let error = match selected.open_document_reader(&roots) {
        Ok(_) => panic!("key access panic unexpectedly succeeded"),
        Err(error) => error,
    };
    let panic = error
        .downcast_ref::<SourcePanic>()
        .context("original access panic lost")?;
    assert!(Arc::ptr_eq(
        panic
            ._payload
            .lock()
            .unwrap()
            .downcast_ref::<Arc<u8>>()
            .unwrap(),
        &clock.original,
    ));
    assert!(selected.cell.failure.get().is_none());
    selected.open_document_reader(&roots)?.close()?;
    drop(error);
    drop(committed);
    drop(selected);
    buffers.drain_startup().await?;
    std::future::poll_fn(|cx| roots.poll_drain(cx)).await?;
    stores.shutdown().await?;
    drop(roots);
    drop(stores);
    fixture.close().await
}

#[tokio::test]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn document_store_native_bootstrap_materialization_obeys_selected_source_seal()
-> crate::test_fixture_failure::FixtureResult<()> {
    let fixture = Fixture::new().await?;
    let selected = fixture.select()?;
    let input = document("bootstrap-sealed", 1, STANDARD.encode(proof()));
    let mut builder = crate::document_restore::Builder::new(
        fixture.image.disk(),
        128 << 20,
        TENANT,
        &incarnation(),
    )?;
    let descriptor = builder.push(&input)?;
    let staged = builder.finish()?;
    assert!(
        crate::document_restore::BootstrapDocuments::new(
            staged.clone(),
            fixture.roots.clone(),
            selected.clone(),
            TENANT,
            &uuid::Uuid::from_u128(74).to_string(),
        )
        .is_err()
    );
    let reader = crate::document_restore::BootstrapDocuments::new(
        staged.clone(),
        fixture.roots.clone(),
        selected.clone(),
        TENANT,
        &incarnation(),
    )?;
    assert_eq!(descriptor.load(&reader)?.as_ref(), &input);
    fixture.roots.seal_consumers();
    assert!(descriptor.load(&reader).is_err());
    // The bytes remain intact; the generation's access gate forbids lending.
    assert_eq!(descriptor.load(&staged)?.as_ref(), &input);
    drop(reader);
    drop(staged);
    drop(selected);
    fixture.close().await
}

#[tokio::test]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn document_store_native_joint_publication_deduplicates_hex_and_base64()
-> crate::test_fixture_failure::FixtureResult<()> {
    let fixture = Fixture::new().await?;
    let bootstrap = fixture.select()?;
    let mut input = document("old-action", 1, hex::encode(proof()));
    input.body["metadata"] = serde_json::json!({
        "quoted\"key": "雪\\\n\t",
        "nested": [null, true, -17, 1.25, {"empty": []}],
    });
    let mut first = PreparedDocuments::new(&fixture.roots, &bootstrap, TENANT, &incarnation())?;
    let old = first.stage(&input)?;
    assert_canonical_descriptor(&input, &old)?;
    assert_eq!(blob_count(first.writes()), 2);
    assert!(old.load(&resolver(&fixture, &bootstrap)?).is_err());
    let (position, selected) = publish(&fixture, None, first.writes())?;
    drop(first);
    assert_eq!(old.load(&resolver(&fixture, &selected)?)?.as_ref(), &input);
    // A previous selected root must not silently refresh to today's native head.
    assert!(old.load(&resolver(&fixture, &bootstrap)?).is_err());

    let second_input = document("new-action", 2, STANDARD.encode(proof()));
    let mut second = PreparedDocuments::new(&fixture.roots, &selected, TENANT, &incarnation())?;
    let new = second.stage(&second_input)?;
    assert_canonical_descriptor(&second_input, &new)?;
    assert_eq!(blob_count(second.writes()), 0);
    assert_eq!(second.writes().len(), 1);
    assert!(matches!(&second.writes()[0], WriteOp::Put { namespace, .. } if namespace == BODIES));
    let (_, updated) = publish(&fixture, Some(&position), second.writes())?;
    drop(second);
    assert_eq!(
        new.load(&resolver(&fixture, &updated)?)?.as_ref(),
        &second_input
    );
    assert_eq!(old.load(&resolver(&fixture, &updated)?)?.as_ref(), &input);
    assert_eq!(old.load(&resolver(&fixture, &selected)?)?.as_ref(), &input);
    assert!(new.load(&resolver(&fixture, &selected)?).is_err());
    drop(updated);
    drop(selected);
    drop(bootstrap);
    fixture.close().await
}

#[tokio::test]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn document_store_native_corrupt_or_missing_blob_never_refreshes_old_view()
-> crate::test_fixture_failure::FixtureResult<()> {
    for missing in [false, true] {
        let fixture = Fixture::new().await?;
        let bootstrap = fixture.select()?;
        let input = document("proof", 7, hex::encode(proof()));
        let mut prepared =
            PreparedDocuments::new(&fixture.roots, &bootstrap, TENANT, &incarnation())?;
        let descriptor = prepared.stage(&input)?;
        let (key, mut value) = prepared
            .writes()
            .iter()
            .find_map(|write| match write {
                WriteOp::Put {
                    namespace,
                    key,
                    value,
                } if namespace == BLOBS => Some((key.clone(), value.clone())),
                _ => None,
            })
            .context("proof chunk was not staged")?;
        let (position, original) = publish(&fixture, None, prepared.writes())?;
        drop(prepared);
        // Fault injection is confined to this synthetic encrypted installation.
        // The old immutable source remains valid after a later physical change.
        value[0] ^= 1;
        let invalid = if missing {
            WriteOp::delete(BLOBS, key)
        } else {
            WriteOp::put(BLOBS, key, value)
        };
        let (_, changed) = publish(&fixture, Some(&position), &[invalid])?;
        assert!(descriptor.load(&resolver(&fixture, &changed)?).is_err());
        assert_eq!(
            descriptor.load(&resolver(&fixture, &original)?)?.as_ref(),
            &input
        );
        drop(changed);
        drop(original);
        drop(bootstrap);
        fixture.close().await?;
    }
    Ok(())
}

#[tokio::test]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn document_store_native_decode_owner_retains_admission_until_last_clone()
-> crate::test_fixture_failure::FixtureResult<()> {
    let fixture = Fixture::new().await?;
    let bootstrap = fixture.select()?;
    let input = document("owner", 9, STANDARD.encode(proof()));
    let mut prepared = PreparedDocuments::new(&fixture.roots, &bootstrap, TENANT, &incarnation())?;
    let descriptor = prepared.stage(&input)?;
    let (_, selected) = publish(&fixture, None, prepared.writes())?;
    drop(prepared);
    drop(bootstrap);
    let reader = resolver(&fixture, &selected)?;
    let before = fixture.storage.admission.snapshot().reserved_bytes;
    let loaded = descriptor.load(&reader)?;
    assert_eq!(loaded.as_ref(), &input);
    let charged = fixture.storage.admission.snapshot().reserved_bytes;
    assert!(charged > before);
    let clone = loaded.clone();
    drop(loaded);
    assert_eq!(fixture.storage.admission.snapshot().reserved_bytes, charged);
    drop(clone);
    assert_eq!(fixture.storage.admission.snapshot().reserved_bytes, before);
    drop(reader);
    drop(selected);
    fixture.close().await
}

#[tokio::test]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn document_store_native_restore_stages_shared_objects_without_live_publication()
-> crate::test_fixture_failure::FixtureResult<()> {
    let fixture = Fixture::new().await?;
    let selected = fixture.select()?;
    let mut builder = crate::document_restore::Builder::new(
        fixture.image.disk(),
        128 << 20,
        TENANT,
        &incarnation(),
    )?;
    let first = document("restore-hex", 1, hex::encode(proof()));
    let second = document("restore-base64", 2, STANDARD.encode(proof()));
    let first_descriptor = builder.push(&first)?;
    let second_descriptor = builder.push(&second)?;
    let staged = builder.finish()?;
    assert_eq!(staged.object_counts()?, (2, 2));
    let before_decode = fixture.storage.admission.snapshot();
    let loaded = first_descriptor.load(&staged)?;
    assert_eq!(loaded.as_ref(), &first);
    let during_decode = fixture.storage.admission.snapshot();
    assert!(
        during_decode
            .resident_reserved_bytes_by_origin
            .document_source
            > before_decode
                .resident_reserved_bytes_by_origin
                .document_source
    );
    let retained = loaded.clone();
    drop(loaded);
    assert_eq!(
        fixture
            .storage
            .admission
            .snapshot()
            .resident_reserved_bytes_by_origin
            .document_source,
        during_decode
            .resident_reserved_bytes_by_origin
            .document_source,
    );
    drop(retained);
    assert_eq!(
        fixture
            .storage
            .admission
            .snapshot()
            .resident_reserved_bytes_by_origin
            .document_source,
        before_decode
            .resident_reserved_bytes_by_origin
            .document_source,
    );
    assert_eq!(second_descriptor.load(&staged)?.as_ref(), &second);
    assert!(
        first_descriptor
            .load(&resolver(&fixture, &selected)?)
            .is_err()
    );
    let mut live_objects = 0;
    fixture
        .stores
        .application()
        .visit(BLOBS, 32 << 20, |_, _| {
            live_objects += 1;
            Ok(())
        })?;
    assert_eq!(live_objects, 0);
    // Finishing scratch alone gives no serving authority or live namespace
    // write; only the coordinator installing the snapshot writes its objects.
    drop(staged);
    drop(selected);
    fixture.close().await
}

/// Every published document object row, by namespace and key.
type Published<T> = std::collections::BTreeMap<(&'static str, Vec<u8>), T>;
type PublishedObjects = Published<Vec<u8>>;

/// Read through a view, which takes key state per row: like reconciliation, a
/// long scan never holds off lease renewal.
fn published<T>(
    store: &Arc<kasumi_store::TenantStore>,
    value: impl Fn(&[u8]) -> T,
) -> Result<Published<T>> {
    let mut objects = Published::new();
    let view = store.read_view()?;
    for namespace in [BODIES, BLOBS] {
        view.visit(namespace, 32 << 20, |key, row| {
            objects.insert((namespace, key.to_vec()), value(row));
            Ok(())
        })?;
    }
    view.close()?;
    Ok(objects)
}

fn published_objects(store: &Arc<kasumi_store::TenantStore>) -> Result<PublishedObjects> {
    published(store, <[u8]>::to_vec)
}

#[tokio::test]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn document_store_native_reopen_reconciles_published_objects_in_bounded_batches()
-> crate::test_fixture_failure::FixtureResult<()> {
    let fixture = Fixture::new().await?;
    let mut builder = crate::document_restore::Builder::new(
        fixture.image.disk(),
        128 << 20,
        TENANT,
        &incarnation(),
    )?;
    let first = document("reopen-hex", 1, hex::encode(proof()));
    let second = document("reopen-base64", 2, STANDARD.encode(proof()));
    let first_descriptor = builder.push(&first)?;
    let second_descriptor = builder.push(&second)?;
    let staged = builder.finish()?;
    let store = fixture.stores.application();
    assert!(published_objects(store)?.is_empty());
    // Missing objects are written: the namespaces hold the snapshot's objects.
    staged.reconcile(store)?;
    let expected = published_objects(store)?;
    let (bodies, blobs) = staged.object_counts()?;
    assert_eq!(expected.len() as u64, bodies + blobs);

    // What a reopening replica finds: a damaged copy, a missing object, and
    // more than one batch of objects that only later documents name.
    let mut snapshot_keys = expected.keys();
    let (damaged_namespace, damaged) = snapshot_keys.next().unwrap().clone();
    let (missing_namespace, missing) = snapshot_keys.next().unwrap().clone();
    let scope = crate::document_store::Scope::new(TENANT, &incarnation())?;
    let mut writes = vec![
        WriteOp::put(damaged_namespace, damaged, b"damaged".to_vec()),
        WriteOp::delete(missing_namespace, missing),
    ];
    for ordinal in 0..9u8 {
        let later = vec![ordinal; 64];
        let namespace = if ordinal < 2 { BODIES } else { BLOBS };
        let digest = <sha2::Sha256 as sha2::Digest>::digest(&later).into();
        writes.push(WriteOp::put(namespace, scope.key(digest), later));
    }
    store.write_batch(&writes)?;
    assert_ne!(published_objects(store)?, expected);
    staged.reconcile(store)?;
    assert_eq!(published_objects(store)?, expected);

    // A selection captured afterwards serves both documents from those rows.
    let selected = fixture.select()?;
    let resolver = resolver(&fixture, &selected)?;
    assert_eq!(first_descriptor.load(&resolver)?.as_ref(), &first);
    assert_eq!(second_descriptor.load(&resolver)?.as_ref(), &second);
    staged.reconcile(store)?;
    assert_eq!(published_objects(store)?, expected);
    let files = fixture.image.disk().snapshot().live_files;
    let empty = crate::document_restore::StagedDocuments::empty(
        fixture.image.disk(),
        128 << 20,
        TENANT,
        &incarnation(),
    )?;
    assert_eq!(fixture.image.disk().snapshot().live_files, files);
    assert!(
        crate::document_restore::BootstrapDocuments::new(
            empty.clone(),
            fixture.roots.clone(),
            selected.clone(),
            TENANT,
            "different-incarnation",
        )
        .is_err(),
        "empty staging still binds its exact scope"
    );
    drop(resolver);
    drop(selected);
    // An empty install's preparation cannot delete the generation still
    // serving. Its later reconciliation must remove both old namespaces.
    empty.write_missing(store)?;
    assert_eq!(published_objects(store)?, expected);
    empty.reconcile(store)?;
    assert!(published_objects(store)?.is_empty());
    assert_eq!(fixture.image.disk().snapshot().live_files, files);
    drop(empty);
    drop(staged);
    fixture.close().await
}

/// 512 KiB of per-document text that is neither hex nor base64, so each
/// 48 KiB chunk is a distinct object.
fn reopen_text(ordinal: u64) -> String {
    let mut state = ordinal.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    (0..512 << 10)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            b"ghijklmnopqrstuvwxyz.,;:"[(state % 24) as usize] as char
        })
        .collect()
}

// Minutes of synchronous work: a worker keeps renewing the 60 s key lease, as
// beside the blocking restore in production.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn document_store_native_reopen_reconciles_more_objects_than_one_transaction_stages()
-> crate::test_fixture_failure::FixtureResult<()> {
    const DOCUMENTS: u64 = 200;
    let fixture = Fixture::new().await?;
    let mut builder = crate::document_restore::Builder::new(
        fixture.image.disk(),
        256 << 20,
        TENANT,
        &incarnation(),
    )?;
    let mut descriptors = Vec::new();
    for ordinal in 0..DOCUMENTS {
        let document = document(&format!("reopen-{ordinal:03}"), 1, reopen_text(ordinal));
        descriptors.push(builder.push(&document)?);
    }
    let staged = builder.finish()?;
    let store = fixture.stores.application();
    // One complete replacement stages every object at once and exceeds the
    // native transaction cap: the restart failure reconciliation replaces.
    let error = store
        .replace_namespaces(&staged.complete_snapshot_replacements(), &[])
        .expect_err("one transaction cannot stage every object");
    assert!(
        format!("{error:#}").contains("storage capacity denied"),
        "{error:#}"
    );
    // The refused writer retires with its failure custody.
    drop(error);
    assert!(published_objects(store)?.is_empty());

    staged.reconcile(store)?;
    let published = published_objects(store)?;
    let (bodies, blobs) = staged.object_counts()?;
    assert_eq!(published.len() as u64, bodies + blobs);
    assert!(published.values().map(Vec::len).sum::<usize>() > kasumi_kv::MAX_BATCH_BYTES);
    drop(published);
    let selected = fixture.select()?;
    let resolver = resolver(&fixture, &selected)?;
    for (ordinal, descriptor) in (0..DOCUMENTS).zip(&descriptors) {
        let loaded = descriptor.load(&resolver)?;
        assert_eq!(loaded.as_ref().id, format!("reopen-{ordinal:03}"));
        assert_eq!(loaded.as_ref().body["proof"], reopen_text(ordinal));
    }
    drop(resolver);
    drop(selected);
    drop(staged);
    fixture.close().await
}

/// Commit `operation` as the replica's next entry; it must succeed.
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
fn commit(
    replica: &OrdinaryFixture,
    operation: Operation,
) -> crate::test_fixture_failure::FixtureResult<()> {
    let response = replica.apply(&replica.input(operation)?, || {})?;
    serde_json::from_slice::<kasumi_types::Result<WriteReceipt>>(&response.data)??;
    Ok(())
}

/// The proof `generation` serves for document `id`.
fn served(generation: &crate::Generation, id: &str) -> Result<serde_json::Value> {
    Ok(crate::test_utils::fixture_document(generation, "docs", id)?.body["proof"].clone())
}

fn put(key: &str, id: &str, proof: String) -> Operation {
    put_all(key, [(id.to_owned(), proof)])
}

fn put_all(key: &str, documents: impl IntoIterator<Item = (String, String)>) -> Operation {
    Operation::Mutate(MutationBatch {
        idempotency_key: key.into(),
        read_set: vec![],
        operations: documents
            .into_iter()
            .map(|(id, proof)| Mutation::Put {
                collection: "docs".into(),
                id,
                body: serde_json::json!({"proof": proof}),
                expected: Precondition::Any,
            })
            .collect(),
    })
}

/// Default limits, except that the change feed keeps only its latest `events`.
fn feed_events(events: usize) -> Limits {
    Limits {
        history: kasumi_types::HistoryLimits {
            max_feed_events: events,
            ..Default::default()
        },
        ..Limits::default()
    }
}

/// The application snapshot a build on `leader` sends at its last entry.
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
fn leader_snapshot(
    leader: &OrdinaryFixture,
) -> crate::test_fixture_failure::FixtureResult<(
    kasumi_raft::SnapshotMeta<u64, kasumi_raft::BasicNode>,
    SnapshotImage,
)> {
    let generation = leader.engine.generation()?;
    let index = generation.state.revision - generation.state.revision_base;
    drop(generation);
    let captured = kasumi_raft::StateMachineBackend::capture_snapshot(leader.engine.as_ref())?;
    let mut spool = kasumi_store::EncryptedSpool::new(
        leader.fixture.stores.application().scratch_disk(),
        1 << 30,
    )?;
    captured.write(&mut spool)?;
    let meta = kasumi_raft::SnapshotMeta {
        last_log_id: Some(openraft::LogId::new(
            openraft::CommittedLeaderId::new(1, 1),
            index,
        )),
        last_membership: Default::default(),
        snapshot_id: uuid::Uuid::new_v4().to_string(),
    };
    Ok((meta, SnapshotImage::freeze(spool)?))
}

/// Install the leader's snapshot through the follower's actual state machine,
/// as openraft does once it has arrived.
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn install(
    follower: &OrdinaryFixture,
    meta: &kasumi_raft::SnapshotMeta<u64, kasumi_raft::BasicNode>,
    image: SnapshotImage,
) -> crate::test_fixture_failure::FixtureResult<()> {
    use openraft::storage::RaftStateMachine as _;
    let buffers = &follower.fixture._buffers;
    let mut machine = kasumi_raft::StateMachine::open(
        follower.fixture.stores.clone(),
        follower.engine.clone(),
        buffers.clone(),
    )
    .await?;
    let received = kasumi_raft::received_application_snapshot_for_test(
        meta,
        image,
        kasumi_raft::RaftLimits::default().max_snapshot_bytes,
        buffers,
    )?;
    machine
        .install_snapshot(meta, Box::new(received))
        .await
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    Ok(())
}

// Minutes of synchronous work, as beside the Reopen fixture above.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn document_store_native_install_publishes_more_objects_than_one_transaction_stages()
-> crate::test_fixture_failure::FixtureResult<()> {
    const DOCUMENTS: u64 = 200;
    // Documents per commit, within one 8 MiB mutation batch.
    const BATCH: usize = 14;
    let leader = OrdinaryFixture::new().await?;
    // The feed keeps one commit's events, so the snapshot carries most bodies
    // once; the same objects back the feed either way.
    commit(&leader, Operation::SetLimits(feed_events(BATCH)))?;
    commit(&leader, Operation::CreateCollection(definition()))?;
    let ordinals = (0..DOCUMENTS).collect::<Vec<_>>();
    for batch in ordinals.chunks(BATCH) {
        let key = format!("install-{}", batch[0]);
        let documents = batch
            .iter()
            .map(|ordinal| (format!("install-{ordinal:03}"), reopen_text(*ordinal)));
        commit(&leader, put_all(&key, documents))?;
    }
    let (meta, image) = leader_snapshot(&leader)?;
    // A new follower. Publishing every object in one transaction was refused,
    // so such a tenant could never gain or replace a replica.
    let follower = OrdinaryFixture::replica(&leader).await?;
    install(&follower, &meta, image).await?;
    let objects = published(follower.fixture.stores.application(), <[u8]>::len)?;
    assert!(objects.values().sum::<usize>() > kasumi_kv::MAX_BATCH_BYTES);
    let installed = follower.engine.generation()?;
    for ordinal in 0..DOCUMENTS {
        let id = format!("install-{ordinal:03}");
        assert_eq!(served(&installed, &id)?, reopen_text(ordinal));
    }
    drop(installed);
    follower.close().await?;
    leader.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn document_store_native_install_keeps_previous_generation_objects_until_it_retires()
-> crate::test_fixture_failure::FixtureResult<()> {
    let leader = OrdinaryFixture::new().await?;
    let follower = OrdinaryFixture::replica(&leader).await?;
    let (first, second, third) = (reopen_text(0), reopen_text(1), reopen_text(2));
    for operation in [
        // One retained feed event: a snapshot names only current versions.
        Operation::SetLimits(feed_events(1)),
        Operation::CreateCollection(definition()),
        put("first", "superseded", first.clone()),
    ] {
        commit(&leader, operation.clone())?;
        commit(&follower, operation)?;
    }
    // The follower falls behind while the leader replaces that version.
    commit(&leader, put("second", "superseded", second.clone()))?;
    commit(&leader, put("third", "added", third.clone()))?;
    let previous = follower.engine.generation()?;
    let previous_cell = previous
        .application_selection
        .get()
        .context("previous selection absent")?
        .cell
        .id;
    let store = follower.fixture.stores.application();
    let replaced = published(store, <[u8]>::len)?;
    let (meta, image) = leader_snapshot(&leader)?;
    install(&follower, &meta, image).await?;

    // The install leaves exactly the snapshot's objects: the leader's, less
    // the superseded version's, which only the previous generation names.
    let mut expected = published(leader.fixture.stores.application(), <[u8]>::len)?;
    expected.retain(|key, _| !replaced.contains_key(key));
    assert_eq!(published(store, <[u8]>::len)?, expected);
    let installed = follower.engine.generation()?;
    assert_eq!(served(&installed, "superseded")?, second);
    assert_eq!(served(&installed, "added")?, third);
    // A reader of the previous generation keeps the root it selected.
    assert_eq!(served(&previous, "superseded")?, first);

    // No selection captured the store before the sweep: an entry naming the
    // swept objects again writes them instead of finding them present.
    commit(&follower, put("fourth", "superseded", first.clone()))?;
    let reapplied = follower.engine.generation()?;
    assert_eq!(served(&reapplied, "superseded")?, first);
    let republished = published(store, <[u8]>::len)?;
    assert!(replaced.keys().all(|key| republished.contains_key(key)));
    assert_eq!(served(&previous, "superseded")?, first);
    // Until it retires: its last handle closes the selected root.
    let registered = |id| {
        follower
            .fixture
            .roots
            .gate
            .lock()
            .unwrap()
            .cells
            .contains_key(&id)
    };
    assert!(registered(previous_cell));
    drop(previous);
    assert!(!registered(previous_cell));
    drop(installed);
    drop(reapplied);
    follower.close().await?;
    leader.close().await
}

#[tokio::test]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn document_store_native_restore_preserves_valid_named_incarnations()
-> crate::test_fixture_failure::FixtureResult<()> {
    let fixture = Fixture::new().await?;
    let mut builder = crate::document_restore::Builder::new(
        fixture.image.disk(),
        128 << 20,
        TENANT,
        "generation",
    )?;
    let input = document("named-incarnation", 1, "small".into());
    let descriptor = builder.push(&input)?;
    let staged = builder.finish()?;
    assert!(staged.contains(&descriptor)?);
    assert_eq!(descriptor.load(&staged)?.as_ref(), &input);
    drop(staged);
    fixture.close().await
}

#[tokio::test]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn document_store_native_staged_read_admission_refuses_and_recovers()
-> crate::test_fixture_failure::FixtureResult<()> {
    let fixture = Fixture::new().await?;
    let mut builder = crate::document_restore::Builder::new(
        fixture.image.disk(),
        128 << 20,
        TENANT,
        &incarnation(),
    )?;
    let input = document("admitted-staged-read", 1, "small".into());
    let descriptor = builder.push(&input)?;
    let staged = builder.finish()?;
    let admission = &fixture.storage.admission;
    let before = admission.snapshot();
    let held = admission
        .reserve_resident(admission.policy().max_inflight_bytes.unwrap() - before.reserved_bytes)?;
    let full = admission.snapshot();
    // Both the bootstrap membership probe and direct staged decode refuse at
    // their own provider-admission boundary before touching encrypted tables.
    for result in [
        staged.contains(&descriptor).map(|_| ()),
        descriptor.load(&staged).map(|_| ()),
    ] {
        let error = result.expect_err("staged read must refuse exhausted capacity");
        let failure = error
            .downcast_ref::<crate::document_restore::ReadAdmissionFailure>()
            .expect("read admission origin was erased");
        assert!(failure.is_capacity_denied());
    }
    assert_eq!(admission.snapshot().reserved_bytes, full.reserved_bytes);
    assert_eq!(
        admission.snapshot().live_reservations,
        full.live_reservations
    );
    drop(held);
    assert_eq!(admission.snapshot().reserved_bytes, before.reserved_bytes);
    assert!(staged.contains(&descriptor)?);
    assert_eq!(descriptor.load(&staged)?.as_ref(), &input);
    drop(staged);
    fixture.close().await
}

#[tokio::test]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn document_store_native_restore_batch_boundaries_keep_one_proof_copy()
-> crate::test_fixture_failure::FixtureResult<()> {
    let fixture = Fixture::new().await?;
    let source_before = fixture
        .storage
        .admission
        .snapshot()
        .resident_reserved_bytes_by_origin
        .document_source;
    let mut builder = crate::document_restore::Builder::new(
        fixture.image.disk(),
        128 << 20,
        TENANT,
        &incarnation(),
    )?;
    let mut last = None;
    let mut logical_bytes = 0u64;
    for index in 0..19 {
        let text = if index % 2 == 0 {
            hex::encode(proof())
        } else {
            STANDARD.encode(proof())
        };
        let input = document(&format!("batch-{index}"), index + 1, text);
        let descriptor = builder.push(&input)?;
        logical_bytes += descriptor.body_bytes;
        last = Some((descriptor, input));
    }
    let staged = builder.finish()?;
    // This crosses two eight-document flushes and a final partial batch.
    // Dedup must work both against pending originals and already committed rows.
    assert_eq!(staged.object_counts()?, (19, 2));
    let (manifest_value_bytes, proof_value_bytes) = staged.object_value_bytes()?;
    assert_eq!(proof_value_bytes, proof().len() as u64);
    let (descriptor, input) = last.unwrap();
    assert_eq!(descriptor.load(&staged)?.as_ref(), &input);
    drop(input);
    let source_retained = fixture
        .storage
        .admission
        .snapshot()
        .resident_reserved_bytes_by_origin
        .document_source
        - source_before;
    assert!(source_retained < logical_bytes / 8);
    eprintln!(
        "native document accounting: documents=19 logical_body_bytes={logical_bytes} manifest_value_bytes={manifest_value_bytes} shared_proof_value_bytes={proof_value_bytes} retained_document_source_admission_bytes={source_retained}; admission and native value lengths, not process RSS or filesystem allocation"
    );
    drop(staged);
    fixture.close().await
}

#[tokio::test]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn document_store_native_failed_restore_push_cannot_finish_partial_tables()
-> crate::test_fixture_failure::FixtureResult<()> {
    let fixture = Fixture::new().await?;
    let mut builder = crate::document_restore::Builder::new(
        fixture.image.disk(),
        128 << 20,
        TENANT,
        &incarnation(),
    )?;
    // Invalid identity is detected after streaming its body; those private
    // scratch rows must never be accepted as a completed snapshot materialization.
    let invalid = document("", 1, hex::encode(proof()));
    assert!(builder.push(&invalid).is_err());
    assert!(builder.push(&document("later", 2, "small".into())).is_err());
    assert!(builder.finish().is_err());
    fixture.close().await
}

#[tokio::test]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn document_store_native_bootstrap_composite_has_exact_owners_and_no_corruption_retry()
-> crate::test_fixture_failure::FixtureResult<()> {
    let fixture = Fixture::new().await?;
    let bootstrap = fixture.select()?;
    let old = document("same-id", 1, hex::encode(proof()));
    let new = document("same-id", 2, STANDARD.encode(proof()));
    let mut builder = crate::document_restore::Builder::new(
        fixture.image.disk(),
        128 << 20,
        TENANT,
        &incarnation(),
    )?;
    let old_descriptor = builder.push(&old)?;
    let staged = builder.finish()?;
    let old_owner = crate::document_restore::BootstrapDocuments::new(
        staged.clone(),
        fixture.roots.clone(),
        bootstrap.clone(),
        TENANT,
        &incarnation(),
    )?;
    assert!(staged.contains(&old_descriptor)?);
    assert_eq!(old_descriptor.load(&old_owner)?.as_ref(), &old);
    let target_incarnation = uuid::Uuid::from_u128(74).to_string();
    let rebound = staged.rebind_scope(TENANT, &target_incarnation)?;
    assert_eq!(rebound.object_value_bytes()?, staged.object_value_bytes()?);
    assert_eq!(old_descriptor.load(&rebound)?.as_ref(), &old);
    assert_eq!(old_descriptor.load(&staged)?.as_ref(), &old);
    drop(rebound);

    let mut prepared = PreparedDocuments::new(&fixture.roots, &bootstrap, TENANT, &incarnation())?;
    let new_descriptor = prepared.stage(&new)?;
    // Also install the old content natively. It will be the positive control
    // demonstrating that a corrupted bootstrap object cannot retry elsewhere.
    assert_eq!(prepared.stage(&old)?, old_descriptor);
    let (_, selected) = publish(&fixture, None, prepared.writes())?;
    drop(prepared);
    assert!(!staged.contains(&new_descriptor)?);
    assert!(new_descriptor.load(&old_owner).is_err());
    let current_owner = crate::document_restore::BootstrapDocuments::new(
        staged.clone(),
        fixture.roots.clone(),
        selected.clone(),
        TENANT,
        &incarnation(),
    )?;
    assert_eq!(old_descriptor.load(&current_owner)?.as_ref(), &old);
    assert_eq!(new_descriptor.load(&current_owner)?.as_ref(), &new);
    let native = resolver(&fixture, &selected)?;
    assert_eq!(old_descriptor.load(&native)?.as_ref(), &old);
    let empty = crate::document_restore::Builder::new(
        fixture.image.disk(),
        128 << 20,
        TENANT,
        &incarnation(),
    )?
    .finish()?;
    assert!(!empty.contains(&old_descriptor)?);
    let empty_owner = crate::document_restore::BootstrapDocuments::new(
        empty,
        fixture.roots.clone(),
        selected.clone(),
        TENANT,
        &incarnation(),
    )?;
    assert_eq!(old_descriptor.load(&empty_owner)?.as_ref(), &old);
    assert_eq!(new_descriptor.load(&empty_owner)?.as_ref(), &new);
    drop(empty_owner);
    staged.corrupt_first_blob_for_test()?;
    assert!(staged.rebind_scope(TENANT, &target_incarnation).is_err());
    assert!(staged.contains(&old_descriptor)?);
    assert!(old_descriptor.load(&current_owner).is_err());
    assert_eq!(old_descriptor.load(&native)?.as_ref(), &old);
    drop(native);
    drop(current_owner);
    drop(old_owner);
    drop(staged);
    drop(selected);
    drop(bootstrap);
    fixture.close().await
}
