//! Real encrypted native rows and paired application/custody publication.
//! These tests exercise the production document store, not a replacement cache.
use super::*;
use crate::document_store::{BLOBS, BODIES, PreparedDocuments, SelectedDocuments};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use kasumi_store::WriteOp;
use kasumi_types::Document;

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
    let input = document("old-action", 1, hex::encode(proof()));
    let mut first = PreparedDocuments::new(&fixture.roots, &bootstrap, TENANT, &incarnation())?;
    let old = first.stage(&input)?;
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
    // Finishing scratch alone gives no serving authority or live namespace write.
    // Production publication must use the full snapshot's actual joint callback.
    assert_eq!(staged.complete_snapshot_replacements().len(), 2);
    drop(staged);
    drop(selected);
    fixture.close().await
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
