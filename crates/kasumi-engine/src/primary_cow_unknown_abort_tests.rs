//! Exact postcommit abort uncertainty on the already-defined synthetic backend.
//! Boundaries are selected from authenticated durable progress, not call counts.
use super::*;

#[derive(Clone, Copy, Debug)]
enum Boundary {
    ChunkProgress,
    ResourceRemoval,
    PendingSettlement,
}
fn chunk_key(object: tree::ObjectId, ordinal: u64) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[..24].copy_from_slice(&key(object));
    bytes[24..].copy_from_slice(&ordinal.to_le_bytes());
    bytes
}
fn inventory(fixture: &Fixture, object: tree::ObjectId) -> Result<Option<Inventory>> {
    fixture.read(
        "engine.primary.inventory",
        &key(object),
        records::INVENTORY_BYTES,
        |bytes| {
            bytes
                .map(|bytes| decode(Inventory::decode(bytes)))
                .transpose()
        },
    )
}
fn attempt(fixture: &Fixture, id: [u8; 16]) -> Result<Option<Attempt>> {
    fixture.read(
        "engine.primary.attempts",
        &id,
        records::ATTEMPT_BYTES,
        |bytes| {
            bytes
                .map(|bytes| decode(Attempt::decode(bytes)))
                .transpose()
        },
    )
}

// Twelve known records in this one-leaf/four-chunk fixture. Their small owned
// observations use the existing fixture input grant and retire before it.
// This is not a namespace scan, unbounded journal snapshot, or producer proof.
struct RecordBefore {
    namespace: &'static str,
    key: Vec<u8>,
    max: usize,
    value: Option<Vec<u8>>,
}
impl RecordBefore {
    fn read(fixture: &Fixture, namespace: &'static str, key: &[u8], max: usize) -> Result<Self> {
        let value = fixture.read(namespace, key, max, |bytes| Ok(bytes.map(<[u8]>::to_vec)))?;
        Ok(Self {
            namespace,
            key: key.to_vec(),
            max,
            value,
        })
    }
    fn verify_unchanged_unless_proposed(
        &self,
        fixture: &Fixture,
        writes: &[WriteOp],
    ) -> Result<()> {
        if writes.iter().any(|write| match write {
            WriteOp::Put { namespace, key, .. } | WriteOp::Delete { namespace, key } => {
                namespace == self.namespace && key == &self.key
            }
        }) {
            return Ok(());
        }
        fixture.read(self.namespace, &self.key, self.max, |bytes| {
            assert_eq!(
                bytes,
                self.value.as_deref(),
                "unmodified {} record changed",
                self.namespace
            );
            Ok(())
        })
    }
}
fn capture_remaining(
    fixture: &Fixture,
    pending: Attempt,
    object: tree::OverflowRef,
    manifest: Manifest,
    manifest_ref: ManifestRef,
) -> Result<[RecordBefore; 12]> {
    let page = manifest.root.context("replacement root absent")?.reference;
    assert_eq!(pending.next_object, 3);
    assert_eq!(pending.retire_count, 3);
    assert_eq!(decode(records::chunk_count(object.encoded_bytes))?, 4);
    // The actual primary_chunk codec has a fixed 140-byte header and 64KiB
    // payload; this is that format bound, not a new accepted DTO limit.
    let chunk_bytes = 140 + records::CHUNK_PAYLOAD_BYTES as usize;
    let retired_key = |ordinal| {
        key(tree::ObjectId {
            attempt: pending.id,
            ordinal,
        })
    };
    Ok([
        RecordBefore::read(
            fixture,
            "engine.primary.chunks",
            &chunk_key(object.id, 0),
            chunk_bytes,
        )?,
        RecordBefore::read(
            fixture,
            "engine.primary.chunks",
            &chunk_key(object.id, 1),
            chunk_bytes,
        )?,
        RecordBefore::read(
            fixture,
            "engine.primary.chunks",
            &chunk_key(object.id, 2),
            chunk_bytes,
        )?,
        RecordBefore::read(
            fixture,
            "engine.primary.chunks",
            &chunk_key(object.id, 3),
            chunk_bytes,
        )?,
        RecordBefore::read(
            fixture,
            "engine.primary.inventory",
            &key(object.id),
            records::INVENTORY_BYTES,
        )?,
        RecordBefore::read(
            fixture,
            "engine.primary.inventory",
            &key(page.id),
            records::INVENTORY_BYTES,
        )?,
        RecordBefore::read(
            fixture,
            "engine.primary.inventory",
            &key(manifest_ref.id),
            records::INVENTORY_BYTES,
        )?,
        RecordBefore::read(
            fixture,
            "engine.primary.pages",
            &key(page.id),
            tree::PAGE_BYTES,
        )?,
        RecordBefore::read(
            fixture,
            "engine.primary.manifests",
            &key(manifest_ref.id),
            records::MANIFEST_BYTES,
        )?,
        RecordBefore::read(
            fixture,
            "engine.primary.retire",
            &retired_key(0),
            records::RETIRE_BYTES,
        )?,
        RecordBefore::read(
            fixture,
            "engine.primary.retire",
            &retired_key(1),
            records::RETIRE_BYTES,
        )?,
        RecordBefore::read(
            fixture,
            "engine.primary.retire",
            &retired_key(2),
            records::RETIRE_BYTES,
        )?,
    ])
}
fn old_inventories(fixture: &Fixture, old: &OldPhysical) -> Result<[RecordBefore; 3]> {
    let page = old.manifest.root.context("old root absent")?.reference;
    let targets = [
        (old.leaf.object.id, records::ResourceKind::Live),
        (page.id, records::ResourceKind::Page),
        (
            old.mapping.manifest.id,
            records::ResourceKind::CollectionManifest,
        ),
    ];
    let read = |(id, kind)| -> Result<RecordBefore> {
        let observed = RecordBefore::read(
            fixture,
            "engine.primary.inventory",
            &key(id),
            records::INVENTORY_BYTES,
        )?;
        let inventory = decode(Inventory::decode(
            observed
                .value
                .as_deref()
                .context("old target inventory absent")?,
        ))?;
        assert_eq!(inventory.id, id);
        assert_eq!(inventory.scope, old.manifest.scope);
        assert_eq!(inventory.tree_id, old.manifest.tree_id);
        assert_eq!(inventory.kind, kind);
        assert_eq!(inventory.phase, records::InventoryPhase::Complete);
        assert_eq!(inventory.cleanup_unit_cursor, 0);
        Ok(observed)
    };
    Ok([read(targets[0])?, read(targets[1])?, read(targets[2])?])
}
fn target(boundary: Boundary, pending: Attempt, object: Option<Inventory>) -> bool {
    if pending.phase != records::AttemptPhase::Aborting {
        return false;
    }
    match boundary {
        Boundary::ChunkProgress => object.is_some_and(|object| {
            pending.abort_object_cursor == 0
                && object.cleanup_unit_cursor + 1 < object.completed_units
        }),
        Boundary::ResourceRemoval => object.is_some_and(|object| {
            pending.abort_object_cursor == 0
                && object.cleanup_unit_cursor + 1 == object.completed_units
        }),
        Boundary::PendingSettlement => {
            pending.live_resources == 0
                && pending.abort_object_cursor == pending.next_object
                && pending.journal_erase_cursor == pending.next_object + pending.retire_count
        }
    }
}
fn require_put(write: &WriteOp, namespace: &str, expected_key: &[u8]) {
    let WriteOp::Put {
        namespace: actual,
        key,
        ..
    } = write
    else {
        panic!("expected put")
    };
    assert_eq!(actual, namespace);
    assert_eq!(key, expected_key);
}
fn require_delete(write: &WriteOp, namespace: &str, expected_key: &[u8]) {
    let WriteOp::Delete {
        namespace: actual,
        key,
    } = write
    else {
        panic!("expected delete")
    };
    assert_eq!(actual, namespace);
    assert_eq!(key, expected_key);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn primary_cow_unknown_abort_reopens_complete_progress_resource_and_settlement_batches()
-> Result<()> {
    for boundary in [
        Boundary::ChunkProgress,
        Boundary::ResourceRemoval,
        Boundary::PendingSettlement,
    ] {
        let scope = Scope::new().await?;
        let fixture = &scope.fixture;
        let image = fixture
            .engine
            .logical_snapshot(fixture.stores.application().scratch_disk())?;
        assert_eq!(
            image.sha256(),
            crate::bootstrap::persisted_bootstrap_digest(fixture.stores.application())?
        );
        fixture.seed(1, false)?;
        let prior = fixture.fresh()?;
        let selected = fixture.selector()?;
        let old_epoch = fixture.epoch(selected.projection_epoch)?;
        let old_tail = fixture.attempt(selected.activation_attempt)?;
        let old_generation = fixture.engine.generation()?;
        let old_physical = OldPhysical::capture(fixture, selected, &old_generation)?;
        let old_inventory = old_inventories(fixture, &old_physical)?;
        let custody = fixture
            .stores
            .custody()
            .store()
            .get("raft.meta", b"applied")?;
        let command_input = fixture.command(puts(
            "large-abort",
            vec![(
                "docs".into(),
                id(0, false),
                json!({"new":"x".repeat(200_000)}),
            )],
        ))?;
        let prepared = fixture.prepare(&command_input)?;
        let (authority, prior, initial, object, manifest, manifest_ref) = {
            let (mut authority, input) = prepared.accepted()?.primary_input()?.split();
            let pending =
                PendingReplacement::prepare(&mut authority, &input, prior, &mut || Ok(())).unwrap();
            let initial = pending.attempt();
            let object = pending.object();
            let manifest = pending.manifest();
            let manifest_ref = pending.manifest_ref();
            assert_eq!(initial.next_object, 3);
            assert_eq!(initial.live_resources, 3);
            assert_eq!(initial.retire_count, 3);
            assert_eq!(manifest.root.unwrap().level, 0);
            assert_eq!(object.id.ordinal, 0);
            let prior = pending.close().unwrap();
            (authority, prior, initial, object, manifest, manifest_ref)
        };
        drop(authority);
        drop(prepared);
        drop(command_input);
        let mut authority = fixture.engine.lock_primary_apply()?;
        let mut abort = PrimaryStage::resume_incremental_abort(&mut authority)?
            .context("new pending absent")?;
        let mut reached = false;
        for _ in 0..32 {
            let current = fixture.attempt(initial.id)?;
            let object = inventory(fixture, object.id)?;
            if target(boundary, current, object) {
                reached = true;
                break;
            }
            let (next, done) = abort.incremental_abort_step(1)?;
            abort = next;
            assert!(!done, "settled before target {boundary:?}");
        }
        assert!(reached, "actual durable boundary not reached: {boundary:?}");
        let before_attempt = fixture.attempt(initial.id)?;
        let before_epoch = fixture.epoch(old_epoch.id)?;
        let before_inventory = inventory(fixture, object.id)?;
        let remaining = capture_remaining(fixture, initial, object, manifest, manifest_ref)?;
        if matches!(boundary, Boundary::PendingSettlement) {
            assert!(remaining.iter().all(|record| record.value.is_none()));
            assert_eq!(before_epoch.pending, Some(initial.id));
        } else {
            let inventory = before_inventory.unwrap();
            assert_eq!(inventory.kind, records::ResourceKind::Live);
            assert_eq!(inventory.completed_units, 4);
            assert_eq!(inventory.total_units, 4);
            assert_eq!(inventory.id, object.id);
            assert_eq!(before_attempt.abort_object_cursor, 0);
            assert_eq!(before_attempt.live_resources, 3);
            assert_eq!(before_epoch.live_resources, old_epoch.live_resources + 3);
        }
        let address = scope.owners.backend.arm(1);
        let before_finishes = scope.owners.backend.state.lock().unwrap().finishes;
        let failure = abort
            .incremental_abort_step(1)
            .err()
            .context("faulted abort returned success")?;
        original_unknown(&failure, address, 1);
        {
            let observed = scope.owners.backend.state.lock().unwrap();
            assert_eq!(observed.finishes - before_finishes, 1);
            assert_eq!(observed.active, observed.failed);
            assert!(observed.failed.is_some() && observed.armed.is_none());
            assert_eq!(observed.closes, 0);
        }
        assert!(scope.owners.admission.check_owner().is_err());
        let retry = fixture
            .stores
            .write_batch(
                &[put("cow.fenced-abort-probe", b"never", b"published")],
                &[],
            )
            .unwrap_err();
        assert!(
            retry.chain().any(|cause| matches!(
                cause.downcast_ref::<kasumi_kv::CoreError>(),
                Some(kasumi_kv::CoreError::OwnerFailed)
            )),
            "fenced abort retry lost owner failure: {retry:#}"
        );
        drop(retry);
        assert!(Arc::ptr_eq(&old_generation, &fixture.engine.generation()?));
        drop(authority);
        let restarted = scope.reopen(&image).await?;
        let reopened = &restarted.fixture;
        assert!(
            reopened
                .stores
                .application()
                .get("cow.fenced-abort-probe", b"never")?
                .is_none()
        );
        let writes = crate::primary_tree::stage::cow::stage_failure_writes_for_test(&failure)
            .context("actual failed abort batch missing")?;
        for write in writes {
            match write {
                WriteOp::Put {
                    namespace,
                    key,
                    value,
                } => reopened.read(namespace, key, value.len(), |actual| {
                    assert_eq!(
                        actual,
                        Some(value.as_slice()),
                        "partial recovered {boundary:?} put"
                    );
                    Ok(())
                })?,
                WriteOp::Delete { namespace, key } => reopened.read(
                    namespace,
                    key,
                    140 + records::CHUNK_PAYLOAD_BYTES as usize,
                    |actual| {
                        assert!(actual.is_none(), "partial recovered {boundary:?} delete");
                        Ok(())
                    },
                )?,
            }
        }
        for record in &remaining {
            record.verify_unchanged_unless_proposed(reopened, writes)?;
        }
        match boundary {
            Boundary::ChunkProgress => {
                let mut expected = before_inventory.unwrap();
                assert_eq!(writes.len(), 2);
                require_delete(
                    &writes[0],
                    "engine.primary.chunks",
                    &chunk_key(object.id, expected.cleanup_unit_cursor),
                );
                require_put(&writes[1], "engine.primary.inventory", &key(object.id));
                expected.phase = records::InventoryPhase::Deleting;
                expected.cleanup_unit_cursor += 1;
                assert_eq!(inventory(reopened, object.id)?, Some(expected));
                assert_eq!(reopened.attempt(initial.id)?, before_attempt);
                assert_eq!(reopened.epoch(old_epoch.id)?, before_epoch);
            }
            Boundary::ResourceRemoval => {
                let expected = before_inventory.unwrap();
                assert_eq!(writes.len(), 4);
                require_delete(
                    &writes[0],
                    "engine.primary.chunks",
                    &chunk_key(object.id, expected.cleanup_unit_cursor),
                );
                require_delete(&writes[1], "engine.primary.inventory", &key(object.id));
                require_put(&writes[2], "engine.primary.attempts", &initial.id);
                require_put(&writes[3], "engine.primary.epochs", &old_epoch.id);
                assert!(inventory(reopened, object.id)?.is_none());
                let mut expected_attempt = before_attempt;
                expected_attempt.live_resources -= 1;
                expected_attempt.abort_object_cursor += 1;
                let mut expected_epoch = before_epoch;
                expected_epoch.live_resources -= 1;
                assert_eq!(reopened.attempt(initial.id)?, expected_attempt);
                assert_eq!(reopened.epoch(old_epoch.id)?, expected_epoch);
            }
            Boundary::PendingSettlement => {
                assert_eq!(writes.len(), 2);
                require_put(&writes[0], "engine.primary.epochs", &old_epoch.id);
                require_delete(&writes[1], "engine.primary.attempts", &initial.id);
                assert!(attempt(reopened, initial.id)?.is_none());
                assert_eq!(reopened.epoch(old_epoch.id)?, old_epoch);
            }
        }
        assert_eq!(reopened.selector()?, selected);
        assert_eq!(reopened.attempt(old_tail.id)?, old_tail);
        assert_eq!(
            reopened
                .stores
                .custody()
                .store()
                .get("raft.meta", b"applied")?,
            custody
        );
        old_physical.verify(reopened)?;
        for record in &old_inventory {
            record.verify_unchanged_unless_proposed(reopened, &[])?;
        }
        let mut authority = reopened.engine.lock_primary_apply()?;
        let finishes = restarted.owners.backend.state.lock().unwrap().finishes;
        let resumed = PrimaryStage::resume_incremental_abort(&mut authority)?;
        if matches!(boundary, Boundary::PendingSettlement) {
            assert!(resumed.is_none());
            drop(resumed);
            assert_eq!(
                restarted.owners.backend.state.lock().unwrap().finishes,
                finishes,
                "already settled branch wrote again"
            );
        } else {
            let mut abort = resumed.context("recovered abort progress absent")?;
            let unchanged = reopened.attempt(initial.id)?;
            let (next, done) = abort.incremental_abort_step(0)?;
            abort = next;
            assert!(!done);
            assert_eq!(reopened.attempt(initial.id)?, unchanged);
            assert_eq!(
                restarted.owners.backend.state.lock().unwrap().finishes,
                finishes,
                "zero allowance published a batch"
            );
            let mut complete = false;
            for _ in 0..32 {
                let (next, done) = abort.incremental_abort_step(1)?;
                abort = next;
                if done {
                    complete = true;
                    break;
                }
            }
            assert!(complete);
            abort.close()?;
        }
        drop(authority);
        assert_eq!(reopened.epoch(old_epoch.id)?, old_epoch);
        assert!(attempt(reopened, initial.id)?.is_none());
        assert_eq!(reopened.selector()?, selected);
        assert_eq!(reopened.attempt(old_tail.id)?, old_tail);
        assert_eq!(
            reopened
                .stores
                .custody()
                .store()
                .get("raft.meta", b"applied")?,
            custody
        );
        old_physical.verify(reopened)?;
        for record in &old_inventory {
            record.verify_unchanged_unless_proposed(reopened, &[])?;
        }
        let generation = reopened.engine.generation()?;
        let source = generation
            .application_selection
            .get()
            .context("exact replay source absent")?;
        let (bootstrap, fingerprint, revision) =
            source.primary_read_proof(generation.state.revision_base)?;
        assert_eq!(revision, selected.revision);
        assert_eq!(bootstrap, selected.bootstrap_sha256);
        assert_eq!(fingerprint.kind, selected.boundary);
        assert_eq!(fingerprint.sha256, selected.boundary_digest);
        let reader = crate::primary_tree::read::SelectedPrimary::open(
            source,
            &reopened.roots,
            &generation.state,
            "docs",
        )
        .unwrap();
        let (reader, version) = reader
            .lookup(&id(0, false), |record| {
                let kasumi_query::Record::Live(document) = record else {
                    anyhow::bail!("old selected kind differs")
                };
                assert_eq!(serde_json::to_vec(document)?, old_physical.canonical);
                Ok(document.version)
            })
            .unwrap();
        assert_eq!(version, Some(2));
        reader.close().unwrap();
        drop(generation);
        original_unknown(&failure, address, 1);
        restarted.close().await;
        drop(failure);
        drop(prior);
        drop(old_generation);
        drop(old_physical);
        drop(old_inventory);
        drop(remaining);
        drop(image);
        let Scope { fixture, owners } = scope;
        cleanup(fixture, owners, true).await;
    }
    Ok(())
}
