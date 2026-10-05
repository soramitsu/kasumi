//! Real postdurable final five-effect fault. Reuses the exact admitted native
//! wrapper and retained cleanup fixture; no publication/rollback mock.
use super::super::publication;
use super::*;

fn final_operation() -> Operation {
    puts(
        "final-unknown",
        vec![(
            "docs".into(),
            id(0, false),
            json!({"published":"z".repeat(200_000)}),
        )],
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn primary_cow_unknown_final_publication_reopens_complete_commit_and_refuses_abort()
-> crate::test_fixture_failure::FixtureResult<()> {
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
    let old_selected = fixture.selector()?;
    let old_epoch = fixture.epoch(old_selected.projection_epoch)?;
    let old_tail = fixture.attempt(old_selected.activation_attempt)?;
    let original_generation = fixture.engine.generation()?;
    let physical = OldPhysical::capture(fixture, old_selected, &original_generation)?;
    let target_ids = [
        physical.leaf.object.id,
        physical.manifest.root.unwrap().reference.id,
        physical.mapping.manifest.id,
    ];
    let mut old_inventory = [Vec::new(), Vec::new(), Vec::new()];
    for ((slot, target), kind) in old_inventory.iter_mut().zip(target_ids).zip([
        records::ResourceKind::Live,
        records::ResourceKind::Page,
        records::ResourceKind::CollectionManifest,
    ]) {
        *slot = fixture.read(
            "engine.primary.inventory",
            &key(target),
            records::INVENTORY_BYTES,
            |bytes| {
                let bytes = bytes.context("original target inventory absent")?;
                let inventory = decode(Inventory::decode(bytes))?;
                assert_eq!(inventory.id, target);
                assert_eq!(inventory.scope, old_selected.scope);
                assert_eq!(inventory.kind, kind);
                assert_eq!(inventory.tree_id, physical.manifest.tree_id);
                assert_eq!(inventory.phase, records::InventoryPhase::Complete);
                assert_eq!(inventory.cleanup_unit_cursor, 0);
                Ok(bytes.to_vec())
            },
        )?;
    }
    let command_input = fixture.command(final_operation())?;
    let prepared = fixture.prepare(&command_input)?;
    let (prepared, publication) = publication::prepare(fixture, prepared, prior).unwrap();
    let expected_position: AppliedEntryContext = prepared.position().clone(); // bounded real input grant owns actual DTO clone
    let address = scope.owners.backend.arm(1);
    let before_finishes = scope.owners.backend.state.lock().unwrap().finishes;
    let failure = publication::publish(fixture, prepared, publication, &mut |_| Ok(()))
        .err()
        .context("unknown final publication acknowledged")?;
    original_unknown(failure.original(), address, 1);
    assert!(!failure.visibility_entered());
    assert_eq!(failure.proposed_writes().len(), 5);
    assert!(Arc::ptr_eq(
        &original_generation,
        &fixture.engine.generation()?
    ));
    {
        let observed = scope.owners.backend.state.lock().unwrap();
        assert_eq!(observed.finishes - before_finishes, 1);
        assert_eq!(observed.active, observed.failed);
        assert!(observed.failed.is_some());
        assert_eq!(observed.closes, 0);
    }
    let restarted = scope.reopen_after(&image, Some(final_operation())).await?;
    let reopened = &restarted.fixture;
    let mut final_selector = None;
    let mut final_attempt = None;
    let mut final_tail = None;
    let mut final_epoch = None;
    for (index, write) in failure.proposed_writes().iter().enumerate() {
        let WriteOp::Put {
            namespace,
            key,
            value,
        } = write
        else {
            unreachable!()
        };
        reopened.read(namespace, key, value.len(), |bytes| {
            assert_eq!(
                bytes,
                Some(value.as_slice()),
                "complete final batch effect {index}"
            );
            match index {
                0 => final_selector = Some(decode(Selector::decode(bytes.unwrap()))?),
                2 => final_attempt = Some(decode(Attempt::decode(bytes.unwrap()))?),
                3 => final_tail = Some(decode(Attempt::decode(bytes.unwrap()))?),
                4 => final_epoch = Some(decode(Epoch::decode(bytes.unwrap()))?),
                _ => {}
            }
            Ok(())
        })?;
    }
    let selected = final_selector.unwrap();
    let attempt = final_attempt.unwrap();
    let epoch = final_epoch.unwrap();
    assert_eq!(selected.revision, 4);
    assert_eq!(selected.activation_attempt, attempt.id);
    assert_eq!(selected.catalog, old_selected.catalog);
    assert_eq!(selected.projection_epoch, old_epoch.id);
    assert_eq!(attempt.phase, records::AttemptPhase::Committed);
    assert_eq!(attempt.previous, Some(old_tail.id));
    assert_eq!(attempt.next, None);
    assert_eq!(
        (
            attempt.next_object,
            attempt.live_resources,
            attempt.retire_count
        ),
        (3, 3, 3)
    );
    assert_eq!(
        (
            attempt.abort_object_cursor,
            attempt.retire_cursor,
            attempt.journal_erase_cursor
        ),
        (0, 0, 0)
    );
    assert_eq!(
        final_tail.unwrap(),
        Attempt {
            next: Some(attempt.id),
            ..old_tail
        }
    );
    assert_eq!(
        epoch,
        Epoch {
            tail: Some(attempt.id),
            pending: None,
            live_resources: old_epoch.live_resources + 3,
            ..old_epoch
        }
    );
    // Independent actual cursor/proof identity, not just expected primary bytes.
    let generation = reopened.engine.generation()?;
    let source = generation
        .application_selection
        .get()
        .context("reopened mutation source absent")?;
    let (_, fingerprint, revision) = source.primary_read_proof(generation.state.revision_base)?;
    let expected = decode(records::boundary::producer(ApplicationBoundaryRef::Entry(
        &expected_position,
    )))?;
    assert_eq!(revision, 4);
    assert_eq!(fingerprint, expected);
    assert_eq!(selected.boundary_digest, fingerprint.sha256);
    let reader = crate::primary_tree::read::SelectedPrimary::open(
        source,
        &reopened.roots,
        &generation.state,
        "docs",
    )
    .unwrap();
    let (reader, row) = reader
        .lookup(&id(0, false), |record| {
            let kasumi_query::Record::Live(document) = record else {
                anyhow::bail!("reopened live absent")
            };
            assert_eq!(document.version, 4);
            assert_eq!(document.body, json!({"published":"z".repeat(200_000)}));
            Ok(document.version)
        })
        .unwrap();
    assert_eq!(row, Some(4));
    reader.close().unwrap();
    // Old graph remains physical inventory, although mapping now selects new.
    physical.verify_resources(reopened)?;
    for (target, expected) in target_ids.into_iter().zip(&old_inventory) {
        reopened.read(
            "engine.primary.inventory",
            &key(target),
            records::INVENTORY_BYTES,
            |bytes| {
                assert_eq!(bytes, Some(expected.as_slice()));
                Ok(())
            },
        )?;
    }
    for ordinal in 0..3 {
        let intention = reopened.read(
            "engine.primary.retire",
            &key(tree::ObjectId {
                attempt: attempt.id,
                ordinal,
            }),
            records::RETIRE_BYTES,
            |bytes| {
                decode(records::Retire::decode(
                    bytes.context("committed retire intention absent")?,
                ))
            },
        )?;
        assert_eq!(
            intention.target,
            [target_ids[1], target_ids[0], target_ids[2]][ordinal as usize],
            "actual path/DTO/manifest intention order"
        );
    }
    let finishes = restarted.owners.backend.state.lock().unwrap().finishes;
    {
        let mut authority = reopened.engine.lock_primary_apply()?;
        assert!(
            PrimaryStage::resume_incremental_abort(&mut authority)?.is_none(),
            "committed resources became abortable"
        );
    }
    assert_eq!(
        restarted.owners.backend.state.lock().unwrap().finishes,
        finishes
    );
    assert_eq!(reopened.epoch(epoch.id)?, epoch);
    original_unknown(failure.original(), address, 1);
    drop(generation);
    drop(expected_position);
    drop(old_inventory);
    drop(physical);
    drop(failure);
    drop(original_generation);
    drop(image);
    drop(command_input);
    restarted.close().await;
    cleanup(scope.fixture, scope.owners, true).await;
    Ok(())
}
