use super::*;
use crate::primary_tree::{
    EncodedPage, Entry, ExpectedPage, KeyRange, Leaf, PAGE_BYTES, RecordKind, Totals, Value,
    records::{Manifest, ManifestRef, Root},
};

fn small_projection<'a, 'b>(
    stage: PrimaryStage<'a, 'b>,
    scope: [u8; 32],
) -> Result<(PrimaryStage<'a, 'b>, EncodedPage, ManifestRef)> {
    let tree = [61; 16];
    let definition = kasumi_types::CollectionDefinition {
        name: "objects".into(),
        write_mode: kasumi_types::CollectionWriteMode::Mutable,
        retention_class: kasumi_types::CollectionRetentionClass::Operational,
        schema: serde_json::json!({}),
        indexes: Vec::new(),
        strict_read_audit: false,
    };
    let document = document(64);
    let (stage, definition) = stage.stage_dto(tree, CanonicalDto::Definition(&definition))?;
    let (stage, object) = stage.stage_dto(tree, CanonicalDto::Live(&document))?;
    let entries = [Entry {
        id: &document.id,
        value: Value::Leaf(Leaf {
            version: document.version,
            kind: RecordKind::Live,
            object,
            semantic_bytes: crate::accounting::encoded_len(&document.body)? as u64,
        }),
    }];
    let (stage, page) = stage.stage_page(tree, 1, 0, &entries)?;
    let (stage, manifest) = stage.stage_manifest(Manifest {
        scope,
        name_hash: decode(records::name_hash("objects"))?,
        tree_id: tree,
        definition,
        data_epoch: 1,
        revision: 1,
        root: Some(Root {
            reference: page.reference,
            level: 0,
        }),
        totals: page.totals,
    })?;
    Ok((stage, page, manifest))
}

#[tokio::test]
async fn primary_stage_fixed_objects_are_journaled_and_old_pin_survives_bounded_abort()
-> crate::test_fixture_failure::FixtureResult<()> {
    let fixture = Fixture::new().await?;
    let engine = engine(&fixture)?;
    let input = fixture.storage.admission.reserve_document_source(1 << 20)?;
    let mut authority = engine.lock_primary_apply()?;
    let scope = authority.scope();
    let (stage, page, manifest) =
        small_projection(PrimaryStage::begin_fresh(&mut authority)?, scope)?;
    assert_eq!(page.reference.id.ordinal, 2);
    assert_eq!(manifest.id.ordinal, 3);
    assert_eq!(page.reference.id.attempt, manifest.id.attempt);
    let (_, epoch, attempt) = pending(&fixture)?;
    assert_eq!(attempt.next_object, 4);
    assert_eq!(attempt.live_resources, 4);
    assert_eq!(epoch.live_resources, 4);
    for (id, kind, hash, size) in [
        (
            page.reference.id,
            ResourceKind::Page,
            page.reference.sha256,
            PAGE_BYTES,
        ),
        (
            manifest.id,
            ResourceKind::CollectionManifest,
            manifest.sha256,
            records::MANIFEST_BYTES,
        ),
    ] {
        let inventory = read(
            &fixture,
            "engine.primary.inventory",
            &key(id),
            records::INVENTORY_BYTES,
            |bytes| decode(Inventory::decode(bytes.context("fixed inventory absent")?)),
        )?;
        assert_eq!(inventory.kind, kind);
        assert_eq!(inventory.phase, InventoryPhase::Complete);
        assert_eq!(inventory.encoded_bytes, size as u64);
        assert_eq!(inventory.sha256, hash);
        assert_eq!(
            (
                inventory.total_units,
                inventory.completed_units,
                inventory.cleanup_unit_cursor
            ),
            (1, 1, 0)
        );
    }
    let old = fixture.select()?;
    stage.close()?;
    // One unit can only mark Aborting; each later unit removes one object.
    let stage = PrimaryStage::resume_abort(&mut authority)?.context("fixed stage absent")?;
    let (mut stage, done) = stage.abort_step(1)?;
    assert!(!done);
    for expected in 1..=4 {
        let (next, done) = stage.abort_step(1)?;
        stage = next;
        assert!(!done);
        let (_, epoch, attempt) = pending(&fixture)?;
        assert_eq!(attempt.abort_object_cursor, expected);
        assert_eq!(attempt.live_resources, 4 - expected);
        assert_eq!(epoch.live_resources, 4 - expected);
        // Drop/reacquire between steps exercises durable cursor continuation.
        stage.close()?;
        stage = PrimaryStage::resume_abort(&mut authority)?.context("abort resume absent")?;
    }
    let (stage, done) = stage.abort_step(1)?;
    assert!(done);
    stage.close()?;
    for (namespace, id, size) in [
        ("engine.primary.pages", page.reference.id, PAGE_BYTES),
        (
            "engine.primary.manifests",
            manifest.id,
            records::MANIFEST_BYTES,
        ),
    ] {
        assert!(read(&fixture, namespace, &key(id), size, |bytes| Ok(
            bytes.is_none()
        ))?);
        assert!(read(
            &fixture,
            "engine.primary.inventory",
            &key(id),
            records::INVENTORY_BYTES,
            |bytes| Ok(bytes.is_none())
        )?);
    }
    let mut old_reader = old.open_primary_reader(&fixture.roots)?;
    let mut grant = fixture.storage.admission.reserve_document_source(4096)?;
    old_reader.with_record(
        &mut grant,
        4096,
        "engine.primary.pages",
        &key(page.reference.id),
        PAGE_BYTES,
        |bytes| {
            let decoded = decode(crate::primary_tree::validate(
                bytes.context("old page absent")?,
                ExpectedPage {
                    tree_id: [61; 16],
                    reference: page.reference,
                    generation_ceiling: 1,
                    level: 0,
                    totals: page.totals,
                    range: KeyRange::default(),
                },
            ))?;
            assert_eq!(decode(decoded.lookup("a"))?.unwrap().version, 1);
            Ok(())
        },
    )?;
    old_reader.with_record(
        &mut grant,
        4096,
        "engine.primary.manifests",
        &key(manifest.id),
        records::MANIFEST_BYTES,
        |bytes| {
            let decoded = decode(Manifest::decode_referenced(
                bytes.context("old manifest absent")?,
                manifest,
            ))?;
            assert_eq!(decoded.root.unwrap().reference, page.reference);
            Ok(())
        },
    )?;
    old_reader.close()?;
    drop(grant);
    drop(authority);
    drop(old);
    drop(input);
    engine.seal();
    drop(engine);
    fixture.close().await
}

#[tokio::test]
async fn primary_stage_fixed_shape_refusal_creates_no_inventory_or_counter_change()
-> crate::test_fixture_failure::FixtureResult<()> {
    for page in [true, false] {
        let fixture = Fixture::new().await?;
        let engine = engine(&fixture)?;
        let mut authority = engine.lock_primary_apply()?;
        let stage = PrimaryStage::begin_fresh(&mut authority)?;
        let error = if page {
            stage.stage_page([71; 16], 1, 0, &[]).err()
        } else {
            stage
                .stage_manifest(Manifest {
                    scope: [0; 32],
                    name_hash: [0; 32],
                    tree_id: [71; 16],
                    definition: crate::primary_tree::OverflowRef {
                        id: ObjectId {
                            attempt: [1; 16],
                            ordinal: 0,
                        },
                        encoded_bytes: 1,
                        sha256: [0; 32],
                    },
                    data_epoch: 0,
                    revision: 0,
                    root: None,
                    totals: Totals::default(),
                })
                .err()
        }
        .context("invalid fixed shape accepted")?;
        assert!(
            error
                .to_string()
                .contains(if page { "Capacity" } else { "scope differs" })
        );
        let (_, epoch, attempt) = pending(&fixture)?;
        assert_eq!(
            (
                attempt.next_object,
                attempt.live_resources,
                epoch.live_resources
            ),
            (0, 0, 0)
        );
        assert!(read(
            &fixture,
            "engine.primary.inventory",
            &key(ObjectId {
                attempt: attempt.id,
                ordinal: 0
            }),
            records::INVENTORY_BYTES,
            |bytes| Ok(bytes.is_none())
        )?);
        drop(error);
        let stage = PrimaryStage::resume_abort(&mut authority)?.context("empty stage absent")?;
        let (stage, done) = stage.abort_step(2)?;
        assert!(done);
        stage.close()?;
        drop(authority);
        engine.seal();
        drop(engine);
        fixture.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn primary_stage_fixed_missing_or_corrupt_objects_refuse_before_abort_progress()
-> crate::test_fixture_failure::FixtureResult<()> {
    for page in [true, false] {
        for missing in [true, false] {
            let fixture = Fixture::new().await?;
            let engine = engine(&fixture)?;
            let input = fixture.storage.admission.reserve_document_source(1 << 20)?;
            let mut authority = engine.lock_primary_apply()?;
            let scope = authority.scope();
            let (stage, page_ref, manifest) =
                small_projection(PrimaryStage::begin_fresh(&mut authority)?, scope)?;
            stage.close()?;
            let (namespace, id, size) = if page {
                ("engine.primary.pages", page_ref.reference.id, PAGE_BYTES)
            } else {
                (
                    "engine.primary.manifests",
                    manifest.id,
                    records::MANIFEST_BYTES,
                )
            };
            let original = read(&fixture, namespace, &key(id), size, |bytes| {
                Ok(bytes.context("fixed object absent")?.to_vec())
            })?;
            let mut corrupt = original.clone();
            corrupt[size - 1] ^= 1;
            fixture.stores.write_batch(
                &[if missing {
                    kasumi_store::WriteOp::delete(namespace, key(id))
                } else {
                    kasumi_store::WriteOp::put(namespace, key(id), corrupt)
                }],
                &[],
            )?;
            let stage = PrimaryStage::resume_abort(&mut authority)?.context("stage absent")?;
            let (stage, done) = stage.abort_step(1 + id.ordinal as usize)?;
            assert!(!done);
            let error = stage
                .abort_step(1)
                .err()
                .context("invalid fixed object erased")?;
            assert!(error.to_string().contains(if missing {
                "object absent"
            } else {
                "digest differs"
            }));
            let (_, epoch, attempt) = pending(&fixture)?;
            assert_eq!(attempt.abort_object_cursor, id.ordinal);
            assert_eq!(attempt.live_resources, 4 - id.ordinal);
            assert_eq!(epoch.live_resources, 4 - id.ordinal);
            assert!(read(
                &fixture,
                "engine.primary.inventory",
                &key(id),
                records::INVENTORY_BYTES,
                |bytes| Ok(bytes.is_some())
            )?);
            drop(error);
            // Only fixture cleanup restores the positively known original bytes.
            fixture.stores.write_batch(
                &[kasumi_store::WriteOp::put(namespace, key(id), original)],
                &[],
            )?;
            let stage =
                PrimaryStage::resume_abort(&mut authority)?.context("failed stage absent")?;
            let (stage, done) = stage.abort_step(64)?;
            assert!(done);
            stage.close()?;
            drop(authority);
            drop(input);
            engine.seal();
            drop(engine);
            fixture.close().await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn primary_stage_fixed_impossible_inventory_progress_refuses_without_erasing_custody()
-> crate::test_fixture_failure::FixtureResult<()> {
    for page in [true, false] {
        let fixture = Fixture::new().await?;
        let engine = engine(&fixture)?;
        let input = fixture.storage.admission.reserve_document_source(1 << 20)?;
        let mut authority = engine.lock_primary_apply()?;
        let scope = authority.scope();
        let (stage, page_ref, manifest) =
            small_projection(PrimaryStage::begin_fresh(&mut authority)?, scope)?;
        stage.close()?;
        let (namespace, id, size) = if page {
            ("engine.primary.pages", page_ref.reference.id, PAGE_BYTES)
        } else {
            (
                "engine.primary.manifests",
                manifest.id,
                records::MANIFEST_BYTES,
            )
        };
        let original = read(&fixture, namespace, &key(id), size, |bytes| {
            Ok(bytes.context("fixed object absent")?.to_vec())
        })?;
        let inventory = read(
            &fixture,
            "engine.primary.inventory",
            &key(id),
            records::INVENTORY_BYTES,
            |bytes| decode(Inventory::decode(bytes.context("fixed inventory absent")?)),
        )?;
        let stage = PrimaryStage::resume_abort(&mut authority)?.context("stage absent")?;
        let (stage, done) = stage.abort_step(1 + id.ordinal as usize)?;
        assert!(!done);
        stage.close()?;
        let before = pending(&fixture)?;
        for (phase, completed, cleanup) in [
            (InventoryPhase::Allocating, 0, 0),
            (InventoryPhase::Allocating, 1, 0),
            (InventoryPhase::Deleting, 1, 0),
            (InventoryPhase::Deleting, 1, 1),
        ] {
            // All of these are legal generic inventory encodings. None is a
            // possible durable state of an atomically published fixed object.
            let invalid = Inventory {
                phase,
                completed_units: completed,
                cleanup_unit_cursor: cleanup,
                ..inventory
            };
            let mut bytes = [0; records::INVENTORY_BYTES];
            decode(invalid.encode(&mut bytes))?;
            fixture.stores.write_batch(
                &[kasumi_store::WriteOp::put(
                    "engine.primary.inventory",
                    key(id),
                    bytes,
                )],
                &[],
            )?;
            let stage = PrimaryStage::resume_abort(&mut authority)?.context("stage absent")?;
            let error = stage
                .abort_step(1)
                .err()
                .context("invalid progress accepted")?;
            assert!(
                error
                    .to_string()
                    .contains("fixed inventory progress differs")
            );
            assert!(error.chain().skip(1).any(|source| {
                source
                    .to_string()
                    .contains("fixed inventory progress differs")
            }));
            assert_eq!(pending(&fixture)?, before);
            assert_eq!(
                read(
                    &fixture,
                    "engine.primary.inventory",
                    &key(id),
                    records::INVENTORY_BYTES,
                    |bytes| decode(Inventory::decode(
                        bytes.context("refused inventory erased")?
                    ))
                )?,
                invalid
            );
            read(&fixture, namespace, &key(id), size, |bytes| {
                assert_eq!(bytes, Some(original.as_slice()));
                Ok(())
            })?;
            drop(error);
        }
        // Restore only the known original fixture inventory for final cleanup.
        let mut bytes = [0; records::INVENTORY_BYTES];
        decode(inventory.encode(&mut bytes))?;
        fixture.stores.write_batch(
            &[kasumi_store::WriteOp::put(
                "engine.primary.inventory",
                key(id),
                bytes,
            )],
            &[],
        )?;
        let stage = PrimaryStage::resume_abort(&mut authority)?.context("stage absent")?;
        let (stage, done) = stage.abort_step(64)?;
        assert!(done);
        stage.close()?;
        drop(authority);
        drop(original);
        drop(input);
        engine.seal();
        drop(engine);
        fixture.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn primary_stage_fixed_page_framing_refuses_even_with_matching_inventory_digest()
-> crate::test_fixture_failure::FixtureResult<()> {
    let fixture = Fixture::new().await?;
    let engine = engine(&fixture)?;
    let input = fixture.storage.admission.reserve_document_source(1 << 20)?;
    let mut authority = engine.lock_primary_apply()?;
    let scope = authority.scope();
    let (stage, page, _) = small_projection(PrimaryStage::begin_fresh(&mut authority)?, scope)?;
    stage.close()?;
    let id = page.reference.id;
    let original = read(
        &fixture,
        "engine.primary.pages",
        &key(id),
        PAGE_BYTES,
        |bytes| Ok(bytes.context("page absent")?.to_vec()),
    )?;
    let inventory = read(
        &fixture,
        "engine.primary.inventory",
        &key(id),
        records::INVENTORY_BYTES,
        |bytes| decode(Inventory::decode(bytes.context("page inventory absent")?)),
    )?;
    let mut corrupt = original.clone();
    corrupt[PAGE_BYTES - 1] = 1; // Noncanonical padding after the sole leaf.
    let invalid = Inventory {
        sha256: Sha256::digest(&corrupt).into(),
        ..inventory
    };
    let mut bytes = [0; records::INVENTORY_BYTES];
    decode(invalid.encode(&mut bytes))?;
    fixture.stores.write_batch(
        &[
            kasumi_store::WriteOp::put("engine.primary.pages", key(id), corrupt.clone()),
            kasumi_store::WriteOp::put("engine.primary.inventory", key(id), bytes),
        ],
        &[],
    )?;
    let stage = PrimaryStage::resume_abort(&mut authority)?.context("stage absent")?;
    let (stage, done) = stage.abort_step(1 + id.ordinal as usize)?;
    assert!(!done);
    let before = pending(&fixture)?;
    let error = stage.abort_step(1).err().context("malformed page erased")?;
    assert!(error.to_string().contains("Padding"));
    assert!(
        error
            .chain()
            .skip(1)
            .any(|source| source.to_string().contains("Padding"))
    );
    assert_eq!(pending(&fixture)?, before);
    assert_eq!(
        read(
            &fixture,
            "engine.primary.inventory",
            &key(id),
            records::INVENTORY_BYTES,
            |bytes| decode(Inventory::decode(bytes.context("page inventory erased")?))
        )?,
        invalid
    );
    read(
        &fixture,
        "engine.primary.pages",
        &key(id),
        PAGE_BYTES,
        |bytes| {
            assert_eq!(bytes, Some(corrupt.as_slice()));
            Ok(())
        },
    )?;
    drop(error);
    // Restore only the known original fixture bytes and their digest.
    decode(inventory.encode(&mut bytes))?;
    fixture.stores.write_batch(
        &[
            kasumi_store::WriteOp::put("engine.primary.pages", key(id), original),
            kasumi_store::WriteOp::put("engine.primary.inventory", key(id), bytes),
        ],
        &[],
    )?;
    let stage = PrimaryStage::resume_abort(&mut authority)?.context("stage absent")?;
    let (stage, done) = stage.abort_step(64)?;
    assert!(done);
    stage.close()?;
    drop(authority);
    drop(corrupt);
    drop(input);
    engine.seal();
    drop(engine);
    fixture.close().await
}

#[tokio::test]
async fn primary_stage_fixed_page_buffer_returns_for_following_multichunk_dto()
-> crate::test_fixture_failure::FixtureResult<()> {
    let fixture = Fixture::new().await?;
    let engine = engine(&fixture)?;
    let input = fixture.storage.admission.reserve_document_source(1 << 20)?;
    let mut authority = engine.lock_primary_apply()?;
    let mut stage = PrimaryStage::begin_fresh(&mut authority)?;
    let tree = [79; 16];
    for (ordinal, payload) in [(0, 64), (2, 140_000)] {
        let doc = document(payload);
        let expected = serde_json::to_vec(&doc)?;
        let (next, object) = stage.stage_dto(tree, CanonicalDto::Live(&doc))?;
        stage = next;
        assert_eq!(object.id.ordinal, ordinal);
        let mut offset = 0;
        stage = stage.visit_staged(object, tree, ResourceKind::Live, |chunk| {
            assert_eq!(chunk, &expected[offset..offset + chunk.len()]);
            offset += chunk.len();
            Ok(())
        })?;
        assert_eq!(offset, expected.len());
        let (next, page) = stage.stage_page(
            tree,
            1,
            0,
            &[Entry {
                id: &doc.id,
                value: Value::Leaf(Leaf {
                    version: doc.version,
                    kind: RecordKind::Live,
                    object,
                    semantic_bytes: crate::accounting::encoded_len(&doc.body)? as u64,
                }),
            }],
        )?;
        stage = next;
        assert_eq!(page.reference.id.ordinal, ordinal + 1);
    }
    let (_, epoch, attempt) = pending(&fixture)?;
    assert_eq!(
        (
            attempt.next_object,
            attempt.live_resources,
            epoch.live_resources
        ),
        (4, 4, 4)
    );
    let (stage, done) = stage.abort_step(64)?;
    assert!(done);
    stage.close()?;
    drop(authority);
    drop(input);
    engine.seal();
    drop(engine);
    fixture.close().await
}
