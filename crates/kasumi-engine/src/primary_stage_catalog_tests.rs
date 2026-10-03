use super::*;
use crate::primary_tree::{
    Totals,
    records::{
        CATALOG_MEMBER_BYTES, CatalogEntry, CatalogId, CatalogMember, Manifest, ManifestRef,
    },
};
const CATALOG: &str = "engine.primary.catalog";
const MEMBERS: &str = "engine.primary.catalog.members";

fn collection<'a, 'b>(
    stage: PrimaryStage<'a, 'b>,
    scope: [u8; 32],
    name: &str,
) -> Result<(PrimaryStage<'a, 'b>, ManifestRef)> {
    let definition = kasumi_types::CollectionDefinition {
        name: name.into(),
        write_mode: kasumi_types::CollectionWriteMode::Mutable,
        retention_class: kasumi_types::CollectionRetentionClass::Operational,
        schema: serde_json::json!({}),
        indexes: Vec::new(),
        strict_read_audit: false,
    };
    let tree = [91; 16];
    let (stage, definition) = stage.stage_dto(tree, CanonicalDto::Definition(&definition))?;
    stage.stage_manifest(Manifest {
        scope,
        name_hash: decode(records::name_hash(name))?,
        tree_id: tree,
        definition,
        data_epoch: 1,
        revision: 1,
        root: None,
        totals: Totals::default(),
    })
}
fn inventory(fixture: &Fixture, id: ObjectId) -> Result<Inventory> {
    read(
        fixture,
        "engine.primary.inventory",
        &key(id),
        records::INVENTORY_BYTES,
        |bytes| {
            decode(Inventory::decode(
                bytes.context("catalog inventory absent")?,
            ))
        },
    )
}
fn set_inventory(fixture: &Fixture, inventory: Inventory) -> Result<()> {
    let mut bytes = [0; records::INVENTORY_BYTES];
    decode(inventory.encode(&mut bytes))?;
    fixture.stores.write_batch(
        &[kasumi_store::WriteOp::put(
            "engine.primary.inventory",
            key(inventory.id),
            bytes,
        )],
        &[],
    )?;
    Ok(())
}
fn mapping(fixture: &Fixture, id: CatalogId, name: &str) -> Result<CatalogEntry> {
    read(
        fixture,
        CATALOG,
        &CatalogEntry::key(id, decode(records::name_hash(name))?),
        records::CATALOG_ENTRY_BYTES,
        |bytes| decode(CatalogEntry::decode(bytes.context("mapping absent")?)),
    )
}
fn member(
    fixture: &Fixture,
    id: CatalogId,
    scope: [u8; 32],
    ordinal: u64,
) -> Result<CatalogMember> {
    read(
        fixture,
        MEMBERS,
        &CatalogMember::key(id, ordinal),
        CATALOG_MEMBER_BYTES,
        |bytes| {
            decode(CatalogMember::decode(
                bytes.context("member absent")?,
                id,
                scope,
                ordinal,
            ))
        },
    )
}
fn next_id(fixture: &Fixture) -> Result<ObjectId> {
    let (_, _, attempt) = pending(fixture)?;
    Ok(ObjectId {
        attempt: attempt.id,
        ordinal: attempt.next_object,
    })
}

#[test]
fn primary_catalog_member_codec_is_fixed_and_contextual() -> Result<()> {
    let id = CatalogId(ObjectId {
        attempt: [7; 16],
        ordinal: 9,
    });
    let name = "Ω".repeat(128);
    let value = decode(CatalogMember::new(id, [8; 32], 17, &name))?;
    let mut bytes = [0; CATALOG_MEMBER_BYTES];
    decode(value.encode(&mut bytes))?;
    assert_eq!(
        decode(CatalogMember::decode(&bytes, id, [8; 32], 17))?.name(),
        name
    );
    assert!(CatalogMember::decode(&bytes, id, [8; 32], 18).is_err());
    assert!(CatalogMember::decode(&bytes, id, [9; 32], 17).is_err());
    for at in [0, 10, 114, 80, 120] {
        let mut corrupt = bytes;
        corrupt[at] ^= 1;
        assert!(CatalogMember::decode(&corrupt, id, [8; 32], 17).is_err());
    }
    let small = decode(CatalogMember::new(id, [8; 32], 17, "a"))?;
    decode(small.encode(&mut bytes))?;
    bytes[375] = 1;
    assert!(CatalogMember::decode(&bytes, id, [8; 32], 17).is_err());
    assert!(CatalogMember::new(id, [8; 32], 0, "").is_err());
    assert!(CatalogMember::new(id, [8; 32], 0, "a\n").is_err());
    let mut short = [77; CATALOG_MEMBER_BYTES - 1];
    assert!(small.encode(&mut short).is_err());
    assert!(short.iter().all(|b| *b == 77));
    Ok(())
}

#[tokio::test]
async fn primary_catalog_encrypted_finish_and_separate_abort_units_preserve_old_pin() -> Result<()>
{
    let fixture = Fixture::new().await?;
    let engine = engine(&fixture)?;
    let input = fixture.storage.admission.reserve_document_source(2 << 20)?;
    let mut authority = engine.lock_primary_apply()?;
    let scope = authority.scope();
    let latest = fixture.roots.gate.lock().unwrap().latest.clone();
    let (stage, alpha) = collection(PrimaryStage::begin_fresh(&mut authority)?, scope, "alpha")?;
    let id = CatalogId(next_id(&fixture)?);
    let stage = stage.begin_catalog()?.append_catalog("alpha", alpha)?;
    let unicode = "Ω".repeat(128);
    let (stage, omega) = collection(stage, scope, &unicode)?;
    let stage = stage.append_catalog(&unicode, omega)?;
    assert!(CellWeak::ptr_eq(
        &latest,
        &fixture.roots.gate.lock().unwrap().latest
    ));
    let before = inventory(&fixture, id.0)?;
    assert_eq!(before.total_units, 2);
    let (stage, done) = stage.finish_catalog_step(0)?;
    assert!(done.is_none());
    assert_eq!(inventory(&fixture, id.0)?, before);
    let (stage, done) = stage.finish_catalog_step(1)?;
    assert!(done.is_none());
    let (stage, done) = stage.finish_catalog_step(0)?;
    assert!(done.is_none());
    let (stage, done) = stage.finish_catalog_step(1)?;
    let done = done.context("catalog not finished")?;
    assert_eq!(
        (done.id(), done.scope(), done.member_count(), done.totals()),
        (id, scope, 2, Totals::default())
    );
    assert_eq!(inventory(&fixture, id.0)?.phase, InventoryPhase::Complete);
    assert_eq!(mapping(&fixture, id, "alpha")?.manifest, alpha);
    assert_eq!(member(&fixture, id, scope, 1)?.name(), unicode);
    let old = fixture.select()?;
    stage.close()?;
    let stage = PrimaryStage::resume_abort(&mut authority)?.context("stage absent")?;
    let (stage, done) = stage.abort_step(3)?;
    assert!(!done); // phase, definition, manifest
    assert_eq!(pending(&fixture)?.2.abort_object_cursor, id.0.ordinal);
    let (stage, done) = stage.abort_step(1)?;
    assert!(!done);
    assert_eq!(inventory(&fixture, id.0)?.cleanup_unit_cursor, 1);
    stage.close()?;
    let stage = PrimaryStage::resume_abort(&mut authority)?.context("stage absent")?;
    let (stage, done) = stage.abort_step(1)?;
    assert!(!done);
    let inv = inventory(&fixture, id.0)?;
    assert_eq!((inv.cleanup_unit_cursor, inv.completed_units), (2, 2));
    assert_eq!(pending(&fixture)?.2.abort_object_cursor, id.0.ordinal);
    stage.close()?;
    let stage = PrimaryStage::resume_abort(&mut authority)?.context("stage absent")?;
    let (stage, done) = stage.abort_step(1)?;
    assert!(!done);
    assert_eq!(pending(&fixture)?.2.abort_object_cursor, id.0.ordinal + 1);
    let (stage, done) = stage.abort_step(64)?;
    assert!(done);
    stage.close()?;
    for (ordinal, name, expected) in [(0, "alpha", alpha), (1, unicode.as_str(), omega)] {
        assert!(read(
            &fixture,
            MEMBERS,
            &CatalogMember::key(id, ordinal),
            CATALOG_MEMBER_BYTES,
            |b| Ok(b.is_none())
        )?);
        assert!(read(
            &fixture,
            CATALOG,
            &CatalogEntry::key(id, decode(records::name_hash(name))?),
            records::CATALOG_ENTRY_BYTES,
            |b| Ok(b.is_none())
        )?);
        let mut reader = old.open_primary_reader(&fixture.roots)?;
        let mut grant = fixture.storage.admission.reserve_document_source(4096)?;
        reader.with_record(
            &mut grant,
            4096,
            MEMBERS,
            &CatalogMember::key(id, ordinal),
            CATALOG_MEMBER_BYTES,
            |b| {
                assert_eq!(
                    decode(CatalogMember::decode(
                        b.context("old member absent")?,
                        id,
                        scope,
                        ordinal
                    ))?
                    .name(),
                    name
                );
                Ok(())
            },
        )?;
        reader.with_record(
            &mut grant,
            4096,
            CATALOG,
            &CatalogEntry::key(id, decode(records::name_hash(name))?),
            records::CATALOG_ENTRY_BYTES,
            |b| {
                assert_eq!(
                    decode(CatalogEntry::decode(b.context("old mapping absent")?))?.manifest,
                    expected
                );
                Ok(())
            },
        )?;
        reader.close()?;
    }
    drop(authority);
    drop(old);
    drop(input);
    engine.seal();
    drop(engine);
    fixture.close().await
}

#[tokio::test]
async fn primary_catalog_empty_zero_work_and_first_finish_bind_actual_records() -> Result<()> {
    for changed in 0..4 {
        let fixture = Fixture::new().await?;
        let engine = engine(&fixture)?;
        let mut authority = engine.lock_primary_apply()?;
        let stage = PrimaryStage::begin_fresh(&mut authority)?;
        let id = next_id(&fixture)?;
        let stage = stage.begin_catalog()?;
        let initial = inventory(&fixture, id)?;
        let before = pending(&fixture)?;
        let (stage, done) = stage.finish_catalog_step(0)?;
        assert!(done.is_none());
        assert_eq!(inventory(&fixture, id)?, initial);
        assert_eq!(pending(&fixture)?, before);
        if changed == 0 || changed == 3 {
            let (stage, done) = stage.finish_catalog_step(1)?;
            assert_eq!(
                done.context("empty catalog did not finish")?.member_count(),
                0
            );
            let error = if changed == 0 {
                stage.finish_catalog_step(1).err()
            } else {
                stage
                    .append_catalog(
                        "unused",
                        ManifestRef {
                            id,
                            sha256: [0; 32],
                        },
                    )
                    .err()
            }
            .context("completed catalog accepted another mutation")?;
            assert!(error.to_string().contains(if changed == 0 {
                "already complete"
            } else {
                "not appending"
            }));
            drop(error);
        } else {
            if changed == 1 {
                set_inventory(
                    &fixture,
                    Inventory {
                        total_units: 1,
                        completed_units: 1,
                        catalog_dense_count: 1,
                        ..initial
                    },
                )?;
            } else {
                let mut attempt = before.2;
                attempt.phase = records::AttemptPhase::Prepared;
                let mut bytes = [0; records::ATTEMPT_BYTES];
                decode(attempt.encode(&mut bytes))?;
                fixture.stores.write_batch(
                    &[kasumi_store::WriteOp::put(
                        "engine.primary.attempts",
                        attempt.id,
                        bytes,
                    )],
                    &[],
                )?;
            }
            let corrupted = inventory(&fixture, id)?;
            let corrupted_pending = pending(&fixture)?;
            let error = stage
                .finish_catalog_step(1)
                .err()
                .context("cached finish accepted mutation")?;
            assert!(error.to_string().contains(if changed == 1 {
                "catalog inventory differs"
            } else {
                "owning attempt differs"
            }));
            assert_eq!(inventory(&fixture, id)?, corrupted);
            assert_eq!(pending(&fixture)?, corrupted_pending);
            drop(error);
            set_inventory(&fixture, initial)?;
            let mut bytes = [0; records::ATTEMPT_BYTES];
            decode(before.2.encode(&mut bytes))?;
            fixture.stores.write_batch(
                &[kasumi_store::WriteOp::put(
                    "engine.primary.attempts",
                    before.2.id,
                    bytes,
                )],
                &[],
            )?;
        }
        let stage = PrimaryStage::resume_abort(&mut authority)?.context("stage absent")?;
        let (stage, done) = stage.abort_step(1)?;
        assert!(!done); // phase only
        let (stage, done) = stage.abort_step(1)?;
        assert!(!done); // empty resource retirement
        assert_eq!(pending(&fixture)?.2.live_resources, 0);
        let (stage, done) = stage.abort_step(1)?;
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
async fn primary_catalog_append_refusals_preserve_durable_membership() -> Result<()> {
    for refusal in 0..7 {
        let fixture = Fixture::new().await?;
        let engine = engine(&fixture)?;
        let input = fixture.storage.admission.reserve_document_source(1 << 20)?;
        let mut authority = engine.lock_primary_apply()?;
        let scope = authority.scope();
        let (stage, alpha) =
            collection(PrimaryStage::begin_fresh(&mut authority)?, scope, "alpha")?;
        let (stage, beta) = collection(stage, scope, "beta")?;
        let id = CatalogId(next_id(&fixture)?);
        let stage = stage.begin_catalog()?.append_catalog("alpha", alpha)?;
        let original_manifest = inventory(&fixture, beta.id)?;
        let before = pending(&fixture)?;
        let before_inv = inventory(&fixture, id.0)?;
        let mut reference = beta;
        let mut name = "beta";
        match refusal {
            0 => {
                name = "alpha";
                reference = alpha;
            }
            1 => name = "A",
            2 => {
                let entry = CatalogEntry {
                    catalog: id,
                    scope,
                    name_hash: decode(records::name_hash(name))?,
                    manifest: beta,
                };
                let mut bytes = [0; records::CATALOG_ENTRY_BYTES];
                decode(entry.encode(&mut bytes))?;
                fixture.stores.write_batch(
                    &[kasumi_store::WriteOp::put(
                        CATALOG,
                        CatalogEntry::key(id, entry.name_hash),
                        bytes,
                    )],
                    &[],
                )?;
            }
            3 => reference.id.attempt = [99; 16],
            4 => fixture.stores.write_batch(
                &[kasumi_store::WriteOp::delete(
                    "engine.primary.inventory",
                    key(beta.id),
                )],
                &[],
            )?,
            5 => set_inventory(
                &fixture,
                Inventory {
                    phase: InventoryPhase::Allocating,
                    ..original_manifest
                },
            )?,
            6 => reference.sha256[0] ^= 1,
            _ => unreachable!(),
        }
        let error = stage
            .append_catalog(name, reference)
            .err()
            .context("invalid append accepted")?;
        assert!(error.chain().count() >= 2);
        assert_eq!(pending(&fixture)?, before);
        assert_eq!(inventory(&fixture, id.0)?, before_inv);
        assert_eq!(member(&fixture, id, scope, 0)?.name(), "alpha");
        assert!(read(
            &fixture,
            MEMBERS,
            &CatalogMember::key(id, 1),
            CATALOG_MEMBER_BYTES,
            |b| Ok(b.is_none())
        )?);
        drop(error);
        if refusal == 2 {
            fixture.stores.write_batch(
                &[kasumi_store::WriteOp::delete(
                    CATALOG,
                    CatalogEntry::key(id, decode(records::name_hash("beta"))?),
                )],
                &[],
            )?;
        }
        set_inventory(&fixture, original_manifest)?;
        let stage = PrimaryStage::resume_abort(&mut authority)?.context("stage absent")?;
        let (stage, done) = stage.abort_step(64)?;
        assert!(done);
        stage.close()?;
        drop(authority);
        drop(input);
        engine.seal();
        drop(engine);
        fixture.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn primary_catalog_partial_verifier_keeps_its_exact_pin() -> Result<()> {
    let fixture = Fixture::new().await?;
    let engine = engine(&fixture)?;
    let input = fixture.storage.admission.reserve_document_source(1 << 20)?;
    let mut authority = engine.lock_primary_apply()?;
    let scope = authority.scope();
    let (stage, alpha) = collection(PrimaryStage::begin_fresh(&mut authority)?, scope, "alpha")?;
    let (stage, beta) = collection(stage, scope, "beta")?;
    let id = CatalogId(next_id(&fixture)?);
    let stage = stage
        .begin_catalog()?
        .append_catalog("alpha", alpha)?
        .append_catalog("beta", beta)?;
    let (stage, done) = stage.finish_catalog_step(1)?;
    assert!(done.is_none());
    let original = mapping(&fixture, id, "beta")?;
    let wrong = CatalogEntry {
        manifest: alpha,
        ..original
    };
    let mut bytes = [0; records::CATALOG_ENTRY_BYTES];
    decode(wrong.encode(&mut bytes))?;
    // Deliberately bypass the real producer guard only to distinguish native
    // snapshots. The result proves the bound pin, not arbitrary current bytes.
    fixture.stores.write_batch(
        &[kasumi_store::WriteOp::put(
            CATALOG,
            CatalogEntry::key(id, original.name_hash),
            bytes,
        )],
        &[],
    )?;
    let (stage, done) = stage.finish_catalog_step(1)?;
    assert_eq!(done.context("old-pin finish absent")?.member_count(), 2);
    assert_eq!(mapping(&fixture, id, "beta")?.manifest, alpha);
    stage.close()?;
    decode(original.encode(&mut bytes))?;
    fixture.stores.write_batch(
        &[kasumi_store::WriteOp::put(
            CATALOG,
            CatalogEntry::key(id, original.name_hash),
            bytes,
        )],
        &[],
    )?;
    let stage = PrimaryStage::resume_abort(&mut authority)?.context("stage absent")?;
    let (stage, done) = stage.abort_step(64)?;
    assert!(done);
    stage.close()?;
    drop(authority);
    drop(input);
    engine.seal();
    drop(engine);
    fixture.close().await
}

#[tokio::test]
async fn primary_catalog_verifier_refuses_mutations_and_pin_replacement() -> Result<()> {
    for action in 0..7 {
        let fixture = Fixture::new().await?;
        let engine = engine(&fixture)?;
        let input = fixture.storage.admission.reserve_document_source(1 << 20)?;
        let mut authority = engine.lock_primary_apply()?;
        let scope = authority.scope();
        let (stage, alpha) =
            collection(PrimaryStage::begin_fresh(&mut authority)?, scope, "alpha")?;
        let (stage, beta) = collection(stage, scope, "beta")?;
        let manifest = read(
            &fixture,
            "engine.primary.manifests",
            &key(alpha.id),
            records::MANIFEST_BYTES,
            |b| decode(Manifest::decode(b.context("manifest absent")?)),
        )?;
        let id = CatalogId(next_id(&fixture)?);
        let stage = stage
            .begin_catalog()?
            .append_catalog("alpha", alpha)?
            .append_catalog("beta", beta)?;
        let (stage, done) = stage.finish_catalog_step(1)?;
        assert!(done.is_none());
        let before = pending(&fixture)?;
        let before_inv = inventory(&fixture, id.0)?;
        let doc = document(32);
        let error = match action {
            0 => stage.stage_dto([91; 16], CanonicalDto::Live(&doc)).err(),
            1 => stage.stage_page([91; 16], 1, 0, &[]).err(),
            2 => stage.stage_manifest(manifest).err(),
            3 => stage
                .visit_staged(
                    manifest.definition,
                    [91; 16],
                    ResourceKind::Definition,
                    |_| Ok(()),
                )
                .err(),
            4 => stage.abort_step(1).err(),
            5 => stage.append_catalog("beta", beta).err(),
            6 => stage.begin_catalog().err(),
            _ => unreachable!(),
        }
        .context("verifier permitted mutation/refresh")?;
        assert!(error.to_string().contains(if action == 5 {
            "not appending"
        } else {
            "verification owns the source pin"
        }));
        assert_eq!(pending(&fixture)?, before);
        assert_eq!(inventory(&fixture, id.0)?, before_inv);
        drop(error);
        let stage = PrimaryStage::resume_abort(&mut authority)?.context("stage absent")?;
        let (stage, done) = stage.abort_step(64)?;
        assert!(done);
        stage.close()?;
        drop(authority);
        drop(doc);
        drop(input);
        engine.seal();
        drop(engine);
        fixture.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn primary_catalog_abort_missing_or_corrupt_owned_rows_retains_progress() -> Result<()> {
    for mapping_row in [false, true] {
        for missing in [false, true] {
            let fixture = Fixture::new().await?;
            let engine = engine(&fixture)?;
            let input = fixture.storage.admission.reserve_document_source(1 << 20)?;
            let mut authority = engine.lock_primary_apply()?;
            let scope = authority.scope();
            let (stage, alpha) =
                collection(PrimaryStage::begin_fresh(&mut authority)?, scope, "alpha")?;
            let id = CatalogId(next_id(&fixture)?);
            let stage = stage.begin_catalog()?.append_catalog("alpha", alpha)?;
            stage.close()?;
            let (namespace, row_key, size) = if mapping_row {
                (
                    CATALOG,
                    CatalogEntry::key(id, decode(records::name_hash("alpha"))?).to_vec(),
                    records::CATALOG_ENTRY_BYTES,
                )
            } else {
                (
                    MEMBERS,
                    CatalogMember::key(id, 0).to_vec(),
                    CATALOG_MEMBER_BYTES,
                )
            };
            let original = read(&fixture, namespace, &row_key, size, |b| {
                Ok(b.context("row absent")?.to_vec())
            })?;
            let mut corrupt = original.clone();
            corrupt[10] = 1;
            fixture.stores.write_batch(
                &[if missing {
                    kasumi_store::WriteOp::delete(namespace, row_key.clone())
                } else {
                    kasumi_store::WriteOp::put(namespace, row_key.clone(), corrupt.clone())
                }],
                &[],
            )?;
            let stage = PrimaryStage::resume_abort(&mut authority)?.context("stage absent")?;
            // Its referenced manifest is removed first. Catalog abort must never
            // require the independently owned manifest to remain present.
            let (stage, done) = stage.abort_step(3)?;
            assert!(!done);
            let before = pending(&fixture)?;
            let before_inv = inventory(&fixture, id.0)?;
            let error = stage.abort_step(1).err().context("invalid row erased")?;
            assert!(error.chain().count() >= 2);
            assert_eq!(pending(&fixture)?, before);
            assert_eq!(inventory(&fixture, id.0)?, before_inv);
            read(&fixture, namespace, &row_key, size, |b| {
                assert_eq!(
                    b,
                    if missing {
                        None
                    } else {
                        Some(corrupt.as_slice())
                    }
                );
                Ok(())
            })?;
            drop(error);
            fixture.stores.write_batch(
                &[kasumi_store::WriteOp::put(namespace, row_key, original)],
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
            fixture.close().await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn primary_catalog_real_admission_denial_precedes_append_effects() -> Result<()> {
    for slots in [false, true] {
        let fixture = Fixture::new().await?;
        let engine = engine(&fixture)?;
        let input = fixture.storage.admission.reserve_document_source(2 << 20)?;
        let mut authority = engine.lock_primary_apply()?;
        let scope = authority.scope();
        let (stage, alpha) =
            collection(PrimaryStage::begin_fresh(&mut authority)?, scope, "alpha")?;
        let id = CatalogId(next_id(&fixture)?);
        let stage = stage.begin_catalog()?;
        let before = pending(&fixture)?;
        let before_inv = inventory(&fixture, id.0)?;
        let admission = &fixture.storage.admission;
        let mut held = Vec::with_capacity(4096);
        if slots {
            while let Ok(grant) = admission.reserve_resident(1) {
                held.push(grant);
                assert!(held.len() <= 4096);
            }
        } else {
            // Find the largest real ordinary reservation allowed by the unchanged
            // installed protection. Each probe is immediately returned.
            let (mut low, mut high) = (0_u64, fixture.budget);
            while low < high {
                let mid = low + (high - low).div_ceil(2);
                if admission.reserve(mid, None).is_ok() {
                    low = mid;
                } else {
                    high = mid - 1;
                }
            }
            assert!(low > 0);
            held.push(admission.reserve(low, None)?);
        }
        let error = stage
            .append_catalog("alpha", alpha)
            .err()
            .context("saturated admission accepted append")?;
        assert!(error.chain().any(|source| {
            source
                .downcast_ref::<kasumi_types::Error>()
                .is_some_and(|e| e.code == kasumi_types::ErrorCode::ResourceExhausted)
        }));
        drop(held); // Release test pressure before observing the encrypted state.
        assert_eq!(pending(&fixture)?, before);
        assert_eq!(inventory(&fixture, id.0)?, before_inv);
        assert!(read(
            &fixture,
            MEMBERS,
            &CatalogMember::key(id, 0),
            CATALOG_MEMBER_BYTES,
            |b| Ok(b.is_none())
        )?);
        drop(error);
        let stage = PrimaryStage::resume_abort(&mut authority)?.context("stage absent")?;
        let (stage, done) = stage.abort_step(64)?;
        assert!(done);
        stage.close()?;
        drop(authority);
        drop(input);
        engine.seal();
        drop(engine);
        fixture.close().await?;
    }
    Ok(())
}

fn live_collection<'a, 'b>(
    stage: PrimaryStage<'a, 'b>,
    scope: [u8; 32],
    name: &str,
    version: u64,
) -> Result<(PrimaryStage<'a, 'b>, ManifestRef, Totals)> {
    use crate::primary_tree::{Entry, Leaf, RecordKind, Value, records::Root};
    let definition = kasumi_types::CollectionDefinition {
        name: name.into(),
        write_mode: kasumi_types::CollectionWriteMode::Mutable,
        retention_class: kasumi_types::CollectionRetentionClass::Operational,
        schema: serde_json::json!({}),
        indexes: Vec::new(),
        strict_read_audit: false,
    };
    let tree = [93; 16];
    let (stage, definition) = stage.stage_dto(tree, CanonicalDto::Definition(&definition))?;
    let mut doc = document(32);
    doc.version = version;
    let (stage, object) = stage.stage_dto(tree, CanonicalDto::Live(&doc))?;
    let (stage, page) = stage.stage_page(
        tree,
        version,
        0,
        &[Entry {
            id: &doc.id,
            value: Value::Leaf(Leaf {
                version,
                kind: RecordKind::Live,
                object,
                semantic_bytes: crate::accounting::encoded_len(&doc.body)? as u64,
            }),
        }],
    )?;
    let (stage, manifest) = stage.stage_manifest(Manifest {
        scope,
        name_hash: decode(records::name_hash(name))?,
        tree_id: tree,
        definition,
        data_epoch: version,
        revision: version,
        root: Some(Root {
            reference: page.reference,
            level: 0,
        }),
        totals: page.totals,
    })?;
    Ok((stage, manifest, page.totals))
}

#[tokio::test]
async fn primary_catalog_nonempty_totals_and_mapping_cow_preserve_membership() -> Result<()> {
    let fixture = Fixture::new().await?;
    let engine = engine(&fixture)?;
    let input = fixture.storage.admission.reserve_document_source(2 << 20)?;
    let mut authority = engine.lock_primary_apply()?;
    let scope = authority.scope();
    let (stage, alpha, first_totals) = live_collection(
        PrimaryStage::begin_fresh(&mut authority)?,
        scope,
        "alpha",
        1,
    )?;
    let (stage, beta, second_totals) = live_collection(stage, scope, "beta", 1)?;
    let (stage, next_alpha, next_totals) = live_collection(stage, scope, "alpha", 2)?;
    assert_eq!(first_totals, next_totals);
    let id = CatalogId(next_id(&fixture)?);
    let stage = stage
        .begin_catalog()?
        .append_catalog("alpha", alpha)?
        .append_catalog("beta", beta)?;
    let (stage, done) = stage.finish_catalog_step(64)?;
    let total = done.context("nonempty catalog did not finish")?.totals();
    assert_eq!(total.live_count, 2);
    assert_eq!(
        total.live_body_bytes,
        first_totals.live_body_bytes + second_totals.live_body_bytes
    );
    assert_eq!(
        (total.archived_count, total.archived_metadata_bytes),
        (0, 0)
    );
    let original_member = member(&fixture, id, scope, 0)?;
    let mut original_bytes = [0; CATALOG_MEMBER_BYTES];
    decode(original_member.encode(&mut original_bytes))?;
    let old = fixture.select()?;
    let entry = CatalogEntry {
        manifest: next_alpha,
        ..mapping(&fixture, id, "alpha")?
    };
    let mut bytes = [0; records::CATALOG_ENTRY_BYTES];
    decode(entry.encode(&mut bytes))?;
    // Exercise the native mapping COW primitive only. The production atomic
    // selector/canonical-boundary/retirement publisher is a later integration.
    fixture.stores.write_batch(
        &[kasumi_store::WriteOp::put(
            CATALOG,
            CatalogEntry::key(id, entry.name_hash),
            bytes,
        )],
        &[],
    )?;
    let new = fixture.select()?;
    for (selected, expected) in [(&old, alpha), (&new, next_alpha)] {
        let mut reader = selected.open_primary_reader(&fixture.roots)?;
        let mut grant = fixture.storage.admission.reserve_document_source(4096)?;
        reader.with_record(
            &mut grant,
            4096,
            CATALOG,
            &CatalogEntry::key(id, entry.name_hash),
            records::CATALOG_ENTRY_BYTES,
            |b| {
                assert_eq!(
                    decode(CatalogEntry::decode(b.context("pinned mapping absent")?))?.manifest,
                    expected
                );
                Ok(())
            },
        )?;
        reader.with_record(
            &mut grant,
            4096,
            MEMBERS,
            &CatalogMember::key(id, 0),
            CATALOG_MEMBER_BYTES,
            |b| {
                assert_eq!(b, Some(original_bytes.as_slice()));
                Ok(())
            },
        )?;
        reader.with_record(
            &mut grant,
            4096,
            "engine.primary.manifests",
            &key(expected.id),
            records::MANIFEST_BYTES,
            |b| {
                let manifest = decode(Manifest::decode_referenced(
                    b.context("pinned manifest absent")?,
                    expected,
                ))?;
                assert_eq!(manifest.name_hash, entry.name_hash);
                assert_eq!(manifest.totals, first_totals);
                Ok(())
            },
        )?;
        reader.close()?;
    }
    stage.close()?;
    let stage = PrimaryStage::resume_abort(&mut authority)?.context("stage absent")?;
    let (stage, done) = stage.abort_step(64)?;
    assert!(done);
    stage.close()?;
    drop(authority);
    drop(old);
    drop(new);
    drop(input);
    engine.seal();
    drop(engine);
    fixture.close().await
}
