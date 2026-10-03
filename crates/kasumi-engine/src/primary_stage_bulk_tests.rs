use super::*;
use crate::primary_tree::{
    ExpectedPage, KeyRange, PAGE_BYTES, RecordKind, Totals, Value,
    records::Manifest,
    stage::bulk::{self, BuiltCollection},
};
use kasumi_query::{
    CollectionRecords, QueryCancellation, ReadFailure, ReadResult, Record, SourceIdentity,
};
use kasumi_types::{
    ArchivedDocument, CollectionDefinition, CollectionRetentionClass, CollectionWriteMode,
};
use std::cell::{Cell, RefCell};

#[derive(Debug)]
struct InputFailure(Box<u64>);
impl std::fmt::Display for InputFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("original bulk input failure")
    }
}
impl std::error::Error for InputFailure {}
#[derive(Clone, Copy)]
enum Behavior {
    Normal,
    Duplicate,
    WrongDocument,
    SwitchOwner,
    Swallow,
}
struct Rows {
    definition: CollectionDefinition,
    incarnation: String,
    count: usize,
    payload: usize,
    long: bool,
    mixed: bool,
    behavior: Behavior,
    switched: Cell<bool>,
    callbacks: Cell<usize>,
    input_failure: RefCell<Option<InputFailure>>,
    panic: RefCell<Option<Box<u64>>>,
}
impl Rows {
    fn new(count: usize) -> Self {
        Self {
            definition: CollectionDefinition {
                name: "objects".into(),
                write_mode: CollectionWriteMode::Mutable,
                retention_class: CollectionRetentionClass::Operational,
                schema: serde_json::json!({}),
                indexes: Vec::new(),
                strict_read_audit: false,
            },
            incarnation: uuid::Uuid::from_u128(73).to_string(),
            count,
            payload: 0,
            long: false,
            mixed: false,
            behavior: Behavior::Normal,
            switched: Cell::new(false),
            callbacks: Cell::new(0),
            input_failure: RefCell::new(None),
            panic: RefCell::new(None),
        }
    }
    fn id(&self, i: usize) -> String {
        if self.long {
            format!("{}{i:04}", "x".repeat(252))
        } else {
            format!("r{i:04}")
        }
    }
    fn doc(&self, i: usize) -> kasumi_types::Document {
        kasumi_types::Document {
            id: self.id(i),
            version: u64::from(i != 0),
            body: if self.payload == 0 {
                serde_json::json!({"value": i})
            } else {
                serde_json::json!({"payload": "x".repeat(self.payload)})
            },
        }
    }
    fn archived(&self) -> ArchivedDocument {
        ArchivedDocument {
            version: 1,
            archive_id: "physical-fixture".into(),
            chunk_index: 0,
            document_sha256: "00".repeat(32),
            document_bytes: 32,
            indexed_fields: std::collections::BTreeMap::new(),
        }
    }
}
impl CollectionRecords for Rows {
    type Failure = InputFailure;
    fn identity(&self) -> SourceIdentity<'_> {
        SourceIdentity::new(
            self,
            if self.switched.get() {
                "foreign"
            } else {
                "selected-sources"
            },
            &self.incarnation,
            &self.definition.name,
        )
    }
    fn definition(&self) -> &CollectionDefinition {
        &self.definition
    }
    fn visit_records(
        &self,
        mut lend: impl for<'a> FnMut(&'a str, Record<'a>) -> kasumi_types::Result<()>,
    ) -> ReadResult<(), InputFailure> {
        if matches!(self.behavior, Behavior::SwitchOwner) {
            self.switched.set(true);
        }
        for i in 0..self.count {
            let index =
                if matches!(self.behavior, Behavior::Duplicate | Behavior::Swallow) && i == 1 {
                    0
                } else {
                    i
                };
            let id = self.id(index);
            self.callbacks.set(self.callbacks.get() + 1);
            let result = if self.mixed && !i.is_multiple_of(2) {
                lend(&id, Record::Archived(&self.archived()))
            } else {
                let mut doc = self.doc(index);
                if matches!(self.behavior, Behavior::WrongDocument) {
                    doc.id = "different".into();
                }
                lend(&id, Record::Live(&doc))
            };
            if !matches!(self.behavior, Behavior::Swallow) {
                result?;
            }
        }
        if let Some(payload) = self.panic.borrow_mut().take() {
            std::panic::panic_any(payload);
        }
        if let Some(original) = self.input_failure.borrow_mut().take() {
            return Err(ReadFailure::Source(original));
        }
        Ok(())
    }
}
fn abort_all(authority: &mut crate::state::PrimaryApplyGuard<'_>) -> Result<()> {
    let mut stage =
        PrimaryStage::resume_abort(authority)?.context("bulk pending attempt absent")?;
    loop {
        let (next, done) = stage.abort_step(64)?;
        stage = next;
        if done {
            break;
        }
    }
    stage.close()
}
fn read_manifest(fixture: &Fixture, built: &BuiltCollection) -> Result<Manifest> {
    read(
        fixture,
        "engine.primary.manifests",
        &key(built.manifest_ref().id),
        records::MANIFEST_BYTES,
        |bytes| {
            decode(Manifest::decode_referenced(
                bytes.context("bulk manifest absent")?,
                built.manifest_ref(),
            ))
        },
    )
}

// Synchronous encrypted tree work must not starve the real key-renewal task.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn primary_bulk_two_level_mixed_stream_zero_version_and_old_pin() -> Result<()> {
    let fixture = Fixture::new().await?;
    {
        let engine = engine(&fixture)?;
        let input = fixture.storage.admission.reserve_document_source(2 << 20)?;
        let mut rows = Rows::new(48);
        rows.long = true;
        rows.mixed = true;
        let mut authority = engine.lock_primary_apply()?;
        let stage = PrimaryStage::begin_fresh(&mut authority)?;
        let (stage, built) =
            bulk::build_fresh_collection(stage, &rows, 1, 1, &QueryCancellation::default())
                .unwrap_or_else(|failure| panic!("bulk build failed: {failure:?}"));
        let manifest = read_manifest(&fixture, &built)?;
        assert_eq!(&manifest, built.manifest());
        let root = manifest.root.context("bulk root absent")?;
        assert_eq!(root.level, 1);
        let children = read(
            &fixture,
            "engine.primary.pages",
            &key(root.reference.id),
            PAGE_BYTES,
            |bytes| {
                let page = decode(crate::primary_tree::validate(
                    bytes.context("bulk root page absent")?,
                    ExpectedPage {
                        tree_id: manifest.tree_id,
                        reference: root.reference,
                        generation_ceiling: 1,
                        level: 1,
                        totals: manifest.totals,
                        range: KeyRange::default(),
                    },
                ))?;
                page.entries()
                    .map(|entry| match entry.value {
                        Value::Child(child) => Ok((entry.id.to_owned(), child)),
                        _ => anyhow::bail!("root has leaf"),
                    })
                    .collect::<Result<Vec<_>>>()
            },
        )?;
        assert_eq!(children.len(), 2);
        assert_eq!(
            children[0].1.totals.live_count + children[0].1.totals.archived_count,
            47
        );
        assert_eq!(
            children[1].1.totals.live_count + children[1].1.totals.archived_count,
            1
        );
        let mut observed = Totals::default();
        let mut count = 0;
        for (i, (lower, child)) in children.iter().enumerate() {
            read(
                &fixture,
                "engine.primary.pages",
                &key(child.reference.id),
                PAGE_BYTES,
                |bytes| {
                    let page = decode(crate::primary_tree::validate(
                        bytes.context("bulk leaf absent")?,
                        ExpectedPage {
                            tree_id: manifest.tree_id,
                            reference: child.reference,
                            generation_ceiling: 1,
                            level: 0,
                            totals: child.totals,
                            range: KeyRange {
                                lower: Some(lower),
                                upper: children.get(i + 1).map(|p| p.0.as_str()),
                            },
                        },
                    ))?;
                    for entry in page.entries() {
                        assert_eq!(entry.id, rows.id(count));
                        let Value::Leaf(leaf) = entry.value else {
                            panic!("leaf has child")
                        };
                        let (expected, kind, semantic_bytes) = if count.is_multiple_of(2) {
                            let doc = rows.doc(count);
                            assert_eq!(leaf.version, doc.version); // restored version zero included
                            let body_bytes = crate::accounting::encoded_len(&doc.body)? as u64;
                            observed.live_count += 1;
                            observed.live_body_bytes += body_bytes;
                            (serde_json::to_vec(&doc)?, RecordKind::Live, body_bytes)
                        } else {
                            let wire = serde_json::to_vec(&rows.archived())?;
                            let semantic = decode(crate::primary_tree::archived_metadata_bytes(
                                entry.id,
                                wire.len() as u64,
                            ))?;
                            observed.archived_count += 1;
                            observed.archived_metadata_bytes += semantic;
                            (wire, RecordKind::Archived, semantic)
                        };
                        assert_eq!(leaf.kind, kind);
                        assert_eq!(leaf.semantic_bytes, semantic_bytes);
                        assert_eq!(leaf.object.encoded_bytes, expected.len() as u64);
                        assert_eq!(
                            leaf.object.sha256,
                            <[u8; 32]>::from(Sha256::digest(&expected))
                        );
                        count += 1;
                    }
                    Ok(())
                },
            )?;
        }
        assert_eq!(count, 48);
        assert_eq!(observed, manifest.totals);
        let old = fixture.select()?;
        stage.close()?;
        abort_all(&mut authority)?;
        assert!(read(
            &fixture,
            "engine.primary.pages",
            &key(root.reference.id),
            PAGE_BYTES,
            |b| Ok(b.is_none())
        )?);
        let mut reader = old.open_primary_reader(&fixture.roots)?;
        let mut grant = fixture.storage.admission.reserve_document_source(4096)?;
        reader.with_record(
            &mut grant,
            4096,
            "engine.primary.manifests",
            &key(built.manifest_ref().id),
            records::MANIFEST_BYTES,
            |bytes| {
                assert_eq!(
                    decode(Manifest::decode_referenced(
                        bytes.context("old manifest absent")?,
                        built.manifest_ref()
                    ))?,
                    manifest
                );
                Ok(())
            },
        )?;
        reader.with_record(
            &mut grant,
            4096,
            "engine.primary.pages",
            &key(root.reference.id),
            PAGE_BYTES,
            |bytes| {
                let page = decode(crate::primary_tree::validate(
                    bytes.context("old root absent")?,
                    ExpectedPage {
                        tree_id: manifest.tree_id,
                        reference: root.reference,
                        generation_ceiling: 1,
                        level: 1,
                        totals: manifest.totals,
                        range: KeyRange::default(),
                    },
                ))?;
                assert_eq!(page.entries().len(), 2);
                Ok(())
            },
        )?;
        reader.close()?;
        drop((old, grant, children, rows, input, authority));
        engine.seal();
    }
    fixture.close().await
}

#[tokio::test]
async fn primary_bulk_empty_stream_has_definition_manifest_and_no_empty_page() -> Result<()> {
    let fixture = Fixture::new().await?;
    {
        let engine = engine(&fixture)?;
        let input = fixture.storage.admission.reserve_document_source(1 << 20)?;
        let rows = Rows::new(0);
        let mut authority = engine.lock_primary_apply()?;
        let (stage, built) = bulk::build_fresh_collection(
            PrimaryStage::begin_fresh(&mut authority)?,
            &rows,
            0,
            0,
            &QueryCancellation::default(),
        )
        .unwrap_or_else(|failure| panic!("empty build failed: {failure:?}"));
        let manifest = read_manifest(&fixture, &built)?;
        assert_eq!(manifest.root, None);
        assert_eq!(manifest.totals, Totals::default());
        assert_eq!(pending(&fixture)?.2.next_object, 2);
        stage.close()?;
        abort_all(&mut authority)?;
        drop((authority, rows, input));
        engine.seal();
    }
    fixture.close().await
}

#[tokio::test]
async fn primary_bulk_rejects_order_identity_and_epoch_without_final_manifest() -> Result<()> {
    let fixture = Fixture::new().await?;
    {
        let engine = engine(&fixture)?;
        let input = fixture.storage.admission.reserve_document_source(1 << 20)?;
        for (behavior, epoch, expected_objects) in [
            (Behavior::Duplicate, 1, 2),
            (Behavior::WrongDocument, 1, 1),
            (Behavior::SwitchOwner, 1, 1),
            (Behavior::Normal, 0, 2),
        ] {
            let mut rows = Rows::new(3);
            rows.behavior = behavior;
            let mut authority = engine.lock_primary_apply()?;
            let result = bulk::build_fresh_collection(
                PrimaryStage::begin_fresh(&mut authority)?,
                &rows,
                1,
                epoch,
                &QueryCancellation::default(),
            );
            let failure = match result {
                Err(failure) => failure,
                Ok(_) => panic!("invalid source accepted"),
            };
            assert!(failure.original().is_some());
            assert_eq!(pending(&fixture)?.2.next_object, expected_objects);
            drop(failure);
            abort_all(&mut authority)?;
        }
        drop(input);
        engine.seal();
    }
    fixture.close().await
}

#[tokio::test]
async fn primary_bulk_swallowed_callback_stays_closed_and_keeps_independent_source_error()
-> Result<()> {
    let fixture = Fixture::new().await?;
    {
        let engine = engine(&fixture)?;
        let input = fixture.storage.admission.reserve_document_source(1 << 20)?;
        let mut rows = Rows::new(4);
        rows.behavior = Behavior::Swallow;
        let marker = Box::new(9123);
        let address = std::ptr::from_ref(marker.as_ref());
        *rows.input_failure.borrow_mut() = Some(InputFailure(marker));
        let mut authority = engine.lock_primary_apply()?;
        let failure = match bulk::build_fresh_collection(
            PrimaryStage::begin_fresh(&mut authority)?,
            &rows,
            1,
            1,
            &QueryCancellation::default(),
        ) {
            Err(failure) => failure,
            Ok(_) => panic!("swallowed failure published"),
        };
        assert!(
            failure
                .original()
                .unwrap()
                .to_string()
                .contains("strictly ordered")
        );
        let Some(ReadFailure::Source(original)) = failure.input() else {
            panic!("original source error lost")
        };
        assert_eq!(std::ptr::from_ref(original.0.as_ref()), address);
        assert_eq!(*original.0, 9123);
        assert_eq!(rows.callbacks.get(), 4);
        assert_eq!(pending(&fixture)?.2.next_object, 2); // definition + first DTO only
        drop(failure);
        abort_all(&mut authority)?;
        drop((authority, rows, input));
        engine.seal();
    }
    fixture.close().await
}

#[tokio::test]
async fn primary_bulk_cancel_inside_large_dto_preserves_original_and_resumes_abort() -> Result<()> {
    let fixture = Fixture::new().await?;
    {
        let engine = engine(&fixture)?;
        let input = fixture.storage.admission.reserve_document_source(2 << 20)?;
        let mut rows = Rows::new(1);
        rows.payload = 3 * 65_536;
        let token = QueryCancellation::default();
        let mut authority = engine.lock_primary_apply()?;
        let stage = PrimaryStage::begin_fresh(&mut authority)?;
        // Cancel only after the actual encrypted first DTO chunk is durable.
        // No timing assumption, synthetic write, or relaxed test budget.
        let mut check = || -> Result<()> {
            let (_, _, attempt) = pending(&fixture)?;
            if attempt.next_object == 2 {
                let inventory = read(
                    &fixture,
                    "engine.primary.inventory",
                    &key(ObjectId {
                        attempt: attempt.id,
                        ordinal: 1,
                    }),
                    records::INVENTORY_BYTES,
                    |bytes| decode(Inventory::decode(bytes.context("large inventory absent")?)),
                )?;
                if inventory.completed_units >= 1 {
                    token.cancel();
                }
            }
            token.check().map_err(Into::into)
        };
        let failure = match bulk::build_checked(stage, &rows, 1, 1, &mut check) {
            Err(failure) => failure,
            Ok(_) => panic!("canceled build completed"),
        };
        assert!(token.is_cancelled());
        assert!(failure.original().unwrap().chain().any(|cause| {
            cause
                .downcast_ref::<kasumi_types::Error>()
                .is_some_and(|error| error.code == kasumi_types::ErrorCode::ResourceExhausted)
        }));
        let (_, _, attempt) = pending(&fixture)?;
        let inventory = read(
            &fixture,
            "engine.primary.inventory",
            &key(ObjectId {
                attempt: attempt.id,
                ordinal: 1,
            }),
            records::INVENTORY_BYTES,
            |bytes| {
                decode(Inventory::decode(
                    bytes.context("interrupted inventory absent")?,
                ))
            },
        )?;
        assert_eq!(inventory.phase, InventoryPhase::Allocating);
        assert_eq!(inventory.completed_units, 1);
        assert!(inventory.total_units > 1);
        drop(failure);
        abort_all(&mut authority)?;
        assert!(PrimaryStage::resume_abort(&mut authority)?.is_none());
        drop((authority, rows, input));
        engine.seal();
    }
    fixture.close().await
}

#[tokio::test]
#[allow(
    clippy::result_large_err,
    reason = "The allocator witness keeps the real typed failure inline; boxing would add unclaimed backing."
)]
async fn primary_bulk_actual_frontier_allocation_stays_charged_through_dealloc() -> Result<()> {
    let fixture = Fixture::new().await?;
    {
        let engine = engine(&fixture)?;
        let input = fixture.storage.admission.reserve_document_source(1 << 20)?;
        let rows = Rows::new(0);
        let mut authority = engine.lock_primary_apply()?;
        let stage = PrimaryStage::begin_fresh(&mut authority)?;
        let before = fixture.storage.admission.snapshot().reserved_bytes;
        let mut checks = 0;
        let token = QueryCancellation::default();
        let mut check = || -> Result<()> {
            checks += 1;
            if checks == 2 {
                token.cancel();
            }
            token.check().map_err(Into::into)
        };
        let (result, live, peak, allocations) =
            crate::document_pool::allocation_tests::measure_topology_input(|| {
                bulk::build_checked(stage, &rows, 1, 1, &mut check)
            });
        let failure = match result {
            Err(failure) => failure,
            Ok(_) => panic!("canceled frontier completed"),
        };
        let charged = fixture.storage.admission.snapshot().reserved_bytes - before;
        assert!(live > 3 << 20 && allocations >= 1);
        assert!(
            peak > 0 && peak as u64 <= charged,
            "actual heap {peak} exceeds frontier grant {charged}"
        );
        let (address, frontier) = failure.retire_frontier_for_test();
        let held = fixture.storage.admission.snapshot().reserved_bytes;
        crate::document_pool::allocation_tests::check_topology_input_drop(
            address,
            move || drop(frontier),
            || {
                assert_eq!(
                    fixture.storage.admission.snapshot().reserved_bytes,
                    held,
                    "grant released before actual Vec deallocation"
                );
            },
        );
        assert_eq!(
            fixture.storage.admission.snapshot().reserved_bytes,
            held - charged
        );
        abort_all(&mut authority)?;
        drop((authority, rows, input));
        engine.seal();
    }
    fixture.close().await
}

#[tokio::test]
async fn primary_bulk_callback_error_survives_later_source_panic() -> Result<()> {
    let fixture = Fixture::new().await?;
    {
        let engine = engine(&fixture)?;
        let input = fixture.storage.admission.reserve_document_source(1 << 20)?;
        let mut rows = Rows::new(3);
        rows.behavior = Behavior::Swallow;
        let payload = Box::new(6429);
        let address = std::ptr::from_ref(payload.as_ref());
        *rows.panic.borrow_mut() = Some(payload);
        let mut authority = engine.lock_primary_apply()?;
        let failure = match bulk::build_fresh_collection(
            PrimaryStage::begin_fresh(&mut authority)?,
            &rows,
            1,
            1,
            &QueryCancellation::default(),
        ) {
            Err(failure) => failure,
            Ok(_) => panic!("panicked source published"),
        };
        assert!(
            failure
                .original()
                .unwrap()
                .to_string()
                .contains("strictly ordered")
        );
        let retained = failure
            .panic_payload()
            .unwrap()
            .downcast_ref::<Box<u64>>()
            .unwrap();
        assert_eq!(std::ptr::from_ref(retained.as_ref()), address);
        assert_eq!(**retained, 6429);
        assert_eq!(pending(&fixture)?.2.next_object, 2);
        drop(failure);
        abort_all(&mut authority)?;
        drop((authority, rows, input));
        engine.seal();
    }
    fixture.close().await
}

#[tokio::test]
#[allow(
    clippy::result_large_err,
    reason = "The refusal witness keeps the real typed failure inline and must not allocate an error box."
)]
async fn primary_bulk_frontier_denial_precedes_backing_allocation_or_source_visit() -> Result<()> {
    let fixture = Fixture::new().await?;
    {
        let engine = engine(&fixture)?;
        let input = fixture.storage.admission.reserve_document_source(1 << 20)?;
        let rows = Rows::new(1);
        let mut authority = engine.lock_primary_apply()?;
        let stage = PrimaryStage::begin_fresh(&mut authority)?;
        let remaining = fixture.budget - fixture.storage.admission.snapshot().reserved_bytes;
        let filler = fixture.storage.admission.reserve_resident(remaining)?;
        let (result, _, peak, _) =
            crate::document_pool::allocation_tests::measure_topology_input(|| {
                bulk::build_fresh_collection(stage, &rows, 1, 1, &QueryCancellation::default())
            });
        let failure = match result {
            Err(failure) => failure,
            Ok(_) => panic!("unfunded frontier accepted"),
        };
        assert!(
            failure
                .original()
                .unwrap()
                .downcast_ref::<kasumi_types::Error>()
                .is_some()
        );
        assert_eq!(rows.callbacks.get(), 0);
        assert!(
            peak < 65_536,
            "denied frontier allocated page backing: {peak}"
        );
        drop((failure, filler));
        assert_eq!(pending(&fixture)?.2.next_object, 0);
        abort_all(&mut authority)?;
        drop((authority, rows, input));
        engine.seal();
    }
    fixture.close().await
}

#[tokio::test]
async fn primary_bulk_swallowed_callback_panic_permanently_stops_writes() -> Result<()> {
    let fixture = Fixture::new().await?;
    {
        let engine = engine(&fixture)?;
        let input = fixture.storage.admission.reserve_document_source(1 << 20)?;
        let mut rows = Rows::new(3);
        rows.behavior = Behavior::Swallow;
        let mut payload = Some(Box::new(5311_u64));
        let address = std::ptr::from_ref(payload.as_ref().unwrap().as_ref());
        let mut check = || -> Result<()> {
            if rows.callbacks.get() == 1 && payload.is_some() {
                std::panic::panic_any(payload.take().unwrap());
            }
            Ok(())
        };
        let mut authority = engine.lock_primary_apply()?;
        let failure = match bulk::build_checked(
            PrimaryStage::begin_fresh(&mut authority)?,
            &rows,
            1,
            1,
            &mut check,
        ) {
            Err(failure) => failure,
            Ok(_) => panic!("swallowed callback panic published"),
        };
        let retained = failure
            .callback_panic_payload()
            .unwrap()
            .downcast_ref::<Box<u64>>()
            .unwrap();
        assert_eq!(std::ptr::from_ref(retained.as_ref()), address);
        assert_eq!(**retained, 5311);
        assert_eq!(rows.callbacks.get(), 3);
        assert_eq!(pending(&fixture)?.2.next_object, 1); // definition only
        drop(failure);
        abort_all(&mut authority)?;
        drop((authority, rows, input));
        engine.seal();
    }
    fixture.close().await
}

fn framing_children(
    fixture: &Fixture,
    expected: ExpectedPage<'_>,
) -> Result<Vec<(String, crate::primary_tree::Child)>> {
    read(
        fixture,
        "engine.primary.pages",
        &key(expected.reference.id),
        PAGE_BYTES,
        |bytes| {
            let page = decode(crate::primary_tree::validate(
                bytes.context("framing interior page absent")?,
                expected,
            ))?;
            assert!(page.entries().len() <= bulk::frontier_fixture::PER_PAGE);
            page.entries()
                .map(|entry| match entry.value {
                    Value::Child(child) => Ok((entry.id.to_owned(), child)),
                    _ => anyhow::bail!("framing interior contains a leaf"),
                })
                .collect()
        },
    )
}

// The recursive encrypted frontier also needs renewal during synchronous work.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn primary_bulk_real_frontier_three_levels_recursive_spill_and_final_collapse() -> Result<()>
{
    use bulk::frontier_fixture as framing;

    // Framing-only fixture: every descriptor names one real staged Archived DTO.
    // It intentionally avoids 2,257 redundant DTO writes, and does not qualify
    // a full accepted CollectionRecords stream, archive eligibility or hydration.
    let fixture = Fixture::new().await?;
    {
        let engine = engine(&fixture)?;
        let input = fixture.storage.admission.reserve_document_source(2 << 20)?;
        let archived = Rows::new(0).archived();
        let wire = serde_json::to_vec(&archived)?;
        let mut authority = engine.lock_primary_apply()?;
        let (stage, built) = framing::stage(PrimaryStage::begin_fresh(&mut authority)?, &archived)?;
        assert_eq!(built.object.encoded_bytes, wire.len() as u64);
        assert_eq!(built.object.sha256, <[u8; 32]>::from(Sha256::digest(&wire)));
        let mut actual_bytes = 0;
        let mut actual_hash = Sha256::new();
        let stage =
            stage.visit_staged(built.object, built.tree, ResourceKind::Archived, |chunk| {
                actual_bytes += chunk.len();
                actual_hash.update(chunk);
                Ok(())
            })?;
        assert_eq!(actual_bytes, wire.len());
        assert_eq!(
            <[u8; 32]>::from(actual_hash.finalize()),
            built.object.sha256
        );

        assert_eq!(built.root.level, 2);
        assert_eq!(built.collapsed, built.root);
        assert_eq!(built.objects_before_collapse, 53); // one DTO + 52 real pages
        assert_eq!(built.objects_after_collapse, built.objects_before_collapse);
        assert_eq!(
            pending(&fixture)?.2.next_object,
            built.objects_after_collapse
        );
        let expected_totals = Totals {
            archived_count: framing::ROWS as u64,
            archived_metadata_bytes: framing::ROWS as u64 * built.semantic_bytes,
            ..Totals::default()
        };
        assert_eq!(built.totals, expected_totals);
        let roots = framing_children(
            &fixture,
            ExpectedPage {
                tree_id: built.tree,
                reference: built.root.reference,
                generation_ceiling: 1,
                level: 2,
                totals: expected_totals,
                range: KeyRange::default(),
            },
        )?;
        assert_eq!(roots.len(), 2);
        assert_eq!(roots[0].1.totals.archived_count, 2209);
        assert_eq!(roots[1].1.totals.archived_count, 48);
        let mut observed = Totals::default();
        let mut next_row = 0;
        let mut leaves = 0;
        for (interior_index, (lower, interior)) in roots.iter().enumerate() {
            assert_eq!(lower.as_bytes(), framing::id(next_row).as_slice());
            let upper = roots.get(interior_index + 1).map(|pair| pair.0.as_str());
            let children = framing_children(
                &fixture,
                ExpectedPage {
                    tree_id: built.tree,
                    reference: interior.reference,
                    generation_ceiling: 1,
                    level: 1,
                    totals: interior.totals,
                    range: KeyRange {
                        lower: Some(lower),
                        upper,
                    },
                },
            )?;
            assert_eq!(children.len(), if interior_index == 0 { 47 } else { 2 });
            for (leaf_index, (lower, child)) in children.iter().enumerate() {
                assert_eq!(lower.as_bytes(), framing::id(next_row).as_slice());
                let upper = children
                    .get(leaf_index + 1)
                    .map(|pair| pair.0.as_str())
                    .or(upper);
                let count = read(
                    &fixture,
                    "engine.primary.pages",
                    &key(child.reference.id),
                    PAGE_BYTES,
                    |bytes| {
                        let page = decode(crate::primary_tree::validate(
                            bytes.context("framing leaf absent")?,
                            ExpectedPage {
                                tree_id: built.tree,
                                reference: child.reference,
                                generation_ceiling: 1,
                                level: 0,
                                totals: child.totals,
                                range: KeyRange {
                                    lower: Some(lower),
                                    upper,
                                },
                            },
                        ))?;
                        let count = page.entries().len();
                        for entry in page.entries() {
                            assert_eq!(entry.id.as_bytes(), framing::id(next_row).as_slice());
                            let Value::Leaf(leaf) = entry.value else {
                                panic!("framing leaf contains a child")
                            };
                            assert_eq!(leaf.kind, RecordKind::Archived);
                            assert_eq!(leaf.version, archived.version);
                            assert_eq!(leaf.object, built.object);
                            assert_eq!(leaf.semantic_bytes, built.semantic_bytes);
                            observed.archived_count += 1;
                            observed.archived_metadata_bytes += leaf.semantic_bytes;
                            next_row += 1;
                        }
                        Ok(count)
                    },
                )?;
                assert_eq!(count, if leaves == 48 { 1 } else { 47 });
                assert_eq!(child.totals.archived_count, count as u64);
                leaves += 1;
            }
        }
        assert_eq!(leaves, 49);
        assert_eq!(next_row, framing::ROWS);
        assert_eq!(observed, expected_totals);
        // Traversal saw 49 leaves + 2 interiors + 1 root: all 52 actual page
        // resources; the final carried-root collapse created no unary wrapper.
        assert_eq!(
            built.objects_after_collapse,
            1 + leaves + roots.len() as u64 + 1
        );
        stage.close()?;
        abort_all(&mut authority)?;
        assert!(PrimaryStage::resume_abort(&mut authority)?.is_none());
        drop((authority, roots, wire, archived, input));
        engine.seal();
    }
    fixture.close().await
}
