//! Explicit fixture publication only. Production root publication is still open.
#![allow(
    clippy::result_large_err,
    reason = "fixtures preserve the real inline read failure without adding an unadmitted enclosing box"
)]
use super::*;
use crate::primary_tree::{
    self as tree,
    read::{CATALOG, MANIFESTS, PAGES, SelectedPrimary},
    records::*,
    stage::{CanonicalDto, PrimaryStage},
};
use kasumi_query::Record;
use kasumi_types::{ArchivedDocument, CollectionDefinition, Document, TenantState};
use sha2::{Digest, Sha256};

// The test harness must not use anyhow's blanket boxing to erase ReadFailure.
// This wrapper keeps it inline and provides only the Debug required by tests.
#[allow(
    clippy::large_enum_variant,
    reason = "test results move the real source failure inline and preserve its allocation retirement contract"
)]
enum TestError {
    Read(crate::primary_tree::read::ReadFailure),
    Other(anyhow::Error),
}
impl std::fmt::Debug for TestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read(error) => f.debug_tuple("Read").field(error).finish(),
            Self::Other(error) => f.debug_tuple("Other").field(error).finish(),
        }
    }
}
impl From<crate::primary_tree::read::ReadFailure> for TestError {
    fn from(error: crate::primary_tree::read::ReadFailure) -> Self {
        Self::Read(error)
    }
}
impl From<anyhow::Error> for TestError {
    fn from(error: anyhow::Error) -> Self {
        Self::Other(error)
    }
}
type TestResult<T> = std::result::Result<T, TestError>;

fn codec<T>(value: std::result::Result<T, tree::CodecError>) -> Result<T> {
    value.map_err(|e| anyhow::anyhow!("test primary codec: {e:?}"))
}
fn key(id: tree::ObjectId) -> [u8; 24] {
    let mut out = [0; 24];
    out[..16].copy_from_slice(&id.attempt);
    out[16..].copy_from_slice(&id.ordinal.to_le_bytes());
    out
}
fn chunk_key(id: tree::ObjectId, ordinal: u64) -> [u8; 32] {
    let mut out = [0; 32];
    out[..24].copy_from_slice(&key(id));
    out[24..].copy_from_slice(&ordinal.to_le_bytes());
    out
}
fn id(ordinal: u64) -> tree::ObjectId {
    tree::ObjectId {
        attempt: [199; 16],
        ordinal,
    }
}
fn bytes(value: &impl serde::Serialize) -> Result<u64> {
    Ok(serde_json::to_vec(value)?.len() as u64)
}
struct Harness {
    fixture: Fixture,
    seed: Fixture,
    engine: TenantEngine,
    state: TenantState,
    live: tree::OverflowRef,
    root: tree::PageRef,
    selector: Selector,
    mapping: CatalogEntry,
    _input: crate::admission::Reservation,
    _seed_input: crate::admission::Reservation,
}
impl Harness {
    async fn new() -> Result<Self> {
        Self::with_version(1).await
    }
    async fn with_version(version: u64) -> Result<Self> {
        let seed = Fixture::new().await?;
        let seed_input = seed.storage.admission.reserve_document_source(16 << 20)?;
        let source = TenantEngine::from_bootstrap("selected-sources", &seed.image)?;
        let generation = source.generation()?;
        let mut state = generation.state.clone();
        state.revision = 1;
        state.revision_base = 1;
        let image = SnapshotImage::capture(
            seed.stores.application().scratch_disk(),
            64 << 20,
            |writer| {
                crate::snapshot_codec::write(
                    &state,
                    &generation.receipts,
                    &generation.backup_bindings,
                    &generation.terminals,
                    &generation.target_resolutions,
                    writer,
                )
            },
        )?;
        drop(generation);
        source.seal();
        drop(source);
        let fixture = Fixture::with_bootstrap(1, Some(&image)).await?;
        drop(image);
        crate::test_utils::install_fixture_audit_placement(fixture.stores.application())?;
        let engine = TenantEngine::from_bootstrap("selected-sources", &fixture.image)?;
        engine.install_storage_access(fixture.stores.application())?;
        engine.install_application_sources(fixture.roots.clone(), &fixture.image)?;
        // Fixture input DTOs, encoding buffers, writes and state have separate
        // real credit; selected reads obtain their own installed-node grants.
        let input = fixture
            .storage
            .admission
            .reserve_document_source(16 << 20)?;
        let definition = CollectionDefinition {
            name: "docs".into(),
            write_mode: kasumi_types::CollectionWriteMode::Mutable,
            retention_class: kasumi_types::CollectionRetentionClass::Operational,
            schema: serde_json::json!({"z": {"z": true, "a": false}, "a": "object"}),
            indexes: Vec::new(),
            strict_read_audit: false,
        };
        let document = Document {
            id: "a".into(),
            version,
            body: serde_json::json!({"payload": "x".repeat(80_000), "nested": [true, {"n": 17}]}),
        };
        let archive = ArchivedDocument {
            version,
            archive_id: "archive".into(),
            chunk_index: 3,
            document_sha256: "ab".repeat(32),
            document_bytes: 80_000,
            indexed_fields: std::collections::BTreeMap::from([(
                "field".into(),
                serde_json::json!(17),
            )]),
        };
        let tree_id = [71; 16];
        let mut authority = engine.lock_primary_apply()?;
        let stage = PrimaryStage::begin_fresh(&mut authority)?;
        let (stage, definition_ref) =
            stage.stage_dto(tree_id, CanonicalDto::Definition(&definition))?;
        let (stage, live) = stage.stage_dto(tree_id, CanonicalDto::Live(&document))?;
        let (stage, archived) = stage.stage_dto(tree_id, CanonicalDto::Archived(&archive))?;
        stage.close()?;
        drop(authority);
        let mut left = [0; tree::PAGE_BYTES];
        let mut right = [0; tree::PAGE_BYTES];
        let mut parent = [0; tree::PAGE_BYTES];
        let l = codec(tree::encode(
            &mut left,
            tree::PageSpec {
                tree_id,
                id: id(1),
                generation: 1,
                level: 0,
            },
            &[tree::Entry {
                id: "a",
                value: tree::Value::Leaf(tree::Leaf {
                    version,
                    kind: tree::RecordKind::Live,
                    object: live,
                    semantic_bytes: bytes(&kasumi_types::CanonicalJsonValue(&document.body))?,
                }),
            }],
        ))?;
        let r = codec(tree::encode(
            &mut right,
            tree::PageSpec {
                tree_id,
                id: id(2),
                generation: 1,
                level: 0,
            },
            &[tree::Entry {
                id: "z",
                value: tree::Value::Leaf(tree::Leaf {
                    version,
                    kind: tree::RecordKind::Archived,
                    object: archived,
                    semantic_bytes: codec(tree::archived_metadata_bytes(
                        "z",
                        archived.encoded_bytes,
                    ))?,
                }),
            }],
        ))?;
        let root = codec(tree::encode(
            &mut parent,
            tree::PageSpec {
                tree_id,
                id: id(3),
                generation: 1,
                level: 1,
            },
            &[
                tree::Entry {
                    id: "a",
                    value: tree::Value::Child(tree::Child {
                        reference: l.reference,
                        totals: l.totals,
                    }),
                },
                tree::Entry {
                    id: "z",
                    value: tree::Value::Child(tree::Child {
                        reference: r.reference,
                        totals: r.totals,
                    }),
                },
            ],
        ))?;
        let bootstrap = codec(boundary::raw_digest(fixture.image.sha256()))?;
        let scope = codec(scope_hash(&state.tenant, &state.incarnation, bootstrap))?;
        let name_hash = codec(name_hash("docs"))?;
        let manifest = Manifest {
            scope,
            name_hash,
            tree_id,
            definition: definition_ref,
            data_epoch: 1,
            revision: 1,
            root: Some(Root {
                reference: root.reference,
                level: 1,
            }),
            totals: root.totals,
        };
        let mut manifest_bytes = [0; MANIFEST_BYTES];
        codec(manifest.encode(&mut manifest_bytes))?;
        let mapping = CatalogEntry {
            catalog: CatalogId(id(5)),
            scope,
            name_hash,
            manifest: ManifestRef {
                id: id(4),
                sha256: Sha256::digest(manifest_bytes).into(),
            },
        };
        let mut mapping_bytes = [0; CATALOG_ENTRY_BYTES];
        codec(mapping.encode(&mut mapping_bytes))?;
        let selector = Selector {
            boundary: Boundary::Bootstrap,
            scope,
            bootstrap_sha256: bootstrap,
            projection_epoch: [81; 16],
            revision: 1,
            revision_base: 1,
            catalog: mapping.catalog,
            collection_count: 1,
            totals: root.totals,
            activation_attempt: [82; 16],
            boundary_digest: bootstrap,
        };
        let mut selector_bytes = [0; SELECTOR_BYTES];
        codec(selector.encode(&mut selector_bytes))?;
        fixture.stores.write_batch(
            &[
                kasumi_store::WriteOp::put(PAGES, key(l.reference.id), left),
                kasumi_store::WriteOp::put(PAGES, key(r.reference.id), right),
                kasumi_store::WriteOp::put(PAGES, key(root.reference.id), parent),
                kasumi_store::WriteOp::put(MANIFESTS, key(mapping.manifest.id), manifest_bytes),
                kasumi_store::WriteOp::put(
                    CATALOG,
                    CatalogEntry::key(mapping.catalog, name_hash),
                    mapping_bytes,
                ),
                kasumi_store::WriteOp::put("engine.primary.meta", b"selected", selector_bytes),
            ],
            &[],
        )?;
        Ok(Self {
            fixture,
            seed,
            engine,
            state,
            live,
            root: root.reference,
            selector,
            mapping,
            _input: input,
            _seed_input: seed_input,
        })
    }
    fn open(
        &self,
        selected: &SelectedApplication,
    ) -> std::result::Result<SelectedPrimary, crate::primary_tree::read::ReadFailure> {
        SelectedPrimary::open(selected, &self.fixture.roots, &self.state, "docs")
    }
    fn raw(&self, namespace: &str, key: &[u8], max: usize) -> Result<Vec<u8>> {
        let mut grant = self
            .fixture
            .storage
            .admission
            .reserve_document_source((max as u64) + 4096)?;
        let mut reader = self.fixture.roots.open_primary_current()?;
        let bytes = reader.with_record(
            &mut grant,
            (max as u64) + 4096,
            namespace,
            key,
            max,
            |value| Ok(value.context("test raw object absent")?.to_vec()),
        )?;
        reader.close()?;
        Ok(bytes)
    }
    async fn close(self) -> Result<()> {
        let Self {
            fixture,
            seed,
            engine,
            state,
            _input,
            _seed_input,
            ..
        } = self;
        engine.seal();
        drop(engine);
        drop(state);
        drop(_input);
        drop(_seed_input);
        fixture.close().await?;
        seed.close().await
    }
}

#[tokio::test]
async fn selected_primary_encrypted_branch_live_archive_absence_and_old_pin() -> TestResult<()> {
    let h = Harness::new().await?;
    let selected = h.fixture.select()?;
    let reader = h.open(&selected)?;
    let (reader, result) = reader.lookup("a", |record| {
        let Record::Live(document) = record else {
            anyhow::bail!("wrong DTO kind")
        };
        assert_eq!(document.id, "a");
        assert_eq!(document.body["payload"].as_str().unwrap().len(), 80_000);
        Ok(document.version)
    })?;
    assert_eq!(result, Some(1));
    let (reader, archive) = reader.lookup("z", |record| {
        let Record::Archived(document) = record else {
            anyhow::bail!("wrong DTO kind")
        };
        assert_eq!(document.archive_id, "archive");
        assert_eq!(document.indexed_fields["field"], 17);
        Ok(document.version)
    })?;
    assert_eq!(archive, Some(1));
    let (reader, absent) = reader.lookup("missing", |_| -> Result<()> {
        panic!("absent record lent")
    })?;
    assert_eq!(absent, None);
    reader.close()?;
    h.fixture.stores.write_batch(
        &[
            kasumi_store::WriteOp::delete(PAGES, key(h.root.id)),
            kasumi_store::WriteOp::delete("engine.primary.chunks", chunk_key(h.live.id, 0)),
        ],
        &[],
    )?;
    // A new current selection sees missing pages; the old selected native pin
    // still supplies its exact authenticated page and multi-chunk DTO.
    let current = h.fixture.select()?;
    let mut lent = false;
    let failure = h
        .open(&current)?
        .lookup("a", |_| {
            lent = true;
            Ok(())
        })
        .err()
        .context("missing page accepted")?;
    assert!(!lent);
    assert!(failure.to_string().contains("page absent"));
    drop(failure);
    drop(current);
    let (reader, found) = h
        .open(&selected)?
        .lookup("a", |record| Ok(record.version()))?;
    assert_eq!(found, Some(1));
    reader.close()?;
    drop(selected);
    h.close().await?;
    Ok(())
}

#[tokio::test]
async fn selected_primary_rejects_catalog_manifest_and_selector_substitution() -> TestResult<()> {
    let h = Harness::new().await?;
    let old = h.fixture.select()?;
    let mut wrong = h.mapping;
    wrong.scope[0] ^= 1;
    let mut wire = [0; CATALOG_ENTRY_BYTES];
    codec(wrong.encode(&mut wire))?;
    h.fixture.stores.write_batch(
        &[kasumi_store::WriteOp::put(
            CATALOG,
            CatalogEntry::key(h.mapping.catalog, h.mapping.name_hash),
            wire,
        )],
        &[],
    )?;
    let selected = h.fixture.select()?;
    let failure = h
        .open(&selected)
        .err()
        .context("foreign mapping accepted")?;
    assert!(failure.to_string().contains("mapping identity"));
    drop(failure);
    drop(selected);
    codec(h.mapping.encode(&mut wire))?;
    let mut manifest = h.raw(MANIFESTS, &key(h.mapping.manifest.id), MANIFEST_BYTES)?;
    manifest[40] ^= 1;
    h.fixture.stores.write_batch(
        &[
            kasumi_store::WriteOp::put(
                CATALOG,
                CatalogEntry::key(h.mapping.catalog, h.mapping.name_hash),
                wire,
            ),
            kasumi_store::WriteOp::put(MANIFESTS, key(h.mapping.manifest.id), manifest),
        ],
        &[],
    )?;
    let selected = h.fixture.select()?;
    let failure = h
        .open(&selected)
        .err()
        .context("manifest corruption accepted")?;
    assert!(failure.to_string().contains("Digest"));
    drop(failure);
    drop(selected);
    let mut wrong = h.selector;
    wrong.scope[0] ^= 1;
    let mut selector = [0; SELECTOR_BYTES];
    codec(wrong.encode(&mut selector))?;
    h.fixture.stores.write_batch(
        &[kasumi_store::WriteOp::put(
            "engine.primary.meta",
            b"selected",
            selector,
        )],
        &[],
    )?;
    let selected = h.fixture.select()?;
    let failure = h
        .open(&selected)
        .err()
        .context("foreign selector accepted")?;
    assert!(failure.to_string().contains("selected producer"));
    drop(failure);
    drop(selected);
    h.open(&old)?.close()?;
    drop(old);
    h.close().await?;
    Ok(())
}

#[tokio::test]
async fn selected_primary_overflow_corruption_and_missing_never_lend_partial_dto() -> TestResult<()>
{
    let h = Harness::new().await?;
    let old = h.fixture.select()?;
    let mut chunk = h.raw("engine.primary.chunks", &chunk_key(h.live.id, 1), 65_676)?;
    chunk[140] ^= 1;
    h.fixture.stores.write_batch(
        &[kasumi_store::WriteOp::put(
            "engine.primary.chunks",
            chunk_key(h.live.id, 1),
            chunk,
        )],
        &[],
    )?;
    let selected = h.fixture.select()?;
    let mut lent = false;
    let failure = h
        .open(&selected)?
        .lookup("a", |_| {
            lent = true;
            Ok(())
        })
        .err()
        .context("corrupt overflow accepted")?;
    assert!(!lent);
    assert!(failure.to_string().contains("digest"));
    drop(failure);
    drop(selected);
    h.fixture.stores.write_batch(
        &[kasumi_store::WriteOp::delete(
            "engine.primary.chunks",
            chunk_key(h.live.id, 1),
        )],
        &[],
    )?;
    let selected = h.fixture.select()?;
    let failure = h
        .open(&selected)?
        .lookup("a", |_| {
            lent = true;
            Ok(())
        })
        .err()
        .context("missing overflow accepted")?;
    assert!(!lent);
    assert!(failure.to_string().contains("absent"));
    drop(failure);
    drop(selected);
    let (reader, value) = h.open(&old)?.lookup("a", |record| Ok(record.version()))?;
    assert_eq!(value, Some(1));
    reader.close()?;
    drop(old);
    h.close().await?;
    Ok(())
}

#[derive(Debug)]
struct VisitorOriginal(Arc<std::sync::atomic::AtomicBool>);
impl std::fmt::Display for VisitorOriginal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("original visitor error")
    }
}
impl std::error::Error for VisitorOriginal {}
impl Drop for VisitorOriginal {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}
#[tokio::test]
async fn selected_primary_failure_retains_original_reader_and_actual_workspace_until_drop()
-> TestResult<()> {
    let h = Harness::new().await?;
    let selected = h.fixture.select()?;
    let before = h.fixture.storage.admission.snapshot();
    let reader = h.open(&selected)?;
    let died = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let failure = reader
        .lookup("a", |_| Err::<(), _>(VisitorOriginal(died.clone()).into()))
        .err()
        .context("visitor error lost")?;
    assert!(
        failure
            .original()
            .downcast_ref::<VisitorOriginal>()
            .is_some()
    );
    assert!(!died.load(Ordering::Acquire));
    assert!(h.fixture.storage.admission.snapshot().reserved_bytes > before.reserved_bytes + 80_000);
    assert!(h.fixture.storage.admission.snapshot().live_reservations > before.live_reservations);
    drop(failure);
    assert!(died.load(Ordering::Acquire));
    assert_eq!(
        h.fixture.storage.admission.snapshot().reserved_bytes,
        before.reserved_bytes
    );
    assert_eq!(
        h.fixture.storage.admission.snapshot().live_reservations,
        before.live_reservations
    );
    drop(selected);
    h.close().await?;
    Ok(())
}

#[tokio::test]
async fn selected_primary_actual_node_denial_precedes_lending_and_keeps_error_credit()
-> TestResult<()> {
    let h = Harness::new().await?;
    let selected = h.fixture.select()?;
    let reader = h.open(&selected)?;
    let before = h.fixture.storage.admission.snapshot();
    let remaining = h
        .fixture
        .budget
        .checked_sub(before.reserved_bytes)
        .context("test grant budget")?;
    let filler = h
        .fixture
        .storage
        .admission
        .reserve_resident(remaining)
        .map_err(anyhow::Error::from)?;
    let mut lent = false;
    let failure = reader
        .lookup("a", |_| {
            lent = true;
            Ok(())
        })
        .err()
        .context("exhausted reader admitted")?;
    assert!(!lent);
    assert!(
        failure
            .original()
            .downcast_ref::<kasumi_types::Error>()
            .is_some()
    );
    assert_eq!(
        h.fixture.storage.admission.snapshot().reserved_bytes,
        before.reserved_bytes + remaining
    );
    drop(filler);
    drop(failure);
    drop(selected);
    h.close().await?;
    Ok(())
}

#[test]
fn primary_catalog_entry_is_fixed_canonical_and_context_explicit() -> Result<()> {
    let value = CatalogEntry {
        catalog: CatalogId(id(1)),
        scope: [2; 32],
        name_hash: [3; 32],
        manifest: ManifestRef {
            id: id(4),
            sha256: [5; 32],
        },
    };
    let mut encoded = [0; CATALOG_ENTRY_BYTES];
    codec(value.encode(&mut encoded))?;
    assert_eq!(codec(CatalogEntry::decode(&encoded))?, value);
    encoded[10] = 1;
    assert!(CatalogEntry::decode(&encoded).is_err());
    assert_ne!(
        CatalogEntry::key(value.catalog, value.name_hash),
        CatalogEntry::key(CatalogId(id(2)), value.name_hash)
    );
    Ok(())
}

#[tokio::test]
async fn selected_primary_actual_decode_denial_retains_complete_wire_without_lending()
-> TestResult<()> {
    let h = Harness::new().await?;
    let selected = h.fixture.select()?;
    let reader = h.open(&selected)?;
    let before = h.fixture.storage.admission.snapshot();
    // Preserve the unchanged default mandatory-work headroom. Two MiB of
    // ordinary growth admits page/chunk plaintext and shape preflight, but not
    // the concrete decoded DTO plus malformed-string diagnostic envelope.
    let headroom = (h.fixture.budget / 4).min(64 << 20);
    let available = headroom + (2 << 20);
    let fill = h
        .fixture
        .budget
        .checked_sub(before.reserved_bytes + available)
        .context("decode-denial fixture room")?;
    let filler = h
        .fixture
        .storage
        .admission
        .reserve_resident(fill)
        .map_err(anyhow::Error::from)?;
    let mut lent = false;
    let failure = reader
        .lookup("a", |_| {
            lent = true;
            Ok(())
        })
        .err()
        .context("decoder unexpectedly admitted")?;
    assert!(!lent);
    assert_eq!(failure.retained_wire_bytes() as u64, h.live.encoded_bytes);
    assert!(
        failure
            .original()
            .downcast_ref::<kasumi_types::Error>()
            .is_some()
    );
    assert!(
        h.fixture.storage.admission.snapshot().reserved_bytes
            > before.reserved_bytes + fill + 80_000
    );
    drop(filler);
    drop(failure);
    drop(selected);
    h.close().await?;
    Ok(())
}

#[tokio::test]
async fn selected_primary_page_corruption_and_foreign_registry_are_rejected() -> TestResult<()> {
    let h = Harness::new().await?;
    let selected = h.fixture.select()?;
    let (other, binding) = SourceRoots::new(
        h.fixture.stores.clone(),
        h.fixture.storage.admission.clone(),
        RaftLimits::default(),
    )?;
    let failure = SelectedPrimary::open(&selected, &other, &h.state, "docs")
        .err()
        .context("foreign source roots accepted")?;
    assert!(failure.to_string().contains("installation differs"));
    drop(failure);
    drop(binding);
    std::future::poll_fn(|cx| other.poll_drain(cx))
        .await
        .map_err(anyhow::Error::from)?;
    drop(other);
    let mut page = h.raw(PAGES, &key(h.root.id), tree::PAGE_BYTES)?;
    page[tree::PAGE_BYTES - 1] ^= 1;
    h.fixture.stores.write_batch(
        &[kasumi_store::WriteOp::put(PAGES, key(h.root.id), page)],
        &[],
    )?;
    let current = h.fixture.select()?;
    let mut lent = false;
    let failure = h
        .open(&current)?
        .lookup("a", |_| {
            lent = true;
            Ok(())
        })
        .err()
        .context("corrupt page accepted")?;
    assert!(!lent);
    assert!(failure.to_string().contains("Digest"));
    drop(failure);
    drop(current);
    h.open(&selected)?.close()?;
    drop(selected);
    h.close().await?;
    Ok(())
}

#[tokio::test]
async fn selected_primary_preserves_restored_zero_document_versions() -> TestResult<()> {
    let h = Harness::with_version(0).await?;
    let selected = h.fixture.select()?;
    let (reader, live) = h
        .open(&selected)?
        .lookup("a", |record| Ok(record.version()))?;
    assert_eq!(live, Some(0));
    let (reader, archived) = reader.lookup("z", |record| Ok(record.version()))?;
    assert_eq!(archived, Some(0));
    reader.close()?;
    drop(selected);
    h.close().await?;
    Ok(())
}

#[tokio::test]
async fn selected_primary_empty_tree_still_rechecks_current_storage_access() -> TestResult<()> {
    let h = Harness::new().await?;
    let bytes = h.raw(MANIFESTS, &key(h.mapping.manifest.id), MANIFEST_BYTES)?;
    let mut manifest = codec(Manifest::decode(&bytes))?;
    manifest.root = None;
    manifest.totals = tree::Totals::default();
    let mut wire = [0; MANIFEST_BYTES];
    codec(manifest.encode(&mut wire))?;
    let mut mapping = h.mapping;
    mapping.manifest.sha256 = Sha256::digest(wire).into();
    let mut mapping_bytes = [0; CATALOG_ENTRY_BYTES];
    codec(mapping.encode(&mut mapping_bytes))?;
    let mut selector = h.selector;
    selector.totals = tree::Totals::default();
    let mut selector_bytes = [0; SELECTOR_BYTES];
    codec(selector.encode(&mut selector_bytes))?;
    h.fixture.stores.write_batch(
        &[
            kasumi_store::WriteOp::put(MANIFESTS, key(mapping.manifest.id), wire),
            kasumi_store::WriteOp::put(
                CATALOG,
                CatalogEntry::key(mapping.catalog, mapping.name_hash),
                mapping_bytes,
            ),
            kasumi_store::WriteOp::put("engine.primary.meta", b"selected", selector_bytes),
        ],
        &[],
    )?;
    let selected = h.fixture.select()?;
    let reader = h.open(&selected)?;
    let (reader, absent) =
        reader.lookup("a", |_| -> Result<()> { panic!("empty tree lent DTO") })?;
    assert_eq!(absent, None);
    let token = kasumi_query::QueryCancellation::default();
    let (header_reader, ()) = h.open(&selected)?.header_after(None, &token, |header| {
        assert!(header.is_none());
        Ok(())
    })?;
    h.fixture.stores.application().seal();
    let failure = header_reader
        .header_after(None, &token, |_| -> Result<()> {
            panic!("sealed empty tree lent header")
        })
        .err()
        .context("empty header skipped current access")?;
    assert!(failure.original().downcast_ref::<SourceFailure>().is_some());
    drop(failure);
    let failure = reader
        .lookup("a", |_| -> Result<()> { panic!("sealed tree lent DTO") })
        .err()
        .context("empty tree skipped current access")?;
    assert!(failure.original().downcast_ref::<SourceFailure>().is_some());
    drop(failure);
    drop(selected);
    h.close().await?;
    Ok(())
}

#[tokio::test]
async fn selected_primary_callback_access_change_is_rechecked_before_success() -> TestResult<()> {
    let h = Harness::new().await?;
    let selected = h.fixture.select()?;
    let failure = h
        .open(&selected)?
        .lookup("a", |record| {
            h.fixture.stores.application().seal();
            Ok(record.version())
        })
        .err()
        .context("callback access change returned success")?;
    assert!(failure.original().downcast_ref::<SourceFailure>().is_some());
    drop(failure);
    drop(selected);
    h.close().await?;
    Ok(())
}

#[tokio::test]
async fn selected_primary_panic_payload_survives_as_original_failure_until_drop() -> TestResult<()>
{
    let h = Harness::new().await?;
    let selected = h.fixture.select()?;
    let died = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let failure = h
        .open(&selected)?
        .lookup("a", |_| -> Result<()> {
            std::panic::panic_any(VisitorOriginal(died.clone()))
        })
        .err()
        .context("callback panic lost")?;
    assert!(failure.to_string().contains("retained original panic"));
    assert!(!died.load(Ordering::Acquire));
    drop(failure);
    assert!(died.load(Ordering::Acquire));
    drop(selected);
    h.close().await?;
    Ok(())
}

#[tokio::test]
async fn selected_primary_headers_cross_leaf_boundaries_without_loading_document_chunks()
-> TestResult<()> {
    let h = Harness::new().await?;
    h.fixture.stores.write_batch(
        &[kasumi_store::WriteOp::delete(
            "engine.primary.chunks",
            chunk_key(h.live.id, 0),
        )],
        &[],
    )?;
    let selected = h.fixture.select()?;
    let mut reader = h.open(&selected)?;
    let token = kasumi_query::QueryCancellation::default();
    for (after, expected) in [
        (None, Some(("a", kasumi_query::RecordKind::Live))),
        (Some("0"), Some(("a", kasumi_query::RecordKind::Live))),
        (Some("a"), Some(("z", kasumi_query::RecordKind::Archived))),
        (
            Some("between"),
            Some(("z", kasumi_query::RecordKind::Archived)),
        ),
        (Some("z"), None),
        (Some("zz"), None),
    ] {
        let (next, ()) = reader.header_after(after, &token, |header| {
            assert_eq!(header.map(|header| (header.id, header.kind)), expected);
            if let Some(header) = header {
                assert_eq!(header.version, 1);
            }
            Ok(())
        })?;
        reader = next;
    }
    // Header success does not fabricate a successful body read.
    let failure = reader
        .lookup("a", |_| -> Result<()> { panic!("missing body lent") })
        .err()
        .context("missing body accepted")?;
    assert!(failure.to_string().contains("absent"));
    drop(failure);
    drop(selected);
    h.close().await?;
    Ok(())
}

#[tokio::test]
async fn selected_primary_headers_use_the_exact_old_root_and_preserve_cancellation()
-> TestResult<()> {
    let h = Harness::new().await?;
    let old = h.fixture.select()?;
    h.fixture
        .stores
        .write_batch(&[kasumi_store::WriteOp::delete(PAGES, key(h.root.id))], &[])?;
    let current = h.fixture.select()?;
    let token = kasumi_query::QueryCancellation::default();
    let failure = h
        .open(&current)?
        .header_after(None, &token, |_| -> Result<()> {
            panic!("missing root lent")
        })
        .err()
        .context("missing current root accepted")?;
    assert!(failure.to_string().contains("page absent"));
    drop(failure);
    drop(current);
    let (reader, ()) = h.open(&old)?.header_after(Some("a"), &token, |header| {
        assert_eq!(header.unwrap().id, "z");
        Ok(())
    })?;
    token.cancel();
    let failure = reader
        .header_after(None, &token, |_| -> Result<()> {
            panic!("canceled header lent")
        })
        .err()
        .context("cancellation ignored")?;
    assert!(failure.to_string().contains("query work cancelled"));
    assert_eq!(failure.retained_wire_bytes(), 0);
    drop(failure);
    let token = kasumi_query::QueryCancellation::default();
    let failure = h
        .open(&old)?
        .header_after(None, &token, |header| {
            assert_eq!(header.unwrap().id, "a");
            token.cancel();
            Ok(())
        })
        .err()
        .context("callback cancellation ignored")?;
    assert!(failure.to_string().contains("query work cancelled"));
    drop(failure);
    drop(old);
    h.close().await?;
    Ok(())
}
