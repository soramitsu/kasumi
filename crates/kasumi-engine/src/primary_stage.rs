//! Real encrypted unselected-object staging and resumable abort. No selector
//! activation, committed retirement or document-cache provenance is installed.
use super::records::{
    self, Attempt, AttemptPhase, Epoch, GcState, Inventory, InventoryPhase, ResourceKind, Selector,
};
use super::{ObjectId, OverflowRef, u16_at, u64_at};
use crate::{
    admission::Reservation,
    application_sources::{SourceReader, SourceRootsRef},
    state::PrimaryApplyGuard,
};
use anyhow::{Context as _, Result, ensure};
use kasumi_query::QueryWorkspace;
use kasumi_store::{TenantStorageSet, WriteOp};
use kasumi_types::{ArchivedDocument, CollectionDefinition, Document};
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    sync::{Arc, Mutex},
};

#[path = "primary_stage_abort.rs"]
mod abort;
#[path = "primary_stage_bulk.rs"]
pub(crate) mod bulk;
#[path = "primary_stage_catalog.rs"]
mod catalog;
#[path = "primary_stage_check.rs"]
mod check;
#[path = "primary_chunk.rs"]
mod chunk;
#[path = "primary_stage_cow.rs"]
pub(crate) mod cow;
#[path = "primary_stage_fixed.rs"]
mod fixed;
#[path = "primary_stage_incremental_abort.rs"]
mod incremental_abort;
#[cfg(test)]
#[path = "primary_stage_workspace_tests.rs"]
mod workspace_tests;
use catalog::CatalogBuildState;
const META: &str = "engine.primary.meta";
const EPOCHS: &str = "engine.primary.epochs";
const ATTEMPTS: &str = "engine.primary.attempts";
const INVENTORY: &str = "engine.primary.inventory";
const CHUNKS: &str = "engine.primary.chunks";
const PAGES: &str = "engine.primary.pages";
const MANIFESTS: &str = "engine.primary.manifests";
const CATALOG: &str = "engine.primary.catalog";
const MEMBERS: &str = "engine.primary.catalog.members";
const RETIRES: &str = "engine.primary.retire";
const MAX_KEY_BYTES: usize = 56;
const MAX_METADATA_BYTES: usize = records::CATALOG_MEMBER_BYTES;
const _: () = assert!(MAX_METADATA_BYTES >= records::MANIFEST_BYTES);
const OPS: usize = 4;
const OP_BYTES: usize = 4 << 20;
fn codec<T>(value: std::result::Result<T, super::CodecError>) -> Result<T> {
    value.map_err(|error| anyhow::anyhow!("primary record invalid: {error:?}"))
}
fn allocated(bytes: usize) -> Result<u64> {
    u64::try_from(
        bytes
            .checked_next_power_of_two()
            .and_then(|n| n.checked_add(64))
            .context("primary allocation quote overflow")?,
    )
    .map_err(Into::into)
}
fn exact_bytes(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut owned = Vec::new();
    owned.try_reserve_exact(bytes.len())?;
    ensure!(
        owned.capacity() == bytes.len(),
        "primary byte capacity differs"
    );
    owned.extend_from_slice(bytes);
    Ok(owned)
}
fn exact_namespace(namespace: &str) -> Result<String> {
    let mut owned = String::new();
    owned.try_reserve_exact(namespace.len())?;
    ensure!(
        owned.capacity() == namespace.len(),
        "primary namespace capacity differs"
    );
    owned.push_str(namespace);
    Ok(owned)
}
fn object_key(id: ObjectId) -> [u8; 24] {
    let mut key = [0; 24];
    id.write(&mut key);
    key
}

pub(crate) struct PrimaryStage<'guard, 'engine> {
    resources: PrimaryResources,
    _authority: &'guard mut PrimaryApplyGuard<'engine>,
}
struct PrimaryResources {
    roots: SourceRootsRef,
    stores: Arc<TenantStorageSet>,
    reader: Option<SourceReader>,
    old_reader: Option<SourceReader>,
    #[cfg(test)]
    interrupt_after_chunks: Option<usize>,
    operations: Vec<WriteOp>,
    chunk: Vec<u8>,
    scope: [u8; 32],
    bootstrap: [u8; 32],
    gc: Option<GcState>,
    epoch: Option<Epoch>,
    attempt: Option<Attempt>,
    active_catalog: Option<CatalogBuildState>,
    cow_frozen: bool,
    baseline: u64,
    // Exact payloads and readers above die before their installed grant.
    reservation: Reservation,
}
/// Original error/panic/native custody must be destroyed before the last grant
/// in resources. Failure consumes live stage authority; it cannot resume writes.
struct StageFailure {
    original: anyhow::Error,
    resources: PrimaryResources,
}
impl std::fmt::Debug for StageFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrimaryStageFailure")
            .field("original", &self.original)
            .field("attempt", &self.resources.attempt.map(|attempt| attempt.id))
            .finish()
    }
}
impl std::fmt::Display for StageFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.original.fmt(f)
    }
}
impl std::error::Error for StageFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.original.as_ref())
    }
}
struct StagePanic {
    _payload: Mutex<Box<dyn std::any::Any + Send>>,
}
impl std::fmt::Debug for StagePanic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("primary stage retained original panic")
    }
}
impl std::fmt::Display for StagePanic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}
impl std::error::Error for StagePanic {}

pub(crate) enum CanonicalDto<'a> {
    Live(&'a Document),
    Archived(&'a ArchivedDocument),
    Definition(&'a CollectionDefinition),
}
impl CanonicalDto<'_> {
    fn kind(&self) -> ResourceKind {
        match self {
            Self::Live(_) => ResourceKind::Live,
            Self::Archived(_) => ResourceKind::Archived,
            Self::Definition(_) => ResourceKind::Definition,
        }
    }
    fn write(&self, out: &mut impl Write) -> Result<()> {
        match self {
            Self::Live(value) => serde_json::to_writer(out, value)?,
            Self::Archived(value) => serde_json::to_writer(out, value)?,
            Self::Definition(value) => serde_json::to_writer(out, value)?,
        };
        Ok(())
    }
    fn workspace(&self) -> Result<u64> {
        self.workspace_checked(&mut || Ok(()))
    }
    fn workspace_checked(&self, check: &mut dyn FnMut() -> Result<()>) -> Result<u64> {
        fn value_peak(
            value: &serde_json::Value,
            check: &mut dyn FnMut() -> Result<()>,
        ) -> Result<u64> {
            check()?;
            match value {
                serde_json::Value::Array(values) => values
                    .iter()
                    .try_fold(0_u64, |peak, value| Ok(peak.max(value_peak(value, check)?))),
                serde_json::Value::Object(values) => {
                    let mut previous = None;
                    let mut sorted = true;
                    for key in values.keys() {
                        check()?;
                        sorted &= previous.is_none_or(|old| old <= key);
                        previous = Some(key);
                    }
                    let own = if sorted {
                        0
                    } else {
                        allocated(
                            values
                                .len()
                                .checked_mul(std::mem::size_of::<(&String, &serde_json::Value)>())
                                .context("canonical entry quote overflow")?,
                        )?
                    };
                    let child = values.values().try_fold(0_u64, |peak, value| {
                        Ok::<_, anyhow::Error>(peak.max(value_peak(value, check)?))
                    })?;
                    own.checked_add(child)
                        .context("canonical serializer peak overflow")
                }
                _ => Ok(0),
            }
        }
        match self {
            Self::Live(doc) => value_peak(&doc.body, check),
            Self::Definition(definition) => value_peak(&definition.schema, check),
            // Archived indexed fields use the ordinary Value serializer, not
            // CanonicalJsonValue; it walks borrowed maps without sorter storage.
            Self::Archived(_) => {
                check()?;
                Ok(0)
            }
        }
    }
}
struct CountHash {
    bytes: u64,
    hash: Sha256,
}
impl CountHash {
    fn new() -> Self {
        Self {
            bytes: 0,
            hash: Sha256::new(),
        }
    }
}
impl Write for CountHash {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len() as u64)
            .ok_or(std::io::ErrorKind::OutOfMemory)?;
        self.hash.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl<'guard, 'engine> PrimaryStage<'guard, 'engine> {
    fn allocate(authority: &'guard mut PrimaryApplyGuard<'engine>) -> Result<Self> {
        let (stores, admission) = authority.roots().primary_installation();
        admission
            .memory()
            .require_store_memory(stores.application())?;
        admission
            .memory()
            .require_store_memory(stores.custody().store())?;
        // Four-slot batches: one chunk plus its descriptor, or bounded journal
        // updates. Native encrypted output/transaction leases are separate.
        let baseline = allocated(std::mem::size_of::<StageFailure>())?
            .checked_add(allocated(OPS * std::mem::size_of::<WriteOp>())?)
            .and_then(|n| n.checked_add(4096))
            .context("primary error-shell quote overflow")?
            .checked_add(
                (allocated(32)? + allocated(MAX_KEY_BYTES)? + allocated(MAX_METADATA_BYTES)?)
                    .checked_mul(OPS as u64)
                    .context("primary write backing quote overflow")?,
            )
            .context("primary control quote overflow")?
            .checked_add(allocated(chunk::BYTES)?)
            .context("primary chunk quote overflow")?;
        let reservation = admission.reserve_application_source(baseline)?;
        let resources = PrimaryResources {
            roots: authority.roots().clone(),
            stores: stores.clone(),
            reader: None,
            old_reader: None,
            #[cfg(test)]
            interrupt_after_chunks: None,
            operations: Vec::new(),
            chunk: Vec::new(),
            scope: authority.scope(),
            bootstrap: authority.bootstrap(),
            gc: None,
            epoch: None,
            attempt: None,
            active_catalog: None,
            cow_frozen: false,
            baseline,
            reservation,
        };
        let stage = Self {
            resources,
            _authority: authority,
        };
        let (stage, ()) = stage.perform(|resources| {
            resources.operations.try_reserve_exact(OPS)?;
            ensure!(
                resources.operations.capacity() == OPS,
                "primary operation capacity differs"
            );
            resources.chunk.try_reserve_exact(chunk::BYTES)?;
            ensure!(
                resources.chunk.capacity() == chunk::BYTES,
                "primary chunk capacity differs"
            );
            resources.reader = Some(resources.roots.open_primary_current()?);
            Ok(())
        })?;
        Ok(stage)
    }
    fn perform<T>(
        mut self,
        work: impl FnOnce(&mut PrimaryResources) -> Result<T>,
    ) -> Result<(Self, T)> {
        let outcome =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| work(&mut self.resources)))
                .unwrap_or_else(|payload| {
                    Err(StagePanic {
                        _payload: Mutex::new(payload),
                    }
                    .into())
                });
        match outcome {
            Ok(value) => Ok((self, value)),
            Err(original) => Err(StageFailure {
                original,
                resources: self.resources,
            }
            .into()),
        }
    }
    /// New physical projection only; ordinary incremental publication requires
    /// the later COW/accepted-delta layer and never calls this as a row fallback.
    pub(crate) fn begin_fresh(authority: &'guard mut PrimaryApplyGuard<'engine>) -> Result<Self> {
        let (stage, ()) =
            Self::allocate(authority)?.perform(|resources| resources.begin_fresh())?;
        Ok(stage)
    }
    pub(crate) fn stage_dto(
        self,
        tree: [u8; 16],
        dto: CanonicalDto<'_>,
    ) -> Result<(Self, OverflowRef)> {
        self.stage_dto_checked(tree, dto, &mut || Ok(()))
    }
    // The borrowed check may refuse between bounded chunks. Its original error
    // is retained by StageFailure, separately from serde's io sentinel.
    fn stage_dto_checked(
        self,
        tree: [u8; 16],
        dto: CanonicalDto<'_>,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<(Self, OverflowRef)> {
        self.perform(|resources| resources.stage_dto(tree, dto, check))
    }
    /// Two passes over one immutable paired pin: validate the entire hash before
    /// lending any payload chunk. DTO decoding/retained cache ownership follows
    /// in the reader cut; this API does not lend an unverified decoded object.
    pub(crate) fn visit_staged(
        self,
        reference: OverflowRef,
        tree: [u8; 16],
        kind: ResourceKind,
        lend: impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<Self> {
        let (stage, ()) =
            self.perform(|resources| resources.visit_staged(reference, tree, kind, lend))?;
        Ok(stage)
    }
    #[cfg(test)]
    pub(crate) fn interrupt_after_chunks(mut self, chunks: usize) -> Self {
        self.resources.interrupt_after_chunks = Some(chunks);
        self
    }
    pub(crate) fn visit_selected(
        self,
        selected: &crate::application_sources::SelectedApplication,
        reference: OverflowRef,
        tree: [u8; 16],
        kind: ResourceKind,
        lend: impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<Self> {
        let (stage, ()) = self.perform(|resources| {
            resources.old_reader = Some(selected.open_primary_reader(&resources.roots)?);
            visit_object(
                resources.old_reader.as_mut().expect("selected reader"),
                &mut resources.reservation,
                resources.baseline,
                resources.scope,
                reference,
                tree,
                kind,
                lend,
            )?;
            resources
                .old_reader
                .take()
                .expect("selected reader")
                .close()
        })?;
        Ok(stage)
    }
    pub(crate) fn close(self) -> Result<()> {
        let (stage, ()) = self.perform(|resources| resources.close_reader())?;
        drop(stage);
        Ok(())
    }
}
impl PrimaryResources {
    fn read<T>(
        &mut self,
        namespace: &str,
        key: &[u8],
        max: usize,
        lend: impl FnOnce(Option<&[u8]>) -> Result<T>,
    ) -> Result<T> {
        self.reader
            .as_mut()
            .context("primary current reader absent")?
            .with_record(
                &mut self.reservation,
                self.baseline,
                namespace,
                key,
                max,
                lend,
            )
    }
    fn close_reader(&mut self) -> Result<()> {
        if let Some(reader) = self.reader.take() {
            reader.close()?;
        }
        Ok(())
    }
    fn refresh(&mut self) -> Result<()> {
        self.require_catalog_mutable()?;
        self.close_reader()?;
        self.reader = Some(self.roots.open_primary_current()?);
        Ok(())
    }
    fn put(&mut self, namespace: &str, key: &[u8], value: &[u8]) -> Result<()> {
        ensure!(
            self.operations.len() < OPS,
            "primary fixed journal batch overflow"
        );
        // These metadata allocations are individually bounded by fixed records,
        // short namespaces and at-most-56-byte keys; the control floor covers
        // all four capacities and their allocator rounding simultaneously.
        ensure!(
            Self::metadata_shape(namespace, key.len(), Some(value.len())),
            "primary journal write shape differs"
        );
        self.operations.push(WriteOp::Put {
            namespace: exact_namespace(namespace)?,
            key: exact_bytes(key)?,
            value: exact_bytes(value)?,
        });
        Ok(())
    }
    fn delete(&mut self, namespace: &str, key: &[u8]) -> Result<()> {
        ensure!(
            self.operations.len() < OPS && Self::metadata_shape(namespace, key.len(), None),
            "primary deletion batch shape differs"
        );
        self.operations.push(WriteOp::Delete {
            namespace: exact_namespace(namespace)?,
            key: exact_bytes(key)?,
        });
        Ok(())
    }
    fn put_chunk(&mut self, key: &[u8]) -> Result<()> {
        ensure!(key.len() == 32, "primary chunk key shape differs");
        self.put_buffer(CHUNKS, key)
    }
    fn put_buffer(&mut self, namespace: &str, key: &[u8]) -> Result<()> {
        ensure!(
            self.operations.is_empty()
                && ((namespace == CHUNKS && key.len() == 32)
                    || (namespace == PAGES
                        && key.len() == 24
                        && self.chunk.len() == super::PAGE_BYTES)),
            "primary buffered batch shape differs"
        );
        ensure!(
            self.chunk.capacity() == chunk::BYTES,
            "primary chunk capacity changed"
        );
        let namespace = exact_namespace(namespace)?;
        let key = exact_bytes(key)?;
        self.operations.push(WriteOp::Put {
            namespace,
            key,
            value: std::mem::take(&mut self.chunk),
        });
        Ok(())
    }
    fn write(&mut self) -> Result<()> {
        let bytes = self.operations.iter().try_fold(0_usize, |total, op| {
            let (namespace, key, value) = match op {
                WriteOp::Put {
                    namespace,
                    key,
                    value,
                } => (namespace, key, value.len()),
                WriteOp::Delete { namespace, key } => (namespace, key, 0),
            };
            total
                .checked_add(namespace.len())
                .and_then(|n| n.checked_add(key.len()))
                .and_then(|n| n.checked_add(value))
                .context("primary batch size overflow")
        })?;
        ensure!(
            self.operations.len() <= OPS && bytes <= OP_BYTES,
            "primary stage batch bound exceeded"
        );
        self.stores.write_batch(&self.operations, &[])?;
        // Successful publication alone allows local high-water advancement.
        // A failure retains this exact proposed batch with the original error.
        while let Some(op) = self.operations.pop() {
            if let WriteOp::Put {
                namespace, value, ..
            } = op
                && (namespace == CHUNKS || namespace == PAGES)
            {
                self.chunk = value;
                self.chunk.clear();
            }
        }
        Ok(())
    }
    fn begin_fresh(&mut self) -> Result<()> {
        let gc = self
            .read(META, b"gc", records::GC_BYTES, |bytes| {
                bytes.map(|bytes| codec(GcState::decode(bytes))).transpose()
            })?
            .unwrap_or(GcState {
                current: None,
                building: None,
                retired: None,
            });
        ensure!(
            gc.building.is_none() && gc.retired.is_none(),
            "primary prior epoch requires cleanup"
        );
        let selected = self.read(META, b"selected", records::SELECTOR_BYTES, |bytes| {
            bytes
                .map(|bytes| codec(Selector::decode(bytes)))
                .transpose()
        })?;
        match selected {
            Some(selected) => ensure!(
                selected.scope == self.scope && gc.current == Some(selected.projection_epoch),
                "primary selected/current epoch differs"
            ),
            None => ensure!(
                gc.current.is_none(),
                "primary current epoch has no selector"
            ),
        }
        let epoch_id = *uuid::Uuid::new_v4().as_bytes();
        let attempt_id = *uuid::Uuid::new_v4().as_bytes();
        ensure!(
            gc.current != Some(epoch_id),
            "primary epoch identity collision"
        );
        ensure!(
            self.read(EPOCHS, &epoch_id, records::EPOCH_BYTES, |bytes| Ok(
                bytes.is_none()
            ))?,
            "primary epoch already exists"
        );
        ensure!(
            self.read(ATTEMPTS, &attempt_id, records::ATTEMPT_BYTES, |bytes| Ok(
                bytes.is_none()
            ))?,
            "primary attempt already exists"
        );
        let epoch = Epoch {
            scope: self.scope,
            id: epoch_id,
            head: Some(attempt_id),
            tail: Some(attempt_id),
            pending: Some(attempt_id),
            live_resources: 0,
        };
        let attempt = Attempt {
            phase: AttemptPhase::Building,
            scope: self.scope,
            epoch: epoch_id,
            id: attempt_id,
            previous: None,
            next: None,
            next_object: 0,
            live_resources: 0,
            retire_count: 0,
            abort_object_cursor: 0,
            retire_cursor: 0,
            journal_erase_cursor: 0,
        };
        let gc = GcState {
            building: Some(epoch_id),
            ..gc
        };
        let mut eb = [0; records::EPOCH_BYTES];
        codec(epoch.encode(&mut eb))?;
        let mut ab = [0; records::ATTEMPT_BYTES];
        codec(attempt.encode(&mut ab))?;
        let mut gb = [0; records::GC_BYTES];
        codec(gc.encode(&mut gb))?;
        self.put(EPOCHS, &epoch_id, &eb)?;
        self.put(ATTEMPTS, &attempt_id, &ab)?;
        self.put(META, b"gc", &gb)?;
        self.write()?;
        self.gc = Some(gc);
        self.epoch = Some(epoch);
        self.attempt = Some(attempt);
        Ok(())
    }
    fn stage_dto(
        &mut self,
        tree: [u8; 16],
        dto: CanonicalDto<'_>,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<OverflowRef> {
        self.require_catalog_mutable()?;
        check()?;
        ensure!(tree != [0; 16], "primary tree identity absent");
        let mut attempt = self.attempt.context("primary attempt absent")?;
        let mut epoch = self.epoch.context("primary epoch absent")?;
        ensure!(
            attempt.phase == AttemptPhase::Building,
            "primary attempt does not accept objects"
        );
        let serializer = dto.workspace_checked(check)?;
        self.reservation.ensure_peak(
            self.baseline
                .checked_add(serializer)
                .context("primary serializer quote overflow")?,
        )?;
        let mut counted = CountHash::new();
        {
            let mut checked = check::CheckedWriter::new(&mut counted, check);
            let serialized = dto.write(&mut checked);
            checked.finish(serialized)?;
        }
        let units = codec(records::chunk_count(counted.bytes))?;
        let reference = OverflowRef {
            id: ObjectId {
                attempt: attempt.id,
                ordinal: attempt.next_object,
            },
            encoded_bytes: counted.bytes,
            sha256: counted.hash.finalize().into(),
        };
        attempt.next_object = attempt
            .next_object
            .checked_add(1)
            .context("primary object ordinal exhausted")?;
        attempt.live_resources = attempt
            .live_resources
            .checked_add(1)
            .context("primary attempt resources overflow")?;
        epoch.live_resources = epoch
            .live_resources
            .checked_add(1)
            .context("primary epoch resources overflow")?;
        let inventory = Inventory {
            kind: dto.kind(),
            phase: InventoryPhase::Allocating,
            scope: self.scope,
            id: reference.id,
            tree_id: tree,
            encoded_bytes: reference.encoded_bytes,
            sha256: reference.sha256,
            total_units: units,
            completed_units: 0,
            cleanup_unit_cursor: 0,
            catalog_dense_count: 0,
        };
        let mut ib = [0; records::INVENTORY_BYTES];
        codec(inventory.encode(&mut ib))?;
        let mut ab = [0; records::ATTEMPT_BYTES];
        codec(attempt.encode(&mut ab))?;
        let mut eb = [0; records::EPOCH_BYTES];
        codec(epoch.encode(&mut eb))?;
        check()?;
        self.put(INVENTORY, &object_key(reference.id), &ib)?;
        self.put(ATTEMPTS, &attempt.id, &ab)?;
        self.put(EPOCHS, &epoch.id, &eb)?;
        self.write()?;
        self.attempt = Some(attempt);
        self.epoch = Some(epoch);
        self.chunk.resize(chunk::HEADER, 0);
        let mut sink = ChunkSink {
            resources: self,
            inventory,
            reference,
            hash: Sha256::new(),
            bytes: 0,
            error: None,
            check,
        };
        let serialized = dto.write(&mut sink);
        if let Some(error) = sink.error.take() {
            return Err(error);
        }
        serialized?;
        ensure!(
            sink.bytes == reference.encoded_bytes
                && <[u8; 32]>::from(sink.hash.clone().finalize()) == reference.sha256,
            "primary canonical DTO changed between passes"
        );
        // The final full or partial chunk is intentionally held until the exact
        // second-pass count/hash succeeds. Complete never precedes verification.
        sink.flush_chunk(true)?;
        self.reservation.retain(self.baseline);
        Ok(reference)
    }
    fn visit_staged(
        &mut self,
        reference: OverflowRef,
        tree: [u8; 16],
        kind: ResourceKind,
        mut lend: impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        ensure!(
            reference.id.attempt == self.attempt.context("primary attempt absent")?.id,
            "staged reader cannot resolve another attempt"
        );
        self.refresh()?;
        let inventory = self.read(
            INVENTORY,
            &object_key(reference.id),
            records::INVENTORY_BYTES,
            |bytes| {
                codec(Inventory::decode(
                    bytes.context("primary object inventory absent")?,
                ))
            },
        )?;
        ensure!(
            inventory.scope == self.scope
                && inventory.id == reference.id
                && inventory.tree_id == tree
                && inventory.kind == kind
                && inventory.encoded_bytes == reference.encoded_bytes
                && inventory.sha256 == reference.sha256
                && inventory.phase == InventoryPhase::Complete,
            "primary object inventory differs"
        );
        visit_object(
            self.reader.as_mut().expect("staged reader"),
            &mut self.reservation,
            self.baseline,
            self.scope,
            reference,
            tree,
            kind,
            &mut lend,
        )?;
        Ok(())
    }
}
struct ChunkSink<'a> {
    resources: &'a mut PrimaryResources,
    inventory: Inventory,
    reference: OverflowRef,
    hash: Sha256,
    bytes: u64,
    error: Option<anyhow::Error>,
    check: &'a mut dyn FnMut() -> Result<()>,
}
impl ChunkSink<'_> {
    fn flush_chunk(&mut self, complete: bool) -> Result<()> {
        (self.check)()?;
        ensure!(
            self.resources.chunk.len() > chunk::HEADER,
            "empty primary payload chunk"
        );
        chunk::frame(
            &mut self.resources.chunk,
            self.resources.scope,
            self.inventory.tree_id,
            self.reference,
            self.inventory.kind,
            self.inventory.completed_units,
        )?;
        let mut next = self.inventory;
        next.completed_units = next
            .completed_units
            .checked_add(1)
            .context("primary chunk high-water overflow")?;
        if complete {
            next.phase = InventoryPhase::Complete;
        }
        let mut ib = [0; records::INVENTORY_BYTES];
        codec(next.encode(&mut ib))?;
        ensure!(
            self.resources.operations.is_empty(),
            "primary chunk batch not empty"
        );
        self.resources.put_chunk(&chunk::key(
            self.reference.id,
            self.inventory.completed_units,
        ))?;
        self.resources.put(INVENTORY, &object_key(next.id), &ib)?;
        self.resources.write()?;
        self.inventory = next;
        (self.check)()?;
        self.resources.chunk.resize(chunk::HEADER, 0);
        #[cfg(test)]
        if let Some(remaining) = self.resources.interrupt_after_chunks.as_mut() {
            *remaining = remaining.saturating_sub(1);
            ensure!(
                *remaining != 0,
                "injected interruption after durable primary chunk"
            );
        }
        Ok(())
    }
}
impl Write for ChunkSink<'_> {
    fn write(&mut self, mut bytes: &[u8]) -> std::io::Result<usize> {
        if self.error.is_some() {
            return Err(std::io::ErrorKind::Other.into());
        }
        let count = bytes.len();
        let result = (|| -> Result<()> {
            while !bytes.is_empty() {
                (self.check)()?;
                ensure!(
                    self.bytes < self.reference.encoded_bytes,
                    "primary DTO exceeds counted length"
                );
                if self.resources.chunk.len() == chunk::BYTES {
                    self.flush_chunk(false)?;
                }
                let copy = bytes.len().min(chunk::BYTES - self.resources.chunk.len());
                self.resources.chunk.extend_from_slice(&bytes[..copy]);
                self.hash.update(&bytes[..copy]);
                self.bytes = self
                    .bytes
                    .checked_add(copy as u64)
                    .context("primary DTO count overflow")?;
                bytes = &bytes[copy..];
            }
            Ok(())
        })();
        match result {
            Ok(()) => Ok(count),
            Err(error) => {
                self.error = Some(error);
                Err(std::io::ErrorKind::Other.into())
            }
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// The same immutable paired pin is retained across both bounded passes. No DTO
// or payload is lent before the first complete hash check succeeds.
#[allow(clippy::too_many_arguments)]
pub(super) fn visit_object(
    reader: &mut SourceReader,
    reservation: &mut Reservation,
    baseline: u64,
    scope: [u8; 32],
    reference: OverflowRef,
    tree: [u8; 16],
    kind: ResourceKind,
    mut lend: impl FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    visit_object_checked(
        reader,
        reservation,
        baseline,
        scope,
        reference,
        tree,
        kind,
        &mut || Ok(()),
        &mut lend,
    )
}
#[allow(clippy::too_many_arguments)]
fn visit_object_checked(
    reader: &mut SourceReader,
    reservation: &mut Reservation,
    baseline: u64,
    scope: [u8; 32],
    reference: OverflowRef,
    tree: [u8; 16],
    kind: ResourceKind,
    check: &mut dyn FnMut() -> Result<()>,
    lend: &mut dyn FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    let units = codec(records::chunk_count(reference.encoded_bytes))?;
    let mut hash = Sha256::new();
    for ordinal in 0..units {
        check()?;
        reader.with_record(
            reservation,
            baseline,
            CHUNKS,
            &chunk::key(reference.id, ordinal),
            chunk::BYTES,
            |bytes| {
                hash.update(chunk::parse(
                    bytes.context("primary chunk absent")?,
                    scope,
                    tree,
                    reference,
                    kind,
                    ordinal,
                )?);
                Ok(())
            },
        )?;
    }
    ensure!(
        <[u8; 32]>::from(hash.finalize()) == reference.sha256,
        "primary object digest differs"
    );
    for ordinal in 0..units {
        check()?;
        reader.with_record(
            reservation,
            baseline,
            CHUNKS,
            &chunk::key(reference.id, ordinal),
            chunk::BYTES,
            |bytes| {
                lend(chunk::parse(
                    bytes.context("primary chunk absent")?,
                    scope,
                    tree,
                    reference,
                    kind,
                    ordinal,
                )?)
            },
        )?;
    }
    Ok(())
}
