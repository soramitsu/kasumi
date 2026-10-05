//! Test-only accepted graph and existing-key COW preparation. No production
//! selector publication, serving activation or committed retirement exists.
use super::*;
use crate::primary_tree::{
    self as tree, Child, EncodedPage, Entry, ExpectedPage, KeyRange, Leaf, PageRef, RecordKind,
    Totals, Value,
};
use crate::{
    application_sources::SelectedApplication,
    state::{Generation, primary_projection::PrimaryCandidate},
};
use records::{CatalogEntry, CatalogId, CatalogMember, Manifest, ManifestRef, Retire, Root};

#[path = "primary_stage_baseline.rs"]
mod baseline;
#[path = "primary_stage_verify.rs"]
mod verify;
pub(crate) use baseline::CommittedBaseline;
#[path = "primary_stage_edit.rs"]
mod edit;
pub(crate) use edit::{PendingReplacement, PreparedReplacement, PublicationFailure};
pub(crate) use verify::BaselineVerifier;

const DEPTH: usize = tree::MAX_LEVEL as usize + 1;
const ENTRIES: usize = (tree::PAGE_BYTES - tree::HEADER_BYTES) / (2 + 1 + tree::DESCRIPTOR_BYTES);

#[derive(Clone, Copy, Debug)]
struct Name {
    bytes: [u8; tree::MAX_ID_BYTES],
    len: usize,
}
impl Name {
    const NONE: Self = Self {
        bytes: [0; tree::MAX_ID_BYTES],
        len: 0,
    };
    fn new(value: Option<&str>) -> Result<Self> {
        let mut out = Self::NONE;
        if let Some(value) = value {
            codec(tree::check_id(value))?;
            out.len = value.len();
            out.bytes[..out.len].copy_from_slice(value.as_bytes());
        }
        Ok(out)
    }
    fn optional(&self) -> Option<&str> {
        (self.len != 0).then(|| self.text())
    }
    fn text(&self) -> &str {
        std::str::from_utf8(&self.bytes[..self.len]).expect("validated fixed name")
    }
}
#[derive(Clone, Copy)]
struct Frame {
    reference: PageRef,
    level: u8,
    generation: u64,
    totals: Totals,
    lower: Name,
    upper: Name,
    next: usize,
}
impl Frame {
    fn root(manifest: Manifest) -> Result<Self> {
        let root = manifest.root.context("primary root absent")?;
        Ok(Self {
            reference: root.reference,
            level: root.level,
            generation: manifest.data_epoch,
            totals: manifest.totals,
            lower: Name::NONE,
            upper: Name::NONE,
            next: 0,
        })
    }
    fn from_expected(value: ExpectedPage<'_>) -> Result<Self> {
        Ok(Self {
            reference: value.reference,
            level: value.level,
            generation: value.generation_ceiling,
            totals: value.totals,
            lower: Name::new(value.range.lower)?,
            upper: Name::new(value.range.upper)?,
            next: 0,
        })
    }
    fn expected(&self, tree_id: [u8; 16]) -> ExpectedPage<'_> {
        ExpectedPage {
            tree_id,
            reference: self.reference,
            generation_ceiling: self.generation,
            level: self.level,
            totals: self.totals,
            range: KeyRange {
                lower: self.lower.optional(),
                upper: self.upper.optional(),
            },
        }
    }
}
// Independent actual grants cover buffers/frames and their deallocation. No
// candidate body or source-bank funding is inferred from these work grants.
struct Work {
    page: Vec<u8>,
    next_page: Vec<u8>,
    new_pages: Vec<EncodedPage>,
    frames: Vec<Frame>,
    targets: Vec<ObjectId>,
    charged: u64,
    _grant: Reservation,
}
impl Work {
    fn allocate(resources: &PrimaryResources) -> Result<Self> {
        let bytes = allocated(ENTRIES * std::mem::size_of::<Entry<'_>>())?
            .checked_add(allocated(tree::PAGE_BYTES)?)
            .context("COW entries quote overflow")?
            .checked_add(allocated(tree::PAGE_BYTES)?)
            .context("COW pages quote overflow")?
            .checked_add(allocated(DEPTH * std::mem::size_of::<EncodedPage>())?)
            .context("COW descriptors quote overflow")?
            .checked_add(allocated(DEPTH * std::mem::size_of::<Frame>())?)
            .and_then(|n| {
                n.checked_add(allocated((DEPTH + 2) * std::mem::size_of::<ObjectId>()).ok()?)
            })
            .and_then(|n| n.checked_add(allocated(std::mem::size_of::<CowFailure>()).ok()?))
            .and_then(|n| n.checked_add(4096))
            .context("primary COW work quote overflow")?;
        let grant = resources
            .roots
            .primary_installation()
            .1
            .reserve_application_source(bytes)?;
        let mut out = Self {
            page: Vec::new(),
            next_page: Vec::new(),
            new_pages: Vec::new(),
            frames: Vec::new(),
            targets: Vec::new(),
            charged: bytes,
            _grant: grant,
        };
        out.page.try_reserve_exact(tree::PAGE_BYTES)?;
        out.next_page.try_reserve_exact(tree::PAGE_BYTES)?;
        out.new_pages.try_reserve_exact(DEPTH)?;
        out.frames.try_reserve_exact(DEPTH)?;
        out.targets.try_reserve_exact(DEPTH + 2)?;
        ensure!(
            out.page.capacity() == tree::PAGE_BYTES
                && out.next_page.capacity() == tree::PAGE_BYTES
                && out.new_pages.capacity() == DEPTH
                && out.frames.capacity() == DEPTH
                && out.targets.capacity() == DEPTH + 2,
            "primary COW work capacity differs"
        );
        Ok(out)
    }
    fn entry_workspace<'a>(&self) -> Result<Vec<Entry<'a>>> {
        let mut entries = Vec::new();
        entries.try_reserve_exact(ENTRIES)?;
        ensure!(
            entries.capacity() == ENTRIES,
            "COW entry workspace capacity differs"
        );
        Ok(entries)
    }
    fn read_page(
        &mut self,
        resources: &mut PrimaryResources,
        frame: Frame,
        tree: [u8; 16],
    ) -> Result<()> {
        self.page.clear();
        resources.read(
            PAGES,
            &object_key(frame.reference.id),
            tree::PAGE_BYTES,
            |bytes| {
                let bytes = bytes.context("primary path page absent")?;
                codec(tree::validate(bytes, frame.expected(tree)))?;
                self.page.extend_from_slice(bytes);
                Ok(())
            },
        )
    }
    fn target(&mut self, id: ObjectId) -> Result<()> {
        ensure!(
            self.targets.len() < DEPTH + 2 && !self.targets.contains(&id),
            "primary repeated retire target"
        );
        self.targets.push(id);
        Ok(())
    }
}

/// Inline noncloneable original plus exact allocations/source custody. No
/// std::error::Error impl permits an implicit extra anyhow allocation.
pub(crate) struct CowFailure {
    original: anyhow::Error,
    _candidate: Option<Arc<Generation>>,
    _work: Option<Work>,
    _resources: Option<PrimaryResources>,
    _selected: Option<SelectedApplication>,
    _baseline: Option<VerifiedBaseline>,
    _prior: Option<CommittedBaseline>,
}
impl CowFailure {
    pub(crate) fn original(&self) -> &anyhow::Error {
        &self.original
    }
    // Read-only evidence for test-only unknown-publication fixtures. The exact
    // charged operation buffers stay owned by this failure; no authority moves.
    pub(crate) fn proposed_writes(&self) -> Option<&[WriteOp]> {
        self._resources
            .as_ref()
            .map(|resources| resources.operations.as_slice())
    }
}
impl std::fmt::Debug for CowFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CowFailure")
            .field("original", &self.original)
            .finish_non_exhaustive()
    }
}
type CowResult<T> = std::result::Result<T, CowFailure>;

pub(crate) struct VerifiedBaseline {
    candidate: Arc<Generation>,
    stores: Arc<TenantStorageSet>,
    scope: [u8; 32],
    bootstrap: [u8; 32],
    catalog: CatalogId,
    epoch: Epoch,
    attempt: Attempt,
    members: u64,
    totals: Totals,
    catalog_digest: [u8; 32],
    // Fixed proof enclosure and any owned diagnostic remain charged.
    _grant: Reservation,
}
impl VerifiedBaseline {
    pub(crate) fn catalog(&self) -> CatalogId {
        self.catalog
    }
    pub(crate) fn totals(&self) -> Totals {
        self.totals
    }
    pub(crate) fn members(&self) -> u64 {
        self.members
    }
    pub(crate) fn epoch(&self) -> Epoch {
        self.epoch
    }
    pub(crate) fn attempt(&self) -> Attempt {
        self.attempt
    }
}

fn original_panic(payload: Box<dyn std::any::Any + Send>) -> anyhow::Error {
    StagePanic {
        _payload: Mutex::new(payload),
    }
    .into()
}
fn same_stores(a: &Arc<TenantStorageSet>, b: &Arc<TenantStorageSet>) -> Result<()> {
    ensure!(
        Arc::ptr_eq(a.application(), b.application())
            && Arc::ptr_eq(a.custody().store(), b.custody().store()),
        "primary store pair differs"
    );
    Ok(())
}
impl PrimaryResources {
    fn check_complete(
        &mut self,
        id: ObjectId,
        tree: [u8; 16],
        kind: ResourceKind,
        bytes: u64,
        hash: [u8; 32],
    ) -> Result<Inventory> {
        let actual = self.read_inventory(id)?;
        ensure!(
            actual.id == id
                && actual.scope == self.scope
                && actual.tree_id == tree
                && actual.kind == kind
                && actual.encoded_bytes == bytes
                && actual.sha256 == hash
                && actual.phase == InventoryPhase::Complete
                && actual.cleanup_unit_cursor == 0
                && actual.completed_units == actual.total_units
                && actual.catalog_dense_count == 0,
            "primary complete inventory differs"
        );
        if matches!(kind, ResourceKind::Page | ResourceKind::CollectionManifest) {
            Self::require_complete_fixed(actual)?;
        } else {
            ensure!(
                actual.total_units == codec(records::chunk_count(bytes))?,
                "primary DTO chunk count differs"
            );
        }
        Ok(actual)
    }
    fn canonical(
        &mut self,
        reference: OverflowRef,
        tree: [u8; 16],
        dto: CanonicalDto<'_>,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.check_complete(
            reference.id,
            tree,
            dto.kind(),
            reference.encoded_bytes,
            reference.sha256,
        )?;
        self.reservation.ensure_peak(
            self.baseline
                .checked_add(dto.workspace_checked(check)?)
                .context("canonical quote overflow")?,
        )?;
        let mut expected = CountHash::new();
        {
            let mut writer = check::CheckedWriter::new(&mut expected, check);
            let serialized = dto.write(&mut writer);
            writer.finish(serialized)?;
        }
        ensure!(
            expected.bytes == reference.encoded_bytes
                && <[u8; 32]>::from(expected.hash.finalize()) == reference.sha256,
            "primary accepted canonical DTO differs"
        );
        self.reservation.retain(self.baseline);
        visit_object_checked(
            self.reader
                .as_mut()
                .context("primary verifier reader absent")?,
            &mut self.reservation,
            self.baseline,
            self.scope,
            reference,
            tree,
            dto.kind(),
            check,
            &mut |_| Ok(()),
        )
    }
    fn mapping(&mut self, catalog: CatalogId, name: [u8; 32]) -> Result<CatalogEntry> {
        self.read(
            CATALOG,
            &CatalogEntry::key(catalog, name),
            records::CATALOG_ENTRY_BYTES,
            |bytes| {
                let value = codec(CatalogEntry::decode(
                    bytes.context("primary catalog mapping absent")?,
                ))?;
                ensure!(
                    value.catalog == catalog && value.name_hash == name,
                    "primary mapping identity differs"
                );
                Ok(value)
            },
        )
    }
    fn manifest(&mut self, reference: ManifestRef) -> Result<Manifest> {
        self.read(
            MANIFESTS,
            &object_key(reference.id),
            records::MANIFEST_BYTES,
            |bytes| {
                codec(Manifest::decode_referenced(
                    bytes.context("primary manifest absent")?,
                    reference,
                ))
            },
        )
    }
}

pub(crate) struct WorkWitness {
    // Same actual per-page entry allocation retires before Work's real grant.
    entries: Vec<Entry<'static>>,
    work: Work,
}
pub(crate) struct WorkMeasurement {
    pub(crate) addresses: [usize; 3],
    pub(crate) charged: u64,
    pub(crate) live: i64,
    pub(crate) peak: i64,
    pub(crate) allocations: usize,
    pub(crate) owner: WorkWitness,
}
pub(crate) fn measure_work_for_test(
    authority: &mut PrimaryApplyGuard<'_>,
) -> Result<WorkMeasurement> {
    let stage = PrimaryStage::allocate(authority)?;
    let (owner, live, peak, allocations) =
        crate::document_pool::allocation_tests::measure_topology_input(
            || -> Result<WorkWitness> {
                let work = Work::allocate(&stage.resources)?;
                let entries = work.entry_workspace()?;
                Ok(WorkWitness { entries, work })
            },
        );
    let owner = owner?;
    stage.close()?;
    Ok(WorkMeasurement {
        addresses: [
            owner.work.page.as_ptr() as usize,
            owner.work.next_page.as_ptr() as usize,
            owner.entries.as_ptr() as usize,
        ],
        charged: owner.work.charged,
        live,
        peak,
        allocations,
        owner,
    })
}

/// Test-only physical inspection: the caller owns this current reader and grant.
/// This validates chunk framing/digest and lends bytes, never producer authority.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn visit_physical_for_test(
    reader: &mut SourceReader,
    grant: &mut Reservation,
    scope: [u8; 32],
    reference: OverflowRef,
    tree: [u8; 16],
    kind: ResourceKind,
    lend: impl FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    visit_object(reader, grant, 4096, scope, reference, tree, kind, lend)
}

/// Borrow the actual failed abort batch; the StageFailure retains its charged
/// operation buffers and original error. This cannot retry or change an effect.
#[cfg(test)]
pub(crate) fn stage_failure_writes_for_test(error: &anyhow::Error) -> Option<&[WriteOp]> {
    error
        .downcast_ref::<StageFailure>()
        .map(|failure| failure.resources.operations.as_slice())
}
