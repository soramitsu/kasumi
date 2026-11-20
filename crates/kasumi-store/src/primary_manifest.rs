//! The ordinary primary directory: one ordered tree of the live, archived and
//! header rows of every document, kept at the exact applied revision.
//!
//! The snapshot application manifest (`application_manifest`) names a tree
//! built from one authenticated Raft snapshot and changes only with snapshot
//! publication. This manifest instead advances with ordinary apply: each
//! candidate publication edits the rows of its changed documents copy-on-write
//! inside the selected primary page space and commits the new root, through
//! this fixed-size row, in the same paired native transaction as the applied
//! cursor. Earlier read views keep the root and pages of their own native
//! generation.
//!
//! A replacement generation (snapshot installation, or reopen without a
//! current directory) is bulk-built into a fresh space staged by
//! `NamespaceStage` and selected with the manifest; the replaced space is
//! retired and reclaimed in bounded batches. The two manifests never write each
//! other's rows, so an asynchronous snapshot checkpoint cannot move this one.
//!
//! Store enforces the monotonic contract inside every native transaction that
//! writes this row: without a selection switch the successor must keep the
//! tree, page space and scope, follow a current predecessor and increase the
//! revision. Covered replay therefore cannot move the directory backward.
//!
//! Deployed revisions predate this row. Their stores open without it and the
//! first snapshot restore with installed application sources builds it.
use super::*;
use crate::ordered_pages::TreeRoot;

pub const MANIFESTS: &str = "kasumi.app.primary.manifest";
pub const CURRENT: &[u8] = b"current";
pub const MAX_MANIFEST_BYTES: usize = 8 << 10;
/// The family selector of primary page spaces.
pub const FAMILY: &str = "kasumi.app.primary";
/// What an absent selector names. A pristine store's first directory edits
/// pages here; the first replacement generation retires it.
pub const INITIAL_SPACE: [&str; 1] = ["kasumi.app.primary"];
const FORMAT: u32 = 1;

/// Whether the tree holds exactly the rows at `revision`. A stale directory
/// keeps naming its last tree so its space stays owned, but readers and
/// ordinary edits ignore it until a replacement generation is selected.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum PrimaryStatus {
    Current,
    Stale,
    Rebuilding(PrimaryRebuild),
}

/// An independent physical rebuild starts at one authenticated ordinary
/// position. The cursor and tree advance in the same native transaction.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PrimaryRebuild {
    pub captured: PrimaryApplied,
    pub through: PrimaryCursor,
    pub cursor: Option<PrimaryCursor>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PrimaryCursor {
    pub collection: String,
    /// None means the whole collection, including an empty one, was visited.
    pub after_document: Option<String>,
}

impl Ord for PrimaryCursor {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.collection.cmp(&other.collection).then_with(|| {
            match (&self.after_document, &other.after_document) {
                (Some(a), Some(b)) => a.cmp(b),
                (None, None) => std::cmp::Ordering::Equal,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (Some(_), None) => std::cmp::Ordering::Less,
            }
        })
    }
}
impl PartialOrd for PrimaryCursor {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// The producer boundary of the revision: the applied Raft log position and,
/// for an ordinary entry, its exact command digest. Snapshot boundaries carry
/// no command. Bootstrap (no applied position) has no boundary.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PrimaryApplied {
    pub index: u64,
    pub log_sha256: [u8; 32],
    pub command_sha256: Option<[u8; 32]>,
}

impl PrimaryApplied {
    /// The same applied position. An entry's command identity must also
    /// agree when both sides carry one; a snapshot boundary carries none.
    pub fn same_position(&self, other: &Self) -> bool {
        self.index == other.index
            && self.log_sha256 == other.log_sha256
            && match (&self.command_sha256, &other.command_sha256) {
                (Some(left), Some(right)) => left == right,
                _ => true,
            }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PrimaryManifest {
    pub format: u32,
    pub tenant: String,
    pub incarnation: String,
    pub revision_base: u64,
    /// The exact applied revision whose rows the tree holds.
    pub revision: u64,
    pub status: PrimaryStatus,
    pub applied: Option<PrimaryApplied>,
    pub page_space: String,
    pub records: TreeRoot,
    pub document_count: u64,
    pub logical_bytes: u64,
}

impl PrimaryManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant: &str,
        incarnation: &str,
        revision_base: u64,
        revision: u64,
        applied: Option<PrimaryApplied>,
        page_space: &str,
        records: TreeRoot,
        document_count: u64,
        logical_bytes: u64,
    ) -> Self {
        Self {
            format: FORMAT,
            tenant: tenant.into(),
            incarnation: incarnation.into(),
            revision_base,
            revision,
            status: PrimaryStatus::Current,
            applied,
            page_space: page_space.into(),
            records,
            document_count,
            logical_bytes,
        }
    }

    pub fn is_current(&self) -> bool {
        self.status == PrimaryStatus::Current
    }

    pub fn rebuild(&self) -> Option<&PrimaryRebuild> {
        match &self.status {
            PrimaryStatus::Rebuilding(progress) => Some(progress),
            _ => None,
        }
    }

    pub(crate) fn is_rebuild_seed(&self) -> bool {
        self.rebuild().is_some_and(|p| {
            p.cursor.is_none()
                && self.records.count() == 0
                && self.applied.as_ref() == Some(&p.captured)
        })
    }

    /// The edited successor at `revision`; tree identity and space are kept.
    pub fn advance(
        &self,
        revision: u64,
        applied: Option<PrimaryApplied>,
        records: TreeRoot,
        document_count: u64,
        logical_bytes: u64,
    ) -> Self {
        Self {
            revision,
            status: PrimaryStatus::Current,
            applied,
            records,
            document_count,
            logical_bytes,
            ..self.clone()
        }
    }

    /// The successor that stops claiming currency at `revision`. Its tree and
    /// space stay named, so the space remains owned until it is replaced.
    pub fn stale(&self, revision: u64, applied: Option<PrimaryApplied>) -> Self {
        Self {
            revision,
            status: PrimaryStatus::Stale,
            applied,
            ..self.clone()
        }
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_MANIFEST_BYTES,
            "primary manifest exceeds its bound"
        );
        let manifest: Self = serde_json::from_slice(bytes)?;
        ensure!(
            serde_json::to_vec(&manifest)? == bytes,
            "noncanonical primary manifest"
        );
        manifest.validate()?;
        Ok(manifest)
    }

    fn validate(&self) -> Result<()> {
        ensure!(self.format == FORMAT, "unsupported primary manifest format");
        ensure!(
            self.revision >= self.revision_base && !self.page_space.is_empty(),
            "invalid primary manifest"
        );
        ensure!(
            self.applied
                .as_ref()
                .is_none_or(
                    |applied| self.revision_base.checked_add(applied.index) == Some(self.revision)
                ),
            "primary manifest boundary differs from its revision"
        );
        if let Some(progress) = self.rebuild() {
            let current = self
                .applied
                .as_ref()
                .context("primary rebuild lost its applied boundary")?;
            ensure!(
                progress.captured.index <= current.index
                    && progress.captured.command_sha256.is_some(),
                "invalid captured primary rebuild position"
            );
            kasumi_types::validate_name(&progress.through.collection)?;
            kasumi_types::validate_name(
                progress
                    .through
                    .after_document
                    .as_deref()
                    .context("primary rebuild missing terminal document")?,
            )?;
            if let Some(cursor) = &progress.cursor {
                kasumi_types::validate_name(&cursor.collection)?;
                if let Some(id) = &cursor.after_document {
                    kasumi_types::validate_name(id)?;
                }
                ensure!(
                    cursor <= &progress.through,
                    "primary cursor exceeds its captured bound"
                );
            }
        }
        kasumi_types::validate_name(&self.tenant)?;
        kasumi_types::validate_name(&self.incarnation)?;
        validate_record(&self.page_space, &[], 0)?;
        ensure!(
            self.page_space == FAMILY
                || self
                    .page_space
                    .strip_prefix(FAMILY)
                    .and_then(|rest| rest.strip_prefix('@'))
                    .is_some_and(|id| Uuid::parse_str(id).is_ok()),
            "primary manifest names a foreign page space"
        );
        Ok(())
    }

    /// The fixed-size write selecting this manifest. It commits with the
    /// applied cursor and every page its tree names.
    pub fn write(&self) -> Result<WriteOp> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        ensure!(
            bytes.len() <= MAX_MANIFEST_BYTES,
            "primary manifest exceeds its bound"
        );
        Ok(WriteOp::put(MANIFESTS, CURRENT, bytes))
    }

    /// Successor rules checked inside the writing native transaction when the
    /// same batch does not select a replacement generation.
    pub(crate) fn check_successor(&self, previous: &Self) -> Result<()> {
        ensure!(
            previous.is_current() || previous.rebuild().is_some(),
            "a stale primary directory needs a replacement generation"
        );
        ensure!(
            self.tenant == previous.tenant
                && self.incarnation == previous.incarnation
                && self.revision_base == previous.revision_base
                && self.page_space == previous.page_space
                && self.records.tree == previous.records.tree,
            "primary directory successor changes its tree or scope"
        );
        if let Some(prior) = previous.rebuild() {
            let next = self.rebuild();
            if let Some(next) = next {
                ensure!(
                    next.captured == prior.captured
                        && next.through == prior.through
                        && next.cursor >= prior.cursor,
                    "primary rebuild changed its captured source or regressed"
                );
            }
            if self.is_current() {
                ensure!(
                    prior.cursor.as_ref() == Some(&prior.through)
                        && self.document_count.checked_mul(2) == Some(self.records.count()),
                    "partial primary directory cannot become current"
                );
            }
            let advanced =
                next.is_some_and(|next| next.cursor > prior.cursor) || self.rebuild().is_none();
            ensure!(
                self.revision > previous.revision
                    || self.revision == previous.revision
                        && self.applied == previous.applied
                        && advanced,
                "primary rebuild repeated or regressed"
            );
        } else {
            ensure!(
                self.rebuild().is_none(),
                "primary rebuild needs a new physical tree"
            );
            ensure!(
                self.revision > previous.revision
                    || self.revision == previous.revision && !self.is_current(),
                "primary directory cannot move backward or repeat a revision"
            );
        }
        Ok(())
    }

    /// The current directory of `store`; callers must hold the publication
    /// gate under which it can change (the tenant apply owner).
    pub fn load(store: &TenantStore) -> Result<Option<Self>> {
        Self::load_from_pages(store)
    }

    /// The directory at a pinned root: its pages remain readable through
    /// `view` even while later edits replace and delete them.
    pub fn load_at(view: &TenantReadView) -> Result<Option<Self>> {
        Self::load_from_pages(view)
    }

    pub fn load_from_pair(view: &TenantStorageReadView) -> Result<Option<Self>> {
        Self::load_from_pages(view)
    }

    fn load_from_pages(view: &dyn crate::ordered_pages::PageSource) -> Result<Option<Self>> {
        view.check_access()?;
        let Some(bytes) = view.read_row(MANIFESTS, CURRENT, MAX_MANIFEST_BYTES)? else {
            return Ok(None);
        };
        let manifest = Self::decode(bytes.as_bytes())?;
        ensure!(
            manifest.tenant == view.domain(),
            "primary manifest tenant differs"
        );
        let selected = SelectedGeneration::load_from_pages(view, FAMILY, &INITIAL_SPACE)?;
        ensure!(
            selected.namespace(0) == manifest.page_space,
            "primary manifest and page-space selection differ"
        );
        Ok(Some(manifest))
    }
}

#[cfg(test)]
mod tests;
