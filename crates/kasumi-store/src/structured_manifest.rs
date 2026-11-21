//! The ordinary structured index directory: one ordered tree of the presence
//! and scalar postings of every indexed field, kept at the exact applied
//! revision.
//!
//! The snapshot application manifest (`application_manifest`) carries ranked
//! dictionaries built from one authenticated Raft snapshot and changes only
//! with snapshot publication. This directory instead advances with ordinary
//! apply: each candidate publication edits the posting rows its changed
//! documents add and remove copy-on-write inside the selected structured page
//! space, and commits the new root through this fixed-size row in the same
//! paired native transaction as the applied cursor. Earlier read views keep
//! the root and pages of their own native generation.
//!
//! A replacement generation (snapshot installation, or reopen without a
//! current directory) is bulk-built into a fresh space staged by
//! `NamespaceStage` and selected with the manifest; the replaced space is
//! retired and reclaimed in bounded batches. This family, its selector and its
//! manifest row are separate from the snapshot and primary directory families,
//! so none of them writes another's rows.
//!
//! Store enforces the monotonic contract inside every native transaction that
//! writes this row: without a selection switch the successor must keep the
//! tree, page space and scope, follow a current predecessor and increase the
//! revision. A partial generation can advance its bounded cursor at the same
//! producer position. Its final promotion keeps the same exhausted root.
//! Covered replay cannot move the directory backward.
//!
//! Deployed revisions predate this row. Their stores open without it and the
//! first snapshot restore with installed application sources builds it.
use super::*;
use crate::ordered_pages::TreeRoot;

pub const MANIFESTS: &str = "kasumi.app.structured.manifest";
pub const CURRENT: &[u8] = b"current";
pub const MAX_MANIFEST_BYTES: usize = 8 << 10;
/// The family selector of structured index page spaces.
pub const FAMILY: &str = "kasumi.app.structured";
/// What an absent selector names. A pristine store's first directory edits
/// pages here; the first replacement generation retires it.
pub const INITIAL_SPACE: [&str; 1] = ["kasumi.app.structured"];
/// Adds order-preserving compound tuple rows to each selected directory.
pub const ORDERED_TUPLE_FORMAT: u32 = 2;

/// Whether the tree holds exactly the rows at `revision`. A stale directory
/// keeps naming its last tree so its space stays owned, but readers and
/// ordinary edits ignore it until a replacement generation is selected.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum StructuredStatus {
    Current,
    Stale,
    Rebuilding(Box<StructuredRebuild>),
}

/// A partial, non-serving generation. The original final document bounds the
/// scan even when ordinary writes append documents to its collection.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StructuredRebuild {
    pub captured: Option<StructuredApplied>,
    pub through: crate::primary_manifest::PrimaryCursor,
    pub cursor: Option<StructuredCursor>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StructuredCursor {
    pub document: crate::primary_manifest::PrimaryCursor,
    /// None means the complete document or collection has been visited.
    pub field: Option<StructuredFieldCursor>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct StructuredFieldCursor {
    pub ordinal: u32,
    pub after: Vec<u8>,
}

impl Ord for StructuredCursor {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.document
            .cmp(&other.document)
            .then_with(|| match (&self.field, &other.field) {
                (Some(a), Some(b)) => a.cmp(b),
                (None, None) => std::cmp::Ordering::Equal,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (Some(_), None) => std::cmp::Ordering::Less,
            })
    }
}
impl PartialOrd for StructuredCursor {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl StructuredRebuild {
    pub fn finished(&self) -> bool {
        self.cursor
            .as_ref()
            .is_some_and(|c| c.document == self.through && c.field.is_none())
    }
}

/// The producer boundary of the revision: the applied Raft log position and,
/// for an ordinary entry, its exact command digest. Snapshot boundaries carry
/// no command. Bootstrap (no applied position) has no boundary.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StructuredApplied {
    pub index: u64,
    pub log_sha256: [u8; 32],
    pub command_sha256: Option<[u8; 32]>,
}

impl StructuredApplied {
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
pub struct StructuredManifest {
    pub format: u32,
    pub tenant: String,
    pub incarnation: String,
    pub revision_base: u64,
    /// The exact applied revision whose rows the tree holds.
    pub revision: u64,
    pub status: StructuredStatus,
    pub applied: Option<StructuredApplied>,
    /// Digest of every collection's index definition, in name order. Row keys
    /// name a field by its ordinal among a collection's indexed paths, so the
    /// rows are meaningful only under exactly these definitions.
    pub layout_sha256: [u8; 32],
    pub page_space: String,
    pub records: TreeRoot,
}

impl StructuredManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant: &str,
        incarnation: &str,
        revision_base: u64,
        revision: u64,
        applied: Option<StructuredApplied>,
        layout_sha256: [u8; 32],
        page_space: &str,
        records: TreeRoot,
    ) -> Self {
        Self {
            format: ORDERED_TUPLE_FORMAT,
            tenant: tenant.into(),
            incarnation: incarnation.into(),
            revision_base,
            revision,
            status: StructuredStatus::Current,
            applied,
            layout_sha256,
            page_space: page_space.into(),
            records,
        }
    }

    pub fn is_current(&self) -> bool {
        self.status == StructuredStatus::Current
    }

    pub fn rebuild(&self) -> Option<&StructuredRebuild> {
        match &self.status {
            StructuredStatus::Rebuilding(progress) => Some(progress),
            _ => None,
        }
    }
    pub(crate) fn is_rebuild_seed(&self) -> bool {
        self.rebuild().is_some_and(|p| {
            p.cursor.is_none() && self.records.count() == 0 && self.applied == p.captured
        })
    }

    pub fn matches_applied(&self, actual: Option<&StructuredApplied>) -> bool {
        match (self.applied.as_ref(), actual) {
            (Some(stored), Some(actual)) => stored.same_position(actual),
            (None, None) => true,
            _ => false,
        }
    }

    /// The edited successor at `revision`; tree identity and space are kept.
    pub fn advance(
        &self,
        revision: u64,
        applied: Option<StructuredApplied>,
        layout_sha256: [u8; 32],
        records: TreeRoot,
    ) -> Self {
        Self {
            revision,
            status: StructuredStatus::Current,
            applied,
            layout_sha256,
            records,
            ..self.clone()
        }
    }

    /// The successor that stops claiming currency at `revision`. Its tree and
    /// space stay named, so the space remains owned until it is replaced.
    pub fn stale(&self, revision: u64, applied: Option<StructuredApplied>) -> Self {
        Self {
            revision,
            status: StructuredStatus::Stale,
            applied,
            ..self.clone()
        }
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_MANIFEST_BYTES,
            "structured manifest exceeds its bound"
        );
        let manifest: Self = serde_json::from_slice(bytes)?;
        ensure!(
            serde_json::to_vec(&manifest)? == bytes,
            "noncanonical structured manifest"
        );
        manifest.validate()?;
        Ok(manifest)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            (1..=ORDERED_TUPLE_FORMAT).contains(&self.format),
            "unsupported structured manifest format"
        );
        ensure!(
            self.revision >= self.revision_base && !self.page_space.is_empty(),
            "invalid structured manifest"
        );
        ensure!(
            self.applied
                .as_ref()
                .is_none_or(
                    |applied| self.revision_base.checked_add(applied.index) == Some(self.revision)
                ),
            "structured manifest boundary differs from its revision"
        );
        if let Some(progress) = self.rebuild() {
            ensure!(
                match (&progress.captured, &self.applied) {
                    (Some(captured), Some(current)) => captured.index <= current.index,
                    (None, None) => self.revision == self.revision_base,
                    (None, Some(_)) => true,
                    _ => false,
                },
                "invalid captured structured position"
            );
            kasumi_types::validate_name(&progress.through.collection)?;
            kasumi_types::validate_name(
                progress
                    .through
                    .after_document
                    .as_deref()
                    .context("missing terminal structured document")?,
            )?;
            if let Some(cursor) = &progress.cursor {
                kasumi_types::validate_name(&cursor.document.collection)?;
                if let Some(id) = &cursor.document.after_document {
                    kasumi_types::validate_name(id)?;
                }
                ensure!(
                    cursor.document <= progress.through
                        && cursor.field.as_ref().is_none_or(|field| cursor
                            .document
                            .after_document
                            .is_some()
                            && field.after.len() <= crate::ordered_pages::MAX_KEY_BYTES),
                    "invalid structured rebuild cursor"
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
            "structured manifest names a foreign page space"
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
            "structured manifest exceeds its bound"
        );
        Ok(WriteOp::put(MANIFESTS, CURRENT, bytes))
    }

    /// Successor rules checked inside the writing native transaction when the
    /// same batch does not select a replacement generation.
    pub(crate) fn check_successor(&self, previous: &Self) -> Result<()> {
        ensure!(
            previous.is_current() || previous.rebuild().is_some(),
            "a stale structured directory needs a replacement generation"
        );
        ensure!(
            self.format == previous.format
                && self.tenant == previous.tenant
                && self.incarnation == previous.incarnation
                && self.revision_base == previous.revision_base
                && self.page_space == previous.page_space
                && self.records.tree == previous.records.tree,
            "structured directory successor changes its tree or scope"
        );
        if let Some(prior) = previous.rebuild() {
            let next = self.rebuild();
            if let Some(next) = next {
                ensure!(
                    next.captured == prior.captured
                        && next.through == prior.through
                        && next.cursor >= prior.cursor
                        && self.layout_sha256 == previous.layout_sha256,
                    "structured rebuild changed its layout, source or cursor"
                );
            }
            if self.is_current() {
                ensure!(
                    prior.finished()
                        && self.layout_sha256 == previous.layout_sha256
                        && self.revision == previous.revision
                        && self.applied == previous.applied
                        && self.records == previous.records,
                    "partial structured directory cannot become current"
                );
            }
            let advanced = next.is_some_and(|next| next.cursor > prior.cursor) || next.is_none();
            let binds_genesis = previous.applied.is_none()
                && self.revision == self.revision_base
                && self
                    .applied
                    .as_ref()
                    .is_some_and(|p| p.index == 0 && p.command_sha256.is_some())
                && self.status == previous.status
                && self.records == previous.records;
            ensure!(
                self.revision > previous.revision
                    || (self.revision == previous.revision
                        && (binds_genesis
                            || (advanced
                                && (self.applied == previous.applied
                                    || self.status == StructuredStatus::Stale)))),
                "structured rebuild repeated a position without progress"
            );
            if self.status == StructuredStatus::Stale {
                ensure!(
                    self.records == previous.records
                        && self.layout_sha256 == previous.layout_sha256,
                    "stale structured rebuild changed its tree"
                );
            }
            return Ok(());
        }
        ensure!(
            self.rebuild().is_none(),
            "structured rebuild requires a new generation"
        );
        // Genesis membership can bind the already verified bootstrap tree
        // without changing its rows, layout or logical revision.
        let binds_genesis = previous.applied.is_none()
            && self.revision == self.revision_base
            && self
                .applied
                .as_ref()
                .is_some_and(|p| p.index == 0 && p.command_sha256.is_some())
            && self.records == previous.records
            && self.layout_sha256 == previous.layout_sha256;
        ensure!(
            self.revision > previous.revision
                || (self.revision == previous.revision && (!self.is_current() || binds_genesis)),
            "structured directory cannot move backward or repeat a revision"
        );
        // A stale successor keeps the last tree it could vouch for.
        ensure!(
            self.is_current()
                || (self.records == previous.records
                    && self.layout_sha256 == previous.layout_sha256),
            "a stale structured directory cannot change its tree"
        );
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
            "structured manifest tenant differs"
        );
        let selected = SelectedGeneration::load_from_pages(view, FAMILY, &INITIAL_SPACE)?;
        ensure!(
            selected.namespace(0) == manifest.page_space,
            "structured manifest and page-space selection differ"
        );
        Ok(Some(manifest))
    }
}

#[cfg(test)]
mod tests;
