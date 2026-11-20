//! The persisted text directory's selector: bounded Tantivy shards of every
//! text-indexed collection, in an ordered tree of their own page family.
//!
//! The directory is separate from the snapshot family (`kasumi.app.pages`)
//! and from any other application family, so an older captured snapshot can
//! never move it. Ordinary publications edit its tree copy-on-write and
//! advance this row in the same native transaction as the applied cursor; a
//! rebuild stages a fresh `kasumi.app.text@<uuid>` generation and selects it
//! with this row. A `Stale` row names no usable shards: the next publication
//! or restore replaces the generation.
use super::*;
use crate::ordered_pages::TreeRoot;

pub const MANIFESTS: &str = "kasumi.app.text.manifest";
pub const CURRENT: &[u8] = b"current";
pub const MAX_MANIFEST_BYTES: usize = 8 << 10;
/// The family selector of text directory page spaces.
pub const FAMILY: &str = "kasumi.app.text";
/// What an absent selector names. It never holds shards: the first directory
/// is always a staged generation, after which this space retires.
pub const INITIAL_SPACE: [&str; 1] = ["kasumi.app.text"];
const FORMAT: u32 = 1;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TextStatus {
    /// Every text-indexed live row of `revision` is in the tree.
    Current,
    /// A publication could not maintain the tree; nothing may read it.
    Stale,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TextManifest {
    pub format: u32,
    pub tenant: String,
    pub incarnation: String,
    pub revision_base: u64,
    /// The exact applied revision whose live rows the tree indexes.
    pub revision: u64,
    pub status: TextStatus,
    pub page_space: String,
    pub records: TreeRoot,
    /// Text-indexed collections, shards and shard file bytes in the tree.
    pub collections: u64,
    pub shards: u64,
    pub shard_bytes: u64,
}

impl TextManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant: &str,
        incarnation: &str,
        revision_base: u64,
        revision: u64,
        status: TextStatus,
        page_space: &str,
        records: TreeRoot,
        collections: u64,
        shards: u64,
        shard_bytes: u64,
    ) -> Self {
        Self {
            format: FORMAT,
            tenant: tenant.into(),
            incarnation: incarnation.into(),
            revision_base,
            revision,
            status,
            page_space: page_space.into(),
            records,
            collections,
            shards,
            shard_bytes,
        }
    }

    pub fn is_current(&self) -> bool {
        self.status == TextStatus::Current
    }

    /// The same directory marked unusable at `revision`.
    pub fn stale_at(&self, revision: u64) -> Self {
        Self {
            revision,
            status: TextStatus::Stale,
            ..self.clone()
        }
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_MANIFEST_BYTES,
            "text manifest exceeds its bound"
        );
        let manifest: Self = serde_json::from_slice(bytes)?;
        ensure!(
            serde_json::to_vec(&manifest)? == bytes,
            "noncanonical text manifest"
        );
        manifest.validate()?;
        Ok(manifest)
    }

    fn validate(&self) -> Result<()> {
        ensure!(self.format == FORMAT, "unsupported text manifest format");
        ensure!(
            self.revision >= self.revision_base && !self.page_space.is_empty(),
            "invalid text manifest"
        );
        ensure!(
            self.page_space != INITIAL_SPACE[0] || self.records.root.is_none(),
            "the initial text space holds no directory"
        );
        kasumi_types::validate_name(&self.tenant)?;
        kasumi_types::validate_name(&self.incarnation)?;
        validate_record(&self.page_space, &[], 0)
    }

    /// The fixed-size write that selects this manifest. It commits with the
    /// applied cursor of `revision` and every row its tree names.
    pub fn write(&self) -> Result<WriteOp> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        ensure!(
            bytes.len() <= MAX_MANIFEST_BYTES,
            "text manifest exceeds its bound"
        );
        Ok(WriteOp::put(MANIFESTS, CURRENT, bytes))
    }

    /// The current directory, read under the caller's publication gate.
    pub fn load(store: &TenantStore) -> Result<Option<Self>> {
        store
            .get_bounded(MANIFESTS, CURRENT, MAX_MANIFEST_BYTES)?
            .map(|bytes| Self::decode(&bytes))
            .transpose()
    }

    /// The directory at a pinned root; its pages stay readable through `view`
    /// after later edits delete them from the current tree.
    pub fn load_at(view: &TenantReadView) -> Result<Option<Self>> {
        Self::load_from_pages(view)
    }

    pub fn load_from_pair(view: &TenantStorageReadView) -> Result<Option<Self>> {
        Self::load_from_pages(view)
    }

    fn load_from_pages(view: &dyn crate::ordered_pages::PageSource) -> Result<Option<Self>> {
        view.check_access()?;
        let selected = SelectedGeneration::load_from_pages(view, FAMILY, &INITIAL_SPACE)?;
        let Some(row) = view.read_row(MANIFESTS, CURRENT, MAX_MANIFEST_BYTES)? else {
            return Ok(None);
        };
        let manifest = Self::decode(row.as_bytes())?;
        ensure!(
            manifest.tenant == view.domain(),
            "text manifest tenant differs"
        );
        ensure!(
            selected.namespace(0) == manifest.page_space,
            "text manifest and page-space selection differ"
        );
        Ok(Some(manifest))
    }

    /// A write without a selection switch edits the selected tree forward:
    /// the same scope, space and tree; a larger revision, or `Stale` at the
    /// same revision. A stale directory is replaced, never edited.
    pub(crate) fn check_successor(&self, previous: &Self) -> Result<()> {
        ensure!(
            self.tenant == previous.tenant
                && self.incarnation == previous.incarnation
                && self.revision_base == previous.revision_base,
            "text manifest scope changed without a new generation"
        );
        ensure!(
            self.page_space == previous.page_space && self.records.tree == previous.records.tree,
            "text manifest tree changed without a new generation"
        );
        ensure!(
            previous.is_current(),
            "a stale text directory is not edited"
        );
        ensure!(
            self.revision > previous.revision
                || (self.revision == previous.revision && !self.is_current()),
            "text manifest does not advance"
        );
        Ok(())
    }
}

#[cfg(test)]
#[path = "text_manifest/tests.rs"]
mod tests;
