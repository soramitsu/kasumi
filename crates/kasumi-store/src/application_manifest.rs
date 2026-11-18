//! The selected application manifest: one bounded record per tenant naming
//! the page space and record tree of its application generation. It commits
//! in the same paired native transaction that advances custody's applied
//! cursor, so a reader of one root sees one exact applied generation.
//!
//! Page spaces form a Store generation family. Ordinary edits stay inside
//! the selected space; a bulk-built generation is staged into a fresh space
//! and selected together with its manifest, and the replaced space is retired
//! and reclaimed in bounded batches. An absent manifest means a store written
//! before manifests existed: its logical records are untouched and still
//! authoritative.
use super::*;
use crate::ordered_pages::TreeRoot;

pub const MANIFESTS: &str = "kasumi.app.manifest";
const CURRENT: &[u8] = b"current";
pub const MAX_MANIFEST_BYTES: usize = 16 << 10;
/// The family selector of application page spaces.
pub const PAGE_FAMILY: &str = "kasumi.app.pages";
/// What an absent selector names. It never holds a generation's pages: the
/// first manifest selects a staged space and retires this one.
pub const INITIAL_PAGE_SPACE: [&str; 1] = ["kasumi.app.pages"];
const FORMAT: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApplicationManifest {
    pub format: u32,
    pub tenant: String,
    pub incarnation: String,
    /// The logical revision this generation was applied at.
    pub revision: u64,
    pub revision_base: u64,
    /// Local layout evolution; never a logical schema epoch or version.
    pub layout_epoch: u32,
    pub page_space: String,
    pub records: TreeRoot,
    pub document_count: u64,
    pub logical_bytes: u64,
}

impl ApplicationManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant: &str,
        incarnation: &str,
        revision: u64,
        revision_base: u64,
        page_space: &str,
        records: TreeRoot,
        document_count: u64,
        logical_bytes: u64,
    ) -> Self {
        Self {
            format: FORMAT,
            tenant: tenant.into(),
            incarnation: incarnation.into(),
            revision,
            revision_base,
            layout_epoch: 1,
            page_space: page_space.into(),
            records,
            document_count,
            logical_bytes,
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_MANIFEST_BYTES,
            "application manifest exceeds its bound"
        );
        let manifest: Self = serde_json::from_slice(bytes)?;
        ensure!(
            serde_json::to_vec(&manifest)? == bytes,
            "noncanonical application manifest"
        );
        manifest.validate()?;
        Ok(manifest)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.format == FORMAT && self.layout_epoch == 1,
            "unsupported application manifest format"
        );
        ensure!(
            self.revision >= self.revision_base && !self.page_space.is_empty(),
            "invalid application manifest"
        );
        validate_record(&self.page_space, &[], 0)
    }

    /// The fixed-size write that selects this manifest. It must commit with
    /// the applied cursor of `revision` and every row its tree names.
    pub fn write(&self) -> Result<WriteOp> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        ensure!(
            bytes.len() <= MAX_MANIFEST_BYTES,
            "application manifest exceeds its bound"
        );
        Ok(WriteOp::put(MANIFESTS, CURRENT, bytes))
    }

    /// The manifest at a pinned root; every page read through `view` belongs
    /// to it even while a later generation replaces its space.
    pub fn load_at(view: &TenantReadView) -> Result<Option<Self>> {
        let Some(bytes) = view.get(MANIFESTS, CURRENT, MAX_MANIFEST_BYTES)? else {
            return Ok(None);
        };
        let manifest = Self::decode(bytes.as_bytes())?;
        ensure!(
            manifest.tenant == view.tenant_store().tenant(),
            "application manifest tenant differs"
        );
        let selected = SelectedGeneration::load_at(view, PAGE_FAMILY, &INITIAL_PAGE_SPACE)?;
        manifest.check_selection(&selected)?;
        Ok(Some(manifest))
    }

    fn check_selection(&self, selected: &SelectedGeneration) -> Result<()> {
        ensure!(
            selected.namespace(0) == self.page_space,
            "application manifest and page-space selection differ"
        );
        Ok(())
    }
}
