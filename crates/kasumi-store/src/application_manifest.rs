//! A bounded snapshot record naming its application descriptor tree. The
//! application manifest, selected page space and authenticated Raft snapshot
//! publish in one paired native transaction. Captures after that position can
//! append log entries while existing readers retain their original root.
//!
//! Deployed snapshots precede manifests. Their original authenticated image
//! remains readable, and the next snapshot can create the descriptor tree.
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
/// Adds structured field-presence postings after the original record families.
pub const FIELD_POSTINGS_LAYOUT: u32 = 2;
/// Adds ordered scalar dictionaries and equality postings.
pub const FIELD_VALUES_LAYOUT: u32 = 3;
/// Adds a single ordered directory of live and archived document headers.
pub const DOCUMENT_HEADERS_LAYOUT: u32 = 4;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApplicationManifest {
    pub format: u32,
    pub tenant: String,
    pub incarnation: String,
    /// The logical revision this generation was applied at.
    pub revision: u64,
    pub revision_base: u64,
    /// Identity of the exact Raft snapshot whose application records this tree indexes.
    pub snapshot_sha256: [u8; 32],
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
        snapshot_sha256: [u8; 32],
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
            snapshot_sha256,
            layout_epoch: DOCUMENT_HEADERS_LAYOUT,
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
            self.format == FORMAT && (1..=DOCUMENT_HEADERS_LAYOUT).contains(&self.layout_epoch),
            "unsupported application manifest format"
        );
        ensure!(
            self.revision >= self.revision_base && !self.page_space.is_empty(),
            "invalid application manifest"
        );
        kasumi_types::validate_name(&self.tenant)?;
        kasumi_types::validate_name(&self.incarnation)?;
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
        Self::load_from_pages(view)
    }

    pub fn load_from_pair(view: &TenantStorageReadView) -> Result<Option<Self>> {
        Self::load_from_pages(view)
    }

    fn load_from_pages(view: &dyn crate::ordered_pages::PageSource) -> Result<Option<Self>> {
        view.check_access()?;
        let selected = SelectedGeneration::load_from_pages(view, PAGE_FAMILY, &INITIAL_PAGE_SPACE)?;
        let Some(bytes) = view.read_row(MANIFESTS, CURRENT, MAX_MANIFEST_BYTES)? else {
            ensure!(
                selected.namespace(0) == INITIAL_PAGE_SPACE[0],
                "selected application page space has no manifest"
            );
            return Ok(None);
        };
        let manifest = Self::decode(bytes.as_bytes())?;
        ensure!(
            manifest.tenant == view.domain(),
            "application manifest tenant differs"
        );
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
