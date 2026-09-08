//! A constant-size authenticated backup root points to bounded manifest pages.
//! Pages form an immutable reverse chain; every edge carries its ciphertext hash.
use kasumi_types::{
    MAX_ARCHIVE_CHUNK_BYTES, MAX_ARCHIVE_MANIFEST_BYTES, validate_name, validate_sha256,
};
use serde::{Deserialize, Serialize};

pub(crate) const CHUNK_BYTES: usize = MAX_ARCHIVE_CHUNK_BYTES;
pub(crate) const MANIFEST_BYTES: usize = MAX_ARCHIVE_MANIFEST_BYTES;
pub(crate) const PAGE_CHUNKS: usize = 256;
pub(crate) const PAGE_BYTES: usize = 256 << 10;
pub(crate) const OBJECT_OVERHEAD: usize = (2 << 20) + 84;
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FullBackupKind {
    FullDatabase,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackupChunk {
    pub object_id: uuid::Uuid,
    pub ciphertext_sha256: String,
    pub plaintext_sha256: String,
    pub plaintext_bytes: usize,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackupPageRef {
    pub object_id: uuid::Uuid,
    pub ciphertext_sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackupPage {
    pub index: u64,
    pub previous: Option<BackupPageRef>,
    pub chunks: Vec<BackupChunk>,
}
impl BackupPage {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.chunks.is_empty()
                && self.chunks.len() <= PAGE_CHUNKS
                && self.previous.is_some() == (self.index > 0),
            "backup page bounds invalid"
        );
        if let Some(previous) = &self.previous {
            previous.validate()?;
        }
        for chunk in &self.chunks {
            validate_sha256(&chunk.ciphertext_sha256)?;
            validate_sha256(&chunk.plaintext_sha256)?;
            anyhow::ensure!(
                !chunk.object_id.is_nil()
                    && chunk.plaintext_bytes > 0
                    && chunk.plaintext_bytes <= CHUNK_BYTES,
                "backup chunk bounds invalid"
            );
        }
        anyhow::ensure!(
            serde_json::to_vec(self)?.len() <= PAGE_BYTES,
            "backup page exceeds limit"
        );
        Ok(())
    }
}
impl BackupPageRef {
    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(!self.object_id.is_nil(), "backup page identity absent");
        validate_sha256(&self.ciphertext_sha256)?;
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct FullBackupManifest {
    pub kind: FullBackupKind,
    pub tenant: String,
    pub source_incarnation: String,
    pub revision: u64,
    pub resident_bytes: u64,
    pub resident_sha256: String,
    pub chunk_count: u64,
    pub page_count: u64,
    pub last_page: BackupPageRef,
}
impl FullBackupManifest {
    pub fn validate(&self) -> anyhow::Result<()> {
        validate_name(&self.tenant)?;
        validate_name(&self.source_incarnation)?;
        validate_sha256(&self.resident_sha256)?;
        self.last_page.validate()?;
        anyhow::ensure!(
            self.resident_bytes > 0
                && self.chunk_count == self.resident_bytes.div_ceil(CHUNK_BYTES as u64)
                && self.page_count == self.chunk_count.div_ceil(PAGE_CHUNKS as u64),
            "full backup state bounds invalid"
        );
        anyhow::ensure!(
            serde_json::to_vec(self)?.len() <= MANIFEST_BYTES,
            "full backup root too large"
        );
        Ok(())
    }
}
