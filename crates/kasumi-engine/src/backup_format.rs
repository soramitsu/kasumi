//! Authenticated full-database envelope. History subsets use a distinct kind
//! and can never be parsed as a complete backup.
use kasumi_types::{
    MAX_ARCHIVE_CHUNK_BYTES, MAX_ARCHIVE_MANIFEST_BYTES, validate_name, validate_sha256,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub(crate) const CHUNK_BYTES: usize = MAX_ARCHIVE_CHUNK_BYTES;
pub(crate) const MANIFEST_BYTES: usize = MAX_ARCHIVE_MANIFEST_BYTES;
pub(crate) const MAX_STATE_BYTES: usize = kasumi_store::MAX_BACKUP_SNAPSHOT_BYTES;
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
pub(crate) struct FullBackupManifest {
    pub kind: FullBackupKind,
    pub tenant: String,
    pub source_incarnation: String,
    pub revision: u64,
    pub resident_bytes: usize,
    pub resident_sha256: String,
    pub chunks: Vec<BackupChunk>,
}

impl FullBackupManifest {
    pub fn validate(&self) -> anyhow::Result<()> {
        validate_name(&self.tenant)?;
        validate_name(&self.source_incarnation)?;
        validate_sha256(&self.resident_sha256)?;
        anyhow::ensure!(
            self.resident_bytes > 0
                && self.resident_bytes <= MAX_STATE_BYTES
                && !self.chunks.is_empty()
                && self.chunks.len() <= MAX_STATE_BYTES.div_ceil(CHUNK_BYTES),
            "full backup state bounds invalid"
        );
        let mut bytes = 0usize;
        let mut ids = BTreeSet::new();
        for (index, chunk) in self.chunks.iter().enumerate() {
            validate_sha256(&chunk.ciphertext_sha256)?;
            validate_sha256(&chunk.plaintext_sha256)?;
            anyhow::ensure!(
                !chunk.object_id.is_nil()
                    && ids.insert(chunk.object_id)
                    && chunk.plaintext_bytes > 0
                    && chunk.plaintext_bytes <= CHUNK_BYTES
                    && (index + 1 == self.chunks.len() || chunk.plaintext_bytes == CHUNK_BYTES),
                "full backup chunk bounds invalid"
            );
            bytes = bytes
                .checked_add(chunk.plaintext_bytes)
                .ok_or_else(|| anyhow::anyhow!("full backup byte count overflow"))?;
        }
        anyhow::ensure!(
            bytes == self.resident_bytes,
            "full backup byte count differs"
        );
        anyhow::ensure!(
            serde_json::to_vec(self)?.len() <= MANIFEST_BYTES,
            "full backup manifest too large"
        );
        Ok(())
    }
}
