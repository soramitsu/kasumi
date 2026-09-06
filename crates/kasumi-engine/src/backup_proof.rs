use kasumi_types::FullBackupCheckpoint;

/// Constructed only after Kasumi verifies a complete encrypted backup graph.
/// This is immutable evidence of that authorized operation, not a serving lease.
///
/// Untrusted serialized observations cannot construct a verified proof:
/// ```compile_fail
/// let _: kasumi_engine::VerifiedBackupCheckpoint = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct VerifiedBackupCheckpoint {
    checkpoint: FullBackupCheckpoint,
}
impl VerifiedBackupCheckpoint {
    pub(crate) fn verified(checkpoint: FullBackupCheckpoint) -> Self {
        Self { checkpoint }
    }
    pub fn checkpoint(&self) -> &FullBackupCheckpoint {
        &self.checkpoint
    }
    pub fn tenant(&self) -> &str {
        &self.checkpoint.tenant
    }
    pub fn source_incarnation(&self) -> &str {
        &self.checkpoint.source_incarnation
    }
    pub fn revision(&self) -> u64 {
        self.checkpoint.revision
    }
    pub fn resident_sha256(&self) -> &str {
        &self.checkpoint.resident_sha256
    }
    pub fn backup_id(&self) -> uuid::Uuid {
        self.checkpoint.backup_id
    }
    pub fn manifest_ciphertext_sha256(&self) -> &str {
        &self.checkpoint.manifest_ciphertext_sha256
    }
    pub fn key_lineage_digest(&self) -> &str {
        &self.checkpoint.key_lineage_digest
    }
}
