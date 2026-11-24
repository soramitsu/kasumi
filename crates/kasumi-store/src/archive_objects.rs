//! Bounded decryption of separately retained encrypted objects under the current
//! tenant gate and fresh authorization of the object's historical key catalog.
use crate::{AccessGuard, BackupContents, EncryptedBackup, TenantStore};
use anyhow::{Result, ensure};

impl TenantStore {
    pub async fn decrypt_backup_object(
        &self,
        bytes: &[u8],
        expected_id: uuid::Uuid,
        max_plaintext_bytes: usize,
    ) -> Result<BackupContents> {
        self.authenticate_object(bytes, expected_id, max_plaintext_bytes)
            .await
            .map(|(_, contents)| contents)
    }

    pub(crate) async fn authenticate_object(
        &self,
        bytes: &[u8],
        expected_id: uuid::Uuid,
        max_plaintext_bytes: usize,
    ) -> Result<(EncryptedBackup, BackupContents)> {
        let _access = AccessGuard(self);
        self.check_access()?;
        let encrypted = EncryptedBackup::from_bytes(bytes, max_plaintext_bytes, self)?;
        ensure!(
            encrypted.id() == expected_id,
            "encrypted object identity mismatch"
        );
        let contents = encrypted
            .decrypt(&self.tenant, self.archive_read_provider()?, self)
            .await?;
        self.check_access()?;
        Ok((encrypted, contents))
    }
}
