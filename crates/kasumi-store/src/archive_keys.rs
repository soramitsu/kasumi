//! A serving store keeps its writable catalog separate from unwrap authority
//! for retained objects. An enrolled roster is immutable across ordinary reopen.
use super::*;

const NAMESPACE: &str = "kasumi.archive.read-keys";
const ROSTER: &[u8] = b"roster";

pub(super) struct ArchiveKeys {
    digest: Option<[u8; 32]>,
    reader: Arc<dyn KeyProvider>,
}

impl TenantStore {
    /// Called by the installed startup owner before replay or serving reads.
    /// Persist the exact constructed primary and historical trust descriptors.
    pub fn install_archive_read_keys(
        &self,
        resolver: Option<Arc<HistoricalKeyResolver>>,
    ) -> Result<()> {
        self.check_access()?;
        let selected = resolver
            .as_ref()
            .map(|keys| -> Result<[u8; 32]> {
                let primary = keys
                    .primary_descriptor()
                    .context("archive keys have no primary")?;
                let catalog = self.catalog.read();
                let active = catalog
                    .keys
                    .get(&catalog.active)
                    .context("active wrapping key missing")?;
                ensure!(
                    primary.dispatch_identity()
                        == (active.provider.as_str(), active.key_ref.as_str()),
                    "archive primary differs from the installed catalog"
                );
                ensure!(
                    !keys.historical_descriptors().is_empty(),
                    "empty historical key roster"
                );
                Ok(Sha256::digest(serde_json::to_vec(&(
                    "kasumi.archive.read-keys.v1",
                    primary,
                    keys.source_set_sha256(),
                ))?)
                .into())
            })
            .transpose()?;
        let mut slot = self.archive_keys.lock();
        if let Some(previous) = slot.as_ref() {
            ensure!(
                previous.digest == selected,
                "live archive key roster differs"
            );
            return Ok(());
        }
        match selected {
            Some(digest) => {
                crate::generation_stage::bind_immutable(self, NAMESPACE, ROSTER, &digest)?
            }
            None => ensure!(
                self.get_bounded(NAMESPACE, ROSTER, 32)?.is_none(),
                "installed archive key roster omitted"
            ),
        }
        *slot = Some(ArchiveKeys {
            digest: selected,
            reader: resolver.map_or_else(
                || self.provider.clone(),
                |keys| keys as Arc<dyn KeyProvider>,
            ),
        });
        Ok(())
    }

    pub(super) fn archive_read_provider(&self) -> Result<Arc<dyn KeyProvider>> {
        if let Some(installed) = self.archive_keys.lock().as_ref() {
            return Ok(installed.reader.clone());
        }
        // Stopped tools and previously deployed stores can read a primary-only
        // catalog. Omitting an already enrolled historical roster fails closed.
        ensure!(
            self.get_bounded(NAMESPACE, ROSTER, 32)?.is_none(),
            "archive key roster has not been installed"
        );
        Ok(self.provider.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn historical_object_uses_its_source_and_reopen_requires_the_same_roster() -> Result<()> {
        let dir = test_utils::private_tempdir()?;
        let memory = test_utils::TestDiskMemory::new(256 << 20, 4096);
        let scratch_dir = test_utils::private_tempdir()?;
        let scratch = ScratchDisk::fixture(scratch_dir.path(), memory.clone());
        let node = |name: &str| {
            NodeStore::create_new_fixture(
                dir.path().join(name),
                Uuid::new_v4(),
                memory.clone(),
                scratch.clone(),
            )
            .expect("create enrolled physical fixture")
        };
        let file =
            |name: &str| FileKeyProvider::initialize(&dir.path().join(name), name).map(Arc::new);
        let old = file("old")?;
        let current = file("primary")?;
        let other = file("unrelated")?;
        let source_node = node("source.kv");
        let source = TenantStore::initialize_catalog_fixture(
            source_node.clone(),
            "tenant".into(),
            old.clone(),
        )
        .await?;
        let bundle = source.encrypt_backup(17, b"archived under the old key")?;
        let id = bundle.id();
        let encoded = bundle.to_bytes()?;
        let active_node = node("active.kv");
        let active = TenantStore::initialize_catalog_fixture(
            active_node.clone(),
            "tenant".into(),
            current.clone(),
        )
        .await?;
        let resolver = |historical: Arc<FileKeyProvider>| -> Result<_> {
            Ok(Arc::new(HistoricalKeyResolver::with_primary(
                HistoricalKeySource::file(current.clone())?,
                vec![HistoricalKeySource::file(historical)?],
            )?))
        };
        assert!(
            active
                .decrypt_backup_object(&encoded, id, 1024)
                .await
                .is_err()
        );
        active.install_archive_read_keys(Some(resolver(old.clone())?))?;
        assert_eq!(
            active
                .decrypt_backup_object(&encoded, id, 1024)
                .await?
                .snapshot
                .as_slice(),
            b"archived under the old key"
        );
        assert!(
            active
                .archive_read_provider()?
                .generate_key("tenant")
                .await
                .is_err()
        );
        assert!(
            active
                .install_archive_read_keys(Some(resolver(other.clone())?))
                .is_err()
        );
        active.shutdown().await?;
        drop(active);
        let reopened = TenantStore::open_existing_fixture(
            active_node.clone(),
            "tenant".into(),
            current.clone(),
        )
        .await?;
        assert!(reopened.install_archive_read_keys(None).is_err());
        assert!(
            reopened
                .decrypt_backup_object(&encoded, id, 1024)
                .await
                .is_err()
        );
        assert!(
            reopened
                .install_archive_read_keys(Some(resolver(other)?))
                .is_err()
        );
        reopened.install_archive_read_keys(Some(resolver(old)?))?;
        assert_eq!(
            reopened
                .decrypt_backup_object(&encoded, id, 1024)
                .await?
                .revision,
            17
        );
        reopened.shutdown().await?;
        source.shutdown().await?;
        active_node.shutdown().await?;
        source_node.shutdown().await?;
        Ok(())
    }
}
