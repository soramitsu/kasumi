//! Read-only recovery key dispatch and its permanent journal binding.
use super::*;
use kasumi_store::{
    HistoricalKeyResolver, HistoricalKeySource, HistoricalSourceSecurityDescriptor,
};

fn open_source(
    settings: &KeyProviderSettings,
    credential: crate::serving_runtime::CredentialSource,
) -> Result<HistoricalKeySource> {
    match settings {
        KeyProviderSettings::File { path } => {
            HistoricalKeySource::file(Arc::new(kasumi_store::FileKeyProvider::open(path)?))
        }
        KeyProviderSettings::Transit(settings) => {
            HistoricalKeySource::transit(settings.provider_with_source(credential)?)
        }
    }
}

/// The journal comparison and the subsequent unwrap use the same constructed
/// providers. A changed CA or key identity cannot slip between the two opens.
pub(crate) struct RecoveryKeys {
    resolver: Arc<HistoricalKeyResolver>,
    binding: serde_json::Value,
}

impl RecoveryKeys {
    pub(super) fn open(
        settings: &KeyProviderSettings,
        historical: &[KeyProviderSettings],
    ) -> Result<Self> {
        Self::open_with(settings, historical, Arc::new(crate::runtime::file_secret))
    }

    pub(crate) fn open_with(
        settings: &KeyProviderSettings,
        historical: &[KeyProviderSettings],
        credential: crate::serving_runtime::CredentialSource,
    ) -> Result<Self> {
        ensure!(
            historical.len() < HistoricalKeyResolver::MAX_SOURCES,
            "too many historical recovery providers"
        );
        let primary = open_source(settings, credential.clone())?;
        let sources = historical
            .iter()
            .map(|source| open_source(source, credential.clone()))
            .collect::<Result<Vec<_>>>()?;
        let resolver = Arc::new(HistoricalKeyResolver::with_primary(primary, sources)?);
        let binding = serde_json::json!({
            "format": 1,
            "primary": resolver.primary_descriptor().context("recovery primary missing")?,
            "historical": resolver.historical_descriptors(),
        });
        Ok(Self { resolver, binding })
    }

    pub(crate) fn digest(&self) -> Result<String> {
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        hash.update(b"kasumi.recovery.read-keys.v1\0");
        hash.update(serde_json::to_vec(&self.binding)?);
        Ok(hex::encode(hash.finalize()))
    }

    pub(crate) fn bound_digest(self, expected: &str) -> Result<Arc<HistoricalKeyResolver>> {
        ensure!(
            self.digest()? == expected,
            "target backup source key roster differs from enrollment"
        );
        Ok(self.resolver)
    }

    pub(super) fn binding(self) -> serde_json::Value {
        self.binding
    }

    pub(super) fn bound(
        self,
        settings: &KeyProviderSettings,
        expected: &serde_json::Value,
    ) -> Result<Arc<HistoricalKeyResolver>> {
        if self.binding != *expected {
            // Deployed format-5 journals recorded one source and no historical
            // roster. Compare exactly what that writer observed. New journals
            // always bind the complete descriptors, including Transit CA trust.
            ensure!(
                self.resolver.historical_descriptors().is_empty(),
                "local recovery historical source set changed"
            );
            let legacy = match (settings, self.resolver.primary_descriptor()) {
                (
                    KeyProviderSettings::File { .. },
                    Some(HistoricalSourceSecurityDescriptor::File { key_ref }),
                ) => {
                    serde_json::json!({"kind": "file", "identity": key_ref})
                }
                (
                    KeyProviderSettings::Transit(_),
                    Some(HistoricalSourceSecurityDescriptor::Transit { .. }),
                ) => settings.identity_descriptor()?,
                _ => anyhow::bail!("local recovery primary provider differs"),
            };
            ensure!(
                *expected == legacy,
                "local source wrapping-key identity differs"
            );
        }
        Ok(self.resolver)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kasumi_store::{FileKeyProvider, KeyProvider};

    #[tokio::test]
    async fn restart_keeps_exact_historical_reads_and_rejects_substituted_sources() -> Result<()> {
        let temporary = kasumi_store::test_utils::private_tempdir()?;
        let keyring = |name: &str| -> Result<_> {
            let path = temporary.path().join(name);
            let provider = FileKeyProvider::initialize(&path, name)?;
            Ok((KeyProviderSettings::File { path }, provider))
        };
        let (primary, current) = keyring("current")?;
        let (old, previous) = keyring("previous")?;
        let (other, _) = keyring("other")?;
        let archived = previous.generate_key("tenant").await?;
        let live = current.generate_key("tenant").await?;
        let prior_journal = primary.identity_descriptor()?;
        let binding = RecoveryKeys::open(&primary, std::slice::from_ref(&old))?.binding();
        let read =
            RecoveryKeys::open(&primary, std::slice::from_ref(&old))?.bound(&primary, &binding)?;
        for version in [&archived, &live] {
            assert_eq!(
                read.unwrap_key("tenant", &version.wrapped)
                    .await?
                    .as_bytes(),
                version.plaintext.as_bytes()
            );
            assert!(read.rewrap_key("tenant", &version.wrapped).await.is_err());
        }
        assert!(read.generate_key("tenant").await.is_err());
        assert!(
            RecoveryKeys::open(&primary, &[])?
                .bound(&primary, &prior_journal)
                .is_ok()
        );
        assert!(
            RecoveryKeys::open(&primary, &[])?
                .bound(&primary, &binding)
                .is_err()
        );
        assert!(
            RecoveryKeys::open(&primary, &[other])?
                .bound(&primary, &binding)
                .is_err()
        );
        assert!(
            RecoveryKeys::open(&primary, std::slice::from_ref(&old))?
                .bound(&primary, &prior_journal)
                .is_err()
        );
        let target = RecoveryKeys::open(&primary, std::slice::from_ref(&old))?;
        let digest = target.digest()?;
        assert_ne!(RecoveryKeys::open(&primary, &[])?.digest()?, digest);
        assert!(
            RecoveryKeys::open(&primary, &[])?
                .bound_digest(&digest)
                .is_err()
        );
        let target = target.bound_digest(&digest)?;
        assert_eq!(
            target
                .unwrap_key("tenant", &archived.wrapped)
                .await?
                .as_bytes(),
            archived.plaintext.as_bytes()
        );
        assert!(RecoveryKeys::open(&primary, std::slice::from_ref(&primary)).is_err());
        Ok(())
    }
}
