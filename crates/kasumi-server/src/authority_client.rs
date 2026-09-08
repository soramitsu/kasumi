//! Operator-installed endpoint and credential sources for authority maintenance.
use crate::{
    runtime::{TlsFiles, parse_certificate_pin, read_bounded},
    serving_runtime::AuthorityEndpoint,
};
use anyhow::{Result, ensure};
use kasumi_client::{KasumiAuthorityPool, KasumiClientConfig};
use kasumi_serving::{AuthorityManifest, AuthorityTrust};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityClientConfig {
    pub manifest: AuthorityManifest,
    pub partition: u16,
    #[serde(deserialize_with = "kasumi_types::deserialize_u64_map")]
    pub endpoints: BTreeMap<u64, AuthorityEndpoint>,
    pub identity: TlsFiles,
    pub server_ca: PathBuf,
    pub token_file: PathBuf,
}
impl AuthorityClientConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let config: Self = serde_json::from_slice(&read_bounded(path.as_ref(), 2 << 20)?)?;
        config.manifest.validate()?;
        ensure!(
            config.manifest.partitions.contains_key(&config.partition),
            "authority client partition is not installed"
        );
        config.identity.validate()?;
        ensure!(
            config.server_ca.is_absolute() && config.token_file.is_absolute(),
            "authority client paths must be installed absolute paths"
        );
        Ok(config)
    }
    pub fn pool(&self) -> Result<KasumiAuthorityPool> {
        let identity = self.identity.load()?;
        let ca = read_bounded(&self.server_ca, 1 << 20)?;
        let connections = self
            .endpoints
            .iter()
            .map(|(id, endpoint)| {
                Ok((
                    *id,
                    KasumiClientConfig {
                        endpoint: endpoint.endpoint.clone(),
                        identity: identity.clone(),
                        trusted_ca_pem: ca.clone(),
                        server_certificate_pins: endpoint
                            .certificate_pins
                            .iter()
                            .map(|pin| parse_certificate_pin(pin))
                            .collect::<Result<_>>()?,
                    },
                ))
            })
            .collect::<Result<_>>()?;
        KasumiAuthorityPool::new(
            connections,
            AuthorityTrust::install(self.manifest.clone())?,
            Arc::new(kasumi_transport::credentials::FileCredentialSource::new(
                self.token_file.clone(),
            )?),
        )
    }
}
