//! Installed source-to-authority connections and bounded renewal. Remote data
//! requests cannot choose an issuer, credential, endpoint, epoch or boot nonce.
use crate::runtime::{TlsFiles, credential_path, origin, parse_certificate_pin, read_bounded};
use anyhow::{Context, Result, ensure};
use kasumi_client::{KasumiAuthorityPool, KasumiClientConfig};
use kasumi_serving::{
    AuthorityManifest, AuthorityTrust, LeaseDiscovery, LeasePurpose, NodeIdentity, ServingBoot,
    ServingGate, VerifiedLease,
};
use kasumi_store::StorageAccess;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::Mutex as AsyncMutex;
use uuid::Uuid;
use zeroize::Zeroizing;

pub(crate) type CredentialSource = Arc<dyn Fn(&str) -> Result<Zeroizing<String>> + Send + Sync>;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityEndpoint {
    pub endpoint: String,
    pub certificate_pins: BTreeSet<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServingAuthorityConfig {
    pub manifest: AuthorityManifest,
    #[serde(deserialize_with = "deserialize_endpoints")]
    pub endpoints: BTreeMap<u16, BTreeMap<u64, AuthorityEndpoint>>,
    pub tls: TlsFiles,
    pub server_ca: PathBuf,
    #[serde(deserialize_with = "deserialize_bearer_files")]
    pub bearer_files: BTreeMap<u16, String>,
    pub principal: String,
}
fn deserialize_endpoints<'de, D>(
    deserializer: D,
) -> std::result::Result<BTreeMap<u16, BTreeMap<u64, AuthorityEndpoint>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(transparent)]
    struct Members(
        #[serde(deserialize_with = "kasumi_types::deserialize_u64_map")]
        BTreeMap<u64, AuthorityEndpoint>,
    );
    Ok(
        kasumi_types::deserialize_u16_map::<D, Members>(deserializer)?
            .into_iter()
            .map(|(partition, members)| (partition, members.0))
            .collect(),
    )
}
fn deserialize_bearer_files<'de, D>(
    deserializer: D,
) -> std::result::Result<BTreeMap<u16, String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    kasumi_types::deserialize_u64_map(deserializer)?
        .into_iter()
        .map(|(partition, path)| Ok((u16::try_from(partition).map_err(D::Error::custom)?, path)))
        .collect()
}
impl ServingAuthorityConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        self.manifest.validate()?;
        self.tls.validate()?;
        ensure!(
            self.server_ca.is_absolute(),
            "authority server CA must be an installed absolute path"
        );
        kasumi_types::validate_name(&self.principal)?;
        ensure!(
            self.bearer_files.keys().eq(self.manifest.partitions.keys()),
            "authority credential files differ from installed partition map"
        );
        let mut credential_files = BTreeSet::new();
        for path in self.bearer_files.values() {
            credential_path(path)?;
            ensure!(
                credential_files.insert(std::path::Path::new(path)),
                "authority partitions require separate credential files"
            );
        }
        ensure!(
            self.endpoints.keys().eq(self.manifest.partitions.keys()),
            "authority endpoints differ from installed partition map"
        );
        for members in self.endpoints.values() {
            ensure!(
                !members.is_empty() && members.len() <= 64 && !members.contains_key(&0),
                "authority partition requires bounded installed member endpoints"
            );
            let mut origins = BTreeSet::new();
            for endpoint in members.values() {
                ensure!(
                    origins.insert(origin(&endpoint.endpoint)?.to_string()),
                    "duplicate authority endpoint"
                );
                ensure!(
                    !endpoint.certificate_pins.is_empty() && endpoint.certificate_pins.len() <= 8,
                    "authority endpoint needs bounded explicit leaf pins"
                );
                for pin in &endpoint.certificate_pins {
                    parse_certificate_pin(pin)?;
                }
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TenantServingConfig {
    Standalone {
        installation_id: Uuid,
    },
    Independent {
        authority: String,
    },
    #[cfg(any(test, feature = "test-utils"))]
    LocalFixture,
}

pub(crate) struct RuntimeLease {
    gate: Arc<ServingGate>,
    boot: ServingBoot,
    client: AsyncMutex<KasumiAuthorityPool>,
    renewal: Arc<crate::runtime_worker::RuntimeWorker>,
    serving: AtomicBool,
}
impl Drop for RuntimeLease {
    fn drop(&mut self) {
        self.gate.close();
        self.renewal.close();
    }
}
impl RuntimeLease {
    #[cfg(test)]
    pub(crate) fn paused_renewal(
        boot: ServingBoot,
        client: KasumiAuthorityPool,
        gate: Arc<ServingGate>,
    ) -> Result<(Arc<Self>, Arc<crate::runtime_worker::WorkerPause>)> {
        let runtime = Arc::new(Self {
            gate,
            boot,
            client: AsyncMutex::new(client),
            renewal: Default::default(),
            serving: AtomicBool::new(true),
        });
        let pause = runtime.renewal.pause_next_upgrade();
        Self::start_renewal(&runtime)?;
        Ok((runtime, pause))
    }
    pub(crate) fn gate(&self) -> &Arc<ServingGate> {
        &self.gate
    }
    pub(crate) async fn shutdown(&self) -> kasumi_types::drain::DrainResult {
        self.close();
        self.renewal.drain().await
    }
    pub(crate) fn close(&self) {
        self.gate.close();
        self.renewal.close();
    }
    pub(crate) async fn acquire(
        config: &ServingAuthorityConfig,
        trust: AuthorityTrust,
        credential: CredentialSource,
        tenant: &str,
        incarnation: Uuid,
        node_id: u64,
        purpose: LeasePurpose,
    ) -> Result<Arc<Self>> {
        let (runtime, _) = Self::acquire_once(
            config,
            trust,
            credential,
            tenant,
            incarnation,
            node_id,
            purpose,
        )
        .await?;
        Self::start_renewal(&runtime)?;
        Ok(runtime)
    }

    /// Explicit first enrollment retains this exact issuer-verified grant and
    /// its original suspend-aware deadline. It starts no renewal worker and
    /// cannot reauthorize a partial installation after the grant expires.
    pub(crate) async fn acquire_for_enrollment(
        config: &ServingAuthorityConfig,
        trust: AuthorityTrust,
        credential: CredentialSource,
        tenant: &str,
        incarnation: Uuid,
        node_id: u64,
    ) -> Result<(Arc<Self>, VerifiedLease)> {
        Self::acquire_once(
            config,
            trust,
            credential,
            tenant,
            incarnation,
            node_id,
            LeasePurpose::Serving,
        )
        .await
    }

    async fn acquire_once(
        config: &ServingAuthorityConfig,
        trust: AuthorityTrust,
        credential: CredentialSource,
        tenant: &str,
        incarnation: Uuid,
        node_id: u64,
        purpose: LeasePurpose,
    ) -> Result<(Arc<Self>, VerifiedLease)> {
        config.validate()?;
        let partition = config.manifest.partition(tenant)?;
        let endpoints = &config.endpoints[&partition];
        let tls = config.tls.load()?;
        let discovery = LeaseDiscovery {
            tenant: tenant.into(),
            incarnation,
            purpose,
            node: NodeIdentity {
                node_id,
                verifier: trust.verifier_identity()?,
                principal: config.principal.clone(),
                certificate_sha256: hex::encode(tls.certificate_pin()),
            },
        };
        ensure!(
            trust.manifest() == &config.manifest,
            "installed live authority verifier differs"
        );
        let connections = endpoints
            .iter()
            .map(|(id, endpoint)| {
                Ok((
                    *id,
                    KasumiClientConfig {
                        endpoint: endpoint.endpoint.clone(),
                        identity: tls.clone(),
                        trusted_ca_pem: read_bounded(&config.server_ca, 1 << 20)?,
                        server_certificate_pins: endpoint
                            .certificate_pins
                            .iter()
                            .map(|pin| parse_certificate_pin(pin))
                            .collect::<Result<_>>()?,
                    },
                ))
            })
            .collect::<Result<_>>()?;
        let path = config.bearer_files[&partition].clone();
        let mut client = KasumiAuthorityPool::new(
            connections,
            trust.clone(),
            Arc::new(move || credential(&path)),
        )?;
        let identity = client
            .discover_lease(&discovery, Duration::from_secs(5))
            .await?;
        let mut boot = ServingBoot::new(trust, identity)?;
        if purpose == LeasePurpose::RestorePreparation {
            boot = boot.for_restore_preparation();
        }
        // Sample before dispatch, including credential acquisition time. No
        // redirect/retry can re-anchor this exact request's local authority.
        let attempt = boot.begin_acquisition()?;
        let lease = client
            .acquire_lease(
                &attempt,
                Duration::from_millis(config.manifest.max_lease_ms.min(5000)),
            )
            .await?;
        let gate = ServingGate::new(lease.clone())?;
        let runtime = Arc::new(Self {
            gate,
            boot,
            client: AsyncMutex::new(client),
            renewal: Default::default(),
            serving: AtomicBool::new(purpose == LeasePurpose::Serving),
        });
        Ok((runtime, lease))
    }
    fn start_renewal(runtime: &Arc<Self>) -> Result<()> {
        let weak = Arc::downgrade(runtime);
        let wake = runtime.renewal.wake();
        let partition = runtime
            .boot
            .authority()
            .manifest()
            .partition(&runtime.boot.identity().tenant)?;
        runtime.boot.authority().start_background_work(
            partition,
            runtime.renewal.work(),
            async move {
                let mut failed = false;
                loop {
                    let delay = {
                        let Some(runtime) = weak.upgrade() else { break };
                        if runtime.renewal.is_closed() {
                            break;
                        }
                        let Ok(remaining) = runtime.gate.remaining() else {
                            break;
                        };
                        if failed {
                            (remaining / 4).min(Duration::from_millis(100))
                        } else {
                            remaining / 3
                        }
                    };
                    tokio::select! {
                        _ = wake.notified() => {},
                        _ = tokio::time::sleep(delay) => {},
                    }
                    let Some(runtime) = weak.upgrade() else { break };
                    #[cfg(test)]
                    runtime.renewal.after_upgrade().await;
                    if runtime.renewal.is_closed() {
                        break;
                    }
                    let Ok(remaining) = runtime.gate.remaining() else {
                        break;
                    };
                    failed = !matches!(
                        tokio::time::timeout(remaining, runtime.renew()).await,
                        Ok(Ok(()))
                    );
                    if runtime.gate.check().is_err() {
                        break;
                    }
                }
            },
        )
    }
    async fn renew(&self) -> Result<()> {
        // Mode changes and acquisitions share one gate, so a queued preparation
        // renewal cannot replace the active lease after successful promotion.
        let mut client = self.client.lock().await;
        let boot = if self.serving.load(Ordering::Acquire) {
            self.boot.clone().for_serving()
        } else {
            self.boot.clone()
        };
        let attempt = boot.begin_acquisition()?;
        let lease = client
            .acquire_lease(&attempt, self.gate.remaining()?.min(Duration::from_secs(5)))
            .await?;
        self.gate.renew(lease)
    }
    pub(crate) fn access(&self) -> Result<StorageAccess> {
        StorageAccess::serving(self.gate.clone())
    }
}

pub(crate) async fn acquire_tenant_access(
    config: &crate::runtime::RuntimeConfig,
    trusts: &BTreeMap<String, AuthorityTrust>,
    credential: CredentialSource,
    tenant: &str,
    incarnation: Uuid,
    purpose: LeasePurpose,
) -> Result<(StorageAccess, Option<Arc<RuntimeLease>>)> {
    let configured = config
        .tenants
        .iter()
        .find(|entry| entry.tenant == tenant)
        .context("tenant serving authority is not installed")?;
    match &configured.serving {
        TenantServingConfig::Standalone { installation_id } => {
            ensure!(
                config.mode == crate::runtime::DeploymentMode::Standalone,
                "standalone storage requires explicit standalone deployment"
            );
            Ok((
                StorageAccess::standalone(*installation_id, tenant, incarnation)?,
                None,
            ))
        }
        TenantServingConfig::Independent { authority } => {
            let installed = config
                .serving_authorities
                .get(authority)
                .context("serving authority is not installed")?;
            let node_id = config
                .replication
                .as_ref()
                .context("independent serving requires replicated data storage")?
                .node_id;
            let lease = RuntimeLease::acquire(
                installed,
                trusts
                    .get(authority)
                    .context("live authority verifier absent")?
                    .clone(),
                credential,
                tenant,
                incarnation,
                node_id,
                purpose,
            )
            .await?;
            Ok((lease.access()?, Some(lease)))
        }
        #[cfg(any(test, feature = "test-utils"))]
        TenantServingConfig::LocalFixture => Ok((StorageAccess::fixture(), None)),
    }
}

#[cfg(test)]
mod partition_credential_tests {
    use super::*;
    fn configured() -> ServingAuthorityConfig {
        let mut config = crate::runtime::example_config(kasumi_store::DirectoryPolicy::fixture())
            .unwrap()
            .serving_authorities
            .remove("storage-fence")
            .unwrap();
        let mut partition = config.manifest.partitions[&0].clone();
        partition.group = "second-issuer".into();
        config.manifest.partitions.insert(1, partition);
        config.endpoints.insert(1, config.endpoints[&0].clone());
        config
            .bearer_files
            .insert(1, "/etc/kasumi/credentials/authority-1-token".into());
        config
    }
    #[test]
    fn credential_files_cover_exact_installed_partitions_without_shared_or_implicit_source() {
        let config = configured();
        config.validate().unwrap();
        let mut missing = config.clone();
        missing.bearer_files.remove(&1);
        assert!(missing.validate().is_err());
        let mut extra = config.clone();
        extra
            .bearer_files
            .insert(2, "/etc/kasumi/credentials/extra".into());
        assert!(extra.validate().is_err());
        let mut shared = config.clone();
        shared
            .bearer_files
            .insert(1, config.bearer_files[&0].clone());
        assert!(shared.validate().is_err());
        let mut relative = config.clone();
        relative
            .bearer_files
            .insert(1, "TOKEN_ENVIRONMENT_NAME".into());
        assert!(relative.validate().is_err());
        let mut old = serde_json::to_value(&config).unwrap();
        old.as_object_mut().unwrap().remove("bearer_files");
        old["bearer_file"] = serde_json::json!("/etc/kasumi/credentials/old");
        assert!(serde_json::from_value::<ServingAuthorityConfig>(old).is_err());
    }
    #[test]
    fn partition_file_decoder_rejects_aliases_duplicates_and_overflow() {
        let config = configured();
        let encoded = serde_json::to_string(&config).unwrap();
        let valid = serde_json::to_string(&config.bearer_files).unwrap();
        for invalid in [
            r#"{"00":"/a","1":"/b"}"#,
            r#"{"0":"/a","0":"/b"}"#,
            r#"{"0":"/a","65536":"/b"}"#,
            r#"{"+0":"/a","1":"/b"}"#,
        ] {
            let replaced = encoded.replace(
                &format!("\"bearer_files\":{valid}"),
                &format!("\"bearer_files\":{invalid}"),
            );
            assert_ne!(replaced, encoded);
            assert!(serde_json::from_str::<ServingAuthorityConfig>(&replaced).is_err());
        }
    }

    #[test]
    fn enrollment_input_preserves_nested_authority_endpoints_and_serialized_identity() {
        let mut configuration =
            crate::runtime::example_config(kasumi_store::DirectoryPolicy::fixture()).unwrap();
        configuration
            .serving_authorities
            .insert("storage-fence".into(), configured());
        let input = crate::node_enrollment::Input::Data {
            configuration: Box::new(configuration),
        };
        let bytes = serde_json::to_vec(&input).unwrap();
        let from_bytes: crate::node_enrollment::Input = serde_json::from_slice(&bytes).unwrap();
        let from_value: crate::node_enrollment::Input =
            serde_json::from_value(serde_json::to_value(&input).unwrap()).unwrap();
        for decoded in [from_bytes, from_value] {
            assert_eq!(serde_json::to_vec(&decoded).unwrap(), bytes);
            let crate::node_enrollment::Input::Data { configuration } = decoded else {
                panic!("data enrollment changed kind");
            };
            configuration.serving_authorities["storage-fence"]
                .validate()
                .unwrap();
        }
    }

    #[test]
    fn enrollment_endpoint_decoder_rejects_aliases_duplicates_and_overflow_at_both_levels() {
        let mut configuration =
            crate::runtime::example_config(kasumi_store::DirectoryPolicy::fixture()).unwrap();
        let authority = configured();
        let endpoint = serde_json::to_string(&authority.endpoints[&0][&1]).unwrap();
        let valid = serde_json::to_string(&authority.endpoints).unwrap();
        configuration
            .serving_authorities
            .insert("storage-fence".into(), authority);
        let encoded = serde_json::to_string(&crate::node_enrollment::Input::Data {
            configuration: Box::new(configuration),
        })
        .unwrap();
        let member = format!("{{\"1\":{endpoint}}}");
        let invalid = [
            format!("{{\"00\":{member}}}"),
            format!("{{\"0\":{member},\"0\":{member}}}"),
            format!("{{\"65536\":{member}}}"),
            format!("{{\"+0\":{member}}}"),
            format!("{{\"0\":{{\"01\":{endpoint}}}}}"),
            format!("{{\"0\":{{\"1\":{endpoint},\"1\":{endpoint}}}}}"),
            format!("{{\"0\":{{\"18446744073709551616\":{endpoint}}}}}"),
            format!("{{\"0\":{{\"+1\":{endpoint}}}}}"),
        ];
        for endpoints in invalid {
            let replaced = encoded.replace(
                &format!("\"endpoints\":{valid}"),
                &format!("\"endpoints\":{endpoints}"),
            );
            assert_ne!(replaced, encoded);
            assert!(serde_json::from_str::<crate::node_enrollment::Input>(&replaced).is_err());
        }
    }
}
