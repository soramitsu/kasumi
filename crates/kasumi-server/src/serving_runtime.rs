//! Installed source-to-authority connections and bounded renewal. Remote data
//! requests cannot choose an issuer, credential, endpoint, epoch or boot nonce.
use crate::runtime::{TlsFiles, environment_name, origin, parse_certificate_pin, read_bounded};
use anyhow::{Context, Result, ensure};
use kasumi_client::{KasumiAuthorityClient, KasumiClientConfig};
use kasumi_serving::{
    AuthorityManifest, AuthorityTrust, LeaseDiscovery, LeasePurpose, NodeIdentity, ServingBoot,
    ServingGate,
};
use kasumi_store::StorageAccess;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::{
        Arc, Mutex,
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
    pub endpoints: BTreeMap<u16, AuthorityEndpoint>,
    pub tls: TlsFiles,
    pub server_ca: PathBuf,
    pub bearer_env: String,
    pub principal: String,
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
        environment_name(&self.bearer_env)?;
        ensure!(
            self.endpoints.keys().eq(self.manifest.partitions.keys()),
            "authority endpoints differ from installed partition map"
        );
        for endpoint in self.endpoints.values() {
            origin(&endpoint.endpoint)?;
            ensure!(
                !endpoint.certificate_pins.is_empty() && endpoint.certificate_pins.len() <= 8,
                "authority endpoint needs bounded explicit leaf pins"
            );
            for pin in &endpoint.certificate_pins {
                parse_certificate_pin(pin)?;
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TenantServingConfig {
    Independent {
        authority: String,
    },
    #[cfg(any(test, feature = "test-utils"))]
    LocalFixture,
}

pub(crate) struct RuntimeLease {
    gate: Arc<ServingGate>,
    boot: ServingBoot,
    client: AsyncMutex<KasumiAuthorityClient>,
    credential: CredentialSource,
    bearer_env: String,
    renewal: Mutex<Option<tokio::task::JoinHandle<()>>>,
    serving: AtomicBool,
}
impl Drop for RuntimeLease {
    fn drop(&mut self) {
        self.gate.close();
        if let Ok(handle) = self.renewal.get_mut()
            && let Some(handle) = handle.take()
        {
            handle.abort();
        }
    }
}
impl RuntimeLease {
    pub(crate) async fn acquire(
        config: &ServingAuthorityConfig,
        credential: CredentialSource,
        tenant: &str,
        incarnation: Uuid,
        node_id: u64,
        purpose: LeasePurpose,
    ) -> Result<Arc<Self>> {
        config.validate()?;
        let partition = config.manifest.partition(tenant)?;
        let endpoint = &config.endpoints[&partition];
        let tls = config.tls.load()?;
        let discovery = LeaseDiscovery {
            tenant: tenant.into(),
            incarnation,
            purpose,
            node: NodeIdentity {
                node_id,
                principal: config.principal.clone(),
                certificate_sha256: hex::encode(tls.certificate_pin()),
            },
        };
        let trust = AuthorityTrust::install(config.manifest.clone())?;
        let connection = KasumiClientConfig {
            endpoint: endpoint.endpoint.clone(),
            identity: tls,
            trusted_ca_pem: read_bounded(&config.server_ca, 1 << 20)?,
            server_certificate_pins: endpoint
                .certificate_pins
                .iter()
                .map(|pin| parse_certificate_pin(pin))
                .collect::<Result<_>>()?,
        };
        let mut client = tokio::time::timeout(
            Duration::from_secs(5),
            KasumiAuthorityClient::connect(&connection, trust.clone()),
        )
        .await
        .context("authority connection timed out")??;
        let bearer = credential(&config.bearer_env)?;
        let identity = tokio::time::timeout(
            Duration::from_secs(5),
            client.discover_lease(&bearer, &discovery),
        )
        .await
        .context("authority discovery timed out")??;
        let mut boot = ServingBoot::new(trust, identity)?;
        if purpose == LeasePurpose::RestorePreparation {
            boot = boot.for_restore_preparation();
        }
        // Sample before dispatch, including credential acquisition time. No
        // redirect/retry can re-anchor this exact request's local authority.
        let attempt = boot.begin_acquisition()?;
        let bearer = credential(&config.bearer_env)?;
        let lease = tokio::time::timeout(
            Duration::from_millis(config.manifest.max_lease_ms.min(5000)),
            client.acquire_lease(&bearer, &attempt),
        )
        .await
        .context("authority lease acquisition timed out")??;
        let gate = ServingGate::new(lease)?;
        let runtime = Arc::new(Self {
            gate,
            boot,
            client: AsyncMutex::new(client),
            credential,
            bearer_env: config.bearer_env.clone(),
            renewal: Mutex::new(None),
            serving: AtomicBool::new(purpose == LeasePurpose::Serving),
        });
        let weak = Arc::downgrade(&runtime);
        let interval = Duration::from_millis((config.manifest.max_lease_ms / 3).max(10));
        let retry = Duration::from_millis((config.manifest.max_lease_ms / 10).clamp(10, 100));
        let task = tokio::spawn(async move {
            let mut delay = interval;
            loop {
                tokio::time::sleep(delay).await;
                let Some(runtime) = weak.upgrade() else { break };
                if runtime.gate.check().is_err() {
                    break;
                }
                let renewed =
                    tokio::time::timeout(interval.min(Duration::from_secs(5)), runtime.renew())
                        .await;
                delay = if matches!(renewed, Ok(Ok(()))) {
                    interval
                } else {
                    retry
                };
                if runtime.gate.check().is_err() {
                    break;
                }
            }
        });
        *runtime
            .renewal
            .lock()
            .map_err(|_| anyhow::anyhow!("renewal registration poisoned"))? = Some(task);
        Ok(runtime)
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
        let bearer = (self.credential)(&self.bearer_env)?;
        let lease = client.acquire_lease(&bearer, &attempt).await?;
        self.gate.renew(lease)
    }
    pub(crate) fn access(&self) -> Result<StorageAccess> {
        StorageAccess::serving(self.gate.clone())
    }
    pub(crate) async fn promote(&self) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut client = self.client.lock().await;
            if self.serving.load(Ordering::Acquire) {
                return self.gate.check_serving();
            }
            let attempt = self.boot.clone().for_serving().begin_acquisition()?;
            let bearer = (self.credential)(&self.bearer_env)?;
            let lease = client.acquire_lease(&bearer, &attempt).await?;
            self.gate.promote_prepared(lease)?;
            self.serving.store(true, Ordering::Release);
            Ok(())
        })
        .await
        .context("active target lease acquisition timed out")?
    }
}

pub(crate) async fn acquire_tenant_access(
    config: &crate::runtime::RuntimeConfig,
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
            let lease =
                RuntimeLease::acquire(installed, credential, tenant, incarnation, node_id, purpose)
                    .await?;
            Ok((lease.access()?, Some(lease)))
        }
        #[cfg(any(test, feature = "test-utils"))]
        TenantServingConfig::LocalFixture => Ok((StorageAccess::fixture(), None)),
    }
}
