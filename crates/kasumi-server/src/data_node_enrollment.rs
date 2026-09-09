//! One-shot local HA genesis provisioning. The owning task never resumes partial
//! effects under another credential or boot; public serving begins only later.
use crate::{
    node_enrollment::{Enrollment, Input},
    runtime::{CONTROL_TENANT, DeploymentMode, KeyProviderSettings, RuntimeConfig},
    serving_runtime::{CredentialSource, RuntimeLease, TenantServingConfig},
};
use anyhow::{Context, Result, ensure};
use kasumi_engine::{Database, ReplicatedBootstrap, SecurityAudit};
use kasumi_serving::{AuthorityTrust, VerifiedLease};
use kasumi_store::{NodeStore, StorageAccess, TenantStorageSet};
use std::{collections::BTreeMap, sync::Arc};
use uuid::Uuid;

pub(crate) async fn initialize(config: RuntimeConfig) -> Result<()> {
    config.validate()?;
    ensure!(
        config.mode == DeploymentMode::Replicated,
        "HA node enrollment requires replicated mode"
    );
    // Only an explicit invocation creates a node. Lost replies retain this
    // operation and its exclusive physical ownership through actual shutdown.
    tokio::spawn(async move {
        let admission = kasumi_engine::admission::NodeAdmission::new(config.admission.clone())?;
        let (node, audit) = crate::node_provision::create(
            &config.database_path,
            config.database_id,
            &config.scratch_disk,
            &config.security_audit,
            admission.clone(),
        )
        .await?;
        let credential: CredentialSource = Arc::new(crate::runtime::file_secret);
        let result = provision(&config, node.clone(), audit.clone(), credential).await;
        audit.shutdown().await;
        drop(audit);
        drop(node);
        result
    })
    .await?
}

pub(crate) fn network(
    config: &crate::runtime::ReplicationConfig,
) -> Result<Arc<crate::cluster::ClusterNetwork>> {
    let identity = config.listener.tls.load()?;
    let ca = crate::runtime::read_bounded(&config.listener.client_ca, 1 << 20)?;
    let peers = config
        .peers
        .iter()
        .map(|peer| {
            Ok(crate::cluster::PeerConfig {
                node_id: peer.node_id,
                endpoint: peer.endpoint.clone(),
                certificate_pins: peer
                    .certificate_pins
                    .iter()
                    .map(|pin| crate::runtime::parse_certificate_pin(pin))
                    .collect::<Result<_>>()?,
            })
        })
        .collect::<Result<_>>()?;
    crate::cluster::ClusterNetwork::new(
        config.node_id,
        &identity,
        &ca,
        peers,
        crate::cluster::PeerLimits::default(),
    )
}

pub(crate) async fn provision(
    config: &RuntimeConfig,
    node: Arc<NodeStore>,
    audit: Arc<SecurityAudit>,
    credential: CredentialSource,
) -> Result<()> {
    let enrollment = Enrollment::begin(
        audit.store(),
        &Input::Data {
            configuration: Box::new(config.clone()),
        },
    )?;
    let mut domains = BTreeMap::new();
    for authority in config.serving_authorities.values() {
        for partition in authority.manifest.partitions.keys() {
            let domain = authority.manifest.signing_domain(*partition)?;
            domains.insert(domain.digest()?, domain);
        }
    }
    let verifier = match &config.signer_verifier {
        Some(configured) => Some(
            configured
                .open(domains, credential.clone(), node.scratch_disk().clone())
                .await?,
        ),
        None => {
            ensure!(domains.is_empty(), "enrollment live verifier is absent");
            None
        }
    };
    let result = async {
        let trusts: BTreeMap<String, AuthorityTrust> = config
            .serving_authorities
            .iter()
            .map(|(alias, authority)| {
                Ok((
                    alias.clone(),
                    verifier
                        .as_ref()
                        .context("enrollment live verifier absent")?
                        .trust(authority.manifest.clone())?,
                ))
            })
            .collect::<Result<_>>()?;
        let replication = config
            .replication
            .as_ref()
            .context("replication configuration missing")?;
        let network = network(replication)?;
        let control = config
            .bootstrap(
                &config.control.initial_policy,
                &config.control.initial_limits,
                config.control.incarnation.as_deref(),
            )?
            .context("Control genesis missing")?;
        initialize_domain(
            config,
            node.clone(),
            audit.clone(),
            network.clone(),
            CONTROL_TENANT,
            &config.control.keys,
            &config.control.custody_keys,
            control,
            StorageAccess::node_control(),
            None,
            credential.clone(),
        )
        .await?;
        for tenant in &config.tenants {
            let incarnation = Uuid::parse_str(
                tenant
                    .incarnation
                    .as_deref()
                    .context("enrollment incarnation missing")?,
            )?;
            let (access, lease, grant) = match &tenant.serving {
                TenantServingConfig::Independent { authority } => {
                    let installed = config
                        .serving_authorities
                        .get(authority)
                        .context("enrollment authority absent")?;
                    let (lease, grant) = RuntimeLease::acquire_for_enrollment(
                        installed,
                        trusts
                            .get(authority)
                            .context("live enrollment trust absent")?
                            .clone(),
                        credential.clone(),
                        &tenant.tenant,
                        incarnation,
                        replication.node_id,
                    )
                    .await?;
                    let admission = (|| {
                        ensure!(
                            grant.identity().authority_epoch == 1
                                && lease.gate().recovery_checkpoint()?.is_none(),
                            "restored or retired generation requires the closed recovery workflow"
                        );
                        enrollment.record_grant(audit.store(), &grant)?;
                        lease.access()
                    })();
                    match admission {
                        Ok(access) => (access, Some(lease), Some(grant)),
                        Err(error) => {
                            lease.shutdown().await?;
                            return Err(error);
                        }
                    }
                }
                TenantServingConfig::Standalone { .. } => {
                    anyhow::bail!("standalone storage cannot enroll as HA")
                }
                #[cfg(any(test, feature = "test-utils"))]
                TenantServingConfig::LocalFixture => (StorageAccess::fixture(), None, None),
            };
            let opened = async {
                let bootstrap = config
                    .bootstrap(
                        &tenant.initial_policy,
                        &tenant.initial_limits,
                        tenant.incarnation.as_deref(),
                    )?
                    .context("tenant genesis missing")?;
                initialize_domain(
                    config,
                    node.clone(),
                    audit.clone(),
                    network.clone(),
                    &tenant.tenant,
                    &tenant.keys,
                    &tenant.custody_keys,
                    bootstrap,
                    access,
                    grant.as_ref(),
                    credential.clone(),
                )
                .await
            }
            .await;
            if let Some(lease) = &lease {
                lease.shutdown().await?;
            }
            opened?;
        }
        enrollment.complete(audit.store())
    }
    .await;
    if let Some(verifier) = verifier {
        verifier.shutdown().await;
    }
    result
}

// The typed fresh-pair initializer owns provisional domains through handoff.
// Retain its complete pair immediately, before other fallible initialization.
// The outer task retains original grants and owns all actual shutdown work.
#[allow(clippy::too_many_arguments)]
async fn initialize_domain(
    config: &RuntimeConfig,
    node: Arc<NodeStore>,
    audit: Arc<SecurityAudit>,
    network: Arc<crate::cluster::ClusterNetwork>,
    tenant: &str,
    application: &KeyProviderSettings,
    custody: &KeyProviderSettings,
    bootstrap: ReplicatedBootstrap,
    access: StorageAccess,
    grant: Option<&VerifiedLease>,
    credential: CredentialSource,
) -> Result<()> {
    let mut retained: Option<Arc<TenantStorageSet>> = None;
    let mut database: Option<Arc<Database>> = None;
    let result = async {
        if let Some(grant) = grant {
            grant.check()?;
        }
        let application_provider = application.provider(credential.clone())?;
        let custody_provider = custody.provider(credential)?;
        let stores = TenantStorageSet::initialize_catalogs(
            node.clone(),
            tenant.into(),
            application_provider,
            custody_provider,
            access,
        )
        .await?;
        retained = Some(stores.clone());
        let app = stores.application().clone();
        config.install_tenant_audit_archive(&app, None)?;
        if let Some(grant) = grant {
            grant.check()?;
        }
        database = Some(
            kasumi_engine::open_replicated(
                config
                    .replication
                    .as_ref()
                    .context("replication missing")?
                    .node_id,
                stores,
                &bootstrap,
                network,
                kasumi_raft::server_config(),
                audit,
            )
            .await?,
        );
        if let Some(grant) = grant {
            grant.check()?;
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let drained = match database {
        Some(database) => database.shutdown().await,
        None => Ok(()),
    };
    if let Some(stores) = retained {
        stores.application().shutdown().await;
        stores.custody().store().shutdown().await;
    }
    let initializers = node.drain_initializers().await;
    result?;
    initializers?;
    drained?;
    if let Some(grant) = grant {
        grant.check()?;
    }
    Ok(())
}
