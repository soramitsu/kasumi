//! One-shot local HA genesis provisioning. The owning task never resumes partial
//! effects under another credential or boot; public serving begins only later.
use crate::{
    node_enrollment::{Enrollment, Input},
    runtime::{CONTROL_TENANT, DeploymentMode, KeyProviderSettings, RuntimeConfig},
    serving_runtime::{CredentialSource, RuntimeLease, TenantServingConfig},
};
use anyhow::{Context, Result, ensure};
use kasumi_engine::{ReplicatedBootstrap, SecurityAudit};
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
    let storage = crate::runtime_memory::RuntimeStorage::installed(&config.admission)?;
    initialize_with_storage(config, storage).await
}

pub(crate) async fn initialize_with_storage(
    config: RuntimeConfig,
    storage: crate::runtime_memory::RuntimeStorage,
) -> Result<()> {
    config.validate()?;
    ensure!(
        config.mode == DeploymentMode::Replicated,
        "HA node enrollment requires replicated mode"
    );
    storage.require_policy(&config.admission)?;
    crate::startup_owner::open(
        crate::startup_owner::Kind::Data,
        initialize_owned(config, storage),
    )
    .await?;
    Ok(())
}

// Only an actually drained result may cross the acknowledged startup handoff.
struct Enrolled;
impl crate::startup_owner::Runtime for Enrolled {
    fn close(
        &mut self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = kasumi_types::drain::DrainResult> + Send + '_>,
    > {
        Box::pin(async { Ok(()) })
    }
}

async fn initialize_owned(
    config: RuntimeConfig,
    storage: crate::runtime_memory::RuntimeStorage,
) -> Result<Enrolled> {
    let mut pending = crate::startup_resources::Resources::default();
    let result = crate::startup_preparation::capture("HA node enrollment", async {
        let admission = storage.facade(&config.admission)?;
        pending.owned_admissions.push(admission.clone());
        let (node, audit) = crate::node_provision::create(
            &config.database_path,
            config.database_id,
            &config.persistent_disk,
            &config.scratch_disk,
            &config.security_audit,
            admission,
            &storage,
        )
        .await?;
        pending.owned_nodes.push(node.clone());
        pending.audits.push(audit.clone());
        #[cfg(test)]
        crate::startup_preparation::checkpoint(config.database_id, "ha-enrollment-node");
        let credential: CredentialSource = Arc::new(crate::runtime::file_secret);
        provision(&config, node, audit, credential).await
    })
    .await;
    let drained = crate::startup_owner::finish(&mut pending).await;
    match (result, drained) {
        (Ok(()), Ok(())) => Ok(Enrolled),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(drain)) => Err(drain.into()),
        (Err(error), Err(drain)) => Err(error.context(drain)),
    }
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
    let mut pending = crate::startup_resources::Resources::default();
    let result = crate::startup_preparation::capture("HA enrollment provisioning", async {
        config.validate_selected_key_domains(&config.tenants.iter().collect::<Vec<_>>())?;
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
                    .open(
                        domains,
                        credential.clone(),
                        node.persistent_disk().clone(),
                        node.scratch_disk().clone(),
                        audit.admission().clone(),
                    )
                    .await?,
            ),
            None => {
                ensure!(domains.is_empty(), "enrollment live verifier is absent");
                None
            }
        };
        if let Some(verifier) = &verifier {
            pending.verifiers.push(verifier.clone());
        }
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
        let control = crate::control_genesis::bootstrap(config)?;
        let control_incarnation = Uuid::parse_str(&control.incarnation)?;
        let control_fingerprint = initialize_domain(
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
        enrollment.record_genesis_tenant(
            audit.store(),
            CONTROL_TENANT,
            control_incarnation,
            control_fingerprint,
        )?;
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
            let fingerprint = opened?;
            if let Some(grant) = &grant {
                grant.check()?;
            }
            enrollment.record_genesis_tenant(
                audit.store(),
                &tenant.tenant,
                incarnation,
                fingerprint,
            )?;
            if let Some(grant) = &grant {
                grant.check()?;
            }
        }
        enrollment.complete(audit.store())
    })
    .await;
    let drained = crate::startup_owner::finish(&mut pending).await;
    match (result, drained) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(drain)) => Err(drain.into()),
        (Err(error), Err(drain)) => Err(error.context(drain)),
    }
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
) -> Result<String> {
    let mut pending = crate::startup_resources::Resources::default();
    pending.borrowed_nodes.push(node.clone());
    let result = crate::startup_preparation::capture("HA domain enrollment", async {
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
        pending.stores.push(stores.application().clone());
        pending.stores.push(stores.custody().store().clone());
        #[cfg(test)]
        if tenant == CONTROL_TENANT {
            crate::startup_preparation::checkpoint(config.database_id, "ha-control-pair");
        }
        let app = stores.application().clone();
        config.install_tenant_audit_archive(&app, None)?;
        if let Some(grant) = grant {
            grant.check()?;
        }
        let database = kasumi_engine::open_replicated(
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
        .await?;
        pending.databases.push(database);
        #[cfg(test)]
        if tenant == CONTROL_TENANT {
            crate::startup_preparation::checkpoint(config.database_id, "ha-control-database");
        }
        #[cfg(test)]
        if tenant == CONTROL_TENANT {
            crate::control_genesis::tests::checkpoint(&config.database_path).await?;
        }
        if let Some(grant) = grant {
            grant.check()?;
        }
        crate::runtime::persisted_bootstrap_fingerprint(&app)
    })
    .await;
    let drained = crate::startup_owner::finish(&mut pending).await;
    let fingerprint = match (result, drained) {
        (Ok(fingerprint), Ok(())) => fingerprint,
        (Err(error), Ok(())) => return Err(error),
        (Ok(_), Err(drain)) => return Err(drain.into()),
        (Err(error), Err(drain)) => {
            return Err(error.context(drain));
        }
    };
    if let Some(grant) = grant {
        grant.check()?;
    }
    Ok(fingerprint)
}
