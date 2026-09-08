//! Independently deployed issuer. This executable has no municipality registry,
//! data listener, restore switch, or source-quorum fallback.
use crate::{
    auth::{AuthConfig, Authenticator},
    cluster::{ClusterNetwork, PeerConfig, PeerLimits},
    rpc::NativeAuthority,
    runtime::{
        KeyProviderSettings, MutualTlsEndpoint, ReplicationConfig, SecurityAuditConfig,
        file_secret, parse_certificate_pin, read_bounded,
    },
    tls,
};
use anyhow::{Context, Result, ensure};
use kasumi_authority::{
    AuthorityBootstrap, AuthorityInstallation, AuthorityNodeSettings, IndependentAuthority,
};
use kasumi_engine::SecurityAudit;
use kasumi_store::{NodeStore, StorageAccess, TenantStorageSet, TenantStore};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{net::TcpListener, sync::watch, task::JoinSet};
fn listener_outcome(
    result: Option<std::result::Result<Result<()>, tokio::task::JoinError>>,
) -> Result<()> {
    result
        .context("authority listener stopped")?
        .context("authority listener panicked")?
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityRuntimeConfig {
    pub installation: AuthorityInstallation,
    pub bootstrap: AuthorityBootstrap,
    pub resource_budget_bytes: u64,
    pub database_path: PathBuf,
    pub operational_signer: crate::signer_runtime::OperationalSignerConfig,
    pub signer_verifier: crate::signer_runtime::SignerVerifierConfig,
    pub keys: KeyProviderSettings,
    pub custody_keys: KeyProviderSettings,
    pub security_audit: SecurityAuditConfig,
    pub auth: AuthConfig,
    pub native: MutualTlsEndpoint,
    pub replication: ReplicationConfig,
}
impl AuthorityRuntimeConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let config: Self = serde_json::from_slice(&read_bounded(path.as_ref(), 2 << 20)?)?;
        config.validate()?;
        Ok(config)
    }
    fn node_settings(&self) -> AuthorityNodeSettings {
        AuthorityNodeSettings {
            bootstrap: self.bootstrap.clone(),
            resource_budget_bytes: self.resource_budget_bytes,
            installed_members: self
                .replication
                .peers
                .iter()
                .map(|peer| {
                    (
                        peer.node_id,
                        kasumi_serving::AuthorityMember {
                            endpoint: peer.endpoint.clone(),
                            failure_domain: peer.failure_domain.clone(),
                            certificate_pins: peer
                                .certificate_pins
                                .iter()
                                .map(|pin| pin.to_ascii_lowercase())
                                .collect(),
                        },
                    )
                })
                .collect(),
        }
    }
    pub fn validate(&self) -> Result<()> {
        self.installation.validate()?;
        self.node_settings().validate(self.replication.node_id)?;
        Authenticator::new(self.auth.clone())?;
        ensure!(
            matches!(
                self.auth.source,
                crate::auth::AuthKeySource::ExternalOAuth { .. }
            ),
            "HA authority requires an external credential issuer"
        );
        ensure!(
            self.database_path.is_absolute(),
            "authority storage path must be an installed absolute path"
        );
        self.signer_verifier.validate()?;
        self.operational_signer.validate(
            &self
                .installation
                .manifest
                .signing_domain(self.installation.partition)?,
        )?;
        ensure!(
            self.signer_verifier.identity.node_id == self.replication.node_id
                && self.signer_verifier.database_path != self.database_path,
            "authority verifier physical identity differs"
        );
        self.native.validate()?;
        self.replication.validate()?;
        ensure!(
            self.replication.voters()? == self.bootstrap.membership.voters,
            "authority bootstrap voters differ from original installed voters"
        );
        ensure!(
            self.native.listen != self.replication.listener.listen,
            "authority listeners collide"
        );
        let roots = [
            self.keys.validate()?,
            self.custody_keys.validate()?,
            self.security_audit.keys.validate()?,
            self.signer_verifier.keys.validate()?,
        ];
        ensure!(
            roots
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == roots.len(),
            "authority/control/security/signer-trust wrapping roots must be independent"
        );
        self.security_audit.validate()?;
        Ok(())
    }
}
pub struct AuthorityRuntime {
    config: AuthorityRuntimeConfig,
    authority: Arc<IndependentAuthority>,
    signer_verifier: Arc<crate::signer_runtime::InstalledSignerVerifier>,
    stores: Arc<TenantStorageSet>,
    audit: Arc<SecurityAudit>,
    audit_store: Arc<TenantStore>,
    network: Arc<ClusterNetwork>,
    native: TcpListener,
    cluster: TcpListener,
    native_tls: kasumi_transport::ReloadableServerConfig,
    tls_reload: crate::tls_reload::RuntimeTlsReload,
    auth: Arc<Authenticator>,
}
impl AuthorityRuntime {
    pub fn tls_reload_handle(&self) -> crate::tls_reload::RuntimeTlsReload {
        self.tls_reload.clone()
    }

    pub async fn open(config: AuthorityRuntimeConfig) -> Result<Self> {
        config.validate()?;
        let auth = Authenticator::new(config.auth.clone())?;
        let native_tls = kasumi_transport::ReloadableServerConfig::new(config.native.load()?);
        let identity = config.replication.listener.tls.load()?;
        let ca = read_bounded(&config.replication.listener.client_ca, 1 << 20)?;
        let peers = config
            .replication
            .peers
            .iter()
            .map(|peer| {
                Ok(PeerConfig {
                    node_id: peer.node_id,
                    endpoint: peer.endpoint.clone(),
                    certificate_pins: peer
                        .certificate_pins
                        .iter()
                        .map(|value| parse_certificate_pin(value))
                        .collect::<Result<_>>()?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let network = ClusterNetwork::new(
            config.replication.node_id,
            &identity,
            &ca,
            peers,
            PeerLimits::default(),
        )?;
        let domain = config
            .installation
            .manifest
            .signing_domain(config.installation.partition)?;
        let signer_verifier = config
            .signer_verifier
            .open(
                std::collections::BTreeMap::from([(domain.digest()?, domain)]),
                Arc::new(file_secret),
            )
            .await?;
        let signer = config.operational_signer.open(&signer_verifier)?;
        let native = TcpListener::bind(config.native.listen).await?;
        let cluster = TcpListener::bind(config.replication.listener.listen).await?;
        let node = NodeStore::open(&config.database_path)?;
        let audit_store = TenantStore::open(
            node.clone(),
            kasumi_engine::SECURITY_TENANT.into(),
            config.security_audit.keys.provider(Arc::new(file_secret))?,
            StorageAccess::security_audit(),
        )
        .await?;
        let audit = config.security_audit.open(
            audit_store.clone(),
            kasumi_engine::admission::NodeAdmission::new(Default::default())?,
        )?;
        auth.install_audit(audit.clone())?;
        network.install_audit(audit.clone())?;
        let stores = TenantStorageSet::open(
            node,
            config.installation.tenant(),
            config.keys.provider(Arc::new(file_secret))?,
            config.custody_keys.provider(Arc::new(file_secret))?,
            StorageAccess::independent_authority(
                &config.installation.manifest,
                config.installation.partition,
            )?,
        )
        .await?;
        let authority = IndependentAuthority::open_replicated(
            stores.clone(),
            config.installation.clone(),
            signer,
            config.replication.node_id,
            config.node_settings(),
            network.clone(),
            kasumi_raft::server_config(),
        )
        .await?;
        let group = &config.installation.manifest.partitions[&config.installation.partition].group;
        let access = stores.clone();
        if let Err(error) = network.register_group_with_bootstrap(
            group.clone(),
            authority.raft_group().raft().clone(),
            config
                .replication
                .peers
                .iter()
                .map(|peer| peer.node_id)
                .collect(),
            authority.bootstrap_digest().into(),
            Arc::new(move || access.check_access()),
        ) {
            authority.shutdown().await?;
            return Err(error);
        }
        let peer_authority = Arc::downgrade(&authority);
        network.install_group_peer_fence(
            group,
            Arc::new(move |peer| {
                peer_authority
                    .upgrade()
                    .context("authority member owner is closed")?
                    .peer_allowed(peer)
            }),
        )?;
        network.install_authority_maintenance(Arc::downgrade(&authority))?;
        authority.install_maintenance_transport(network.clone())?;
        let tls_reload = crate::tls_reload::RuntimeTlsReload::new(
            vec![(
                crate::tls_reload::ListenerSource::Mutual(config.native.clone()),
                native_tls.clone(),
            )],
            None,
            audit.clone(),
        );
        Ok(Self {
            tls_reload,
            config,
            authority,
            signer_verifier,
            stores,
            audit,
            audit_store,
            network,
            native,
            cluster,
            native_tls,
            auth,
        })
    }
    pub async fn serve(self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        let (stop, stopped) = watch::channel(false);
        let mut tasks = JoinSet::new();
        tasks.spawn(tls::serve_tls(
            self.cluster,
            self.network.server_tls(),
            self.network.router(),
            tls::ListenerLimits::default(),
            self.audit.clone(),
            stopped.clone(),
        ));
        let startup = async {
            let group = &self.config.installation.manifest.partitions
                [&self.config.installation.partition]
                .group;
            while !self.authority.raft_group().raft().is_initialized().await? {
                let mut ready = true;
                for voter in self.config.replication.voters()? {
                    match self.network.bootstrap_fingerprint(voter, group).await {
                        Ok(actual) => ensure!(
                            actual == self.authority.bootstrap_digest(),
                            "independent authority bootstrap fingerprint differs"
                        ),
                        Err(_) => {
                            ready = false;
                            break;
                        }
                    }
                }
                if ready {
                    self.authority.initialize().await?;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Ok::<_, anyhow::Error>(())
        };
        let (mut outcome, initialized) = if *shutdown.borrow() {
            (Ok(()), false)
        } else {
            tokio::select! {
                result = startup => (result, true),
                _ = shutdown.changed() => (Ok(()), false),
                result = tasks.join_next() => (listener_outcome(result), false),
            }
        };
        if initialized && outcome.is_ok() && !*shutdown.borrow() {
            let router = tonic::service::Routes::new(
                NativeAuthority::new(self.authority.clone(), self.auth).service(),
            )
            .into_axum_router();
            tasks.spawn(tls::serve_tls(
                self.native,
                self.native_tls,
                router,
                tls::ListenerLimits::default(),
                self.audit.clone(),
                stopped,
            ));
            outcome = tokio::select! {
                _ = shutdown.changed() => Ok(()),
                result = tasks.join_next() => listener_outcome(result),
            };
        }
        stop.send_replace(true);
        while let Some(result) = tasks.join_next().await {
            if let Err(error) = result.map_err(Into::into).and_then(|value| value)
                && outcome.is_ok()
            {
                outcome = Err(error);
            }
        }
        let close = self.authority.shutdown().await;
        self.stores.application().shutdown().await;
        self.stores.custody().store().shutdown().await;
        self.audit_store.shutdown().await;
        self.signer_verifier.shutdown().await;
        outcome.and(close)
    }
}
