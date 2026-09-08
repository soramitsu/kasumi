//! Independently deployed issuer. This executable has no municipality registry,
//! data listener, restore switch, or source-quorum fallback.
use crate::{
    auth::{AuthConfig, Authenticator},
    cluster::{ClusterNetwork, PeerConfig, PeerLimits},
    rpc::NativeAuthority,
    runtime::{
        KeyProviderSettings, MutualTlsEndpoint, ReplicationConfig, SecurityAuditConfig,
        file_secret, parse_certificate_pin, read_bounded, read_private_file,
    },
    tls,
};
use anyhow::{Context, Result, ensure};
use kasumi_authority::{AuthorityInstallation, IndependentAuthority};
use kasumi_engine::SecurityAudit;
use kasumi_serving::AuthoritySigner;
use kasumi_store::{NodeStore, StorageAccess, TenantStorageSet, TenantStore};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
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
    pub database_path: PathBuf,
    pub signing_key: PathBuf,
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
    pub fn validate(&self) -> Result<()> {
        self.installation.validate()?;
        ensure!(
            self.database_path.is_absolute() && self.signing_key.is_absolute(),
            "authority storage and signing key paths must be installed absolute paths"
        );
        self.native.validate()?;
        self.replication.validate()?;
        ensure!(
            self.replication.peers.len() == 3 && self.replication.voters()?.len() == 3,
            "authority first-release voters are fixed at three"
        );
        ensure!(
            self.native.listen != self.replication.listener.listen,
            "authority listeners collide"
        );
        let roots = [
            self.keys.validate()?,
            self.custody_keys.validate()?,
            self.security_audit.keys.validate()?,
        ];
        ensure!(
            roots[0] != roots[1] && roots[0] != roots[2] && roots[1] != roots[2],
            "authority/control/security wrapping roots must be independent"
        );
        ensure!(
            self.security_audit.max_records > 0,
            "authority security audit limit must be explicit"
        );
        Ok(())
    }
}
pub struct AuthorityRuntime {
    config: AuthorityRuntimeConfig,
    authority: Arc<IndependentAuthority>,
    stores: Arc<TenantStorageSet>,
    audit: Arc<SecurityAudit>,
    audit_store: Arc<TenantStore>,
    network: Arc<ClusterNetwork>,
    native: TcpListener,
    cluster: TcpListener,
    native_tls: Arc<rustls::ServerConfig>,
    auth: Arc<Authenticator>,
}
impl AuthorityRuntime {
    pub async fn open(config: AuthorityRuntimeConfig) -> Result<Self> {
        config.validate()?;
        let auth = Authenticator::new(config.auth.clone())?;
        let native_tls = config.native.load()?;
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
        let signer = Arc::new(AuthoritySigner::from_pkcs8(&read_private_file(
            &config.signing_key,
            64 << 10,
        )?)?);
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
        let audit = SecurityAudit::open(audit_store.clone(), config.security_audit.max_records)?;
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
        let voters: BTreeMap<_, _> = config
            .replication
            .peers
            .iter()
            .map(|peer| {
                (
                    peer.node_id,
                    kasumi_raft::BasicNode::new(peer.endpoint.clone()),
                )
            })
            .collect();
        let authority = IndependentAuthority::open_replicated(
            stores.clone(),
            config.installation.clone(),
            signer,
            config.replication.node_id,
            voters,
            network.clone(),
            kasumi_raft::server_config(),
        )
        .await?;
        let group = &config.installation.manifest.partitions[&config.installation.partition].group;
        let access = stores.clone();
        if let Err(error) = network.register_group_with_bootstrap(
            group.clone(),
            authority.raft_group().raft().clone(),
            config.replication.voters()?,
            authority.bootstrap_digest().into(),
            Arc::new(move || access.check_access()),
        ) {
            authority.shutdown().await?;
            return Err(error);
        }
        Ok(Self {
            config,
            authority,
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
        outcome.and(close)
    }
}
