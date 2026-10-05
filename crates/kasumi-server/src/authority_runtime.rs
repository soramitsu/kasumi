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
use tokio::{net::TcpListener, sync::watch};
use uuid::Uuid;
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
    pub admission: kasumi_engine::admission::AdmissionConfig,
    pub database_path: PathBuf,
    pub database_id: Uuid,
    pub persistent_disk: kasumi_store::NodeDiskConfig,
    pub scratch_disk: kasumi_store::ScratchDiskConfig,
    pub operational_signer_file: PathBuf,
    pub signer_verifier: crate::signer_runtime::SignerVerifierConfig,
    #[serde(deserialize_with = "kasumi_types::require_explicit_option")]
    pub signer_publications: Option<crate::signer_publication_runtime::SignerPublicationConfig>,
    #[serde(deserialize_with = "kasumi_types::deserialize_u64_map")]
    pub installed_verifiers: std::collections::BTreeMap<u64, kasumi_serving::TrustVerifierIdentity>,
    pub keys: KeyProviderSettings,
    pub custody_keys: KeyProviderSettings,
    pub security_audit: SecurityAuditConfig,
    pub auth: AuthConfig,
    pub native: MutualTlsEndpoint,
    pub replication: ReplicationConfig,
}
pub use crate::authority_enrollment_terminal::{
    EnrollmentFailure, EnrollmentReport, EnrollmentTerminalFacade,
};
impl AuthorityRuntimeConfig {
    /// Explicit local issuer enrollment creates its node, audit, domain pair and
    /// immutable authority genesis before any normal startup or Raft handshake.
    pub async fn provision_node(&self) -> std::result::Result<(), EnrollmentFailure> {
        crate::authority_node_enrollment::initialize(self.clone()).await
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let config: Self = serde_json::from_slice(&read_bounded(path.as_ref(), 2 << 20)?)?;
        config.validate()?;
        Ok(config)
    }
    fn node_settings(&self) -> Result<AuthorityNodeSettings> {
        Ok(AuthorityNodeSettings {
            resource_budget_bytes: self.resource_budget_bytes,
            installed_members: self
                .replication
                .peers
                .iter()
                .map(|peer| {
                    Ok((
                        peer.node_id,
                        kasumi_serving::AuthorityMember {
                            verifier: self
                                .installed_verifiers
                                .get(&peer.node_id)
                                .context("authority member physical verifier is not installed")?
                                .clone(),
                            endpoint: peer.endpoint.clone(),
                            failure_domain: peer.failure_domain.clone(),
                            certificate_pins: peer
                                .certificate_pins
                                .iter()
                                .map(|pin| pin.to_ascii_lowercase())
                                .collect(),
                        },
                    ))
                })
                .collect::<Result<_>>()?,
        })
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.database_id.is_nil(),
            "installed authority node database identity is nil"
        );
        self.installation.validate()?;
        kasumi_serving::SigningCertificateVerification::verify(
            &self.bootstrap.initial_signer_certificate,
            &self
                .installation
                .manifest
                .signing_domain(self.installation.partition)?,
        )?;

        self.scratch_disk.validate()?;
        self.validate_persistent_disk()?;
        self.admission.validate()?;
        if let Some(publications) = &self.signer_publications {
            publications.validate()?;
        }
        self.node_settings()?.validate(self.replication.node_id)?;
        ensure!(
            self.installed_verifiers.len() == self.replication.peers.len()
                && self.installed_verifiers.get(&self.replication.node_id)
                    == Some(&self.signer_verifier.identity),
            "authority member verifier roster differs from installed physical identity"
        );
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
        crate::signer_runtime::OperationalSignerConfig::load(
            &self.operational_signer_file,
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
// UUID's canonical hyphenated representation and the full u16 decimal range
// bound this formatting buffer; it is not an operational capacity or quota.
const AUTHORITY_PARTICIPANT_PREFIX: &str = "kasumi.authority.";
const AUTHORITY_PARTICIPANT_BYTES: usize = AUTHORITY_PARTICIPANT_PREFIX.len()
    + uuid::fmt::Hyphenated::LENGTH
    + 1
    + (u16::MAX.ilog10() as usize + 1);
pub(crate) struct AuthorityParticipantName {
    bytes: [u8; AUTHORITY_PARTICIPANT_BYTES],
    len: usize,
}
impl AuthorityParticipantName {
    pub(crate) fn new(authority: Uuid, partition: u16) -> Self {
        use std::fmt::Write;
        let mut name = Self {
            bytes: [0; AUTHORITY_PARTICIPANT_BYTES],
            len: 0,
        };
        write!(
            name,
            "{AUTHORITY_PARTICIPANT_PREFIX}{authority}.{partition}"
        )
        .expect("concrete UUID/u16 authority participant bound");
        name
    }
    pub(crate) fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes[..self.len]).expect("canonical ASCII authority participant")
    }
}
impl std::fmt::Write for AuthorityParticipantName {
    fn write_str(&mut self, value: &str) -> std::fmt::Result {
        let end = self.len.checked_add(value.len()).ok_or(std::fmt::Error)?;
        self.bytes
            .get_mut(self.len..end)
            .ok_or(std::fmt::Error)?
            .copy_from_slice(value.as_bytes());
        self.len = end;
        Ok(())
    }
}

pub struct AuthorityRuntime {
    serving_registration: Option<crate::serving_owner::Registration>,
    startup_drain: kasumi_types::drain::DrainReport,
    original_recoveries: crate::administration::OriginalRecoveries,
    config: AuthorityRuntimeConfig,
    node: NodeStore,
    authority: Arc<IndependentAuthority>,
    signer_verifier: Arc<crate::signer_runtime::InstalledSignerVerifier>,
    stores: Arc<TenantStorageSet>,
    audit: Arc<SecurityAudit>,
    audit_store: Arc<TenantStore>,
    network: Arc<ClusterNetwork>,
    native: Option<TcpListener>,
    cluster: Option<TcpListener>,
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
        let storage = crate::runtime_memory::RuntimeStorage::installed(&config.admission)?;
        Self::open_with_storage(config, storage).await
    }

    pub(crate) async fn open_with_storage(
        config: AuthorityRuntimeConfig,
        storage: crate::runtime_memory::RuntimeStorage,
    ) -> Result<Self> {
        storage.require_policy(&config.admission)?;
        crate::startup_owner::open(
            crate::startup_owner::Kind::Authority,
            Self::open_owned(config, storage),
        )
        .await
    }

    /// Join cancelled/incomplete opens after stopping new startup admission.
    pub async fn drain_startups() -> Result<()> {
        crate::startup_owner::drain(crate::startup_owner::Kind::Authority).await
    }

    /// Close an opened runtime that has not entered its consuming serve loop.
    pub async fn shutdown(&mut self) -> kasumi_types::drain::DrainResult {
        use crate::runtime_drain::observe;
        let report = &mut self.startup_drain;
        let mut retained = None;
        self.original_recoveries.seal();
        if self.original_recoveries.retained().await {
            let issue = report.record(
                "authority original constructor inventory",
                0,
                anyhow::anyhow!("authority constructor custody remains retained"),
            );
            retained = Some(kasumi_types::drain::DrainFailure::retained(issue));
        }
        observe(report, &mut retained, self.authority.shutdown().await);
        observe(
            report,
            &mut retained,
            self.audit.admission().drain_snapshot_startups().await,
        );
        observe(report, &mut retained, self.stores.shutdown().await);
        observe(report, &mut retained, self.audit.shutdown().await);
        observe(report, &mut retained, self.audit_store.shutdown().await);
        observe(report, &mut retained, self.signer_verifier.shutdown().await);
        if retained.is_none() {
            observe(report, &mut retained, self.node.shutdown().await);
        }
        report.outcome(retained)
    }

    #[allow(
        clippy::result_large_err,
        reason = "the native constructor returns whole inline custody into the same preadmitted inventory before any foreign marker; boxing the error would allocate outside that boundary"
    )]
    async fn open_owned(
        config: AuthorityRuntimeConfig,
        storage: crate::runtime_memory::RuntimeStorage,
    ) -> Result<Self> {
        let mut pending = crate::startup_resources::Resources::default();
        let outcome: Result<Self> = crate::startup_preparation::capture("authority runtime", async {
            config.validate()?;
            let admission = storage.facade(&config.admission)?;
            pending.owned_admissions.push(admission.clone());
            let participant = AuthorityParticipantName::new(
                config.installation.manifest.authority_id, config.installation.partition);
            pending.original_recoveries = Some(crate::administration::OriginalRecoveries::new(
                &admission,
                crate::administration::OriginalRecoveryParticipants::one(participant.as_str()),
            )?);
            pending.signer_original_recoveries = Some(config.signer_verifier.node_start_inventory(&admission)?);
            let persistent_disk = crate::persistent_disk::open(&config.persistent_disk, &storage)?;
            let scratch_disk = storage.open_scratch(&config.scratch_disk)?;
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
                    persistent_disk.clone(),
                    scratch_disk.clone(),
                    admission.clone(),
                    pending.signer_original_recoveries.as_ref().expect("same preinstalled signer original inventory"),
                )
                .await?;
            pending.verifiers.push(signer_verifier.clone());
            let signer = crate::signer_runtime::OperationalSignerConfig::load(
                &config.operational_signer_file,
                &config
                    .installation
                    .manifest
                    .signing_domain(config.installation.partition)?,
            )?
            .open(&signer_verifier)?;
            let native = TcpListener::bind(config.native.listen).await?;
            let cluster = TcpListener::bind(config.replication.listener.listen).await?;
            let node = {
                let mut constructor = pending.original_recoveries.as_ref()
                    .expect("same installed authority startup inventory").claim(0).await;
                constructor.begin_node().map_err(|observed| observed.foreign_error())?.run_node(|| NodeStore::open_existing(
                    &config.database_path,
                    config.database_id,
                    persistent_disk.clone(),
                    scratch_disk.clone(),
                    persistent_disk.native_storage_config(),
                )).map_err(|observed| observed.foreign_error())?
            };
            pending.owned_nodes.push(node.clone());
            node.prepare_cache_warming().await?;
            let audit_store = TenantStore::open_existing(
                node.clone(),
                kasumi_engine::SECURITY_TENANT.into(),
                config.security_audit.keys.provider(Arc::new(file_secret))?,
                StorageAccess::security_audit(),
            )
            .await?;
            pending.stores.push(audit_store.clone());
            crate::node_enrollment::require_complete(
                &audit_store,
                config.database_id,
                crate::node_enrollment::Kind::Authority,
            )?;
            let audit = config
                .security_audit
                .open(audit_store.clone(), admission.clone())?;
            pending.audits.push(audit.clone());
            auth.install_audit(audit.clone())?;
            network.install_audit(audit.clone())?;
            let stores = TenantStorageSet::open_existing(
                node.clone(),
                config.installation.tenant(),
                config.keys.provider(Arc::new(file_secret))?,
                config.custody_keys.provider(Arc::new(file_secret))?,
                StorageAccess::independent_authority(
                    &config.installation.manifest,
                    config.installation.partition,
                )?,
            )
            .await?;
            pending.stores.push(stores.application().clone());
            pending.stores.push(stores.custody().store().clone());
            let authority = {
                let mut constructor = pending.original_recoveries.as_ref()
                    .expect("initial authority constructor inventory").claim(0).await;
                constructor.run_snapshot(async {
                    IndependentAuthority::open_existing_replicated(
                        stores.clone(),
                        config.installation.clone(),
                        signer,
                        config.replication.node_id,
                        config.node_settings()?,
                        network.clone(),
                        kasumi_raft::server_config(),
                        request_budget(&admission)?,
                        admission.snapshot_buffer_owner()?,
                    ).await.map_err(kasumi_engine::SnapshotFailure::from)
                }).await.map_err(crate::administration::original_serving_runtime::OriginalRecoveryObservation::foreign_error)?
            };
            pending.authorities.push(authority.clone());
            let group =
                &config.installation.manifest.partitions[&config.installation.partition].group;
            let access = stores.clone();
            network.register_group_with_bootstrap(
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
            )?;
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
            if let Some(publications) = &config.signer_publications {
                authority.install_signer_publication_transport(
                    publications.open(config.installation.manifest.clone())?,
                )?;
            }
            let tls_reload = crate::tls_reload::RuntimeTlsReload::new(
                vec![(
                    crate::tls_reload::ListenerSource::Mutual(config.native.clone()),
                    native_tls.clone(),
                )],
                None,
                audit.clone(),
            );
            let serving_registration = crate::serving_owner::Registration::new(
                crate::serving_owner::Kind::Authority,
                config.database_id,
                audit.admission(),
            )?;
            Ok(Self {
                serving_registration: Some(serving_registration),
                startup_drain: Default::default(),
                original_recoveries: pending.original_recoveries.take()
                    .expect("same initial authority constructor inventory"),
                tls_reload,
                config,
                node,
                authority,
                signer_verifier,
                stores,
                audit,
                audit_store,
                network,
                native: Some(native),
                cluster: Some(cluster),
                native_tls,
                auth,
            })
        })
        .await;
        if outcome.is_err()
            && let Err(cleanup) = crate::startup_owner::finish(&mut pending).await
        {
            return outcome.map_err(|error| error.context(cleanup));
        }
        outcome
    }
    pub fn serve(
        mut self,
        shutdown: watch::Receiver<bool>,
    ) -> impl std::future::Future<Output = Result<()>> + Send + 'static {
        let registration = self
            .serving_registration
            .take()
            .expect("opened runtime has one serving registration");
        crate::serving_owner::serve(
            crate::serving_owner::Kind::Authority,
            registration,
            AuthorityServing {
                tasks: crate::runtime::ServingTasks::new(),
                report: Default::default(),
                runtime: self,
            },
            shutdown,
        )
    }

    /// Stop opening new instances before joining all retained serving owners.
    pub async fn drain_serving() -> Result<()> {
        crate::serving_owner::drain(crate::serving_owner::Kind::Authority).await
    }

    async fn serve_owned(
        &mut self,
        tasks: &mut crate::runtime::ServingTasks,
        shutdown: &mut crate::serving_owner::Shutdown,
    ) -> Result<()> {
        if shutdown.requested() {
            return Ok(());
        }
        let stopped = tasks.cluster_stop.subscribe();
        tasks.spawn_listener(tls::serve_tls(
            self.cluster.take().expect("cluster listener starts once"),
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
                for voter in &self.authority.bootstrap().membership.voters {
                    match self.network.bootstrap_fingerprint(*voter, group).await {
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
        let (mut outcome, initialized) = if shutdown.requested() {
            (Ok(()), false)
        } else {
            tokio::select! {
                result = startup => (result, true),
                _ = shutdown.changed() => (Ok(()), false),
                result = tasks.listeners.join_next() => (listener_outcome(result), false),
            }
        };
        if initialized && outcome.is_ok() && !shutdown.requested() {
            let router = tonic::service::Routes::new(
                NativeAuthority::new(self.authority.clone(), self.auth.clone())
                    .with_signer_verifier(self.signer_verifier.clone())
                    .with_operational_signer_file(self.config.operational_signer_file.clone())
                    .service(),
            )
            .into_axum_router();
            tasks.spawn_listener(tls::serve_tls(
                self.native.take().expect("native listener starts once"),
                self.native_tls.clone(),
                router,
                tls::ListenerLimits::default(),
                self.audit.clone(),
                stopped,
            ));
            outcome = tokio::select! {
                _ = shutdown.changed() => Ok(()),
                result = tasks.listeners.join_next() => listener_outcome(result),
            };
        }
        outcome
    }
}

impl crate::startup_owner::Runtime for AuthorityRuntime {
    fn handoff(&mut self) -> Result<()> {
        self.node.activate_cache_warming()?;
        self.signer_verifier.activate_cache_warming()
    }

    fn close(
        &mut self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = kasumi_types::drain::DrainResult> + Send + '_>,
    > {
        Box::pin(AuthorityRuntime::shutdown(self))
    }
}

struct AuthorityServing {
    tasks: crate::runtime::ServingTasks,
    report: kasumi_types::drain::DrainReport,
    runtime: AuthorityRuntime,
}
impl crate::serving_owner::Owner for AuthorityServing {
    fn run<'a>(
        &'a mut self,
        shutdown: &'a mut crate::serving_owner::Shutdown,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(self.runtime.serve_owned(&mut self.tasks, shutdown))
    }
    fn close(
        &mut self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = kasumi_types::drain::DrainResult> + Send + '_>,
    > {
        Box::pin(async move {
            self.runtime.authority.close_admission();
            let mut retained = None;
            crate::runtime_drain::observe(
                &mut self.report,
                &mut retained,
                self.tasks.shutdown().await,
            );
            // The runtime owns the physical databases. Listener tasks must
            // actually drain before those databases may release their files.
            if retained.is_none() {
                crate::runtime_drain::observe(
                    &mut self.report,
                    &mut retained,
                    self.runtime.shutdown().await,
                );
            }
            self.report.outcome(retained)
        })
    }
}

/// Charge the full bounded request-child inventory to the installed node governor.
pub(crate) fn request_budget(
    admission: &Arc<kasumi_engine::admission::NodeAdmission>,
) -> Result<kasumi_serving::BackgroundWorkBudget> {
    let bytes = kasumi_authority::authority_request_metadata_bytes()?
        .checked_add(kasumi_types::SharedBudgetCharge::required_bytes::<
            kasumi_engine::admission::Reservation,
        >()?)
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let mut charge = admission.reserve(bytes, None)?;
    charge.retain(bytes);
    kasumi_serving::BackgroundWorkBudget::new(
        kasumi_authority::AUTHORITY_REQUEST_SLOTS,
        kasumi_types::SharedBudgetCharge::new(charge),
    )
}

#[cfg(test)]
mod participant_tests {
    use super::*;

    #[test]
    fn authority_participant_formats_full_uuid_partition_range_without_allocation() {
        let authority = Uuid::from_u128(42);
        let watching = crate::recovery_allocation_watch::Watch::begin();
        let minimum = AuthorityParticipantName::new(authority, u16::MIN);
        let maximum = AuthorityParticipantName::new(authority, u16::MAX);
        assert_eq!(
            minimum.as_str(),
            "kasumi.authority.00000000-0000-0000-0000-00000000002a.0"
        );
        assert_eq!(
            maximum.as_str(),
            "kasumi.authority.00000000-0000-0000-0000-00000000002a.65535"
        );
        assert_eq!(maximum.len, AUTHORITY_PARTICIPANT_BYTES);
        let observed = watching.finish();
        assert!(!observed.overflow);
        assert_eq!(
            observed.count, 0,
            "no name backing precedes the initial donor quote"
        );
    }

    #[tokio::test]
    async fn authority_initial_donor_captures_whole_source_before_foreign_cleanup_marker() {
        use kasumi_engine::{SnapshotFailure, admission::NodeAdmission};
        let admission = NodeAdmission::new(Default::default()).unwrap();
        let name = AuthorityParticipantName::new(Uuid::from_u128(42), 0);
        let mut pending = crate::startup_resources::Resources::default();
        pending.original_recoveries = Some(
            crate::administration::OriginalRecoveries::new(
                &admission,
                crate::administration::OriginalRecoveryParticipants::one(name.as_str()),
            )
            .unwrap(),
        );
        let charged = admission.snapshot();
        let original = anyhow::anyhow!("original authority constructor source");
        let pointer: &(dyn std::error::Error + Send + Sync + 'static) = original.as_ref();
        let pointer = pointer as *const _ as *const () as usize;
        let inventory = pending.original_recoveries.as_ref().unwrap();
        let mut constructor = inventory.claim(0).await;
        let marker = constructor
            .run_snapshot(async { Err::<(), _>(SnapshotFailure::Source(original)) })
            .await
            .err()
            .unwrap()
            .foreign_error();
        constructor
            .with_failure(|failure| {
                let original: &(dyn std::error::Error + Send + Sync + 'static) =
                    failure.original().source_error().unwrap().as_ref();
                assert_eq!(original as *const _ as *const () as usize, pointer);
            })
            .unwrap();
        drop(marker);
        drop(constructor);
        assert!(inventory.retained().await);
        drop(pending);
        assert_eq!(admission.snapshot().reserved_bytes, charged.reserved_bytes);
        assert_eq!(
            admission.snapshot().live_reservations,
            charged.live_reservations
        );
    }
}
