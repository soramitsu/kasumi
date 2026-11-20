//! A data-only writer has a different credential from topology observation.
//! Control calls the enrolled data listener to check the pending operation.
use crate::{
    installed_clients,
    remote_control::RemoteControlConfig,
    runtime::{TlsFiles, credential_path},
    serving_runtime::AuthorityEndpoint,
};
use anyhow::{Context, Result, ensure};
use kasumi_client::{ClientError, KasumiAdminClient, KasumiClientConfig};
use kasumi_engine::{
    BackupSourceCapability, RemoteBackupFuture, RemoteBackupSourceVerifier, RemoteBackupTransport,
    admission::NodeAdmission, control::ControlTopology,
};
use kasumi_transport::credentials::{FileCredentialSource, token};
use kasumi_types::{
    Action, Error, ErrorCode, MAX_REMOTE_BACKUP_BYTES, RemoteBackupAction, RemoteBackupChallenge,
    RemoteBackupCommand, RemoteBackupConfirmation, RemoteBackupRecord, RequestContext,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupAccess {
    pub bearer_file: String,
    pub principal: String,
    pub tls: TlsFiles,
    pub source_certificate_pins: BTreeSet<String>,
    pub callback_principal: String,
    pub callback_certificate_pins: BTreeSet<String>,
}
impl BackupAccess {
    pub(crate) fn validate(&self, remote: &RemoteControlConfig) -> Result<()> {
        kasumi_types::validate_name(&self.principal)?;
        kasumi_types::validate_name(&self.callback_principal)?;
        validate_pins(&self.source_certificate_pins)?;
        credential_path(&self.bearer_file)?;
        self.tls.validate()?;
        ensure!(
            self.bearer_file != remote.bearer_file
                && self.principal != remote.principal
                && self.principal != self.callback_principal
                && self.callback_principal != remote.principal
                && !remote.observers.contains(&self.principal)
                && !remote.observers.contains(&self.callback_principal),
            "backup and topology credentials need distinct enrolled identities"
        );
        validate_pins(&self.callback_certificate_pins)?;
        ensure!(
            self.callback_certificate_pins
                .is_disjoint(&self.source_certificate_pins),
            "backup source and callback certificates overlap"
        );
        Ok(())
    }
}

fn validate_pins(pins: &BTreeSet<String>) -> Result<()> {
    ensure!(
        (1..=8).contains(&pins.len()),
        "backup requires one to eight certificate pins"
    );
    for pin in pins {
        kasumi_types::validate_sha256(pin)?;
    }
    Ok(())
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRoute {
    pub admin: AuthorityEndpoint,
    pub writer_principal: String,
    pub source_certificate_pins: BTreeSet<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupSources {
    pub tls: TlsFiles,
    pub server_ca: PathBuf,
    pub bearer_file: String,
    pub callback_principal: String,
    #[serde(deserialize_with = "kasumi_types::deserialize_u64_map")]
    pub members: BTreeMap<u64, SourceRoute>,
}
impl BackupSources {
    fn endpoints(&self) -> BTreeMap<u64, AuthorityEndpoint> {
        self.members
            .iter()
            .map(|(id, route)| (*id, route.admin.clone()))
            .collect()
    }
    pub(crate) fn validate(&self, topology: &ControlTopology) -> Result<()> {
        installed_clients::validate(&self.endpoints())?;
        self.tls.validate()?;
        ensure!(
            self.server_ca.is_absolute(),
            "backup source CA must be absolute"
        );
        credential_path(&self.bearer_file)?;
        kasumi_types::validate_name(&self.callback_principal)?;
        let mut principals = BTreeSet::new();
        let mut client_pins = BTreeSet::new();
        let mut listener_pins = BTreeSet::new();
        for (id, route) in &self.members {
            kasumi_types::validate_name(&route.writer_principal)?;
            validate_pins(&route.source_certificate_pins)?;
            let member = topology
                .nodes
                .get(id)
                .context("backup source absent from enrolled data topology")?;
            ensure!(
                topology
                    .tenants
                    .values()
                    .any(|group| group.voters.contains(id))
                    && route
                        .source_certificate_pins
                        .is_subset(&member.certificate_pins)
                    && route.writer_principal != self.callback_principal
                    && principals.insert(&route.writer_principal)
                    && route
                        .source_certificate_pins
                        .iter()
                        .all(|pin| client_pins.insert(pin))
                    && route
                        .admin
                        .certificate_pins
                        .iter()
                        .all(|pin| listener_pins.insert(pin)),
                "backup source requires a distinct enrolled writer, listener and data member"
            );
        }
        Ok(())
    }
}

/// Each installed client retains its own opened TLS identity and CA. All PEM
/// inputs have the runtime's 1 MiB cap. Reserve their copies plus parsing
/// workspace before opening any member, then retain just the installed bound.
fn route_budget(
    admission: &Arc<NodeAdmission>,
    members: usize,
    metadata: &impl Serialize,
) -> Result<(kasumi_engine::admission::Reservation, u64)> {
    ensure!(
        (1..=64).contains(&members),
        "backup member count exceeds bound"
    );
    let (_, encoded) = kasumi_types::staged_digest(metadata)?;
    let resident = (members as u64) * (4 << 20) + (encoded as u64) * 4 + 65536;
    Ok((admission.reserve_resident(resident + (8 << 20))?, resident))
}

fn denied() -> Error {
    Error::new(ErrorCode::Forbidden, "remote backup authority refused")
}
fn unavailable() -> Error {
    Error::new(
        ErrorCode::Unavailable,
        "remote backup authority unavailable",
    )
}
fn physical(error: impl Into<anyhow::Error>) -> Error {
    unavailable().with_physical_source(error.into())
}
fn client_error(error: ClientError) -> Error {
    let code = error.code().unwrap_or(ErrorCode::Unavailable);
    Error::new(code, "remote backup request failed").with_physical_source(error.into())
}
fn authorize(
    actor: &RequestContext,
    incarnation: Uuid,
    principal: &str,
    scope: Action,
) -> kasumi_types::Result<()> {
    actor.authorization.check_live()?;
    let resource = actor.authorization.resource().ok_or_else(denied)?;
    resource.require_control(&incarnation.to_string())?;
    if actor.tenant != crate::runtime::CONTROL_TENANT
        || actor.principal != principal
        || actor.scopes.len() != 1
        || !actor.scopes.contains(&scope)
    {
        return Err(denied());
    }
    Ok(())
}

#[derive(Clone)]
pub(crate) enum Endpoint {
    Control(Arc<kasumi_engine::Database>),
    Source(Arc<DataTransport>),
}

pub(crate) struct DataTransport {
    incarnation: Uuid,
    config: BackupAccess,
    writer_pin: String,
    routes: BTreeMap<u64, KasumiClientConfig>,
    bearer: FileCredentialSource,
    admission: Arc<NodeAdmission>,
    pending: Mutex<BTreeMap<Uuid, Arc<BackupSourceCapability>>>,
    _routes_budget: kasumi_engine::admission::Reservation,
}
impl DataTransport {
    pub(crate) fn open(
        remote: &RemoteControlConfig,
        config: &BackupAccess,
        admission: Arc<NodeAdmission>,
    ) -> Result<Arc<Self>> {
        config.validate(remote)?;
        let (mut routes_budget, resident) = route_budget(
            &admission,
            remote.endpoints.len(),
            &(config, &remote.endpoints),
        )?;
        let routes =
            installed_clients::connections(&remote.endpoints, &config.tls, &remote.server_ca)?;
        let writer_pin = hex::encode(
            routes
                .values()
                .next()
                .context("backup has no installed Control route")?
                .identity
                .certificate_pin(),
        );
        ensure!(
            config.source_certificate_pins.contains(&writer_pin)
                && routes
                    .values()
                    .all(|route| hex::encode(route.identity.certificate_pin()) == writer_pin),
            "backup writer certificate differs from enrolled data member"
        );
        routes_budget.retain(resident);
        Ok(Arc::new(Self {
            _routes_budget: routes_budget,
            incarnation: remote.root.control_incarnation,
            writer_pin,
            config: config.clone(),
            routes,
            bearer: FileCredentialSource::new(&config.bearer_file)?,
            admission,
            pending: Mutex::new(BTreeMap::new()),
        }))
    }
    pub(crate) async fn confirm(
        &self,
        actor: &RequestContext,
        peer: &str,
        challenge: &RemoteBackupChallenge,
    ) -> kasumi_types::Result<kasumi_engine::VerifiedBackupSource> {
        authorize(
            actor,
            self.incarnation,
            &self.config.callback_principal,
            Action::Read,
        )?;
        if !self.config.callback_certificate_pins.contains(peer) {
            return Err(denied());
        }
        let source = self
            .pending
            .lock()
            .map_err(|_| unavailable())?
            .get(&challenge.reference.nonce)
            .cloned()
            .ok_or_else(denied)?;
        let reply = source.confirm(challenge).await?;
        authorize(
            actor,
            self.incarnation,
            &self.config.callback_principal,
            Action::Read,
        )?;
        if reply.observation().source_certificate_sha256 != self.writer_pin {
            return Err(denied());
        }
        Ok(reply)
    }
}
struct Pending<'a> {
    data: &'a DataTransport,
    nonce: Uuid,
}
impl Drop for Pending<'_> {
    fn drop(&mut self) {
        // Stop admitting reverse requests. The engine's source guard still
        // owns the final lease/policy check on this transport's returned row.
        // Its drop closes any callback that already borrowed the capability.
        self.data
            .pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.nonce);
    }
}
impl RemoteBackupTransport for DataTransport {
    fn control_incarnation(&self) -> Uuid {
        self.incarnation
    }
    fn execute<'a>(
        &'a self,
        source: Arc<BackupSourceCapability>,
        action: RemoteBackupAction,
    ) -> RemoteBackupFuture<'a, Option<RemoteBackupRecord>> {
        Box::pin(async move {
            let _workspace = self
                .admission
                .reserve_waiting(3 * MAX_REMOTE_BACKUP_BYTES as u64, None)?;
            let command = RemoteBackupCommand {
                reference: source.reference().clone(),
                action,
            };
            command.validate()?;
            let nonce = command.reference.nonce;
            {
                let mut pending = self.pending.lock().map_err(|_| unavailable())?;
                if pending.len() >= 64 || pending.contains_key(&nonce) {
                    return Err(Error::new(
                        ErrorCode::ResourceExhausted,
                        "backup source callbacks occupied",
                    ));
                }
                pending.insert(nonce, source);
            }
            let _pending = Pending { data: self, nonce };
            let deadline = tokio::time::Instant::now() + Duration::from_secs(29);
            let mut last = None;
            for route in self.routes.values() {
                let outcome = tokio::time::timeout_at(deadline, async {
                    let mut client = tokio::time::timeout(
                        Duration::from_secs(3),
                        KasumiAdminClient::connect(route),
                    )
                    .await
                    .map_err(|error| ClientError::Connection(error.into()))??;
                    let bearer = token(&self.bearer).map_err(ClientError::Connection)?;
                    client.exchange_backup_binding(&bearer, &command).await
                })
                .await
                .map_err(physical)?;
                match outcome {
                    Ok(value) => return Ok(value),
                    Err(error)
                        if matches!(error, ClientError::Connection(_))
                            || matches!(
                                error.code(),
                                Some(ErrorCode::Unavailable | ErrorCode::UnknownOutcome)
                            )
                            || matches!(&error,ClientError::Transport(s) if matches!(s.code(),tonic::Code::Unavailable|tonic::Code::DeadlineExceeded)) =>
                    {
                        last = Some(client_error(error))
                    }
                    Err(error) => return Err(client_error(error)),
                }
            }
            Err(last.unwrap_or_else(unavailable))
        })
    }
}

pub(crate) struct ControlVerifier {
    config: BackupSources,
    routes: BTreeMap<u64, KasumiClientConfig>,
    bearer: FileCredentialSource,
    _routes_budget: kasumi_engine::admission::Reservation,
}
impl ControlVerifier {
    pub(crate) fn open(
        config: &BackupSources,
        admission: &Arc<NodeAdmission>,
    ) -> Result<Arc<Self>> {
        let (mut routes_budget, resident) = route_budget(admission, config.members.len(), config)?;
        let routes =
            installed_clients::connections(&config.endpoints(), &config.tls, &config.server_ca)?;
        routes_budget.retain(resident);
        Ok(Arc::new(Self {
            _routes_budget: routes_budget,
            routes,
            bearer: FileCredentialSource::new(&config.bearer_file)?,
            config: config.clone(),
        }))
    }
}
impl RemoteBackupSourceVerifier for ControlVerifier {
    fn confirm<'a>(
        &'a self,
        challenge: &'a RemoteBackupChallenge,
        actor: &'a RequestContext,
        peer: &'a str,
    ) -> RemoteBackupFuture<'a, RemoteBackupConfirmation> {
        Box::pin(async move {
            let id = challenge.reference.source_node;
            let enrolled = self.config.members.get(&id).ok_or_else(denied)?;
            authorize(
                actor,
                challenge.reference.control_incarnation,
                &enrolled.writer_principal,
                Action::Write,
            )?;
            if !enrolled.source_certificate_pins.contains(peer) {
                return Err(denied());
            }
            let route = self.routes.get(&id).ok_or_else(denied)?;
            let bearer = token(&self.bearer).map_err(physical)?;
            let confirmation = tokio::time::timeout(Duration::from_secs(10), async {
                let mut client = KasumiAdminClient::connect(route).await?;
                client.confirm_backup_source(&bearer, challenge).await
            })
            .await
            .map_err(physical)?
            .map_err(client_error)?;
            authorize(
                actor,
                challenge.reference.control_incarnation,
                &enrolled.writer_principal,
                Action::Write,
            )?;
            if confirmation.source_certificate_sha256 != peer {
                return Err(denied());
            }
            Ok(confirmation)
        })
    }
}
