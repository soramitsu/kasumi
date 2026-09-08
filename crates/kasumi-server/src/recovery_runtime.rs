//! Installed Control recovery dispatch. Request bodies name durable semantic
//! identities; endpoints, trust and resource-specific credentials come only from
//! the installed route whose complete configuration digest was frozen at start.
use crate::{
    runtime::{
        AdminClientConfig, RuntimeConfig, credential_path, parse_certificate_pin, read_bounded,
    },
    serving_runtime::ServingAuthorityConfig,
};
use anyhow::{Context, Result, ensure};
use kasumi_client::{KasumiAuthorityPool, KasumiClientConfig, KasumiTargetClient};
use kasumi_engine::{Database, LifecycleSigner, VerifiedRecoveryPhase, VerifiedRecoveryStatus};
use kasumi_serving::{AuthorityTrust, ControlTrust};
use kasumi_transport::credentials::{FileCredentialSource, token};
use kasumi_types::*;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryMember {
    pub node: LifecycleNode,
    pub replication: TargetPeer,
    pub client: AdminClientConfig,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRoute {
    pub tenant: String,
    pub source_incarnation: Uuid,
    pub source_purpose_sha256: String,
    pub authority: String,
    pub issuer_admin_bearer_file: String,
    #[serde(deserialize_with = "kasumi_types::deserialize_u64_map")]
    pub targets: BTreeMap<u64, RecoveryMember>,
    #[serde(deserialize_with = "kasumi_types::require_explicit_option")]
    pub source: Option<AdminClientConfig>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRuntimeConfig {
    pub routes: BTreeMap<String, RecoveryRoute>,
}
impl RecoveryRuntimeConfig {
    pub(crate) fn validate(&self, runtime: &RuntimeConfig) -> Result<()> {
        ensure!(
            (1..=64).contains(&self.routes.len()),
            "recovery requires bounded installed routes"
        );
        let lifecycle = runtime
            .control
            .lifecycle
            .as_ref()
            .context("recovery requires closed lifecycle Control")?;
        let mut digests = std::collections::BTreeSet::new();
        for (name, route) in &self.routes {
            validate_name(name)?;
            validate_name(&route.tenant)?;
            validate_sha256(&route.source_purpose_sha256)?;
            ensure!(
                !route.source_incarnation.is_nil() && !route.tenant.starts_with("__kasumi_"),
                "invalid installed recovery source"
            );
            credential_path(&route.issuer_admin_bearer_file)?;
            let authority = runtime
                .serving_authorities
                .get(&route.authority)
                .context("recovery issuer not installed")?;
            ensure!(
                authority
                    .manifest
                    .lifecycle_controls
                    .get(&lifecycle.installation.root.control_incarnation)
                    == Some(&lifecycle.installation.root.public_key),
                "recovery issuer does not install exact Control root"
            );
            let partition = authority
                .manifest
                .control_partition(authority.manifest.partition(&route.tenant)?)?;
            ensure!(
                lifecycle.installation.partitions.get(&partition.key()) == Some(&partition),
                "recovery issuer differs from immutable Control partition"
            );
            ensure!(
                route.targets.len() == 3,
                "recovery requires three exact installed target voters"
            );
            let mut domains = std::collections::BTreeSet::new();
            for (id, member) in &route.targets {
                member.node.validate()?;
                member.client.validate()?;
                ensure!(
                    member.client.token_file != route.issuer_admin_bearer_file,
                    "target Control and issuer administration need independent credential sources"
                );
                validate_name(&member.replication.failure_domain)?;
                ensure!(
                    *id == member.node.node_id
                        && domains.insert(&member.replication.failure_domain)
                        && !member.replication.endpoint.is_empty()
                        && member.replication.endpoint.len() <= 2048,
                    "recovery voter identity or failure domains differ"
                );
            }
            if let Some(source) = &route.source {
                source.validate()?;
                ensure!(
                    route
                        .targets
                        .values()
                        .all(|target| target.client.token_file != source.token_file)
                        && source.token_file != route.issuer_admin_bearer_file,
                    "planned source credentials must be independently installed"
                );
            }
            ensure!(
                digests.insert(route.digest(authority)?),
                "duplicate recovery dispatch configuration"
            );
        }
        Ok(())
    }
}
impl RecoveryRoute {
    pub fn digest(&self, authority: &ServingAuthorityConfig) -> Result<String> {
        Ok(staged_digest(&("kasumi.recovery-dispatch-configuration.v1", self, authority))?.0)
    }
    fn accepts(&self, request: &RecoveryStart, authority: &ServingAuthorityConfig) -> Result<()> {
        request.validate()?;
        ensure!(
            self.digest(authority)? == request.dispatch_configuration_sha256
                && self.tenant == request.tenant
                && self.source_incarnation == request.source_incarnation
                && self.source_purpose_sha256 == request.source_purpose_sha256
                && self.targets.len() == request.target_nodes.len(),
            "recovery request differs from installed frozen dispatch configuration"
        );
        for (id, target) in &self.targets {
            ensure!(
                request.target_nodes.get(id) == Some(&target.node)
                    && request.materialization.voters.get(id) == Some(&target.replication),
                "recovery target identity, verifier, attestation or placement differs"
            );
        }
        ensure!(
            matches!(request.source_mode, RecoverySourceMode::SourceUnavailable)
                || self.source.is_some(),
            "planned recovery has no independently installed source credentials"
        );
        let partition = authority
            .manifest
            .control_partition(authority.manifest.partition(&request.tenant)?)?;
        ensure!(
            request.authority_partition == partition.key(),
            "recovery issuer partition differs"
        );
        Ok(())
    }
}
pub(crate) struct ControlRecoveryCoordinator {
    pub(crate) database: Arc<Database>,
    signer: Arc<LifecycleSigner>,
    configured: RecoveryRuntimeConfig,
    authorities: BTreeMap<String, ServingAuthorityConfig>,
    trusts: BTreeMap<String, AuthorityTrust>,
}
impl ControlRecoveryCoordinator {
    pub(crate) fn new(
        runtime: &RuntimeConfig,
        database: Arc<Database>,
        signer: Arc<LifecycleSigner>,
        trusts: BTreeMap<String, AuthorityTrust>,
    ) -> Result<Arc<Self>> {
        let configured = runtime
            .control
            .lifecycle
            .as_ref()
            .and_then(|c| c.recovery.clone())
            .context("recovery dispatcher is not installed")?;
        configured.validate(runtime)?;
        for route in configured.routes.values() {
            let trust = trusts
                .get(&route.authority)
                .context("recovery issuer lacks installed live verifier ownership")?;
            ensure!(
                trust.manifest() == &runtime.serving_authorities[&route.authority].manifest,
                "recovery issuer verifier installation differs"
            );
        }
        Ok(Arc::new(Self {
            database,
            signer,
            configured,
            authorities: runtime.serving_authorities.clone(),
            trusts,
        }))
    }
    pub(crate) fn control_incarnation(&self) -> Uuid {
        self.signer.root().control_incarnation
    }
    fn route(
        &self,
        request: &RecoveryStart,
    ) -> Result<(&RecoveryRoute, &ServingAuthorityConfig, &AuthorityTrust)> {
        for route in self.configured.routes.values() {
            let authority = &self.authorities[&route.authority];
            if route.digest(authority)? == request.dispatch_configuration_sha256 {
                route.accepts(request, authority)?;
                return Ok((route, authority, &self.trusts[&route.authority]));
            }
        }
        anyhow::bail!("exact recovery dispatch configuration is not installed")
    }
    pub(crate) async fn start(
        &self,
        context: RequestContext,
        request: RecoveryStart,
    ) -> Result<VerifiedRecoveryStatus> {
        self.route(&request)?;
        Ok(self
            .database
            .recovery_control(context, RecoveryControlCommand::Start(Box::new(request)))
            .await?)
    }
    pub(crate) async fn resume(
        &self,
        context: RequestContext,
        operation_id: Uuid,
        max_steps: u16,
    ) -> Result<VerifiedRecoveryStatus> {
        ensure!(
            (1..=16).contains(&max_steps),
            "recovery resume work limit is one to sixteen phases"
        );
        for _ in 0..max_steps {
            let status = self
                .database
                .recovery_status(context.clone(), operation_id)
                .await?;
            let head = status.record().clone();
            self.route(&head.request)?;
            if head.phase.terminal() {
                return Ok(status);
            }
            status.release().await?;
            drop(status);
            if let Some(id) = head.pending_phase {
                let prepared = self
                    .database
                    .recovery_phase(context.clone(), operation_id, id)
                    .await?;
                let outcome = self.dispatch(&context, &head, &prepared).await;
                match outcome {
                    Ok(outcome) => {
                        self.database
                            .resolve_recovery_dispatch(context.clone(), operation_id, id, outcome)
                            .await?;
                    }
                    Err(error) => {
                        // Only an explicitly supported expired target phase can
                        // produce a fresh committed admission. The prior entry
                        // stays unresolved in history; its deadline never moves.
                        let next_id = Uuid::new_v4();
                        if let Ok(Some(input)) = self
                            .database
                            .next_recovery_dispatch(&context, operation_id, next_id)
                            .await
                        {
                            self.database
                                .prepare_recovery_dispatch(
                                    context.clone(),
                                    operation_id,
                                    next_id,
                                    head.next_phase_sequence,
                                    head.pending_phase,
                                    input,
                                )
                                .await?;
                        } else {
                            return Err(error);
                        }
                    }
                }
            } else {
                let next_id = Uuid::new_v4();
                let Some(input) = self
                    .database
                    .next_recovery_dispatch(&context, operation_id, next_id)
                    .await?
                else {
                    return self
                        .database
                        .recovery_status(context, operation_id)
                        .await
                        .map_err(Into::into);
                };
                self.database
                    .prepare_recovery_dispatch(
                        context.clone(),
                        operation_id,
                        next_id,
                        head.next_phase_sequence,
                        None,
                        input,
                    )
                    .await?;
            }
        }
        Ok(self.database.recovery_status(context, operation_id).await?)
    }
    async fn dispatch(
        &self,
        context: &RequestContext,
        head: &RecoveryRecord,
        prepared: &VerifiedRecoveryPhase,
    ) -> Result<RecoveryDispatchOutcome> {
        let (route, authority, trust) = self.route(&head.request)?;
        prepared.release().await?;
        let duration = Duration::from_millis(head.request.phase_timeout_ms);
        match &prepared.record().input {
            RecoveryDispatch::Authority(command) => {
                let mut pool = authority_pool(
                    authority,
                    trust.clone(),
                    &head.request.tenant,
                    &route.issuer_admin_bearer_file,
                )?;
                if let Some(receipt) = pool
                    .receipt(&command.tenant, command.command_id, duration)
                    .await?
                {
                    ensure!(
                        receipt.receipt.command == **command,
                        "original issuer receipt differs"
                    );
                    prepared.release().await?;
                    return Ok(RecoveryDispatchOutcome::Authority(Box::new(receipt)));
                }
                prepared.admit_dispatch().await?;
                let result = pool.execute(command, duration).await?;
                prepared.release().await?;
                Ok(RecoveryDispatchOutcome::Authority(Box::new(result)))
            }
            RecoveryDispatch::ControlIntent(command) => {
                let reference = ReadLifecycleStatus {
                    command_id: command.command_id,
                    expected_incarnation: self.control_incarnation(),
                };
                let status = self
                    .database
                    .read_lifecycle_status(context, reference.clone())
                    .await?;
                if let Some(LifecycleCommandStatus::Intent(intent)) = &status.command {
                    self.database
                        .check_lifecycle_status_release(context, &status)
                        .await?;
                    ensure!(
                        intent.request == **command,
                        "original Control commitment differs"
                    );
                    return Ok(RecoveryDispatchOutcome::ControlIntent(intent.clone()));
                }
                ensure!(
                    status.command.is_none(),
                    "Control phase ID is used for another command"
                );
                prepared.admit_dispatch().await?;
                let mut limited = context.clone();
                limited.authorization = context
                    .authorization
                    .with_expiry_limit(prepared.dispatch_limit().await?)?;
                self.database
                    .lifecycle_control(
                        limited,
                        LifecycleControlCommand::CommitIntent(command.clone()),
                    )
                    .await?;
                let status = self
                    .database
                    .read_lifecycle_status(context, reference)
                    .await?;
                self.database
                    .check_lifecycle_status_release(context, &status)
                    .await?;
                let Some(LifecycleCommandStatus::Intent(intent)) = status.command else {
                    anyhow::bail!("accepted Control phase outcome absent")
                };
                Ok(RecoveryDispatchOutcome::ControlIntent(intent))
            }
            RecoveryDispatch::Target { node_id, request } => {
                prepared.admit_dispatch().await?;
                let phase = self
                    .database
                    .observe_lifecycle_intent(context.clone(), request.command_id)
                    .await?;
                let signed = self.signer.sign_intent(&phase).await?;
                let control = ControlTrust::install(self.signer.root().clone())?;
                let verified = control.verify_intent(&signed)?;
                let target = route
                    .targets
                    .get(node_id)
                    .context("target route not installed")?;
                let config = connection(&target.client)?;
                let credential = FileCredentialSource::new(&target.client.token_file)?;
                let bearer = token(&credential)?;
                let mut client =
                    KasumiTargetClient::connect(&config, control, trust.clone(), *node_id).await?;
                prepared.admit_dispatch().await?;
                let acknowledgement =
                    tokio::time::timeout(duration, client.execute(&bearer, &verified, request))
                        .await??;
                prepared.release().await?;
                phase.release().await?;
                Ok(RecoveryDispatchOutcome::Target(Box::new(
                    acknowledgement.response().clone(),
                )))
            }
            _ => anyhow::bail!("recovery dispatch phase is not installed"),
        }
    }
}
fn connection(config: &AdminClientConfig) -> Result<KasumiClientConfig> {
    config.validate()?;
    Ok(KasumiClientConfig {
        endpoint: config.endpoint.clone(),
        identity: config.identity.load()?,
        trusted_ca_pem: read_bounded(&config.server_ca, 1 << 20)?,
        server_certificate_pins: config
            .server_certificate_pins
            .iter()
            .map(|pin| parse_certificate_pin(pin))
            .collect::<Result<_>>()?,
    })
}
fn authority_pool(
    config: &ServingAuthorityConfig,
    trust: AuthorityTrust,
    tenant: &str,
    credential: &str,
) -> Result<KasumiAuthorityPool> {
    let partition = config.manifest.partition(tenant)?;
    let identity = config.tls.load()?;
    let ca = read_bounded(&config.server_ca, 1 << 20)?;
    let endpoints = config.endpoints[&partition]
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
        endpoints,
        trust,
        Arc::new(FileCredentialSource::new(credential)?),
    )
}
