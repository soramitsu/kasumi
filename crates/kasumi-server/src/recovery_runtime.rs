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
use kasumi_client::{
    KasumiAuthorityPool, KasumiClientConfig, KasumiRetirementPool, KasumiTargetClient,
};
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
/// One independently authorized source service, reached only through installed members.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverySource {
    #[serde(deserialize_with = "kasumi_types::deserialize_u64_map")]
    pub members: BTreeMap<u64, crate::serving_runtime::AuthorityEndpoint>,
    pub identity: crate::runtime::TlsFiles,
    pub server_ca: std::path::PathBuf,
    pub token_file: String,
}
impl RecoverySource {
    pub(crate) fn validate(&self) -> Result<()> {
        crate::installed_clients::validate(&self.members)?;
        self.identity.validate()?;
        ensure!(
            self.server_ca.is_absolute(),
            "source CA path must be absolute"
        );
        credential_path(&self.token_file)?;
        Ok(())
    }
    fn connections(&self) -> Result<BTreeMap<u64, KasumiClientConfig>> {
        self.validate()?;
        crate::installed_clients::connections(&self.members, &self.identity, &self.server_ca)
    }
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
    pub source: Option<RecoverySource>,
    #[serde(deserialize_with = "kasumi_types::require_explicit_option")]
    pub source_custody: Option<RecoverySource>,
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
            ensure!(
                route.source.is_some() == route.source_custody.is_some(),
                "planned recovery installs both application and custody sources"
            );
            if let (Some(source), Some(custody)) = (&route.source, &route.source_custody) {
                source.validate()?;
                custody.validate()?;
                ensure!(
                    source.token_file != custody.token_file,
                    "application retirement and custody verification require distinct credential sources"
                );
                for client in [source, custody] {
                    ensure!(
                        route
                            .targets
                            .values()
                            .all(|target| target.client.token_file != client.token_file)
                            && client.token_file != route.issuer_admin_bearer_file,
                        "planned source credentials must be independently installed"
                    );
                }
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
                if let AuthorityAction::ActivateCommitted { control, .. } = &command.action {
                    let accepted = pool
                        .read_lifecycle_receipt(&control.reference, duration)
                        .await?;
                    if let Some(accepted) = accepted {
                        ensure!(
                            accepted.receipt.reference == control.reference
                                && accepted.receipt.request_sha256 == control.intent_sha256,
                            "retained issuer activation intent differs"
                        );
                    } else {
                        let LifecycleAuthorityIdentity::Intent(id) = control.reference.identity
                        else {
                            anyhow::bail!("activation intent reference differs")
                        };
                        let observed = self
                            .database
                            .observe_lifecycle_intent(context.clone(), id)
                            .await?;
                        let signed = self.signer.sign_intent(&observed).await?;
                        let acceptance = kasumi_serving::LifecycleAuthorityRequest::AcceptIntent(
                            Box::new(signed),
                        );
                        ensure!(
                            acceptance.reference() == control.reference
                                && acceptance.digest()? == control.intent_sha256,
                            "fresh issuer observation changed immutable activation identity"
                        );
                        prepared.admit_dispatch().await?;
                        let accepted = pool.execute_lifecycle(&acceptance, duration).await?;
                        ensure!(
                            accepted.receipt.reference == control.reference
                                && accepted.receipt.request_sha256 == control.intent_sha256,
                            "issuer returned another activation acceptance"
                        );
                        observed.release().await?;
                    }
                    prepared.admit_dispatch().await?;
                }
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
                // An unreachable installed voter must not consume the entire
                // current phase before another voter can be tried. The wait
                // covers connection as well as dispatch, while the exact request
                // and its target-owned operation keep their original cap.
                let remaining = prepared.dispatch_remaining().await?;
                let wait = target_route_wait(head, request, duration.min(remaining));
                let acknowledgement = tokio::time::timeout(wait, async {
                    let mut client =
                        KasumiTargetClient::connect(&config, control, trust.clone(), *node_id)
                            .await?;
                    prepared.admit_dispatch().await?;
                    Ok::<_, anyhow::Error>(client.execute(&bearer, &verified, request).await?)
                })
                .await??;
                prepared.release().await?;
                phase.release().await?;
                Ok(RecoveryDispatchOutcome::Target(Box::new(
                    acknowledgement.response().clone(),
                )))
            }
            RecoveryDispatch::PublishRoute(_) => {
                let published = self
                    .database
                    .publish_recovery_route(
                        context.clone(),
                        head.request.operation_id,
                        prepared.record().phase_id,
                    )
                    .await?;
                let outcome = published
                    .record()
                    .outcome
                    .clone()
                    .context("atomic route publication has no retained outcome")?;
                published.release().await?;
                prepared.release().await?;
                Ok(outcome)
            }
            RecoveryDispatch::RetireSource(request) => {
                let source = route
                    .source
                    .as_ref()
                    .context("planned application source is absent")?;
                let custody = route
                    .source_custody
                    .as_ref()
                    .context("planned custody source is absent")?;
                let custody_config = custody.connections()?;
                let custody_bearer = token(&FileCredentialSource::new(&custody.token_file)?)?;
                let verified = dispatch_planned_retirement(
                    || {
                        Ok((
                            source.connections()?,
                            token(&FileCredentialSource::new(&source.token_file)?)?,
                        ))
                    },
                    &custody_config,
                    &custody_bearer,
                    request,
                    duration,
                    async { prepared.admit_dispatch().await.map_err(Into::into) },
                )
                .await?;
                prepared.release().await?;
                Ok(RecoveryDispatchOutcome::SourceRetired(Box::new(
                    verified.receipt().clone(),
                )))
            }
            _ => anyhow::bail!("recovery dispatch phase is not installed"),
        }
    }
}
fn target_route_wait(
    head: &RecoveryRecord,
    request: &TargetRuntimeRequest,
    remaining: Duration,
) -> Duration {
    let established = head.phase == RecoveryPhase::Complete
        && matches!(
            request.step,
            TargetRuntimeStep::Start(
                TargetReplicaInput::Completion(_)
                    | TargetReplicaInput::CompletionAttemptStatus(_)
                    | TargetReplicaInput::CompletionTerminalStatus(_)
                    | TargetReplicaInput::CompletionResolution(_)
                    | TargetReplicaInput::Inspection(_)
            ) | TargetRuntimeStep::PrepareComplete(_)
                | TargetRuntimeStep::Complete(_)
                | TargetRuntimeStep::InspectCompletionAttempt(_)
                | TargetRuntimeStep::InspectCompletionResolution(_)
                | TargetRuntimeStep::ResolveComplete(_)
                | TargetRuntimeStep::Inspect(_)
        );
    if established {
        // RecoveryStart validates exactly three installed voters. Leave time for
        // their routes and the final current-Control response/phase commit.
        remaining / 5
    } else {
        remaining
    }
}

// Exact custody verification is independent of application admission. A failed
// custody read is never proof of absence: only an authenticated application
// status with no original outcome permits the unchanged retirement dispatch.
pub(crate) async fn dispatch_planned_retirement<S, F>(
    source: S,
    custody: &BTreeMap<u64, KasumiClientConfig>,
    custody_bearer: &str,
    request: &RetireSourceRequest,
    duration: Duration,
    admit: F,
) -> Result<kasumi_client::VerifiedRetirementReceipt>
where
    S: FnOnce() -> Result<(
        BTreeMap<u64, KasumiClientConfig>,
        zeroize::Zeroizing<String>,
    )>,
    F: std::future::Future<Output = Result<()>>,
{
    use kasumi_clock::LeaseClock;
    let clock = kasumi_clock::SystemLeaseClock;
    let mut last = clock.now();
    let end = last
        .checked_add(duration)
        .context("retirement deadline overflow")?;
    let mut remaining = || -> Result<Duration> {
        let now = clock.now();
        ensure!(
            now >= last && now < end,
            "retirement deadline elapsed or clock regressed"
        );
        last = now;
        Ok(end - now)
    };
    tokio::time::timeout(duration, async {
        remaining()?;
        let reference = request.reference()?;
        let credential = zeroize::Zeroizing::new(custody_bearer.to_owned());
        let mut custody =
            KasumiRetirementPool::new(custody.clone(), Arc::new(move || Ok(credential.clone())))?;
        let verify = |proof: kasumi_client::VerifiedRetirementReceipt| -> Result<_> {
            ensure!(
                proof.receipt().checkpoint == request.checkpoint
                    && proof.receipt().target_incarnation == request.target_incarnation
                    && proof.receipt().admitted_at_ms <= request.not_after_ms,
                "source custody verification returned a different original retirement"
            );
            Ok(proof)
        };
        if let Ok(proof) = custody
            .verify_retirement_receipt(&reference, remaining()?)
            .await
        {
            remaining()?;
            return verify(proof);
        }
        let (connections, bearer) = source()?;
        remaining()?;
        let mut application =
            KasumiRetirementPool::new(connections, Arc::new(move || Ok(bearer.clone())))?;
        let observed = application
            .retirement_status(&reference, remaining()?)
            .await;
        remaining()?;
        let proof = match observed {
            Ok(None) => {
                admit.await?;
                // Exact original identity and nonrenewed admission survive ambiguity.
                let mutation = application.retire_source(request, remaining()?).await;
                let proof = custody
                    .verify_retirement_receipt(&reference, remaining()?)
                    .await;
                match proof {
                    Ok(proof) => verify(proof),
                    Err(failure) => {
                        mutation?;
                        Err(failure.into())
                    }
                }
            }
            Ok(Some(status)) => {
                ensure!(
                    status.outcome.is_ok(),
                    "original source retirement was permanently rejected"
                );
                verify(
                    custody
                        .verify_retirement_receipt(&reference, remaining()?)
                        .await?,
                )
            }
            Err(original) => {
                // An unsuccessful read never authorizes another source effect.
                match custody
                    .verify_retirement_receipt(&reference, remaining()?)
                    .await
                {
                    Ok(proof) => verify(proof),
                    Err(_) => Err(original.into()),
                }
            }
        }?;
        remaining()?;
        Ok(proof)
    })
    .await?
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
