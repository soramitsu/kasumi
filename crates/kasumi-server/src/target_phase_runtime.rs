//! Concrete installed Control and issuer channels. No caller-supplied signed DTO
//! can stand in for the current Control quorum observation used here.
use crate::{
    runtime::{parse_certificate_pin, read_bounded},
    serving_runtime::{CredentialSource, RuntimeLease, ServingAuthorityConfig},
};
use anyhow::{Context, Result, ensure};
use kasumi_client::{KasumiAuthorityPool, KasumiClientConfig, KasumiLifecycleClient};
use kasumi_engine::{
    TargetLifecycleInvocation, TargetOperation, TargetOperationScope, TargetRequestAdmission,
};
use kasumi_serving::{
    AuthorityTrust, ControlTrust, LifecycleBoot, LifecycleGate, NodeIdentity, VerifiedControlIntent,
};
use kasumi_types::{Action, LifecyclePhase, RequestContext};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::Mutex as AsyncMutex;
use uuid::Uuid;
use zeroize::Zeroizing;

pub(crate) struct RuntimeTargetPhase {
    scope: Arc<TargetOperationScope>,
    serving: Option<Arc<RuntimeLease>>,
    control: AsyncMutex<KasumiLifecycleClient>,
    original: VerifiedControlIntent,
    control_bearer: Zeroizing<String>,
    authority: AsyncMutex<KasumiAuthorityPool>,
    authority_admin: AsyncMutex<KasumiAuthorityPool>,
    boot: LifecycleBoot,
    renewal: Mutex<Option<tokio::task::JoinHandle<()>>>,
}
impl Drop for RuntimeTargetPhase {
    fn drop(&mut self) {
        self.scope.close();
        if let Ok(handle) = self.renewal.get_mut()
            && let Some(handle) = handle.take()
        {
            handle.abort();
        }
    }
}
impl RuntimeTargetPhase {
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn acquire(
        configured: &super::target_runtime_config::TargetRecoveryConfig,
        authority: &ServingAuthorityConfig,
        credential: CredentialSource,
        node_id: u64,
        original_context: RequestContext,
        original_bearer: Zeroizing<String>,
        command_id: Uuid,
        admission: &TargetRequestAdmission,
    ) -> Result<Arc<Self>> {
        admission.require_context(&original_context)?;
        original_context.authorization.check_live()?;
        original_context
            .authorization
            .require_control(&configured.control_root.control_incarnation.to_string())?;
        ensure!(
            original_context.tenant == "__kasumi_control"
                && original_context.scopes.contains(&Action::Admin),
            "current installed Control Admin required"
        );
        authority.validate()?;
        let control_connection = configured.control_connection()?;
        let trust = ControlTrust::install(configured.control_root.clone())?;
        let mut control = admission
            .run(async {
                Ok(tokio::time::timeout(
                    Duration::from_secs(5),
                    KasumiLifecycleClient::connect(&control_connection, trust),
                )
                .await??)
            })
            .await?;
        let original = admission
            .run(async { Ok(control.observe_intent(&original_bearer, command_id).await?) })
            .await?;
        let intent = &original.observation().intent;
        ensure!(
            intent.original_principal == original_context.principal,
            "current invocation differs from original phase actor"
        );
        let partition = authority.manifest.partition(&intent.request.tenant)?;
        ensure!(
            authority.manifest.control_partition(partition)?
                == original.observation().authority_partition
                && authority
                    .manifest
                    .lifecycle_controls
                    .get(&intent.control_incarnation)
                    == Some(&configured.control_root.public_key),
            "phase belongs to another installed issuer"
        );
        let endpoints = &authority.endpoints[&partition];
        let tls = authority.tls.load()?;
        let node = NodeIdentity {
            node_id,
            principal: authority.principal.clone(),
            certificate_sha256: hex::encode(tls.certificate_pin()),
        };
        let committed_node = intent
            .request
            .target_nodes
            .get(&node_id)
            .context("target node not approved")?;
        ensure!(
            configured.node == node
                && committed_node.principal == node.principal
                && committed_node.certificate_sha256 == node.certificate_sha256,
            "actual target TLS identity differs from committed placement"
        );
        let connections = endpoints
            .iter()
            .map(|(id, endpoint)| {
                Ok((
                    *id,
                    KasumiClientConfig {
                        endpoint: endpoint.endpoint.clone(),
                        identity: tls.clone(),
                        trusted_ca_pem: read_bounded(&authority.server_ca, 1 << 20)?,
                        server_certificate_pins: endpoint
                            .certificate_pins
                            .iter()
                            .map(|p| parse_certificate_pin(p))
                            .collect::<Result<_>>()?,
                    },
                ))
            })
            .collect::<Result<_>>()?;
        let trust = AuthorityTrust::install(authority.manifest.clone())?;
        let path = authority.bearer_file.clone();
        let source = credential.clone();
        let mut issuer =
            KasumiAuthorityPool::new(connections, trust.clone(), Arc::new(move || source(&path)))?;
        let accepted = kasumi_serving::LifecycleAuthorityRequest::AcceptIntent(Box::new(
            original.signed().clone(),
        ));
        let admin_env = configured
            .issuer_admin_bearer_file
            .get(&authority.manifest.authority_id)
            .context("installed issuer control-admission credential missing")?;
        let path = admin_env.clone();
        let source = credential.clone();
        let mut issuer_admin = issuer
            .clone()
            .with_credential(Arc::new(move || source(&path)));
        admission
            .run(async {
                Ok(issuer_admin
                    .execute_lifecycle(&accepted, Duration::from_secs(5))
                    .await?)
            })
            .await?;
        let boot = LifecycleBoot::new(trust, node)?;
        // Anchored before credential acquisition and dispatch; retries construct
        // distinct attempts, never reset the deadline of an earlier response.
        let attempt = boot.begin(&original)?;
        let lease = admission
            .run(async {
                Ok(issuer
                    .acquire_lifecycle(
                        &attempt,
                        Duration::from_millis(authority.manifest.max_lease_ms.min(5000)),
                    )
                    .await?)
            })
            .await?;
        let purpose = lease.signed().claims.application_purpose;
        let gate = LifecycleGate::new(original_context, lease)?;
        let scope = TargetOperationScope::new(TargetLifecycleInvocation::from_verified(gate)?)?;
        let serving = if intent.request.phase == LifecyclePhase::StopLocal {
            None
        } else {
            let purpose = purpose.context("issuer phase has no application role")?;
            Some(
                admission
                    .run(RuntimeLease::acquire(
                        authority,
                        credential.clone(),
                        &intent.request.tenant,
                        intent.request.target_incarnation,
                        node_id,
                        purpose,
                    ))
                    .await?,
            )
        };
        let runtime = Arc::new(Self {
            scope,
            serving,
            control: AsyncMutex::new(control),
            original,
            control_bearer: original_bearer,
            authority: AsyncMutex::new(issuer),
            boot,
            authority_admin: AsyncMutex::new(issuer_admin),
            renewal: Mutex::new(None),
        });
        admission.run(runtime.check_current()).await?;
        let weak = Arc::downgrade(&runtime);
        let worker = tokio::spawn(async move {
            let mut failed = false;
            loop {
                let delay = {
                    let Some(runtime) = weak.upgrade() else { break };
                    let Ok(remaining) = runtime.scope.invocation().gate().remaining() else {
                        break;
                    };
                    if failed {
                        (remaining / 4).min(Duration::from_millis(100))
                    } else {
                        remaining / 3
                    }
                };
                tokio::time::sleep(delay).await;
                let Some(runtime) = weak.upgrade() else { break };
                let Ok(remaining) = runtime.scope.invocation().gate().remaining() else {
                    runtime.scope.close();
                    break;
                };
                failed = !matches!(
                    tokio::time::timeout(remaining, runtime.renew()).await,
                    Ok(Ok(()))
                );
                if runtime.scope.invocation().check().is_err() {
                    runtime.scope.close();
                    break;
                }
            }
        });
        *runtime
            .renewal
            .lock()
            .map_err(|_| anyhow::anyhow!("target renewal poisoned"))? = Some(worker);
        admission.check()?;
        Ok(runtime)
    }
    pub(crate) fn scope(&self) -> &Arc<TargetOperationScope> {
        &self.scope
    }
    pub(crate) fn original(&self) -> &VerifiedControlIntent {
        &self.original
    }
    pub(crate) fn access(&self) -> Result<kasumi_store::StorageAccess> {
        self.scope.invocation().check()?;
        kasumi_store::StorageAccess::target_phase(
            self.serving
                .as_ref()
                .context("cleanup cannot open target payload")?
                .gate()
                .clone(),
            self.scope.invocation().gate().clone(),
        )
    }
    /// This live check uses the exact installed Control route and original
    /// credential, not a historical signature or a renewable node lease alone.
    pub(crate) async fn check_current(&self) -> Result<()> {
        self.scope.invocation().check()?;
        let mut control = self.control.lock().await;
        let fresh = control
            .observe_intent(
                &self.control_bearer,
                self.original.observation().intent.request.command_id,
            )
            .await?;
        ensure!(
            fresh.observation().intent == self.original.observation().intent
                && fresh.observation().root == self.original.observation().root
                && fresh.observation().authority_partition
                    == self.original.observation().authority_partition,
            "current Control phase differs"
        );
        self.scope.invocation().check()?;
        Ok(())
    }
    pub(crate) async fn check_request(
        &self,
        admission: &TargetRequestAdmission,
        context: &RequestContext,
        bearer: &str,
    ) -> Result<()> {
        admission.require_context(context)?;
        context.authorization.require_control(
            &self
                .original
                .observation()
                .root
                .control_incarnation
                .to_string(),
        )?;
        ensure!(
            context.principal == self.original.observation().intent.original_principal
                && context.tenant == "__kasumi_control"
                && context.scopes.contains(&Action::Admin),
            "current request actor or resource differs"
        );
        admission.run(self.check_current()).await?;
        admission.run(self.observe_with(bearer)).await?;
        admission.check()?;
        Ok(())
    }
    pub(crate) async fn check_operation(
        &self,
        operation: &TargetOperation,
        bearer: &str,
    ) -> Result<()> {
        operation.check()?;
        ensure!(
            Arc::ptr_eq(
                operation.invocation().gate(),
                self.scope.invocation().gate()
            ),
            "operation belongs to another target phase"
        );
        operation.run(self.check_current()).await?;
        operation.run(self.observe_with(bearer)).await?;
        operation.check()
    }
    async fn observe_with(&self, bearer: &str) -> Result<()> {
        let mut control = self.control.lock().await;
        let fresh = control
            .observe_intent(
                bearer,
                self.original.observation().intent.request.command_id,
            )
            .await?;
        ensure!(
            fresh.observation().intent == self.original.observation().intent
                && fresh.observation().root == self.original.observation().root
                && fresh.observation().authority_partition
                    == self.original.observation().authority_partition,
            "fresh request Control observation differs"
        );
        Ok(())
    }
    pub(crate) async fn activation_receipt(
        &self,
        id: Uuid,
    ) -> Result<kasumi_serving::SignedAuthorityReceipt> {
        self.scope.invocation().check()?;
        let mut issuer = self.authority_admin.lock().await;
        let signed = issuer
            .receipt(
                &self.original.observation().intent.request.tenant,
                id,
                Duration::from_secs(5),
            )
            .await?
            .context("issuer activation outcome not retained")?;
        self.scope
            .invocation()
            .gate()
            .current()?
            .authority()
            .verify_activation(signed.clone())?;
        self.scope.invocation().check()?;
        Ok(signed)
    }
    pub(crate) async fn target_stop(
        &self,
        operation: &TargetOperation,
        reference: &kasumi_serving::TargetStopReference,
    ) -> Result<kasumi_serving::VerifiedTargetStop> {
        operation.check()?;
        let proof = operation
            .run(async {
                let mut issuer = self.authority_admin.lock().await;
                Ok(issuer
                    .verify_target_stop(reference, Duration::from_secs(5))
                    .await?)
            })
            .await?;
        operation.check()?;
        Ok(proof)
    }
    async fn renew(&self) -> Result<()> {
        self.check_current().await?;
        let mut issuer = self.authority.lock().await;
        let attempt = self.boot.begin(&self.original)?;
        let lease = issuer
            .acquire_lifecycle(
                &attempt,
                self.scope
                    .invocation()
                    .gate()
                    .remaining()?
                    .min(Duration::from_secs(5)),
            )
            .await?;
        self.scope.invocation().gate().renew(lease)?;
        Ok(())
    }
}
