//! Closed activation consumes the exact committed control identity in the same
//! ordering as epoch stops and incarnation changes. Receipt recovery does not
//! issue a new grant or re-run an expired effect.
use super::*;
use kasumi_types::LifecyclePhase;

fn binding(
    command: &AuthorityCommand,
    admitted_at_ms: u64,
    receipt: &LifecycleAuthorityReceipt,
) -> Result<()> {
    let AuthorityAction::ActivateCommitted {
        fence_id,
        fence_digest,
        target,
        control,
    } = &command.action
    else {
        anyhow::bail!("committed activation required")
    };
    let LifecycleAuthorityRequest::AcceptIntent(signed) = &receipt.request else {
        anyhow::bail!("activation identity is not an accepted intent")
    };
    let intent = &signed.observation.intent;
    let request = &intent.request;
    let completion = &control.completion.observation.fact;
    completion
        .origin
        .accepts_phase(intent, LifecyclePhase::Activate)?;
    kasumi_serving::verify_target_completion(&completion.origin, &control.completion)?;
    ensure!(
        completion.admitted_at_ms <= admitted_at_ms,
        "activation predates actual completed target"
    );
    ensure!(
        receipt.reference == control.reference
            && receipt.request_sha256 == control.intent_sha256
            && request.phase == LifecyclePhase::Activate
            && request.tenant == command.tenant
            && request.target_incarnation == target.incarnation
            && request.source_incarnation.to_string() == target.checkpoint.source_incarnation
            && request.checkpoint == target.checkpoint
            && same_nodes(&target.nodes, &request.target_nodes)
            && request.phase_input_sha256
                == ActivateTargetInput {
                    completion_sha256: completion.digest()?,
                    fence_id: *fence_id,
                    fence_digest: fence_digest.clone(),
                    target: target.clone(),
                }
                .digest()?
            && admitted_at_ms >= intent.accepted_at_ms
            && admitted_at_ms < intent.original_credential_expires_at_ms,
        "activation differs from exact original committed authority"
    );
    Ok(())
}
fn same_nodes(
    nodes: &BTreeSet<NodeIdentity>,
    expected: &BTreeMap<u64, kasumi_types::LifecycleNode>,
) -> bool {
    nodes.len() == expected.len()
        && nodes.iter().all(|n| {
            expected.get(&n.node_id).is_some_and(|e| {
                e.node_id == n.node_id
                    && e.principal == n.principal
                    && e.certificate_sha256 == n.certificate_sha256
            })
        })
}
impl Backend {
    pub(super) fn validate_activation_control(
        &self,
        command: &AuthorityCommand,
        admitted_at_ms: u64,
    ) -> Result<()> {
        match &command.action {
            AuthorityAction::Activate { .. } => ensure!(
                self.installation.manifest.lifecycle_controls.is_empty(),
                "raw activation disabled by installed Control roots"
            ),
            AuthorityAction::ActivateCommitted { control, .. } => {
                let receipt = self
                    .lifecycle_receipt(&control.reference)?
                    .context("activation intent not accepted")?;
                ensure!(
                    self.lifecycle_receipt(&control.reference.epoch_stop())?
                        .is_none(),
                    "activation control epoch is stopped"
                );
                binding(command, admitted_at_ms, &receipt)?;
                ensure!(
                    control
                        .completion
                        .observation
                        .fact
                        .origin
                        .authority_manifest_sha256
                        == self.installation.manifest.digest()?,
                    "target completion issuer differs"
                );
                let AuthorityAction::ActivateCommitted { target, .. } = &command.action else {
                    unreachable!()
                };
                let Some(Record::Preparation(prepared)) =
                    self.record(&key_preparation(&command.tenant, target.incarnation))?
                else {
                    anyhow::bail!("committed activation target preparation missing")
                };
                ensure!(
                    prepared.target == *target,
                    "committed activation target preparation differs"
                );
                let LifecycleAuthorityRequest::AcceptIntent(signed) = &receipt.request else {
                    unreachable!()
                };
                let source = self
                    .tenant_record(&command.tenant)?
                    .context("activation source missing")?;
                ensure!(
                    source.incarnation == signed.observation.intent.request.source_incarnation
                        && source.authority_epoch
                            == signed.observation.intent.request.source_authority_epoch,
                    "committed activation source epoch differs"
                );
            }
            _ => anyhow::bail!("not an activation command"),
        }
        Ok(())
    }
    pub(super) fn validate_activation_snapshot(&self, snapshot: &Snapshot) -> Result<()> {
        for record in snapshot.records.values() {
            let Record::Receipt(accepted) = record else {
                continue;
            };
            if !matches!(accepted.outcome, AuthorityOutcome::Activated { .. }) {
                continue;
            }
            match &accepted.command.action {
                AuthorityAction::Activate { .. } => ensure!(
                    self.installation.manifest.lifecycle_controls.is_empty(),
                    "snapshot raw activation bypasses installed Control"
                ),
                AuthorityAction::ActivateCommitted { control, .. } => {
                    let Some(Record::Lifecycle(intent)) =
                        snapshot.records.get(&control.reference.key()?)
                    else {
                        anyhow::bail!("snapshot committed activation intent missing")
                    };
                    binding(&accepted.command, accepted.admitted_at_ms, intent)?;
                    ensure!(
                        control
                            .completion
                            .observation
                            .fact
                            .origin
                            .authority_manifest_sha256
                            == self.installation.manifest.digest()?,
                        "snapshot target completion issuer differs"
                    );
                    let LifecycleAuthorityRequest::AcceptIntent(signed) = &intent.request else {
                        unreachable!()
                    };
                    ensure!(
                        matches!(accepted.outcome,AuthorityOutcome::Activated{authority_epoch,..} if Some(authority_epoch)==signed.observation.intent.request.source_authority_epoch.checked_add(1)),
                        "snapshot committed activation epoch differs"
                    );
                    ensure!(
                        intent.accepted_revision < accepted.revision,
                        "snapshot activation predates its intent"
                    );
                    if let Some(Record::Lifecycle(stop)) =
                        snapshot.records.get(&control.reference.epoch_stop().key()?)
                    {
                        ensure!(
                            stop.accepted_revision > accepted.revision,
                            "snapshot activation follows stopped epoch"
                        );
                    }
                }
                _ => anyhow::bail!("snapshot activation command differs"),
            }
        }
        Ok(())
    }
}
