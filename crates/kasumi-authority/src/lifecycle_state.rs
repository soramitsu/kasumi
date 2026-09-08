//! Permanent compact control commitments share the issuer's ordered storage.
//! Fresh invocation assertions are not part of the permanent command identity.
use super::*;
use kasumi_types::{
    ControlAuthorityPartition, ControlIntentCommitment, ControlSigningRoot, LifecyclePhase,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PreparedLifecycle {
    pub context: RequestContext,
    pub request: LifecycleAuthorityRequest,
    pub admitted_at_ms: u64,
    pub authority_term: u64,
    pub expected_policy_epoch: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ControlEpochRecord {
    reference: LifecycleAuthorityReference,
    root: ControlSigningRoot,
    partition: ControlAuthorityPartition,
    installation_sha256: String,
    installation_generation: u64,
    partition_set_sha256: String,
    first_intent: LifecycleAuthorityReference,
}
impl ControlEpochRecord {
    fn from_intent(
        reference: &LifecycleAuthorityReference,
        commitment: &ControlIntentCommitment,
    ) -> Self {
        Self {
            reference: reference.epoch_stop(),
            root: commitment.root.clone(),
            partition: commitment.authority_partition.clone(),
            installation_sha256: commitment.intent.request.installation_sha256.clone(),
            installation_generation: commitment.intent.installation_generation,
            partition_set_sha256: commitment.partition_set_sha256.clone(),
            first_intent: reference.clone(),
        }
    }
    fn matches_stop(&self, stop: &kasumi_types::ControlEpochStop) -> bool {
        self.reference.control_incarnation == stop.control_incarnation
            && self.reference.control_policy_epoch == stop.control_policy_epoch
            && self.partition == stop.authority_partition
            && self.installation_sha256 == stop.installation_sha256
            && self.installation_generation == stop.installation_generation
            && self.partition_set_sha256 == stop.partition_set_sha256
    }
}
pub(crate) struct LifecycleLeaseMaterial {
    pub commitment: ControlIntentCommitment,
    pub revision: u64,
    pub target_drain: Option<String>,
    pub application_purpose: Option<LeasePurpose>,
}
impl Backend {
    pub fn lifecycle_receipt(
        &self,
        reference: &LifecycleAuthorityReference,
    ) -> Result<Option<LifecycleAuthorityReceipt>> {
        match self.record(&reference.key()?)? {
            Some(Record::Lifecycle(value)) => Ok(Some(*value)),
            None => Ok(None),
            _ => anyhow::bail!("lifecycle record type differs"),
        }
    }
    pub(super) fn reduce_lifecycle(
        &self,
        position: &AppliedEntryContext,
        prepared: PreparedLifecycle,
    ) -> Result<kasumi_types::Result<LifecycleAuthorityReceipt>> {
        let mut meta = self.meta()?;
        if let Err(error) = prepared
            .context
            .authorization
            .check_admitted_at(prepared.admitted_at_ms)
            .and_then(|()| self.authorize(&meta, &prepared.context).map(|_| ()))
        {
            return Ok(Err(error));
        }
        if prepared.authority_term != position.log_id.leader_id.term
            || prepared.expected_policy_epoch != meta.policy_epoch
        {
            return Ok(Err(conflict(
                "lifecycle issuer admission term or policy changed",
            )));
        }
        if self
            .installation
            .manifest
            .verify_lifecycle_request(self.installation.partition, &prepared.request)
            .is_err()
        {
            return Ok(Err(Error::new(
                ErrorCode::Forbidden,
                "installed current control signature required",
            )));
        }
        let reference = prepared.request.reference();
        let request_sha256 = prepared.request.digest()?;
        if let Some(retained) = self.lifecycle_receipt(&reference)? {
            return Ok(if retained.request_sha256 == request_sha256 {
                Ok(retained)
            } else {
                Err(conflict("permanent control issuer identity differs"))
            });
        }
        let mut writes = Vec::new();
        match &prepared.request {
            LifecycleAuthorityRequest::AcceptIntent(signed) => {
                if prepared.admitted_at_ms
                    >= signed.observation.intent.original_credential_expires_at_ms
                {
                    return Ok(Err(Error::new(
                        ErrorCode::Unauthorized,
                        "original committed control credential expired",
                    )));
                }
                if self.lifecycle_receipt(&reference.epoch_stop())?.is_some() {
                    return Ok(Err(conflict("control epoch permanently stopped")));
                }
                let candidate = ControlEpochRecord::from_intent(&reference, &signed.observation);
                match self.record(&reference.epoch_key()?)? {
                    Some(Record::ControlEpoch(existing)) => {
                        let expected = ControlEpochRecord {
                            first_intent: existing.first_intent.clone(),
                            ..candidate
                        };
                        if existing != expected {
                            return Ok(Err(conflict("control epoch installation changed")));
                        }
                    }
                    None => {
                        let bytes = serde_json::to_vec(&Record::ControlEpoch(candidate))?;
                        add_count(&mut meta.state_bytes, u64::try_from(bytes.len())?)?;
                        add_count(&mut meta.lifecycle_epochs, 1)?;
                        add_count(&mut meta.open_control_epochs, 1)?;
                        writes.push(WriteOp::put(NS, reference.epoch_key()?.as_bytes(), bytes));
                    }
                    _ => anyhow::bail!("control epoch anchor type differs"),
                }
            }
            LifecycleAuthorityRequest::StopEpoch(signed) => {
                match self.record(&reference.epoch_key()?)? {
                    Some(Record::ControlEpoch(epoch)) => {
                        if !epoch.matches_stop(&signed.observation.stop) {
                            return Ok(Err(conflict(
                                "stop does not match original exhaustive installation",
                            )));
                        }
                        meta.open_control_epochs = meta
                            .open_control_epochs
                            .checked_sub(1)
                            .context("control stop reservation underflow")?;
                    }
                    None => {}
                    _ => anyhow::bail!("control epoch anchor type differs"),
                }
            }
        }
        let receipt = LifecycleAuthorityReceipt {
            authority_id: self.installation.manifest.authority_id,
            authority_manifest_sha256: self.installation.manifest.digest()?,
            partition: self.installation.partition,
            reference: reference.clone(),
            request: prepared.request,
            request_sha256,
            original_principal: prepared.context.principal,
            accepted_revision: position.log_id.index,
            accepted_term: position.log_id.leader_id.term,
        };
        let bytes = serde_json::to_vec(&Record::Lifecycle(Box::new(receipt.clone())))?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Ok(Err(Error::new(
                ErrorCode::ResourceExhausted,
                "lifecycle receipt exceeds hard bound",
            )));
        }
        add_count(&mut meta.lifecycle_receipts, 1)?;
        add_count(&mut meta.state_bytes, u64::try_from(bytes.len())?)?;
        if meta
            .state_bytes
            .saturating_add(Self::completion_reserve(&meta))
            > meta
                .operational
                .capacity
                .max_state_bytes
                .saturating_sub(meta.operational.capacity.maintenance_reserve_bytes)
        {
            return Ok(Err(Error::new(
                ErrorCode::ResourceExhausted,
                "permanent control commitment and stop reservation quota exhausted",
            )));
        }
        writes.push(WriteOp::put(NS, reference.key()?.as_bytes(), bytes));
        meta.revision = position.log_id.index;
        writes.push(WriteOp::put(NS, META, serde_json::to_vec(&meta)?));
        self.store.write_batch(&writes)?;
        Ok(Ok(receipt))
    }
    pub fn lifecycle_lease_view(
        &self,
        request: &LifecycleLeaseRequest,
    ) -> Result<LifecycleLeaseMaterial> {
        let _lock = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("authority state poisoned"))?;
        request.validate()?;
        ensure!(
            request.authority_manifest_sha256 == self.installation.manifest.digest()?,
            "lifecycle lease installation differs"
        );
        let receipt = self
            .lifecycle_receipt(&request.reference)?
            .context("control intent not accepted")?;
        ensure!(
            receipt.request_sha256 == request.intent_sha256
                && self
                    .lifecycle_receipt(&request.reference.epoch_stop())?
                    .is_none(),
            "control intent differs or epoch stopped"
        );
        let LifecycleAuthorityRequest::AcceptIntent(signed) = receipt.request else {
            anyhow::bail!("lifecycle identity is not an intent")
        };
        let commitment = signed.observation;
        let i = &commitment.intent.request;
        let expected = i
            .target_nodes
            .get(&request.target_node.node_id)
            .context("target node not approved")?;
        ensure!(
            expected.principal == request.target_node.principal
                && expected.certificate_sha256 == request.target_node.certificate_sha256,
            "target credential differs"
        );
        let stop = self.record(&key_target_stop(&i.tenant, i.target_incarnation))?;
        let (target_drain, application_purpose) = if i.phase == LifecyclePhase::StopLocal {
            let Some(Record::TargetStop(stop)) = stop else {
                anyhow::bail!("local cleanup requires permanent incarnation stop")
            };
            let AuthorityOutcome::TargetStopped {
                source_incarnation,
                source_epoch,
                target,
            } = &stop.outcome
            else {
                anyhow::bail!("target stop outcome differs")
            };
            ensure!(
                *source_incarnation == i.source_incarnation
                    && *source_epoch == i.source_authority_epoch
                    && target.incarnation == i.target_incarnation
                    && target.checkpoint == i.checkpoint
                    && same_nodes(&target.nodes, &i.target_nodes),
                "local stop binding differs"
            );
            (Some(stop.digest()?), None)
        } else {
            ensure!(stop.is_none(), "target incarnation permanently stopped");
            let tenant = self
                .tenant_record(&i.tenant)?
                .context("source not enrolled")?;
            let prepared = match self.record(&key_preparation(&i.tenant, i.target_incarnation))? {
                Some(Record::Preparation(p)) => p,
                _ => anyhow::bail!("target is not independently prepared"),
            };
            ensure!(
                prepared.source_incarnation == i.source_incarnation
                    && prepared.source_epoch == i.source_authority_epoch
                    && prepared.target.checkpoint == i.checkpoint
                    && same_nodes(&prepared.target.nodes, &i.target_nodes),
                "prepared target differs from committed intent"
            );
            // Activation retry can observe the exact winning target; other phases
            // cannot re-materialize it under a newly issued grant.
            let source = tenant.incarnation == i.source_incarnation
                && tenant.authority_epoch == i.source_authority_epoch;
            let activated = matches!(
                i.phase,
                LifecyclePhase::Activate | LifecyclePhase::InspectTarget
            ) && tenant.incarnation == i.target_incarnation
                && tenant.authority_epoch == i.source_authority_epoch + 1
                && tenant.recovery_checkpoint.as_ref() == Some(&i.checkpoint);
            ensure!(source || activated, "current source epoch differs");
            ensure!(
                i.phase != LifecyclePhase::Activate || activated,
                "activation needs the actual independently activated incarnation"
            );
            (
                None,
                Some(if activated {
                    LeasePurpose::Serving
                } else {
                    LeasePurpose::RestorePreparation
                }),
            )
        };
        Ok(LifecycleLeaseMaterial {
            commitment,
            revision: self.meta()?.revision,
            target_drain,
            application_purpose,
        })
    }
    pub(super) fn validate_lifecycle_snapshot(&self, snapshot: &Snapshot) -> Result<()> {
        let (mut receipts, mut epochs, mut open) = (0, 0, 0);
        snapshot.records.visit(|key, record| {
            match record {
                Record::Lifecycle(receipt) => {
                    add_count(&mut receipts, 1)?;
                    receipt.validate(&self.installation.manifest, self.installation.partition)?;
                    ensure!(
                        key == receipt.reference.key()?
                            && receipt.accepted_revision <= snapshot.meta.revision,
                        "control receipt snapshot position differs"
                    );
                    match &receipt.request {
                        LifecycleAuthorityRequest::AcceptIntent(signed) => {
                            let Some(Record::ControlEpoch(epoch)) =
                                snapshot.records.get(&receipt.reference.epoch_key()?)?
                            else {
                                anyhow::bail!("control epoch anchor missing")
                            };
                            let expected = ControlEpochRecord {
                                first_intent: epoch.first_intent.clone(),
                                ..ControlEpochRecord::from_intent(
                                    &receipt.reference,
                                    &signed.observation,
                                )
                            };
                            ensure!(
                                epoch == expected,
                                "control intent snapshot installation differs"
                            );
                        }
                        LifecycleAuthorityRequest::StopEpoch(signed) => {
                            if let Some(Record::ControlEpoch(epoch)) =
                                snapshot.records.get(&receipt.reference.epoch_key()?)?
                            {
                                ensure!(
                                    epoch.matches_stop(&signed.observation.stop),
                                    "control stop snapshot installation differs"
                                );
                            }
                        }
                    }
                }
                Record::ControlEpoch(epoch) => {
                    add_count(&mut epochs, 1)?;
                    ensure!(
                        key == epoch.reference.epoch_key()?
                            && epoch.reference == epoch.first_intent.epoch_stop(),
                        "control anchor identity differs"
                    );
                    let Some(Record::Lifecycle(first)) =
                        snapshot.records.get(&epoch.first_intent.key()?)?
                    else {
                        anyhow::bail!("first control intent missing")
                    };
                    ensure!(
                        matches!(first.request, LifecycleAuthorityRequest::AcceptIntent(_)),
                        "control anchor is not an intent"
                    );
                    if !snapshot.records.contains_key(&epoch.reference.key()?)? {
                        add_count(&mut open, 1)?;
                    }
                }
                _ => {}
            }
            Ok(())
        })?;
        ensure!(
            (receipts, epochs, open)
                == (
                    snapshot.meta.lifecycle_receipts,
                    snapshot.meta.lifecycle_epochs,
                    snapshot.meta.open_control_epochs
                ),
            "control snapshot accounting differs"
        );
        Ok(())
    }
    pub(super) fn validate_lifecycle_history(&self, snapshot: &Snapshot) -> Result<()> {
        self.store.visit(NS, MAX_RECORD_BYTES, |key, bytes| {
            if key.starts_with(b"lc/") {
                let name = std::str::from_utf8(key)?;
                ensure!(
                    snapshot
                        .records
                        .get(name)?
                        .as_ref()
                        .map(serde_json::to_vec)
                        .transpose()?
                        .as_deref()
                        == Some(bytes),
                    "permanent control history cannot be removed or substituted"
                );
            }
            Ok(())
        })
    }
}
fn same_nodes(
    nodes: &BTreeSet<NodeIdentity>,
    expected: &BTreeMap<u64, kasumi_types::LifecycleNode>,
) -> bool {
    nodes.len() == expected.len()
        && nodes.iter().all(|node| {
            expected.get(&node.node_id).is_some_and(|n| {
                n.principal == node.principal && n.certificate_sha256 == node.certificate_sha256
            })
        })
}
