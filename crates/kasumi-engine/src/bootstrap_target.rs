//! The actual verified full-backup path under a closed target phase. No source
//! data credential is synthesized and no source data quorum is consulted here.
use super::*;
use crate::TargetOperation;

/// Explicit target materialization configuration. Raft configuration belongs to
/// the later owned startup phase, never this backup publication operation.
pub struct TargetMaterializationConfig {
    pub node_id: u64,
    pub incarnation: uuid::Uuid,
    pub voters: BTreeMap<u64, ReplicaPlacement>,
    pub admission: Arc<crate::admission::NodeAdmission>,
}
pub struct MaterializedTargetReplica {
    pub stores: Arc<TenantStorageSet>,
    pub bootstrap: ReplicatedBootstrap,
    pub proof: VerifiedTargetMaterialization,
}
/// Private construction follows actual complete backup verification, durable
/// publication and readback under the same original registered invocation.
pub struct VerifiedTargetMaterialization {
    stores: Arc<TenantStorageSet>,
    fact: TargetMaterializationFact,
    admission: Arc<crate::admission::NodeAdmission>,
    release: crate::target_invocation::TargetReleaseFence,
}
impl VerifiedTargetMaterialization {
    pub fn fact(&self) -> &TargetMaterializationFact {
        &self.fact
    }
    pub async fn release(&self, operation: &TargetOperation) -> anyhow::Result<()> {
        self.release.check(operation)?;
        operation
            .invocation()
            .check_target(self.stores.application(), LifecyclePhase::Materialize)?;
        let stores = self.stores.clone();
        let expected = self.fact.bootstrap_sha256.clone();
        let reservation = Arc::new(self.admission.reserve(
            (CHUNK * 3 + 64 * 1024) as u64,
            Some(operation.token.clone()),
        )?);
        operation
            .run(async {
                operation
                    .deadline
                    .blocking(reservation, Some(operation.work.clone()), move || {
                        verify_persisted_digest(&stores, &expected)
                    })
                    .await
            })
            .await?;
        self.release.check(operation)
    }
}
fn verify_persisted_digest(stores: &TenantStorageSet, expected: &str) -> anyhow::Result<()> {
    stores.check_access()?;
    let encoded = stores
        .application()
        .get_bounded(NS, b"manifest", 64 << 10)?
        .ok_or_else(|| anyhow::anyhow!("target bootstrap absent"))?;
    let manifest: Manifest = serde_json::from_slice(&encoded)?;
    anyhow::ensure!(
        manifest.format == 2
            && manifest.bytes > 0
            && manifest.chunks == manifest.bytes.div_ceil(CHUNK as u64)
            && manifest.digest == expected,
        "target bootstrap manifest differs"
    );
    let mut digest = Sha256::new();
    let mut read = 0;
    for index in 0..manifest.chunks {
        let bytes = stores
            .application()
            .get_bounded(NS, &index.to_be_bytes(), CHUNK)?
            .ok_or_else(|| anyhow::anyhow!("target bootstrap chunk absent"))?;
        anyhow::ensure!(
            bytes.len() as u64 == (manifest.bytes - read).min(CHUNK as u64),
            "target bootstrap chunk length differs"
        );
        read += bytes.len() as u64;
        digest.update(&bytes);
        stores.check_access()?;
    }
    anyhow::ensure!(
        read == manifest.bytes && hex::encode(digest.finalize()) == expected,
        "target durable bootstrap digest differs"
    );
    anyhow::ensure!(
        stores
            .custody()
            .store()
            .get_bounded("raft.meta", b"application_bootstrap_sha256", 256)?
            .as_deref()
            == Some(serde_json::to_vec(expected)?.as_slice()),
        "target custody bootstrap binding differs"
    );
    stores.check_access()
}
#[allow(clippy::too_many_arguments)]
pub async fn materialize_target_replica(
    operation: &TargetOperation,
    source: &RestoreSource,
    targets: Arc<TenantStorageSet>,
    input: TargetMaterializationInput,
    replica: TargetMaterializationConfig,
    security_audit: Arc<SecurityAudit>,
) -> anyhow::Result<MaterializedTargetReplica> {
    security_audit.require_admission(&replica.admission)?;
    operation.check()?;
    let target = targets.application().clone();
    operation
        .invocation()
        .check_target(&target, LifecyclePhase::Materialize)?;
    let lease = operation.invocation().gate().current()?;
    input.validate(&lease.commitment().intent)?;
    anyhow::ensure!(
        operation.timeout_ms <= source.timeout_ms
            && source.destination_alias == input.destination_alias
            && replica.incarnation == input.target_incarnation
            && replica.node_id == lease.signed().claims.request.target_node.node_id,
        "installed materialization route or original timeout differs"
    );
    let voters: BTreeMap<_, _> = input
        .voters
        .iter()
        .map(|(id, p)| {
            (
                *id,
                ReplicaPlacement {
                    address: p.endpoint.clone(),
                    failure_domain: p.failure_domain.clone(),
                },
            )
        })
        .collect();
    anyhow::ensure!(
        serde_json::to_vec(&replica.voters)? == serde_json::to_vec(&voters)?,
        "installed target peer placement differs"
    );
    let origin = TargetOrigin {
        authority_manifest_sha256: lease
            .signed()
            .claims
            .request
            .authority_manifest_sha256
            .clone(),
        materialization: lease.commitment().intent.clone(),
        input: input.clone(),
    };
    let _gate = operation
        .run(async { Ok(BOOTSTRAP_GATE.lock().await) })
        .await?;
    operation.check()?;
    // Complete graph verification runs even on an uncertain first publication;
    // exact deterministic genesis bytes must match any retained manifest.
    let verified = operation
        .run(async {
            backup_restore::load_authorized(
                source,
                input.backup_id,
                &target,
                backup_restore::RestoreAuthorization::Lifecycle(operation.invocation()),
                &security_audit,
                &replica.admission,
                operation.deadline,
                Some(operation.work.clone()),
                Some(operation.token.clone()),
            )
            .await
        })
        .await?;
    let _workspace = verified._reservation.clone();
    let bootstrap = ReplicatedBootstrap {
        incarnation: replica.incarnation.to_string(),
        initial_policy: verified.state.policy.clone(),
        initial_limits: verified.state.limits.clone(),
        voters,
    };
    bootstrap.validate()?;
    let restored = operation
        .run(verified.into_genesis(
            operation.deadline,
            target.tenant().into(),
            bootstrap.incarnation.clone(),
            Some(origin.clone()),
        ))
        .await?;
    operation.check()?;
    let stores = targets.clone();
    let binding = serde_json::to_vec(&("replicated", &bootstrap))?;
    let bytes = restored.bytes;
    let expected = restored.sha256.clone();
    let authorization = TargetPublication {
        invocation: operation.invocation().clone(),
        token: operation.token.clone(),
        deadline: operation.deadline,
    };
    operation
        .run(
            operation
                .deadline
                .blocking(_workspace, Some(operation.work.clone()), move || {
                    authorization.check()?;
                    bind_deployment(&stores, &binding)?;
                    authorization.check()?;
                    if stores
                        .application()
                        .get_bounded(NS, b"manifest", 64 << 10)?
                        .is_some()
                    {
                        verify_persisted_digest(&stores, &expected)?;
                    } else {
                        persist_target(&stores, &bytes, &authorization)?;
                    }
                    authorization.check()
                }),
        )
        .await?;
    let proof = VerifiedTargetMaterialization {
        stores: targets.clone(),
        fact: TargetMaterializationFact {
            origin,
            node_id: replica.node_id,
            bootstrap_sha256: restored.sha256,
            revision_base: restored.engine.generation()?.state.revision_base,
        },
        admission: replica.admission.clone(),
        release: operation.release_fence(),
    };
    proof.release(operation).await?;
    operation.check()?;
    // Materialization starts no Raft tasks or membership. A later distinct
    // Initialize phase consumes the three durable native attestations.
    Ok(MaterializedTargetReplica {
        stores: targets,
        bootstrap,
        proof,
    })
}
struct TargetPublication {
    invocation: crate::TargetLifecycleInvocation,
    token: kasumi_query::QueryCancellation,
    deadline: crate::backup_verify::VerificationDeadline,
}
impl TargetPublication {
    fn check(&self) -> anyhow::Result<()> {
        self.token.check()?;
        self.deadline.check()?;
        self.invocation.check()?;
        Ok(())
    }
}
fn persist_target(
    stores: &TenantStorageSet,
    bytes: &SnapshotImage,
    authorization: &TargetPublication,
) -> anyhow::Result<()> {
    authorization.check()?;
    anyhow::ensure!(
        stores
            .application()
            .get_bounded(NS, b"manifest", 64 << 10)?
            .is_none()
            && stores
                .custody()
                .store()
                .get("raft.meta", b"node_id")?
                .is_none(),
        "target publication would replace an initialized generation"
    );
    let chunks = bytes.len().div_ceil(CHUNK as u64);
    let mut reader = bytes.reader();
    for i in 0..chunks {
        let mut chunk = vec![0; (bytes.len() - i * CHUNK as u64).min(CHUNK as u64) as usize];
        reader.read_exact(&mut chunk)?;
        authorization.check()?;
        stores
            .application()
            .write_batch(&[WriteOp::put(NS, i.to_be_bytes(), chunk)])?;
    }
    let manifest = Manifest {
        format: 2,
        bytes: bytes.len(),
        chunks,
        digest: bytes.sha256().to_owned(),
    };
    authorization.check()?;
    stores.write_batch(
        &[WriteOp::put(
            NS,
            b"manifest",
            serde_json::to_vec(&manifest)?,
        )],
        &[WriteOp::put(
            "raft.meta",
            b"application_bootstrap_sha256",
            serde_json::to_vec(&manifest.digest)?,
        )],
    )?;
    authorization.check()
}
