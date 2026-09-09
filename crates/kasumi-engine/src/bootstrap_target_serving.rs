//! Existing activated target startup. The independent projection and fresh
//! issuer lease precede application keys; actual replayed local facts gate data.
use super::*;
use crate::{TargetReplicaConfig, VerifiedTargetServingProjection};
use anyhow::Context;

pub struct TargetServingReplica {
    database: Arc<Database>,
    projection: Arc<VerifiedTargetServingProjection>,
    bootstrap: ReplicatedBootstrap,
    shutdown_runtime: tokio::runtime::Handle,
    closed: bool,
}
impl TargetServingReplica {
    /// Only actual validated local state can enter the ordinary native registry.
    pub fn database(&self) -> anyhow::Result<Arc<Database>> {
        self.check()?;
        Ok(self.database.clone())
    }
    pub fn bootstrap(&self) -> &ReplicatedBootstrap {
        &self.bootstrap
    }
    pub fn check(&self) -> anyhow::Result<()> {
        let store = self.database.store();
        let gate = store
            .storage_access()
            .serving_gate()
            .context("serving gate absent")?;
        self.projection.check(gate)?;
        self.database.check_serving()?;
        let generation = self.database.engine().generation()?;
        anyhow::ensure!(
            generation.state.incarnation == self.projection.target_incarnation().to_string()
                && generation.state.tenant == self.projection.tenant()
                && generation
                    .state
                    .target_lifecycle
                    .get(&generation.state.incarnation)
                    == Some(&self.projection.execution()?)
                && !generation.state.retired,
            "actual local activated target differs from independent projection"
        );
        let execution = self.projection.execution()?;
        // Activation checked its actual original quorum when this immutable
        // fact committed. Replay must retain that exact fact and independently
        // persisted application coverage. The latest applied membership and
        // suspension are operational state, not the activation's identity.
        self.database.raft_group().confirm_local_application(
            &execution
                .activation
                .as_ref()
                .context("activation missing")?
                .position,
        )?;
        self.projection.check(gate)
    }
    pub async fn close(&mut self) -> anyhow::Result<()> {
        self.database.shutdown().await?;
        self.closed = true;
        Ok(())
    }
}
impl Drop for TargetServingReplica {
    fn drop(&mut self) {
        if !self.closed {
            let database = self.database.clone();
            self.shutdown_runtime.spawn(async move {
                let _ = database.shutdown().await;
            });
        }
    }
}
/// Opens only an already materialized exact target. This never creates a new
/// bootstrap, changes membership, or reads a source backup/key on recovery.
/// The detached owner retains actual startup work through caller cancellation.
pub async fn open_serving_target(
    projection: Arc<VerifiedTargetServingProjection>,
    stores: Arc<TenantStorageSet>,
    config: TargetReplicaConfig,
    transport: Arc<dyn RaftTransport>,
    audit: Arc<SecurityAudit>,
) -> anyhow::Result<TargetServingReplica> {
    audit.require_admission(&config.admission)?;
    let gate = stores
        .application()
        .storage_access()
        .serving_gate()
        .context("fresh serving lease missing")?
        .clone();
    projection.check(&gate)?;
    anyhow::ensure!(
        stores
            .application()
            .storage_access()
            .lifecycle_gate()
            .is_none()
            && config.node_id == gate.identity().node.node_id,
        "ordinary startup cannot reuse phase storage or another node"
    );
    let task = tokio::spawn(async move {
        let _serial = BOOTSTRAP_GATE.lock().await;
        projection.check(&gate)?;
        let reservation = Arc::new(
            config
                .admission
                .reserve(recovery_workspace_bytes(&stores)?, None)?,
        );
        let material = stores.clone();
        let proof = projection.clone();
        let live = gate.clone();
        let (engine, bootstrap) = tokio::task::spawn_blocking(move || {
            let _reservation = reservation;
            proof.check(&live)?;
            let bytes =
                load(material.application())?.context("published target bootstrap missing")?;
            validate_bootstrap_control(&material, &bytes)?;
            let engine = Arc::new(TenantEngine::from_bootstrap(
                material.application().tenant(),
                &bytes,
            )?);
            let expected = proof.execution()?;
            let state = engine.generation()?;
            anyhow::ensure!(
                state
                    .state
                    .target_lifecycle
                    .get(&state.state.incarnation)
                    .is_some_and(|entry| entry.origin == expected.origin)
                    && bytes.sha256()
                        == expected
                            .completion
                            .as_ref()
                            .context("completion missing")?
                            .bootstrap_sha256,
                "existing physical bootstrap differs from committed target"
            );
            let encoded = material
                .custody()
                .store()
                .get_bounded("engine.deployment", b"mode", 256 << 10)?
                .context("target deployment absent")?;
            let (mode, bootstrap): (String, ReplicatedBootstrap) =
                serde_json::from_slice(&encoded)?;
            bootstrap.validate()?;
            anyhow::ensure!(
                mode == "replicated"
                    && bootstrap.incarnation == proof.target_incarnation().to_string()
                    && bootstrap.voters.len() == expected.origin.input.voters.len()
                    && bootstrap.voters.iter().all(|(id, peer)| expected
                        .origin
                        .input
                        .voters
                        .get(id)
                        .is_some_and(|original| peer.address == original.endpoint
                            && peer.failure_domain == original.failure_domain)),
                "target deployment identity differs"
            );
            drop(state);
            engine.install_storage_access(material.application())?;
            engine.verify_bootstrap_dependencies_checked(|| proof.check(&live))?;
            proof.check(&live)?;
            Ok::<_, anyhow::Error>((engine, bootstrap))
        })
        .await??;
        projection.check(&gate)?;
        engine.install_audit_maintenance(&config.admission)?;
        let group = RaftGroup::open(
            config.node_id,
            format!("{}/{}", projection.tenant(), bootstrap.incarnation),
            stores.clone(),
            engine.clone(),
            transport,
            config.raft,
        )
        .await?;
        let database = Database::new_with_admission(
            engine,
            group,
            stores.application().clone(),
            config.admission,
            audit,
        );
        let owner = TargetServingReplica {
            database,
            projection,
            bootstrap,
            shutdown_runtime: tokio::runtime::Handle::current(),
            closed: false,
        };
        // Raft open replays its persisted committed prefix. An uncommitted or
        // missing local activation cannot be promoted by a foreign signed DTO.
        owner.check()?;
        Ok::<_, anyhow::Error>(owner)
    });
    task.await?
}
