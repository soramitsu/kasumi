//! Immutable, deterministic initial Control state. This is an installation
//! baseline, not an applied Raft entry or a proof of a currently available quorum.
use super::*;
use crate::control::{CONTROL_TENANT, ControlPlane, ControlTopology, DeploymentMode};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "control",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ReplicatedGenesis {
    Application,
    Control(ControlGenesis),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlGenesis {
    pub topology: ControlTopology,
    pub lifecycle: ControlLifecycleGenesis,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ControlLifecycleGenesis {
    Disabled,
    Installed {
        command_id: uuid::Uuid,
        installation: LifecycleInstallation,
    },
}

impl ReplicatedGenesis {
    pub(super) fn validate(&self, incarnation: &str) -> anyhow::Result<()> {
        if let Self::Control(control) = self {
            control.validate(incarnation)?;
        }
        Ok(())
    }

    pub(super) fn require_domain(&self, store: &TenantStore) -> anyhow::Result<()> {
        use kasumi_store::StoragePurpose;
        match self {
            Self::Control(_) => anyhow::ensure!(
                store.tenant() == CONTROL_TENANT
                    && matches!(
                        store.storage_access().purpose(),
                        StoragePurpose::NodeControl
                    ),
                "Control genesis requires its exact Control storage domain"
            ),
            Self::Application => anyhow::ensure!(
                store.tenant() != CONTROL_TENANT
                    && (matches!(
                        store.storage_access().purpose(),
                        StoragePurpose::Serving { .. }
                    ) || store.storage_access().purpose().is_local_fixture()),
                "application genesis requires its own replicated application domain"
            ),
        }
        Ok(())
    }

    pub(super) fn engine(
        &self,
        tenant: &str,
        bootstrap: &ReplicatedBootstrap,
    ) -> anyhow::Result<TenantEngine> {
        anyhow::ensure!(
            (tenant == CONTROL_TENANT) == matches!(self, Self::Control(_)),
            "genesis namespace and kind differ"
        );
        Ok(TenantEngine::new_genesis(
            tenant.into(),
            bootstrap.incarnation.clone(),
            bootstrap.initial_policy.clone(),
            bootstrap.initial_limits.clone(),
            match self {
                Self::Application => None,
                Self::Control(control) => Some(control),
            },
        )?)
    }

    pub(super) fn verify_image(
        &self,
        store: &TenantStore,
        bootstrap: &ReplicatedBootstrap,
        installed: &SnapshotImage,
    ) -> anyhow::Result<()> {
        if matches!(self, Self::Control(_)) {
            // Compare only the immutable encrypted bootstrap, never a later
            // applied topology or lifecycle policy. The bounded spool is owned
            // by this call and no existing state is repaired or published.
            let expected = self
                .engine(store.tenant(), bootstrap)?
                .logical_snapshot(store.scratch_disk())?;
            anyhow::ensure!(
                expected.sha256() == installed.sha256(),
                "installed Control bootstrap differs from its immutable genesis"
            );
        }
        Ok(())
    }
}

impl ControlGenesis {
    fn validate(&self, incarnation: &str) -> anyhow::Result<()> {
        self.topology.validate()?;
        anyhow::ensure!(
            !self.topology.nodes.is_empty()
                && self
                    .topology
                    .tenants
                    .values()
                    .all(|route| route.mode == DeploymentMode::Replicated),
            "Control genesis requires replicated placement"
        );
        if let ControlLifecycleGenesis::Installed {
            command_id,
            installation,
        } = &self.lifecycle
        {
            installation.validate()?;
            anyhow::ensure!(
                !command_id.is_nil()
                    && installation.root.control_incarnation.to_string() == incarnation,
                "Control genesis lifecycle resource differs"
            );
        }
        Ok(())
    }

    pub(crate) fn seed(&self, state: &mut TenantState) -> Result<()> {
        self.validate(&state.incarnation)
            .map_err(|error| Error::new(ErrorCode::InvalidArgument, error.to_string()))?;
        if state.tenant != CONTROL_TENANT || state.revision != 0 || !state.collections.is_empty() {
            return Err(Error::new(
                ErrorCode::Conflict,
                "Control genesis needs an empty initial state",
            ));
        }
        let body = serde_json::to_value(&self.topology).map_err(|_| {
            Error::new(
                ErrorCode::InvalidArgument,
                "invalid Control genesis topology",
            )
        })?;
        let bytes = crate::accounting::encoded_len(&body)?;
        if bytes > state.limits.max_document_bytes || bytes as u64 > state.limits.max_logical_bytes
        {
            return Err(Error::new(
                ErrorCode::QuotaExceeded,
                "Control genesis exceeds its document budget",
            ));
        }
        // Revision 1 names the trusted initial baseline. Raft retains no applied
        // position for it. The first consensus index advances from this base.
        state.revision = 1;
        state.revision_base = 1;
        state.policy_epoch = 1;
        state.schema_epoch = 1;
        state.document_count = 1;
        state.logical_bytes = bytes as u64;
        state.collections.insert(
            "topology".into(),
            CollectionState {
                definition: ControlPlane::topology_definition(),
                data_epoch: 1,
                documents: imbl::OrdMap::from_iter([(
                    "current".to_owned(),
                    Arc::new(Document {
                        id: "current".into(),
                        version: 1,
                        body,
                    }),
                )]),
                archived_documents: imbl::OrdMap::new(),
                archived_document_bytes: 0,
            },
        );
        if let ControlLifecycleGenesis::Installed {
            command_id,
            installation,
        } = &self.lifecycle
        {
            state.lifecycle_control = Some(LifecycleControlState {
                installation: installation.clone(),
                installation_command_id: *command_id,
                installation_revision: 1,
                installation_policy_epoch: state.policy_epoch,
                installation_policy: state.policy.clone(),
                retired: false,
                pending_change: None,
                intents: BTreeMap::new(),
                changes: BTreeMap::new(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "bootstrap_control_genesis_tests.rs"]
mod tests;
