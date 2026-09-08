//! Mandatory installed storage purpose. A persisted identity is not a capability:
//! reopening a serving catalog requires a fresh signed lease before key access.
use anyhow::{Result, ensure};
use kasumi_serving::{AuthorityManifest, ServingGate, ServingIdentity};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum StoragePurpose {
    Standalone {
        installation_id: uuid::Uuid,
        tenant: String,
        incarnation: uuid::Uuid,
    },
    Serving {
        manifest_digest: String,
        identity: ServingIdentity,
        recovery_checkpoint: Option<Box<kasumi_types::FullBackupCheckpoint>>,
    },
    SecurityAudit,
    NodeControl,
    LiveSignerTrust {
        verifier: kasumi_serving::TrustVerifierIdentity,
    },
    TargetJournal {
        control_root: kasumi_types::ControlSigningRoot,
        node: kasumi_serving::NodeIdentity,
    },
    IndependentAuthority {
        manifest_digest: String,
        authority_id: uuid::Uuid,
        partition: u16,
    },
    RetirementCustody {
        application_tenant: String,
    },
    #[cfg(any(test, feature = "test-utils"))]
    LocalFixture,
}
impl StoragePurpose {
    /// Fixture purposes cannot be decoded or constructed in production builds.
    /// This query lets consumers follow the store's feature gate without adding
    /// a second, independently selectable fixture policy.
    pub fn is_local_fixture(&self) -> bool {
        #[cfg(any(test, feature = "test-utils"))]
        if matches!(self, Self::LocalFixture) {
            return true;
        }
        false
    }
    /// Historical provenance equality for the immutable installation and database
    /// incarnation. The original HA writer and authority epoch remain authenticated
    /// fields, but do not have to be the current verifier's node or renewable epoch.
    /// This comparison grants no live storage capability.
    pub fn same_application_resource(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Standalone {
                    installation_id: a,
                    tenant: at,
                    incarnation: ai,
                },
                Self::Standalone {
                    installation_id: b,
                    tenant: bt,
                    incarnation: bi,
                },
            ) => a == b && at == bt && ai == bi,
            (
                Self::Serving {
                    manifest_digest: a,
                    identity: ai,
                    ..
                },
                Self::Serving {
                    manifest_digest: b,
                    identity: bi,
                    ..
                },
            ) => a == b && ai.tenant == bi.tenant && ai.incarnation == bi.incarnation,
            #[cfg(any(test, feature = "test-utils"))]
            (Self::LocalFixture, Self::LocalFixture) => true,
            _ => false,
        }
    }
    /// Validate historical application provenance without granting current access
    /// or substituting the verifier's node for the original writer.
    pub fn validate_application_identity(&self, tenant: &str, incarnation: &str) -> Result<()> {
        let matches = match self {
            Self::Standalone {
                installation_id,
                tenant: source,
                incarnation: source_incarnation,
            } => {
                !installation_id.is_nil()
                    && !source_incarnation.is_nil()
                    && source == tenant
                    && source_incarnation.to_string() == incarnation
            }
            Self::Serving {
                manifest_digest,
                identity,
                recovery_checkpoint,
            } => {
                kasumi_types::validate_sha256(manifest_digest)?;
                identity.validate()?;
                if let Some(checkpoint) = recovery_checkpoint {
                    checkpoint.validate()?;
                }
                identity.tenant == tenant && identity.incarnation.to_string() == incarnation
            }
            #[cfg(any(test, feature = "test-utils"))]
            Self::LocalFixture => true,
            _ => false,
        };
        ensure!(
            matches,
            "backup source purpose differs from application identity"
        );
        Ok(())
    }
}
/// No deserializer and no optional gate. `Serving` can only be installed using
/// an opaque cryptographically verified lease gate; reserved control purposes
/// cannot open municipality namespaces.
#[derive(Clone)]
pub struct StorageAccess {
    purpose: StoragePurpose,
    gate: Option<Arc<ServingGate>>,
    lifecycle: Option<Arc<kasumi_serving::LifecycleGate>>,
}
impl StorageAccess {
    /// Explicit trusted-host standalone capability. The containing NodeStore
    /// owns the exclusive database lock, and catalog equality prevents reopening
    /// an HA catalog or a different standalone generation with this capability.
    pub fn standalone(
        installation_id: uuid::Uuid,
        tenant: &str,
        incarnation: uuid::Uuid,
    ) -> Result<Self> {
        kasumi_types::validate_name(tenant)?;
        ensure!(
            !installation_id.is_nil() && !incarnation.is_nil(),
            "standalone identity cannot be nil"
        );
        let access = Self {
            purpose: StoragePurpose::Standalone {
                installation_id,
                tenant: tenant.into(),
                incarnation,
            },
            gate: None,
            lifecycle: None,
        };
        access.validate_tenant(tenant)?;
        Ok(access)
    }
    pub fn serving(gate: Arc<ServingGate>) -> Result<Self> {
        gate.check()?;
        ensure!(
            !gate.is_prepared()? || !gate.requires_lifecycle()?,
            "restore preparation requires an exact committed lifecycle gate"
        );
        Self::serving_inner(gate, None)
    }
    /// Same immutable catalog identity with an additional live exact phase.
    /// A different phase requires draining and dropping every old store owner.
    pub fn target_phase(
        gate: Arc<ServingGate>,
        lifecycle: Arc<kasumi_serving::LifecycleGate>,
    ) -> Result<Self> {
        let phase = lifecycle.current()?.commitment().intent.request.phase;
        ensure!(
            gate.is_prepared()?
                || matches!(
                    phase,
                    kasumi_types::LifecyclePhase::Activate
                        | kasumi_types::LifecyclePhase::InspectTarget
                ),
            "active target requires activation or metadata inspection capability"
        );
        ensure!(
            phase != kasumi_types::LifecyclePhase::StopLocal,
            "cleanup cannot open application storage"
        );
        lifecycle.check_target(&gate, phase)?;
        Self::serving_inner(gate, Some(lifecycle))
    }
    fn serving_inner(
        gate: Arc<ServingGate>,
        lifecycle: Option<Arc<kasumi_serving::LifecycleGate>>,
    ) -> Result<Self> {
        Ok(Self {
            purpose: StoragePurpose::Serving {
                manifest_digest: gate.authority_digest().into(),
                identity: gate.identity().clone(),
                recovery_checkpoint: gate.recovery_checkpoint()?.map(Box::new),
            },
            gate: Some(gate),
            lifecycle,
        })
    }
    pub fn security_audit() -> Self {
        Self {
            purpose: StoragePurpose::SecurityAudit,
            gate: None,
            lifecycle: None,
        }
    }
    pub fn node_control() -> Self {
        Self {
            purpose: StoragePurpose::NodeControl,
            gate: None,
            lifecycle: None,
        }
    }
    /// Independent local trust metadata is never part of a restored data image.
    pub fn live_signer_trust(verifier: kasumi_serving::TrustVerifierIdentity) -> Result<Self> {
        verifier.validate()?;
        Ok(Self {
            purpose: StoragePurpose::LiveSignerTrust { verifier },
            gate: None,
            lifecycle: None,
        })
    }
    /// Installed metadata purpose, separately keyed from application/custody.
    /// This can access only the exact reserved target journal namespace.
    pub fn target_journal(
        root: &kasumi_types::ControlSigningRoot,
        node: &kasumi_serving::NodeIdentity,
    ) -> Result<Self> {
        root.validate()?;
        node.validate()?;
        Ok(Self {
            purpose: StoragePurpose::TargetJournal {
                control_root: root.clone(),
                node: node.clone(),
            },
            gate: None,
            lifecycle: None,
        })
    }
    pub fn independent_authority(manifest: &AuthorityManifest, partition: u16) -> Result<Self> {
        manifest.validate()?;
        ensure!(
            manifest.partitions.contains_key(&partition),
            "unknown authority partition"
        );
        Ok(Self {
            purpose: StoragePurpose::IndependentAuthority {
                manifest_digest: manifest.digest()?,
                authority_id: manifest.authority_id,
                partition,
            },
            gate: None,
            lifecycle: None,
        })
    }
    pub(crate) fn custody(application_tenant: &str) -> Self {
        Self {
            purpose: StoragePurpose::RetirementCustody {
                application_tenant: application_tenant.into(),
            },
            gate: None,
            lifecycle: None,
        }
    }
    #[cfg(any(test, feature = "test-utils"))]
    pub fn fixture() -> Self {
        Self {
            purpose: StoragePurpose::LocalFixture,
            gate: None,
            lifecycle: None,
        }
    }
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn fixture_for(tenant: &str) -> Self {
        if let Some(application) = tenant.strip_prefix("kasumi.custody/") {
            return Self::custody(application);
        }
        if tenant == "__kasumi_security" {
            return Self::security_audit();
        }
        if tenant == "__kasumi_control" {
            return Self::node_control();
        }
        Self::fixture()
    }
    pub fn purpose(&self) -> &StoragePurpose {
        &self.purpose
    }
    pub fn serving_gate(&self) -> Option<&Arc<ServingGate>> {
        self.gate.as_ref()
    }
    pub fn lifecycle_gate(&self) -> Option<&Arc<kasumi_serving::LifecycleGate>> {
        self.lifecycle.as_ref()
    }
    pub fn check(&self) -> Result<()> {
        if let Some(lifecycle) = &self.lifecycle {
            lifecycle.check()?;
        }
        if let Some(gate) = &self.gate {
            gate.check()?;
        }
        Ok(())
    }
    /// Read-only target inspection may replay existing consensus state, but it
    /// cannot admit a fresh payload, membership or lifecycle proposal.
    pub fn check_consensus_proposal(&self) -> Result<()> {
        self.check()?;
        if let Some(gate) = &self.lifecycle {
            ensure!(
                gate.current()?.commitment().intent.request.phase
                    != kasumi_types::LifecyclePhase::InspectTarget,
                "target inspection cannot admit consensus mutations"
            );
        }
        Ok(())
    }
    pub fn check_serving(&self) -> Result<()> {
        ensure!(
            self.lifecycle.is_none(),
            "target phase cannot serve ordinary tenant traffic"
        );
        if let Some(gate) = &self.gate {
            gate.check_serving()?;
        }
        Ok(())
    }
    pub(crate) fn validate_tenant(&self, tenant: &str) -> Result<()> {
        self.check()?;
        let matches = match &self.purpose {
            StoragePurpose::Standalone {
                tenant: installed, ..
            } => {
                installed == tenant
                    && !tenant.starts_with("kasumi.")
                    && !tenant.starts_with("__kasumi_")
            }
            StoragePurpose::Serving { identity, .. } => {
                identity.tenant == tenant
                    && !tenant.starts_with("kasumi.")
                    && !tenant.starts_with("__kasumi_")
            }
            StoragePurpose::SecurityAudit => tenant == "__kasumi_security",
            StoragePurpose::NodeControl => tenant == "__kasumi_control",
            StoragePurpose::LiveSignerTrust { verifier } => tenant == verifier.tenant(),
            StoragePurpose::TargetJournal { control_root, node } => {
                tenant
                    == format!(
                        "kasumi.target.{}.{}",
                        control_root.control_incarnation, node.node_id
                    )
            }
            StoragePurpose::IndependentAuthority {
                authority_id,
                partition,
                ..
            } => tenant == format!("kasumi.authority.{authority_id}.{partition}"),
            StoragePurpose::RetirementCustody { application_tenant } => {
                tenant == super::CustodyStore::catalog_name(application_tenant)
            }
            #[cfg(any(test, feature = "test-utils"))]
            StoragePurpose::LocalFixture => true,
        };
        ensure!(
            matches,
            "installed storage purpose cannot access this tenant namespace"
        );
        Ok(())
    }
}
