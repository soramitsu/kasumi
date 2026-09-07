//! Mandatory installed storage purpose. A persisted identity is not a capability:
//! reopening a serving catalog requires a fresh signed lease before key access.
use anyhow::{Result, ensure};
use kasumi_serving::{AuthorityManifest, ServingGate, ServingIdentity};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum StoragePurpose {
    Serving {
        manifest_digest: String,
        identity: ServingIdentity,
        recovery_checkpoint: Option<Box<kasumi_types::FullBackupCheckpoint>>,
    },
    SecurityAudit,
    NodeControl,
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
/// No deserializer and no optional gate. `Serving` can only be installed using
/// an opaque cryptographically verified lease gate; reserved control purposes
/// cannot open municipality namespaces.
#[derive(Clone)]
pub struct StorageAccess {
    purpose: StoragePurpose,
    gate: Option<Arc<ServingGate>>,
}
impl StorageAccess {
    pub fn serving(gate: Arc<ServingGate>) -> Result<Self> {
        gate.check()?;
        Ok(Self {
            purpose: StoragePurpose::Serving {
                manifest_digest: gate.authority_digest().into(),
                identity: gate.identity().clone(),
                recovery_checkpoint: gate.recovery_checkpoint()?.map(Box::new),
            },
            gate: Some(gate),
        })
    }
    pub fn security_audit() -> Self {
        Self {
            purpose: StoragePurpose::SecurityAudit,
            gate: None,
        }
    }
    pub fn node_control() -> Self {
        Self {
            purpose: StoragePurpose::NodeControl,
            gate: None,
        }
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
        })
    }
    pub(crate) fn custody(application_tenant: &str) -> Self {
        Self {
            purpose: StoragePurpose::RetirementCustody {
                application_tenant: application_tenant.into(),
            },
            gate: None,
        }
    }
    #[cfg(any(test, feature = "test-utils"))]
    pub fn fixture() -> Self {
        Self {
            purpose: StoragePurpose::LocalFixture,
            gate: None,
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
    pub fn check(&self) -> Result<()> {
        if let Some(gate) = &self.gate {
            gate.check()?;
        }
        Ok(())
    }
    pub fn check_serving(&self) -> Result<()> {
        if let Some(gate) = &self.gate {
            gate.check_serving()?;
        }
        Ok(())
    }
    pub(crate) fn validate_tenant(&self, tenant: &str) -> Result<()> {
        self.check()?;
        let matches = match &self.purpose {
            StoragePurpose::Serving { identity, .. } => {
                identity.tenant == tenant
                    && !tenant.starts_with("kasumi.")
                    && !tenant.starts_with("__kasumi_")
            }
            StoragePurpose::SecurityAudit => tenant == "__kasumi_security",
            StoragePurpose::NodeControl => tenant == "__kasumi_control",
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
