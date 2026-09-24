//! Closed control installation is immutable startup input. Operator settings
//! cannot silently replace signer, partition membership or an accepted command.
use crate::runtime::{DeploymentMode, read_private_file};
use anyhow::{Result, ensure};
use kasumi_engine::LifecycleSigner;
use kasumi_types::{LifecycleInstallation, TenantState};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Arc};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleRuntimeConfig {
    pub command_id: Uuid,
    pub installation: LifecycleInstallation,
    pub signing_key: PathBuf,
    #[serde(deserialize_with = "kasumi_types::require_explicit_option")]
    pub recovery: Option<crate::recovery_runtime::RecoveryRuntimeConfig>,
}
impl LifecycleRuntimeConfig {
    pub fn validate(&self, mode: DeploymentMode, incarnation: Option<&str>) -> Result<()> {
        self.installation.validate()?;
        ensure!(
            mode == DeploymentMode::Replicated,
            "closed lifecycle control requires replicated startup"
        );
        ensure!(
            !self.command_id.is_nil() && self.signing_key.is_absolute(),
            "invalid control installation identity or signer path"
        );
        ensure!(
            incarnation
                == Some(
                    self.installation
                        .root
                        .control_incarnation
                        .to_string()
                        .as_str()
                ),
            "configured control incarnation differs from installed signer"
        );
        Ok(())
    }
    pub(crate) fn signer(&self) -> Result<Arc<LifecycleSigner>> {
        Ok(Arc::new(LifecycleSigner::from_pkcs8(
            self.installation.root.clone(),
            &read_private_file(&self.signing_key, 16 << 10)?,
        )?))
    }
}

/// Followers inspect only their actual applied installation; this is a local
/// readiness prerequisite, never a fabricated current-quorum proof.
pub(crate) fn applied(
    state: &TenantState,
    configured: Option<&LifecycleRuntimeConfig>,
) -> Result<bool> {
    match (&state.lifecycle_control, configured) {
        (None, None) => Ok(true),
        (None, Some(_)) => Ok(false),
        (Some(_), None) => {
            anyhow::bail!("durable lifecycle installation cannot be disabled at startup")
        }
        (Some(current), Some(configured)) => {
            ensure!(
                current.installation_command_id == configured.command_id
                    && current.installation == configured.installation,
                "configured lifecycle installation differs from committed control state"
            );
            Ok(true)
        }
    }
}
pub(crate) fn require_applied(
    state: &TenantState,
    configured: Option<&LifecycleRuntimeConfig>,
) -> Result<()> {
    ensure!(
        applied(state, configured)?,
        "installed lifecycle Control state is missing"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn lifecycle_startup_requires_explicit_configuration() {
        let mut value = serde_json::to_value(crate::runtime::example_config()).unwrap();
        assert!(serde_json::from_value::<crate::runtime::RuntimeConfig>(value.clone()).is_ok());
        value["control"]
            .as_object_mut()
            .unwrap()
            .remove("lifecycle");
        assert!(serde_json::from_value::<crate::runtime::RuntimeConfig>(value).is_err());
    }
}
