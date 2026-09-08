//! Local credential administration. Families are durable identities; renewal
//! preserves their exact principal, resource and scopes until explicit revocation.
use crate::{Action, CredentialResource, Error, ErrorCode, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;

pub const DEFAULT_CREDENTIAL_LIFETIME_SECONDS: u64 = 3600;
fn lifetime() -> u64 {
    DEFAULT_CREDENTIAL_LIFETIME_SECONDS
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CreateCredential {
    pub family_id: Uuid,
    pub principal: String,
    pub tenant: String,
    pub resource: CredentialResource,
    pub scopes: BTreeSet<Action>,
    #[serde(default = "lifetime")]
    pub lifetime_seconds: u64,
}
impl CreateCredential {
    pub fn validate(&self) -> Result<()> {
        crate::validate_name(&self.principal)?;
        crate::validate_name(&self.tenant)?;
        self.resource.validate()?;
        if self.family_id.is_nil()
            || self.scopes.is_empty()
            || !(1..=3600).contains(&self.lifetime_seconds)
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "invalid credential family, scopes or lifetime",
            ));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RenewCredential {
    pub family_id: Uuid,
    pub renewal_id: Uuid,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CredentialReference {
    pub family_id: Uuid,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CredentialStatus {
    pub specification: CreateCredential,
    pub created_at_ms: u64,
    pub revoked_at_ms: Option<u64>,
}
/// Bearer material is intentionally excluded from Debug.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuedCredential {
    pub family_id: Uuid,
    pub token: String,
    pub expires_at_ms: u64,
}
