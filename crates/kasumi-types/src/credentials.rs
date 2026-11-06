//! Local credential administration. Families are durable identities; renewal
//! preserves their exact principal, resource and scopes until explicit revocation.
use crate::{Action, CredentialResource, Error, ErrorCode, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;

pub const DEFAULT_CREDENTIAL_LIFETIME_SECONDS: u64 = 3600;
/// How long after it expires a local family's latest credential may still
/// renew that family online (`RecoverCredential`, docs/credential-lifetime.md).
/// A hard bound: nothing configures it longer. Superseded or revoked
/// credentials never recover, and a credential still live renews instead.
pub const EXPIRED_CREDENTIAL_RECOVERY_WINDOW_SECONDS: u64 = 24 * 3600;
fn lifetime() -> u64 {
    DEFAULT_CREDENTIAL_LIFETIME_SECONDS
}

/// Which listeners accept a family's tokens: their audience.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialAudience {
    /// The native data and administrative listeners.
    #[default]
    Native,
    /// The MCP listener, which takes no client certificate. An MCP family is
    /// never certificate-bound and is renewed by a Control administrator.
    Mcp,
}
impl CredentialAudience {
    pub fn is_native(&self) -> bool {
        *self == Self::Native
    }
}

/// A family's durable specification. The two fields added for certificate
/// binding are omitted when they hold their defaults, so a family written
/// before them keeps its exact bytes.
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
    /// Lowercase hex SHA-256 of the DER of the one client certificate over
    /// whose TLS connections this family's tokens are accepted; tokens carry
    /// it as `cnf.x5t#S256` (RFC 8705). Absent: unbound, as every family
    /// issued before certificate binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_certificate_sha256: Option<String>,
    /// Absent: native.
    #[serde(default, skip_serializing_if = "CredentialAudience::is_native")]
    pub audience: CredentialAudience,
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
        if let Some(binding) = &self.client_certificate_sha256 {
            if binding.len() != 64
                || !binding
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "client certificate binding must be 64 lowercase hex digits",
                ));
            }
            if self.audience == CredentialAudience::Mcp {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "an MCP credential cannot be bound to a client certificate",
                ));
            }
        }
        Ok(())
    }

    /// The SHA-256 of the client certificate this family is bound to.
    pub fn certificate_binding(&self) -> Option<[u8; 32]> {
        let binding = self.client_certificate_sha256.as_deref()?;
        let mut pin = [0; 32];
        for (index, byte) in pin.iter_mut().enumerate() {
            *byte = u8::from_str_radix(binding.get(index * 2..index * 2 + 2)?, 16).ok()?;
        }
        Some(pin)
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
