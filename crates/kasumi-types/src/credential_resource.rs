//! Mandatory signed native credential purpose. This is deterministic metadata
//! after verification, never a public constructor for live authorization.
use crate::{Error, ErrorCode, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CredentialResource {
    Database { incarnation: Uuid },
    Control { incarnation: Uuid },
    Authority { authority_id: Uuid, partition: u16 },
    Custody { incarnation: Uuid },
}
impl CredentialResource {
    pub fn validate(&self) -> Result<()> {
        let identity = match self {
            Self::Database { incarnation }
            | Self::Control { incarnation }
            | Self::Custody { incarnation } => incarnation,
            Self::Authority {
                authority_id,
                partition,
            } => {
                if *partition >= 1024 {
                    return Err(invalid());
                }
                authority_id
            }
        };
        if identity.is_nil() {
            return Err(invalid());
        }
        Ok(())
    }
    /// Exact comparison only. A control or custody credential never becomes an
    /// ordinary database credential because its UUID happens to be the same.
    pub fn require_database(&self, incarnation: &str) -> Result<()> {
        match self {
            Self::Database {
                incarnation: expected,
            } if Uuid::try_parse(incarnation).ok().as_ref() == Some(expected) => Ok(()),
            _ => Err(invalid()),
        }
    }
    pub fn require_control(&self, incarnation: &str) -> Result<()> {
        match self {
            Self::Control {
                incarnation: expected,
            } if Uuid::try_parse(incarnation).ok().as_ref() == Some(expected) => Ok(()),
            _ => Err(invalid()),
        }
    }
    pub fn require_custody(&self, incarnation: &str) -> Result<()> {
        match self {
            Self::Custody {
                incarnation: expected,
            } if Uuid::try_parse(incarnation).ok().as_ref() == Some(expected) => Ok(()),
            _ => Err(invalid()),
        }
    }
    pub fn require_authority(&self, authority_id: Uuid, partition: u16) -> Result<()> {
        match self {
            Self::Authority {
                authority_id: expected,
                partition: expected_partition,
            } if *expected == authority_id && *expected_partition == partition => Ok(()),
            _ => Err(invalid()),
        }
    }
}
fn invalid() -> Error {
    Error::new(
        ErrorCode::Unauthorized,
        "authenticated resource binding differs",
    )
}
