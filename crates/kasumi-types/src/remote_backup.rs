//! A dedicated Control voter must resolve the opaque nonce at the original
//! enrolled data member. None of these wire values conveys source authority.
use crate::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;

pub const BACKUP_DELEGATION_COLLECTION: &str = "backup_bindings";
pub const MAX_REMOTE_BACKUP_BYTES: usize = 4 << 20;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RemoteBackupAction {
    Read {
        session_id: Uuid,
    },
    Claim {
        claim: BackupBindingClaim,
    },
    Decide {
        claim: BackupBindingClaim,
        terminal: Box<BackupBindingTerminal>,
    },
}
impl RemoteBackupAction {
    pub fn session(&self) -> Uuid {
        match self {
            Self::Read { session_id } => *session_id,
            Self::Claim { claim } | Self::Decide { claim, .. } => claim.session_id,
        }
    }
    pub fn validate(&self) -> Result<()> {
        if self.session().is_nil() {
            return Err(Error::new(ErrorCode::InvalidArgument, "nil backup session"));
        }
        match self {
            Self::Read { .. } => Ok(()),
            Self::Claim { claim } => claim.validate(),
            Self::Decide { claim, terminal } => {
                claim.validate()?;
                terminal.validate(claim)
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteBackupReference {
    pub nonce: Uuid,
    pub control_incarnation: Uuid,
    pub source_node: u64,
    pub tenant: String,
    pub source_incarnation: String,
    pub session: Uuid,
    pub action_sha256: String,
}
impl RemoteBackupReference {
    pub fn validate(&self) -> Result<()> {
        validate_name(&self.tenant)?;
        validate_name(&self.source_incarnation)?;
        validate_sha256(&self.action_sha256)?;
        if self.nonce.is_nil()
            || self.session.is_nil()
            || self.control_incarnation.is_nil()
            || self.source_node == 0
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "invalid remote backup operation identity",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteBackupCommand {
    pub reference: RemoteBackupReference,
    pub action: RemoteBackupAction,
}
impl RemoteBackupCommand {
    pub fn validate(&self) -> Result<()> {
        self.reference.validate()?;
        self.action.validate()?;
        if self.action.session() != self.reference.session
            || staged_digest(&self.action)?.0 != self.reference.action_sha256
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "remote backup input differs from its reference",
            ));
        }
        if let RemoteBackupAction::Claim { claim } | RemoteBackupAction::Decide { claim, .. } =
            &self.action
            && (claim.tenant != self.reference.tenant
                || claim.source_incarnation != self.reference.source_incarnation)
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "remote backup claim differs from its source",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteBackupChallenge {
    pub reference: RemoteBackupReference,
    pub challenge: Uuid,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteBackupConfirmation {
    pub original: RemoteBackupChallenge,
    /// The original incarnation of this exact checkpoint, when selected by
    /// the current source's authenticated restore lineage.
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub restore_source_incarnation: Option<String>,
    pub policy_epoch: u64,
    pub purpose_sha256: String,
    pub source_certificate_sha256: String,
    pub term: u64,
    pub leader: u64,
    pub committed_term: u64,
    pub committed_index: u64,
    pub membership_term: u64,
    pub membership_index: u64,
    pub voters: BTreeSet<u64>,
}
impl RemoteBackupConfirmation {
    pub fn validate(&self) -> Result<()> {
        self.original.reference.validate()?;
        if let Some(inc) = &self.restore_source_incarnation {
            validate_name(inc)?;
        }
        validate_sha256(&self.purpose_sha256)?;
        validate_sha256(&self.source_certificate_sha256)?;
        if self.original.challenge.is_nil()
            || self.term == 0
            || self.committed_term == 0
            || self.committed_index == 0
            // OpenRaft's initialized membership is its genuine (0, 0)
            // entry. Application genesis likewise starts at policy epoch zero.
            || (self.membership_term == 0) != (self.membership_index == 0)
            || self.committed_index < self.membership_index
            || self.committed_term > self.term
            || self.membership_term > self.committed_term
            || self.voters.len() != 3
            || !self.voters.contains(&self.leader)
            || !self.voters.contains(&self.original.reference.source_node)
            || self.voters.contains(&0)
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "invalid data quorum backup confirmation",
            ));
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteBackupRecord {
    pub record: BackupBindingRecord,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub terminal: Option<BackupBindingTerminal>,
}
impl RemoteBackupRecord {
    pub fn validate(&self) -> Result<()> {
        self.record.validate()?;
        if let Some(terminal) = &self.terminal {
            terminal.validate(&self.record.claim)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn genesis_membership_still_requires_an_elected_committed_source_barrier() {
        let mut source = RemoteBackupConfirmation {
            original: RemoteBackupChallenge {
                reference: RemoteBackupReference {
                    nonce: Uuid::new_v4(),
                    control_incarnation: Uuid::new_v4(),
                    source_node: 2,
                    tenant: "tenant".into(),
                    source_incarnation: Uuid::new_v4().to_string(),
                    session: Uuid::new_v4(),
                    action_sha256: "ab".repeat(32),
                },
                challenge: Uuid::new_v4(),
            },
            restore_source_incarnation: None,
            policy_epoch: 0,
            purpose_sha256: "ab".repeat(32),
            source_certificate_sha256: "cd".repeat(32),
            term: 1,
            leader: 2,
            committed_term: 1,
            committed_index: 1,
            membership_term: 0,
            membership_index: 0,
            voters: BTreeSet::from([1, 2, 3]),
        };
        source.validate().unwrap();
        source.membership_index = 1;
        assert!(source.validate().is_err());
        source.membership_term = 1;
        source.validate().unwrap();
        source.committed_index = 0;
        assert!(source.validate().is_err());
    }
}
