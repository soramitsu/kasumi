//! Read one enrolled Data member's physical service inventory through its Data leader.
use crate::{
    Error, ErrorCode, KeyCatalogDomain, KeyReference, KeyRetentionEntry,
    MAX_MISSING_KEY_DEPENDENCIES, Result, TrustVerifierIdentity, staged_digest, validate_name,
    validate_sha256,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;

pub const DATA_MEMBER_CATALOG_LIMIT: u16 = 4;
pub const DATA_CATALOG_MAX_MEMBERS: usize = 64;
pub const DATA_MEMBER_CATALOG_BYTES: usize = 320 << 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataMemberService {
    Signer,
    SecurityAudit,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataMemberCatalogRead {
    pub tenant: String,
    pub incarnation: Uuid,
    pub verifier: TrustVerifierIdentity,
    pub service: DataMemberService,
    pub nonce: Uuid,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub after: Option<KeyRetentionEntry>,
    pub limit: u16,
}

impl DataMemberCatalogRead {
    pub fn validate(&self) -> Result<()> {
        validate_name(&self.tenant)?;
        self.verifier.validate()?;
        if self.tenant.starts_with("__kasumi_")
            || self.incarnation.is_nil()
            || self.nonce.is_nil()
            || !(1..=DATA_MEMBER_CATALOG_LIMIT).contains(&self.limit)
        {
            return Err(invalid("invalid Data service catalog request"));
        }
        if let Some(after) = &self.after {
            after.validate()?;
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        Ok(staged_digest(&("kasumi.data-member-catalog-read.v1", self))?.0)
    }
}

/// These IDs corroborate the enrolled routes. Only an independently installed
/// endpoint may be contacted when the current voter or learner set changes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataCatalogMembership {
    pub leader: u64,
    pub term: u64,
    pub membership_index: u64,
    pub membership_sha256: String,
    #[serde(deserialize_with = "member_ids")]
    pub voters: BTreeSet<u64>,
    #[serde(deserialize_with = "member_ids")]
    pub members: BTreeSet<u64>,
}

impl DataCatalogMembership {
    fn validate(&self, member: u64) -> Result<()> {
        validate_sha256(&self.membership_sha256)?;
        if self.term == 0
            || self.members.contains(&0)
            || self.members.len() > DATA_CATALOG_MAX_MEMBERS
            || !self.voters.contains(&self.leader)
            || !self.voters.is_subset(&self.members)
            || !self.members.contains(&member)
        {
            return Err(invalid("invalid Data service catalog membership"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "service", rename_all = "snake_case", deny_unknown_fields)]
pub enum DataCatalogContents {
    Signer {
        partitions_sha256: String,
    },
    SecurityAudit {
        stream: Uuid,
        archives_sha256: [u8; 32],
        #[serde(deserialize_with = "unreadable_ids")]
        unreadable_objects: BTreeSet<Uuid>,
        truncated: bool,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataMemberCatalogPage {
    pub request_sha256: String,
    pub membership: DataCatalogMembership,
    pub applied_index: u64,
    pub verifier: TrustVerifierIdentity,
    pub catalog: Uuid,
    pub catalog_sha256: [u8; 32],
    pub contents: DataCatalogContents,
    #[serde(deserialize_with = "catalog_entries")]
    pub entries: Vec<KeyRetentionEntry>,
}

impl DataMemberCatalogPage {
    pub fn validate(&self, read: &DataMemberCatalogRead) -> Result<()> {
        self.membership.validate(read.verifier.node_id)?;
        if self.request_sha256 != read.digest()?
            || self.verifier != read.verifier
            || self.catalog.is_nil()
            || self.membership.membership_index > self.applied_index
            || self.entries.len() > usize::from(read.limit) + 1
            || self.entries.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(invalid(
                "Data service catalog differs from its enrolled member or request",
            ));
        }
        let (domain, audit_stream) = match (&self.contents, read.service) {
            (DataCatalogContents::Signer { partitions_sha256 }, DataMemberService::Signer) => {
                validate_sha256(partitions_sha256)?;
                (KeyCatalogDomain::LiveSignerTrust, None)
            }
            (
                DataCatalogContents::SecurityAudit {
                    stream,
                    unreadable_objects,
                    truncated,
                    ..
                },
                DataMemberService::SecurityAudit,
            ) if !stream.is_nil()
                && unreadable_objects.len() <= MAX_MISSING_KEY_DEPENDENCIES
                && (!truncated || unreadable_objects.len() == MAX_MISSING_KEY_DEPENDENCIES)
                && !unreadable_objects.contains(&Uuid::nil()) =>
            {
                (KeyCatalogDomain::SecurityAudit, Some(*stream))
            }
            _ => return Err(invalid("Data member returned another service inventory")),
        };
        for entry in &self.entries {
            entry.validate()?;
            if read.after.as_ref().is_some_and(|after| entry <= after)
                || !match entry.reference {
                    KeyReference::Catalog {
                        node_id,
                        catalog_id,
                        domain: actual,
                    } => {
                        node_id == self.verifier.node_id
                            && catalog_id == self.catalog
                            && actual == domain
                    }
                    KeyReference::AuditArchive { stream_id, .. } => audit_stream == Some(stream_id),
                    _ => false,
                }
            {
                return Err(invalid(
                    "Data catalog entry belongs to another owner or window",
                ));
            }
        }
        Ok(())
    }
}

fn invalid(message: &'static str) -> Error {
    Error::new(ErrorCode::InvalidArgument, message)
}

/// The configured administrative routes for one Data group, including learners.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataCatalogGroup {
    pub incarnation: Uuid,
    pub members: BTreeSet<u64>,
}

fn member_ids<'de, D: serde::Deserializer<'de>>(
    input: D,
) -> std::result::Result<BTreeSet<u64>, D::Error> {
    crate::key_retention::ascending(input, DATA_CATALOG_MAX_MEMBERS, "Data membership")
        .map(|v| v.into_iter().collect())
}
fn unreadable_ids<'de, D: serde::Deserializer<'de>>(
    input: D,
) -> std::result::Result<BTreeSet<Uuid>, D::Error> {
    crate::key_retention::ascending(
        input,
        MAX_MISSING_KEY_DEPENDENCIES,
        "unreadable Data audit objects",
    )
    .map(|v| v.into_iter().collect())
}
fn catalog_entries<'de, D: serde::Deserializer<'de>>(
    input: D,
) -> std::result::Result<Vec<KeyRetentionEntry>, D::Error> {
    crate::key_retention::ascending(
        input,
        usize::from(DATA_MEMBER_CATALOG_LIMIT) + 1,
        "Data catalog entries",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn data_membership_rejects_duplicate_and_oversized_wire_lists() {
        let observed = DataCatalogMembership {
            leader: 1,
            term: 2,
            membership_index: 5,
            membership_sha256: "aa".repeat(32),
            voters: BTreeSet::from([1, 2, 3]),
            members: BTreeSet::from([1, 2, 3, 4]),
        };
        let original = serde_json::to_value(&observed).unwrap();
        for input in [vec![1, 1], vec![3, 2, 1], (1..=65).collect()] {
            let mut record = original.clone();
            record["members"] = serde_json::json!(input);
            assert!(serde_json::from_value::<DataCatalogMembership>(record).is_err());
        }
        assert_eq!(
            serde_json::from_value::<DataCatalogMembership>(original).unwrap(),
            observed
        );
    }
}
