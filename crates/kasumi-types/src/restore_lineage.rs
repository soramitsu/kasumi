//! Immutable restoration provenance. Wire records are observations, not live
//! authority; only authenticated engine/SDK wrappers construct verified proofs.
use crate::{Error, ErrorCode, FullBackupCheckpoint, Result, validate_name, validate_sha256};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const MAX_RESTORE_LINEAGE_LINKS: usize = 1024;
pub const MAX_RESTORE_LINEAGE_BYTES: usize = 1 << 20;

/// Internal authenticated state retained by each restored genesis. Application
/// mutation operations cannot alter this chain. Full backups cover it in the
/// resident state hash; user-visible read proofs expose only commitments below.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RestoreLineageLink {
    pub checkpoint: FullBackupCheckpoint,
    pub target_incarnation: String,
}

/// Narrow proof input: the caller must currently be allowed to read this exact
/// existing collection, and the database must match the requested incarnation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadRestoreLineage {
    pub expected_incarnation: String,
    pub collection: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RestoreLineageCommitment {
    pub source_incarnation: String,
    pub target_incarnation: String,
    pub source_revision: u64,
    pub source_resident_sha256: String,
    /// Commitment to the complete internally retained FullBackupCheckpoint.
    /// This deliberately does not reveal key lineage or object location fields.
    pub checkpoint_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RestoreLineageObservation {
    pub tenant: String,
    pub incarnation: String,
    pub collection: String,
    pub revision: u64,
    pub policy_epoch: u64,
    pub links: Vec<RestoreLineageCommitment>,
}

impl RestoreLineageObservation {
    /// Shape checks only. Deserializing a plausible observation is never proof.
    pub fn validate(&self) -> Result<()> {
        validate_name(&self.tenant)?;
        validate_name(&self.incarnation)?;
        validate_name(&self.collection)?;
        bounded(&self.links)?;
        let mut previous: Option<(&str, u64)> = None;
        let mut seen = BTreeSet::new();
        for link in &self.links {
            validate_name(&link.source_incarnation)?;
            validate_name(&link.target_incarnation)?;
            validate_sha256(&link.source_resident_sha256)?;
            validate_sha256(&link.checkpoint_sha256)?;
            if let Some((target, revision)) = previous {
                if target != link.source_incarnation || link.source_revision <= revision {
                    return Err(invalid("restore lineage is discontinuous"));
                }
            } else {
                seen.insert(link.source_incarnation.as_str());
            }
            if !seen.insert(link.target_incarnation.as_str()) {
                return Err(invalid("restore lineage reuses an incarnation"));
            }
            previous = Some((&link.target_incarnation, link.source_revision));
        }
        if let Some((target, revision)) = previous
            && (target != self.incarnation || revision >= self.revision)
        {
            return Err(invalid("restore lineage differs from current incarnation"));
        }
        Ok(())
    }
}

/// Validate the complete retained chain before snapshot acceptance or restoring
/// another hop. The exact final checkpoint must remain equal to restored_from.
pub fn validate_restore_lineage(
    tenant: &str,
    incarnation: &str,
    revision: u64,
    restored_from: Option<&FullBackupCheckpoint>,
    links: &[RestoreLineageLink],
) -> Result<()> {
    bounded(links)?;
    if links.last().map(|link| &link.checkpoint) != restored_from {
        return Err(invalid("restore lineage origin differs"));
    }
    let mut previous: Option<(&str, u64)> = None;
    let mut seen = BTreeSet::new();
    for link in links {
        link.checkpoint.validate()?;
        validate_name(&link.target_incarnation)?;
        if link.checkpoint.tenant != tenant {
            return Err(invalid("restore lineage crosses tenants"));
        }
        if let Some((target, last_revision)) = previous {
            if target != link.checkpoint.source_incarnation
                || link.checkpoint.revision <= last_revision
            {
                return Err(invalid("restore lineage is discontinuous"));
            }
        } else {
            seen.insert(link.checkpoint.source_incarnation.as_str());
        }
        if !seen.insert(link.target_incarnation.as_str()) {
            return Err(invalid("restore lineage reuses an incarnation"));
        }
        previous = Some((&link.target_incarnation, link.checkpoint.revision));
    }
    if let Some((target, source_revision)) = previous
        && (target != incarnation || source_revision >= revision)
    {
        return Err(invalid("restore lineage differs from current incarnation"));
    }
    Ok(())
}

fn bounded<T: Serialize>(links: &[T]) -> Result<()> {
    if links.len() > MAX_RESTORE_LINEAGE_LINKS {
        return Err(invalid("restore lineage link bound reached"));
    }
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, value: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(value.len());
            if self.0 > MAX_RESTORE_LINEAGE_BYTES {
                return Err(std::io::Error::other("restore lineage byte bound reached"));
            }
            Ok(value.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(&mut Counter(0), links)
        .map_err(|_| invalid("restore lineage byte bound reached"))?;
    Ok(())
}

fn invalid(message: &str) -> Error {
    Error::new(ErrorCode::InvalidArgument, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn link(source: u128, target: u128, revision: u64) -> RestoreLineageLink {
        RestoreLineageLink {
            checkpoint: FullBackupCheckpoint {
                tenant: "tenant".into(),
                source_incarnation: uuid::Uuid::from_u128(source).to_string(),
                revision,
                resident_sha256: "1".repeat(64),
                backup_id: uuid::Uuid::from_u128(100 + source),
                manifest_ciphertext_sha256: "2".repeat(64),
                key_lineage_digest: "3".repeat(64),
            },
            target_incarnation: uuid::Uuid::from_u128(target).to_string(),
        }
    }
    #[test]
    fn closed_lineage_rejects_substitution_discontinuity_and_resource_overflow() {
        let chain = vec![link(1, 2, 10), link(2, 3, 20)];
        let current = uuid::Uuid::from_u128(3).to_string();
        let check = |candidate: &[RestoreLineageLink]| {
            validate_restore_lineage(
                "tenant",
                &current,
                21,
                Some(&chain[1].checkpoint),
                candidate,
            )
        };
        check(&chain).unwrap();
        for field in 0..6 {
            let mut bad = chain.clone();
            match field {
                0 => bad[0].checkpoint.tenant = "other".into(),
                1 => bad[0].target_incarnation = uuid::Uuid::from_u128(9).to_string(),
                2 => bad[1].target_incarnation = uuid::Uuid::from_u128(1).to_string(),
                3 => bad[1].checkpoint.resident_sha256 = "4".repeat(64),
                4 => bad[0].checkpoint.revision = 20,
                _ => bad[0].checkpoint.key_lineage_digest = "invalid".into(),
            }
            assert!(check(&bad).is_err(), "case {field}");
        }
        assert!(check(&[]).is_err());
        assert!(bounded(&vec![0; MAX_RESTORE_LINEAGE_LINKS + 1]).is_err());
        assert!(bounded(&["x".repeat(MAX_RESTORE_LINEAGE_BYTES)]).is_err());
        assert!(
            validate_restore_lineage("tenant", &current, 20, Some(&chain[1].checkpoint), &chain)
                .is_err()
        );
        validate_restore_lineage("tenant", &current, 1, None, &[]).unwrap();
    }
}
