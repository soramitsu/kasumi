//! Transport observations about a complete authenticated backup. These records
//! are not authority: verified proof wrappers belong to the engine and secure SDK.
use crate::{Error, ErrorCode, Result, validate_name, validate_sha256};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// An exact physical backup namespace, independent of its display alias.
/// Filesystem fields must come from a retained, verified owner and its marker;
/// no configured path alone is sufficient to mint this value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BackupNamespaceBinding {
    Filesystem {
        installation_id: uuid::Uuid,
        origin_node_id: u64,
        namespace_id: uuid::Uuid,
        device: u64,
        inode: u64,
    },
    S3 {
        https_origin: String,
        region: String,
        bucket: String,
        prefix: String,
    },
}

impl BackupNamespaceBinding {
    pub fn validate(&self) -> Result<()> {
        let valid_segment = |value: &str| {
            !value.is_empty()
                && value != "."
                && value != ".."
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
        };
        let valid = match self {
            Self::Filesystem {
                installation_id,
                origin_node_id,
                namespace_id,
                device,
                inode,
            } => {
                !installation_id.is_nil()
                    && *origin_node_id != 0
                    && !namespace_id.is_nil()
                    && *device != 0
                    && *inode != 0
            }
            Self::S3 {
                https_origin,
                region,
                bucket,
                prefix,
            } => {
                let canonical = https_origin.len() <= 2048
                    && url::Url::parse(https_origin).ok().is_some_and(|parsed| {
                        parsed.scheme() == "https"
                            && parsed.host_str().is_some()
                            && parsed.username().is_empty()
                            && parsed.password().is_none()
                            && parsed.query().is_none()
                            && parsed.fragment().is_none()
                            && parsed.path() == "/"
                            && parsed.as_str() == https_origin
                    });
                canonical
                    && region.len() <= 256
                    && valid_segment(region)
                    && bucket.len() <= 256
                    && valid_segment(bucket)
                    && prefix.len() <= 1024
                    && (prefix.is_empty() || prefix.split('/').all(valid_segment))
            }
        };
        if !valid {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "invalid physical backup namespace binding",
            ));
        }
        Ok(())
    }
}

/// Maximum encrypted Intent bytes retained by one permanent Control point row.
/// A source must check this before it proposes a claim or writes any destination
/// object. The point-table encoder must separately charge its encoded row size.
pub const MAX_BACKUP_BINDING_INTENT_BYTES: usize = 256 << 10;

/// Exact immutable source claim prepared by the live application database.
/// Structural validation cannot authenticate source facts: the source preflight
/// must derive these fields from its own authorized generation and installed
/// destination, and Control must only accept that opaque preflight capability.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BackupBindingClaim {
    pub session_id: uuid::Uuid,
    pub tenant: String,
    pub source_incarnation: String,
    pub revision: u64,
    pub source_purpose_sha256: String,
    pub namespace_binding: BackupNamespaceBinding,
    pub binding_nonce: uuid::Uuid,
    pub principal: String,
    pub request_id: String,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub destination_alias: Option<String>,
    pub command_id: uuid::Uuid,
    pub intent_ciphertext_sha256: String,
    /// Exact encrypted bytes are retained so a crash after the Control commit
    /// cannot cause a fresh randomized encryption under the same session UUID.
    pub intent_ciphertext: Vec<u8>,
}

impl std::fmt::Debug for BackupBindingClaim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackupBindingClaim")
            .field("session_id", &self.session_id)
            .field("tenant", &self.tenant)
            .field("source_incarnation", &self.source_incarnation)
            .field("revision", &self.revision)
            .field("source_purpose_sha256", &self.source_purpose_sha256)
            .field("namespace_binding", &self.namespace_binding)
            .field("binding_nonce", &self.binding_nonce)
            .field("principal", &self.principal)
            .field("request_id", &self.request_id)
            .field("destination_alias", &self.destination_alias)
            .field("command_id", &self.command_id)
            .field("intent_ciphertext_sha256", &self.intent_ciphertext_sha256)
            .field("intent_ciphertext_len", &self.intent_ciphertext.len())
            .finish()
    }
}

impl BackupBindingClaim {
    /// Validate the exact persistent value before any proposed Control write.
    /// Equality is byte-for-byte, including command identity and ciphertext;
    /// there is no alias or old-format equivalence rule for a reused UUID.
    pub fn validate(&self) -> Result<()> {
        validate_name(&self.tenant)?;
        validate_name(&self.source_incarnation)?;
        validate_name(&self.principal)?;
        if let Some(alias) = &self.destination_alias {
            validate_name(alias)?;
        }
        validate_sha256(&self.source_purpose_sha256)?;
        validate_sha256(&self.intent_ciphertext_sha256)?;
        self.namespace_binding.validate()?;
        if self.session_id.is_nil()
            || self.binding_nonce.is_nil()
            || self.command_id.is_nil()
            || self.request_id.is_empty()
            || self.request_id.len() > 1024
            || self.intent_ciphertext.is_empty()
            || self.intent_ciphertext.len() > MAX_BACKUP_BINDING_INTENT_BYTES
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "invalid Control backup binding claim",
            ));
        }
        let digest = format!("{:x}", Sha256::digest(&self.intent_ciphertext));
        if digest != self.intent_ciphertext_sha256 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "backup binding intent ciphertext digest differs",
            ));
        }
        Ok(())
    }
}

/// Adapter-assigned committed identity. A request cannot select these values.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BackupBindingPosition {
    pub term: u64,
    pub index: u64,
    pub command_sha256: String,
}

/// Value for a permanent encrypted point row selected by an authenticated
/// Control head. The enclosing row key, ordinal, chain hash and applied cursor
/// must be checked separately. This is not a quorum-read or write grant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BackupBindingRecord {
    pub claim: BackupBindingClaim,
    pub position: BackupBindingPosition,
}

impl BackupBindingRecord {
    pub fn validate(&self) -> Result<()> {
        self.claim.validate()?;
        validate_sha256(&self.position.command_sha256)?;
        if self.position.term == 0 || self.position.index == 0 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "invalid committed Control backup position",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FullBackupCheckpoint {
    pub tenant: String,
    pub source_incarnation: String,
    pub revision: u64,
    pub resident_sha256: String,
    pub backup_id: uuid::Uuid,
    pub manifest_ciphertext_sha256: String,
    pub key_lineage_digest: String,
}
impl FullBackupCheckpoint {
    /// Checks wire shape only; it does not authenticate a checkpoint.
    pub fn validate(&self) -> Result<()> {
        validate_name(&self.tenant)?;
        validate_name(&self.source_incarnation)?;
        validate_sha256(&self.resident_sha256)?;
        validate_sha256(&self.manifest_ciphertext_sha256)?;
        validate_sha256(&self.key_lineage_digest)?;
        if self.backup_id.is_nil() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "nil backup checkpoint identity",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateBackupCheckpoint {
    pub destination: String,
    pub session_id: uuid::Uuid,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyBackupCheckpoint {
    pub destination: String,
    pub backup_id: uuid::Uuid,
}

/// One durable identity is chosen before the first object is uploaded.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BackupSessionIntent {
    pub session_id: uuid::Uuid,
    pub tenant: String,
    pub source_incarnation: String,
    pub revision: u64,
    pub principal: String,
    pub request_id: String,
}
impl BackupSessionIntent {
    pub fn validate(&self) -> Result<()> {
        validate_name(&self.tenant)?;
        validate_name(&self.source_incarnation)?;
        validate_name(&self.principal)?;
        if self.session_id.is_nil() || self.request_id.len() > 1024 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "invalid backup session intent",
            ));
        }
        Ok(())
    }
}
/// Exactly one create-only outcome can win. It is never a cleanup target.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum BackupSessionOutcome {
    Complete {
        intent_ciphertext_sha256: String,
        checkpoint: FullBackupCheckpoint,
    },
    Aborted {
        intent_ciphertext_sha256: String,
        session_id: uuid::Uuid,
        principal: String,
        reason: String,
    },
}
impl BackupSessionOutcome {
    pub fn validate(&self, intent: &BackupSessionIntent, digest: &str) -> Result<()> {
        intent.validate()?;
        validate_sha256(digest)?;
        let actual = match self {
            Self::Complete {
                intent_ciphertext_sha256,
                checkpoint,
            } => {
                checkpoint.validate()?;
                if checkpoint.backup_id != intent.session_id
                    || checkpoint.tenant != intent.tenant
                    || checkpoint.source_incarnation != intent.source_incarnation
                    || checkpoint.revision != intent.revision
                {
                    return Err(Error::new(
                        ErrorCode::Corruption,
                        "completed backup differs from session intent",
                    ));
                }
                intent_ciphertext_sha256
            }
            Self::Aborted {
                intent_ciphertext_sha256,
                session_id,
                principal,
                reason,
            } => {
                validate_name(principal)?;
                if *session_id != intent.session_id || reason.is_empty() || reason.len() > 1024 {
                    return Err(Error::new(
                        ErrorCode::Corruption,
                        "aborted backup differs from session intent",
                    ));
                }
                intent_ciphertext_sha256
            }
        };
        if actual != digest {
            return Err(Error::new(
                ErrorCode::Corruption,
                "backup outcome intent digest differs",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupSessionRequest {
    pub destination: String,
    pub session_id: uuid::Uuid,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbortBackupSession {
    pub destination: String,
    pub session_id: uuid::Uuid,
    pub reason: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupBackupSession {
    pub destination: String,
    pub session_id: uuid::Uuid,
    pub max_objects: usize,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupSessionStatus {
    pub intent: BackupSessionIntent,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub outcome: Option<BackupSessionOutcome>,
    pub source_purpose_sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupCleanupResult {
    pub session_id: uuid::Uuid,
    pub deleted_objects: u64,
    pub more_objects_observed: bool,
}

#[cfg(test)]
mod namespace_binding_tests {
    use super::*;

    #[test]
    fn s3_binding_requires_one_canonical_origin_and_bounded_segments() {
        let original = BackupNamespaceBinding::S3 {
            https_origin: "https://s3.example/".into(),
            region: "us-east-1".into(),
            bucket: "backups".into(),
            prefix: "prod/tenant".into(),
        };
        original.validate().unwrap();
        let encoded = serde_json::to_vec(&original).unwrap();
        let decoded: BackupNamespaceBinding = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, original);
        for origin in [
            "http://s3.example/",
            "https://S3.EXAMPLE/",
            "https://s3.example:443/",
            "https://s3.example/path",
            "https://user@s3.example/",
            "https://s3.example/?q=1",
        ] {
            let mut changed = original.clone();
            let BackupNamespaceBinding::S3 { https_origin, .. } = &mut changed else {
                unreachable!()
            };
            *https_origin = origin.into();
            assert!(changed.validate().is_err(), "accepted {origin}");
        }
        let mut changed = original.clone();
        let BackupNamespaceBinding::S3 { prefix, .. } = &mut changed else {
            unreachable!()
        };
        *prefix = "prod/../tenant".into();
        assert!(changed.validate().is_err());
        assert!(
            serde_json::from_value::<BackupNamespaceBinding>(serde_json::json!({
                "kind":"s3", "https_origin":"https://s3.example/",
                "region":"us-east-1", "bucket":"backups", "prefix":"prod",
                "unknown":"not-a-binding"
            }))
            .is_err()
        );
    }

    #[test]
    fn filesystem_binding_requires_all_physical_owner_fields() {
        let valid = BackupNamespaceBinding::Filesystem {
            installation_id: uuid::Uuid::new_v4(),
            origin_node_id: 7,
            namespace_id: uuid::Uuid::new_v4(),
            device: 9,
            inode: 11,
        };
        valid.validate().unwrap();
        for field in 0..5 {
            let mut changed = valid.clone();
            let BackupNamespaceBinding::Filesystem {
                installation_id,
                origin_node_id,
                namespace_id,
                device,
                inode,
            } = &mut changed
            else {
                unreachable!()
            };
            match field {
                0 => *installation_id = uuid::Uuid::nil(),
                1 => *origin_node_id = 0,
                2 => *namespace_id = uuid::Uuid::nil(),
                3 => *device = 0,
                4 => *inode = 0,
                _ => unreachable!(),
            }
            assert!(
                changed.validate().is_err(),
                "accepted invalid field {field}"
            );
        }
    }
}

#[cfg(test)]
mod control_backup_binding_tests {
    use super::*;

    fn claim() -> BackupBindingClaim {
        let intent_ciphertext = b"one exact encrypted Intent".to_vec();
        BackupBindingClaim {
            session_id: uuid::Uuid::from_u128(1),
            tenant: "tenant".into(),
            source_incarnation: uuid::Uuid::from_u128(2).to_string(),
            revision: 7,
            source_purpose_sha256: "11".repeat(32),
            namespace_binding: BackupNamespaceBinding::S3 {
                https_origin: "https://s3.example/".into(),
                region: "us-east-1".into(),
                bucket: "backups".into(),
                prefix: "prod".into(),
            },
            binding_nonce: uuid::Uuid::from_u128(3),
            principal: "operator".into(),
            request_id: "request".into(),
            destination_alias: Some("original-display-name".into()),
            command_id: uuid::Uuid::from_u128(4),
            intent_ciphertext_sha256: format!("{:x}", Sha256::digest(&intent_ciphertext)),
            intent_ciphertext,
        }
    }

    #[test]
    fn exact_claim_roundtrip_requires_present_alias_field_and_rejects_unknowns() {
        let claim = claim();
        claim.validate().unwrap();
        let encoded = serde_json::to_value(&claim).unwrap();
        let decoded: BackupBindingClaim = serde_json::from_value(encoded.clone()).unwrap();
        decoded.validate().unwrap();
        assert_eq!(decoded, claim);

        let mut missing = encoded.clone();
        missing.as_object_mut().unwrap().remove("destination_alias");
        assert!(serde_json::from_value::<BackupBindingClaim>(missing).is_err());
        let mut unknown = encoded;
        unknown
            .as_object_mut()
            .unwrap()
            .insert("legacy_alias".into(), serde_json::Value::Null);
        assert!(serde_json::from_value::<BackupBindingClaim>(unknown).is_err());
    }

    #[test]
    fn exact_claim_rejects_changed_ciphertext_binding_and_non_nil_identity() {
        let original = claim();
        let mut changed = original.clone();
        changed.intent_ciphertext.push(0);
        assert!(changed.validate().is_err());
        changed = original.clone();
        changed.binding_nonce = uuid::Uuid::nil();
        assert!(changed.validate().is_err());
        changed = original.clone();
        changed.namespace_binding = BackupNamespaceBinding::S3 {
            https_origin: "https://s3.example/".into(),
            region: "us-east-1".into(),
            bucket: "backups".into(),
            prefix: "other".into(),
        };
        changed.validate().unwrap();
        assert_ne!(changed, original);
        changed = original;
        changed.intent_ciphertext = vec![7; MAX_BACKUP_BINDING_INTENT_BYTES + 1];
        assert!(changed.validate().is_err());
    }

    #[test]
    fn committed_record_requires_a_position_and_preserves_exact_claim() {
        let claim = claim();
        let mut record = BackupBindingRecord {
            claim: claim.clone(),
            position: BackupBindingPosition {
                term: 2,
                index: 9,
                command_sha256: "22".repeat(32),
            },
        };
        record.validate().unwrap();
        let decoded: BackupBindingRecord =
            serde_json::from_slice(&serde_json::to_vec(&record).unwrap()).unwrap();
        assert_eq!(decoded, record);
        assert_eq!(decoded.claim, claim);
        record.position.index = 0;
        assert!(record.validate().is_err());
    }
}
