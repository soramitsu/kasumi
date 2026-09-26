//! Exact historical wrapping-key dependencies, ReadKeyRetention pages and
//! race-safe key version retirement contracts. A decoded page or coverage
//! report is an observation, never proof that a version is unreferenced and
//! never a retirement or key-access capability.
use crate::{
    AuditArchiveKeyDependency, Error, ErrorCode, Result, staged_digest, validate_name,
    validate_sha256,
};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{Error as _, SeqAccess, Visitor},
};
use std::{collections::BTreeSet, fmt, marker::PhantomData};
use uuid::Uuid;

/// Same provider and key reference bounds as `AuditArchiveKeyDependency`.
pub const MAX_KEY_PROVIDER_BYTES: usize = 1024;
pub const MAX_KEY_REF_BYTES: usize = 8192;
pub const MAX_KEY_DEPENDENCIES: usize = 4096;
pub const MAX_KEY_RETENTION_PAGE_ENTRIES: u16 = 256;
pub const MAX_MISSING_KEY_DEPENDENCIES: usize = 64;

/// One installed wrapping resource. Each retained version is a separate
/// `KeyVersionRef`; this names a resource and grants no key access.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct KeyIdentityRef {
    pub provider: String,
    pub key_ref: String,
}

impl KeyIdentityRef {
    pub fn validate(&self) -> Result<()> {
        validate_identity(&self.provider, &self.key_ref)
    }
}

/// Exact wrapping key version. Field order is the canonical ordering:
/// provider, then key reference (both bytewise), then numeric version.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct KeyVersionRef {
    pub provider: String,
    pub key_ref: String,
    pub version: u64,
}

impl KeyVersionRef {
    pub fn validate(&self) -> Result<()> {
        validate_identity(&self.provider, &self.key_ref)?;
        if self.version == 0 {
            return Err(invalid("key version must be positive"));
        }
        Ok(())
    }

    pub fn identity(&self) -> KeyIdentityRef {
        KeyIdentityRef {
            provider: self.provider.clone(),
            key_ref: self.key_ref.clone(),
        }
    }

    /// Exact resource equality; no provider aliasing or key reference folding.
    pub fn is_version_of(&self, identity: &KeyIdentityRef) -> bool {
        self.provider == identity.provider && self.key_ref == identity.key_ref
    }
}

impl From<&AuditArchiveKeyDependency> for KeyVersionRef {
    fn from(dependency: &AuditArchiveKeyDependency) -> Self {
        Self {
            provider: dependency.provider.clone(),
            key_ref: dependency.key_ref.clone(),
            version: dependency.version,
        }
    }
}

fn validate_identity(provider: &str, key_ref: &str) -> Result<()> {
    if provider.is_empty()
        || provider.len() > MAX_KEY_PROVIDER_BYTES
        || key_ref.is_empty()
        || key_ref.len() > MAX_KEY_REF_BYTES
    {
        return Err(invalid("key identity outside first-release bounds"));
    }
    Ok(())
}

/// Sorted, distinct exact key versions. Construction and decoding reject
/// unsorted, duplicate, invalid or oversized input; nothing is normalized.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "KeyDependencySetRecord")]
pub struct KeyDependencySet {
    versions: Vec<KeyVersionRef>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyDependencySetRecord {
    #[serde(deserialize_with = "dependency_versions")]
    versions: Vec<KeyVersionRef>,
}

impl TryFrom<KeyDependencySetRecord> for KeyDependencySet {
    type Error = Error;
    fn try_from(record: KeyDependencySetRecord) -> Result<Self> {
        Self::new(record.versions)
    }
}

impl KeyDependencySet {
    pub fn new(versions: Vec<KeyVersionRef>) -> Result<Self> {
        validate_ascending(&versions, MAX_KEY_DEPENDENCIES, "key dependency set")?;
        for version in &versions {
            version.validate()?;
        }
        Ok(Self { versions })
    }

    /// Writer-side union of authenticated catalog versions. The bound and each
    /// version are still checked; an oversized union is rejected, not truncated.
    pub fn from_set(versions: BTreeSet<KeyVersionRef>) -> Result<Self> {
        if versions.len() > MAX_KEY_DEPENDENCIES {
            return Err(invalid("key dependency set exceeds its entry bound"));
        }
        Self::new(versions.into_iter().collect())
    }

    pub fn versions(&self) -> &[KeyVersionRef] {
        &self.versions
    }

    pub fn len(&self) -> usize {
        self.versions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.versions.is_empty()
    }

    pub fn contains(&self, version: &KeyVersionRef) -> bool {
        self.versions.binary_search(version).is_ok()
    }

    /// Stable domain-separated digest of the canonical record.
    pub fn sha256(&self) -> Result<String> {
        Ok(staged_digest(&("kasumi.key-dependency-set.v1", self))?.0)
    }
}

/// Each scope covers every current member's catalogs plus the scope's own
/// replicated and node-local journal records. Empty variants are structs so
/// that unknown fields are rejected like every other tagged record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum KeyRetentionScope {
    Tenant { tenant: String },
    Control {},
    SecurityAudit {},
    Signer {},
    TargetJournal {},
    LocalRecovery {},
}

impl KeyRetentionScope {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Tenant { tenant } => validate_name(tenant),
            Self::Control {}
            | Self::SecurityAudit {}
            | Self::Signer {}
            | Self::TargetJournal {}
            | Self::LocalRecovery {} => Ok(()),
        }
    }

    pub fn sha256(&self) -> Result<String> {
        self.validate()?;
        Ok(staged_digest(&("kasumi.key-retention-scope.v1", self))?.0)
    }
}

/// Installed storage purpose kind of one member's key catalog, without the
/// purpose's identity fields.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum KeyCatalogDomain {
    Application,
    RetirementCustody,
    NodeControl,
    SecurityAudit,
    LiveSignerTrust,
    TargetJournal,
    IndependentAuthority,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum KeyReferenceKind {
    Catalog,
    BackupSession,
    CompletedBackup,
    AuditArchive,
    HistoryArchive,
    RecoveryRecord,
    TargetJournal,
    LocalRecovery,
}

/// The durable record that retains a key version. Derived ordering (variant
/// declaration order, then fields) is part of the canonical page order.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum KeyReference {
    Catalog {
        node_id: u64,
        catalog_id: Uuid,
        domain: KeyCatalogDomain,
    },
    BackupSession {
        session_id: Uuid,
    },
    CompletedBackup {
        backup_id: Uuid,
        checkpoint_sha256: String,
    },
    AuditArchive {
        stream_id: Uuid,
        first_sequence: u64,
    },
    /// A chunk or manifest object whose authenticated catalog names the key.
    HistoryArchive {
        archive_id: String,
        object_id: String,
    },
    RecoveryRecord {
        operation_id: Uuid,
    },
    TargetJournal {
        node_id: u64,
        incarnation: Uuid,
    },
    LocalRecovery {
        operation_id: Uuid,
    },
}

impl KeyReference {
    pub fn kind(&self) -> KeyReferenceKind {
        match self {
            Self::Catalog { .. } => KeyReferenceKind::Catalog,
            Self::BackupSession { .. } => KeyReferenceKind::BackupSession,
            Self::CompletedBackup { .. } => KeyReferenceKind::CompletedBackup,
            Self::AuditArchive { .. } => KeyReferenceKind::AuditArchive,
            Self::HistoryArchive { .. } => KeyReferenceKind::HistoryArchive,
            Self::RecoveryRecord { .. } => KeyReferenceKind::RecoveryRecord,
            Self::TargetJournal { .. } => KeyReferenceKind::TargetJournal,
            Self::LocalRecovery { .. } => KeyReferenceKind::LocalRecovery,
        }
    }

    pub fn validate(&self) -> Result<()> {
        let valid = match self {
            Self::Catalog {
                node_id,
                catalog_id,
                ..
            } => *node_id > 0 && !catalog_id.is_nil(),
            Self::BackupSession { session_id } => !session_id.is_nil(),
            Self::CompletedBackup {
                backup_id,
                checkpoint_sha256,
            } => {
                validate_sha256(checkpoint_sha256)?;
                !backup_id.is_nil()
            }
            Self::AuditArchive { stream_id, .. } => !stream_id.is_nil(),
            Self::HistoryArchive {
                archive_id,
                object_id,
            } => {
                validate_name(archive_id)?;
                validate_name(object_id)?;
                true
            }
            Self::RecoveryRecord { operation_id } | Self::LocalRecovery { operation_id } => {
                !operation_id.is_nil()
            }
            Self::TargetJournal {
                node_id,
                incarnation,
            } => *node_id > 0 && !incarnation.is_nil(),
        };
        if !valid {
            return Err(invalid("invalid key retention reference"));
        }
        Ok(())
    }
}

/// Canonical page order is `(key, reference)`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct KeyRetentionEntry {
    pub key: KeyVersionRef,
    pub reference: KeyReference,
}

impl KeyRetentionEntry {
    pub fn validate(&self) -> Result<()> {
        self.key.validate()?;
        self.reference.validate()
    }
}

/// Continuation for one scope at one coverage position. Its fields are opaque
/// to callers but validated: a cursor never restarts and never moves to
/// another scope, coverage revision or membership epoch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KeyRetentionCursor {
    pub scope_sha256: String,
    pub coverage_revision: u64,
    pub membership_epoch: u64,
    /// Last emitted entry; the next page starts strictly after it.
    pub after: KeyRetentionEntry,
}

impl KeyRetentionCursor {
    pub fn validate(&self) -> Result<()> {
        validate_sha256(&self.scope_sha256)?;
        self.after.validate()
    }

    pub fn require_scope(&self, scope: &KeyRetentionScope) -> Result<()> {
        if self.scope_sha256 != scope.sha256()? {
            return Err(invalid("key retention cursor belongs to another scope"));
        }
        Ok(())
    }

    /// Continuation check against the currently pinned coverage position. A
    /// changed revision or epoch expires the cursor instead of restarting it.
    pub fn require_current(
        &self,
        scope: &KeyRetentionScope,
        coverage_revision: u64,
        membership_epoch: u64,
    ) -> Result<()> {
        self.validate()?;
        self.require_scope(scope)?;
        if self.coverage_revision != coverage_revision || self.membership_epoch != membership_epoch
        {
            return Err(Error::new(
                ErrorCode::CursorExpired,
                "key retention coverage changed after cursor",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReadKeyRetentionRequest {
    pub scope: KeyRetentionScope,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub cursor: Option<KeyRetentionCursor>,
    /// Exactly 1..=256. An out-of-range limit is rejected, never clamped.
    pub limit: u16,
}

impl ReadKeyRetentionRequest {
    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        if !(1..=MAX_KEY_RETENTION_PAGE_ENTRIES).contains(&self.limit) {
            return Err(invalid("key retention limit must be within 1..=256"));
        }
        if let Some(cursor) = &self.cursor {
            cursor.validate()?;
            cursor.require_scope(&self.scope)?;
        }
        Ok(())
    }
}

/// Missing or unreadable dependency that makes coverage incomplete.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MissingKeyDependency {
    /// The durable backup session index is not installed or not readable.
    SessionIndexUnavailable {},
    ArchiveUnavailable {
        id: String,
    },
    MemberUnreported {
        node_id: u64,
    },
    RecordUnreadable {
        record_kind: KeyReferenceKind,
        id: String,
    },
    ProviderUnavailable {
        identity: KeyIdentityRef,
    },
}

impl MissingKeyDependency {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::SessionIndexUnavailable {} => Ok(()),
            Self::ArchiveUnavailable { id } | Self::RecordUnreadable { id, .. } => {
                validate_name(id)
            }
            Self::MemberUnreported { node_id } if *node_id > 0 => Ok(()),
            Self::MemberUnreported { .. } => Err(invalid("invalid unreported member")),
            Self::ProviderUnavailable { identity } => identity.validate(),
        }
    }
}

/// Coverage of the whole scope at one pinned coverage revision and membership
/// epoch. Only `Complete` can admit a retirement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum KeyRetentionCoverage {
    /// Every current member reported at this epoch and every referenced record
    /// was readable. The digest commits to the complete scope listing.
    Complete {
        coverage_revision: u64,
        membership_epoch: u64,
        coverage_sha256: String,
    },
    /// Sorted distinct missing dependencies, at most 64; `truncated` reports
    /// that more exist than are listed.
    Incomplete {
        coverage_revision: u64,
        membership_epoch: u64,
        #[serde(deserialize_with = "missing_dependencies")]
        missing: Vec<MissingKeyDependency>,
        truncated: bool,
    },
}

impl KeyRetentionCoverage {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Complete {
                coverage_sha256, ..
            } => validate_sha256(coverage_sha256),
            Self::Incomplete {
                missing, truncated, ..
            } => {
                validate_ascending(
                    missing,
                    MAX_MISSING_KEY_DEPENDENCIES,
                    "missing key dependencies",
                )?;
                if missing.is_empty()
                    || (*truncated && missing.len() < MAX_MISSING_KEY_DEPENDENCIES)
                {
                    return Err(invalid("incomplete key retention coverage is malformed"));
                }
                missing.iter().try_for_each(MissingKeyDependency::validate)
            }
        }
    }

    pub fn coverage_revision(&self) -> u64 {
        match self {
            Self::Complete {
                coverage_revision, ..
            }
            | Self::Incomplete {
                coverage_revision, ..
            } => *coverage_revision,
        }
    }

    pub fn membership_epoch(&self) -> u64 {
        match self {
            Self::Complete {
                membership_epoch, ..
            }
            | Self::Incomplete {
                membership_epoch, ..
            } => *membership_epoch,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KeyRetentionPage {
    #[serde(deserialize_with = "page_entries")]
    pub entries: Vec<KeyRetentionEntry>,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub next_cursor: Option<KeyRetentionCursor>,
    pub coverage: KeyRetentionCoverage,
}

impl KeyRetentionPage {
    /// Shape check against the exact request. Entries stay within the limit,
    /// in canonical order and after the request cursor; a continuation names
    /// the last entry at the same scope and coverage position.
    pub fn validate(&self, request: &ReadKeyRetentionRequest) -> Result<()> {
        request.validate()?;
        validate_ascending(
            &self.entries,
            usize::from(request.limit),
            "key retention page",
        )?;
        self.entries
            .iter()
            .try_for_each(KeyRetentionEntry::validate)?;
        self.coverage.validate()?;
        let (revision, epoch) = (
            self.coverage.coverage_revision(),
            self.coverage.membership_epoch(),
        );
        if let Some(cursor) = &request.cursor {
            cursor.require_current(&request.scope, revision, epoch)?;
            if self
                .entries
                .first()
                .is_some_and(|first| *first <= cursor.after)
            {
                return Err(invalid("key retention page repeats the cursor position"));
            }
        }
        if let Some(next) = &self.next_cursor {
            next.require_current(&request.scope, revision, epoch)?;
            if self.entries.last() != Some(&next.after) {
                return Err(invalid("key retention continuation differs from page"));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RetireKeyVersionsRequest {
    pub retirement_id: String,
    pub scope: KeyRetentionScope,
    pub identity: KeyIdentityRef,
    /// Versions strictly below this bound are retired; the bound itself stays.
    pub retire_below_version: u64,
    /// `Complete` coverage digest from the latest ReadKeyRetention of the scope.
    pub expected_coverage_sha256: String,
}

impl RetireKeyVersionsRequest {
    pub fn validate(&self) -> Result<()> {
        validate_name(&self.retirement_id)?;
        self.scope.validate()?;
        self.identity.validate()?;
        validate_sha256(&self.expected_coverage_sha256)?;
        if self.retire_below_version < 2 {
            return Err(invalid("key retirement must retire at least one version"));
        }
        Ok(())
    }

    pub fn request_sha256(&self) -> Result<String> {
        self.validate()?;
        Ok(staged_digest(&("kasumi.retire-key-versions.v1", self))?.0)
    }

    pub fn retires(&self, key: &KeyVersionRef) -> bool {
        key.is_version_of(&self.identity) && key.version < self.retire_below_version
    }

    /// A retirement is admitted only against the exact complete coverage it
    /// names. Incomplete coverage never admits one, whatever its digest.
    pub fn require_coverage(&self, coverage: &KeyRetentionCoverage) -> Result<()> {
        match coverage {
            KeyRetentionCoverage::Complete {
                coverage_sha256, ..
            } if *coverage_sha256 == self.expected_coverage_sha256 => Ok(()),
            KeyRetentionCoverage::Complete { .. } => Err(Error::new(
                ErrorCode::Conflict,
                "key retention coverage differs from expected",
            )),
            KeyRetentionCoverage::Incomplete { .. } => Err(Error::new(
                ErrorCode::Unavailable,
                "key retention coverage is incomplete",
            )),
        }
    }
}

/// Permanent fence committed by BeginKeyRetirement. While it is present every
/// dependency writer rejects a new reference to a retired version.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KeyRetirementFence {
    pub request: RetireKeyVersionsRequest,
    pub request_sha256: String,
    pub fence_revision: u64,
    pub membership_epoch: u64,
}

impl KeyRetirementFence {
    pub fn validate(&self) -> Result<()> {
        if self.request.request_sha256()? != self.request_sha256 || self.fence_revision == 0 {
            return Err(invalid("key retirement fence binding differs"));
        }
        Ok(())
    }

    pub fn rejects(&self, key: &KeyVersionRef) -> bool {
        self.request.retires(key)
    }
}

/// Permanent completed retirement. Provider actions, such as removing file
/// keyring versions or reporting a Transit minimum decryption version, require
/// this exact record; it is not itself a provider capability.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KeyRetirementRecord {
    pub fence: KeyRetirementFence,
    pub completed_revision: u64,
    /// Complete coverage recomputed after the fence at the fence's membership
    /// epoch, with no reference to a retired version.
    pub completed_coverage_sha256: String,
}

impl KeyRetirementRecord {
    pub fn validate(&self) -> Result<()> {
        self.fence.validate()?;
        validate_sha256(&self.completed_coverage_sha256)?;
        if self.completed_revision <= self.fence.fence_revision {
            return Err(invalid("key retirement completed before its fence"));
        }
        Ok(())
    }

    pub fn retires(&self, key: &KeyVersionRef) -> bool {
        self.fence.request.retires(key)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum KeyRetirementStatus {
    Fenced {
        fence: KeyRetirementFence,
    },
    Completed {
        record: KeyRetirementRecord,
    },
    /// Explicit abort removed the fence; the retirement identity stays spent.
    Aborted {
        fence: KeyRetirementFence,
        aborted_revision: u64,
    },
}

impl KeyRetirementStatus {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Fenced { fence } => fence.validate(),
            Self::Completed { record } => record.validate(),
            Self::Aborted {
                fence,
                aborted_revision,
            } => {
                fence.validate()?;
                if *aborted_revision <= fence.fence_revision {
                    return Err(invalid("key retirement aborted before its fence"));
                }
                Ok(())
            }
        }
    }

    pub fn request(&self) -> &RetireKeyVersionsRequest {
        match self {
            Self::Fenced { fence } | Self::Aborted { fence, .. } => &fence.request,
            Self::Completed { record } => &record.fence.request,
        }
    }
}

fn validate_ascending<T: Ord>(values: &[T], max: usize, name: &str) -> Result<()> {
    if values.len() > max {
        return Err(invalid(format!("{name} exceeds {max} entries")));
    }
    if !values.is_sorted_by(|left, right| left < right) {
        return Err(invalid(format!("{name} is unsorted or duplicated")));
    }
    Ok(())
}

/// Streaming bound and order check: an oversized, unsorted or duplicated
/// sequence is rejected before more than `max` entries are retained.
struct Ascending<T> {
    max: usize,
    name: &'static str,
    marker: PhantomData<T>,
}

impl<'de, T: Deserialize<'de> + Ord> Visitor<'de> for Ascending<T> {
    type Value = Vec<T>;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{} of at most {} strictly ascending entries",
            self.name, self.max
        )
    }

    fn visit_seq<A: SeqAccess<'de>>(
        self,
        mut sequence: A,
    ) -> std::result::Result<Vec<T>, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<T>()? {
            if values.len() == self.max {
                return Err(A::Error::custom(format_args!(
                    "{} exceeds {} entries",
                    self.name, self.max
                )));
            }
            if values.last().is_some_and(|last| *last >= value) {
                return Err(A::Error::custom(format_args!(
                    "{} is unsorted or duplicated",
                    self.name
                )));
            }
            values.push(value);
        }
        Ok(values)
    }
}

fn ascending<'de, D: Deserializer<'de>, T: Deserialize<'de> + Ord>(
    deserializer: D,
    max: usize,
    name: &'static str,
) -> std::result::Result<Vec<T>, D::Error> {
    deserializer.deserialize_seq(Ascending {
        max,
        name,
        marker: PhantomData,
    })
}

fn dependency_versions<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<KeyVersionRef>, D::Error> {
    ascending(deserializer, MAX_KEY_DEPENDENCIES, "key dependency set")
}

fn page_entries<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<KeyRetentionEntry>, D::Error> {
    ascending(
        deserializer,
        usize::from(MAX_KEY_RETENTION_PAGE_ENTRIES),
        "key retention page",
    )
}

fn missing_dependencies<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<MissingKeyDependency>, D::Error> {
    ascending(
        deserializer,
        MAX_MISSING_KEY_DEPENDENCIES,
        "missing key dependencies",
    )
}

fn invalid(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::InvalidArgument, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exact_json::decode_exact;
    use serde::de::DeserializeOwned;
    use serde_json::{Value, json};

    fn version(provider: &str, key_ref: &str, version: u64) -> KeyVersionRef {
        KeyVersionRef {
            provider: provider.into(),
            key_ref: key_ref.into(),
            version,
        }
    }

    fn versions() -> Vec<KeyVersionRef> {
        vec![
            version("file", "keyring-a", 1),
            version("file", "keyring-a", 2),
            version("transit", "https://bao.example/v1/transit/keys/kasumi", 7),
        ]
    }

    fn tenant() -> KeyRetentionScope {
        KeyRetentionScope::Tenant {
            tenant: "tenant".into(),
        }
    }

    fn entry(key_version: u64, session: u128) -> KeyRetentionEntry {
        KeyRetentionEntry {
            key: version("file", "keyring-a", key_version),
            reference: KeyReference::BackupSession {
                session_id: Uuid::from_u128(session),
            },
        }
    }

    fn cursor(scope: &KeyRetentionScope, after: KeyRetentionEntry) -> KeyRetentionCursor {
        KeyRetentionCursor {
            scope_sha256: scope.sha256().unwrap(),
            coverage_revision: 10,
            membership_epoch: 3,
            after,
        }
    }

    fn complete() -> KeyRetentionCoverage {
        KeyRetentionCoverage::Complete {
            coverage_revision: 10,
            membership_epoch: 3,
            coverage_sha256: "c".repeat(64),
        }
    }

    fn missing(count: usize) -> Vec<MissingKeyDependency> {
        (1..=count as u64)
            .map(|node_id| MissingKeyDependency::MemberUnreported { node_id })
            .collect()
    }

    fn incomplete(missing: Vec<MissingKeyDependency>, truncated: bool) -> KeyRetentionCoverage {
        KeyRetentionCoverage::Incomplete {
            coverage_revision: 10,
            membership_epoch: 3,
            missing,
            truncated,
        }
    }

    fn request(limit: u16, cursor: Option<KeyRetentionCursor>) -> ReadKeyRetentionRequest {
        ReadKeyRetentionRequest {
            scope: tenant(),
            cursor,
            limit,
        }
    }

    fn retirement() -> RetireKeyVersionsRequest {
        RetireKeyVersionsRequest {
            retirement_id: "retire-a".into(),
            scope: tenant(),
            identity: KeyIdentityRef {
                provider: "file".into(),
                key_ref: "keyring-a".into(),
            },
            retire_below_version: 2,
            expected_coverage_sha256: "c".repeat(64),
        }
    }

    fn fence() -> KeyRetirementFence {
        KeyRetirementFence {
            request_sha256: retirement().request_sha256().unwrap(),
            request: retirement(),
            fence_revision: 11,
            membership_epoch: 3,
        }
    }

    fn record() -> KeyRetirementRecord {
        KeyRetirementRecord {
            fence: fence(),
            completed_revision: 12,
            completed_coverage_sha256: "d".repeat(64),
        }
    }

    fn references() -> Vec<KeyReference> {
        vec![
            KeyReference::Catalog {
                node_id: 1,
                catalog_id: Uuid::from_u128(1),
                domain: KeyCatalogDomain::Application,
            },
            KeyReference::BackupSession {
                session_id: Uuid::from_u128(2),
            },
            KeyReference::CompletedBackup {
                backup_id: Uuid::from_u128(3),
                checkpoint_sha256: "a".repeat(64),
            },
            KeyReference::AuditArchive {
                stream_id: Uuid::from_u128(4),
                first_sequence: 0,
            },
            KeyReference::HistoryArchive {
                archive_id: "archive".into(),
                object_id: "object".into(),
            },
            KeyReference::RecoveryRecord {
                operation_id: Uuid::from_u128(5),
            },
            KeyReference::TargetJournal {
                node_id: 2,
                incarnation: Uuid::from_u128(6),
            },
            KeyReference::LocalRecovery {
                operation_id: Uuid::from_u128(7),
            },
        ]
    }

    fn all_missing() -> Vec<MissingKeyDependency> {
        vec![
            MissingKeyDependency::SessionIndexUnavailable {},
            MissingKeyDependency::ArchiveUnavailable {
                id: "archive".into(),
            },
            MissingKeyDependency::MemberUnreported { node_id: 4 },
            MissingKeyDependency::RecordUnreadable {
                record_kind: KeyReferenceKind::HistoryArchive,
                id: "archive".into(),
            },
            MissingKeyDependency::ProviderUnavailable {
                identity: version("transit", "key", 1).identity(),
            },
        ]
    }

    fn scopes() -> Vec<KeyRetentionScope> {
        vec![
            tenant(),
            KeyRetentionScope::Control {},
            KeyRetentionScope::SecurityAudit {},
            KeyRetentionScope::Signer {},
            KeyRetentionScope::TargetJournal {},
            KeyRetentionScope::LocalRecovery {},
        ]
    }

    fn statuses() -> Vec<KeyRetirementStatus> {
        vec![
            KeyRetirementStatus::Fenced { fence: fence() },
            KeyRetirementStatus::Completed { record: record() },
            KeyRetirementStatus::Aborted {
                fence: fence(),
                aborted_revision: 12,
            },
        ]
    }

    fn code(result: Result<()>) -> ErrorCode {
        result.unwrap_err().code
    }

    /// Current-writer bytes decode exactly, and one added field at the top
    /// level or inside any nested object is rejected.
    fn exact_and_closed<T: Serialize + DeserializeOwned + PartialEq + fmt::Debug>(value: &T) {
        let bytes = serde_json::to_vec(value).unwrap();
        assert_eq!(
            &decode_exact::<T>(&bytes, 1 << 20, "key retention record").unwrap(),
            value
        );
        let encoded = serde_json::to_value(value).unwrap();
        let mut paths = Vec::new();
        objects(&encoded, &mut Vec::new(), &mut paths);
        assert!(!paths.is_empty());
        for path in paths {
            let mut changed = encoded.clone();
            let mut object = &mut changed;
            for step in &path {
                object = match step {
                    Ok(key) => &mut object[key.as_str()],
                    Err(index) => &mut object[*index],
                };
            }
            object["legacy_field"] = json!(true);
            assert!(
                serde_json::from_value::<T>(changed).is_err(),
                "unknown field accepted at {path:?}"
            );
        }
    }

    fn objects(
        value: &Value,
        path: &mut Vec<std::result::Result<String, usize>>,
        found: &mut Vec<Vec<std::result::Result<String, usize>>>,
    ) {
        match value {
            Value::Object(fields) => {
                found.push(path.clone());
                for (key, value) in fields {
                    path.push(Ok(key.clone()));
                    objects(value, path, found);
                    path.pop();
                }
            }
            Value::Array(values) => {
                for (index, value) in values.iter().enumerate() {
                    path.push(Err(index));
                    objects(value, path, found);
                    path.pop();
                }
            }
            _ => {}
        }
    }

    #[test]
    fn every_record_round_trips_exactly_and_rejects_unknown_fields() {
        exact_and_closed(&version("file", "keyring-a", 1));
        exact_and_closed(&version("file", "keyring-a", 1).identity());
        exact_and_closed(&KeyDependencySet::new(versions()).unwrap());
        for scope in scopes() {
            scope.validate().unwrap();
            exact_and_closed(&scope);
        }
        for reference in references() {
            reference.validate().unwrap();
            exact_and_closed(&KeyRetentionEntry {
                key: version("file", "keyring-a", 1),
                reference,
            });
        }
        for dependency in all_missing() {
            dependency.validate().unwrap();
            exact_and_closed(&dependency);
        }
        let mut sorted = all_missing();
        sorted.sort();
        for coverage in [complete(), incomplete(sorted, false)] {
            coverage.validate().unwrap();
            exact_and_closed(&coverage);
        }
        let first = request(256, None);
        first.validate().unwrap();
        exact_and_closed(&first);
        let next = request(2, Some(cursor(&tenant(), entry(1, 1))));
        next.validate().unwrap();
        exact_and_closed(&next);
        let page = KeyRetentionPage {
            entries: vec![entry(1, 2), entry(2, 1)],
            next_cursor: Some(cursor(&tenant(), entry(2, 1))),
            coverage: complete(),
        };
        page.validate(&next).unwrap();
        exact_and_closed(&page);
        retirement().validate().unwrap();
        exact_and_closed(&retirement());
        exact_and_closed(&fence());
        exact_and_closed(&record());
        for status in statuses() {
            status.validate().unwrap();
            assert_eq!(status.request(), &retirement());
            exact_and_closed(&status);
        }
    }

    #[test]
    fn explicit_nullable_fields_and_empty_variants_are_required_exactly() {
        let mut value = serde_json::to_value(request(1, None)).unwrap();
        value.as_object_mut().unwrap().remove("cursor");
        assert!(serde_json::from_value::<ReadKeyRetentionRequest>(value).is_err());
        let page = KeyRetentionPage {
            entries: vec![],
            next_cursor: None,
            coverage: complete(),
        };
        let mut value = serde_json::to_value(page).unwrap();
        value.as_object_mut().unwrap().remove("next_cursor");
        assert!(serde_json::from_value::<KeyRetentionPage>(value).is_err());
        assert_eq!(
            serde_json::to_value(KeyRetentionScope::Control {}).unwrap(),
            json!({"kind":"control"})
        );
        for text in [
            r#"{"kind":"control","tenant":"tenant"}"#,
            r#"{"kind":"tenant"}"#,
            r#"{"kind":"authority"}"#,
            r#""control""#,
        ] {
            assert!(
                serde_json::from_str::<KeyRetentionScope>(text).is_err(),
                "{text}"
            );
        }
        assert!(
            serde_json::from_str::<MissingKeyDependency>(
                r#"{"kind":"session_index_unavailable","id":"x"}"#
            )
            .is_err()
        );
        assert!(serde_json::from_str::<KeyReference>(r#"{"kind":"catalog","node_id":1}"#).is_err());
    }

    #[test]
    fn key_versions_require_positive_versions_and_bounded_identities() {
        version("f", "k", 1).validate().unwrap();
        version(
            &"p".repeat(MAX_KEY_PROVIDER_BYTES),
            &"k".repeat(MAX_KEY_REF_BYTES),
            u64::MAX,
        )
        .validate()
        .unwrap();
        for bad in [
            version("file", "keyring-a", 0),
            version("", "keyring-a", 1),
            version("file", "", 1),
            version(&"p".repeat(MAX_KEY_PROVIDER_BYTES + 1), "k", 1),
            version("file", &"k".repeat(MAX_KEY_REF_BYTES + 1), 1),
        ] {
            assert_eq!(code(bad.validate()), ErrorCode::InvalidArgument, "{bad:?}");
            assert!(KeyDependencySet::new(vec![bad.clone()]).is_err());
            let encoded = json!({"versions":[bad]});
            assert!(serde_json::from_value::<KeyDependencySet>(encoded).is_err());
        }
        assert!(
            KeyIdentityRef {
                provider: String::new(),
                key_ref: "k".into()
            }
            .validate()
            .is_err()
        );
        let dependency = AuditArchiveKeyDependency {
            provider: "file".into(),
            key_ref: "keyring-a".into(),
            version: 3,
            wrapped_key_sha256: "0".repeat(64),
        };
        assert_eq!(
            KeyVersionRef::from(&dependency),
            version("file", "keyring-a", 3)
        );
    }

    #[test]
    fn dependency_sets_are_sorted_distinct_bounded_and_digest_stably() {
        let set = KeyDependencySet::new(versions()).unwrap();
        assert_eq!(set.versions(), versions().as_slice());
        assert_eq!(set.len(), 3);
        assert!(set.contains(&version("file", "keyring-a", 2)));
        assert!(!set.contains(&version("file", "keyring-a", 3)));
        // Pinned to the exact canonical bytes, independently hashed:
        // ["kasumi.key-dependency-set.v1",{"versions":[...]}].
        assert_eq!(
            set.sha256().unwrap(),
            "51577275125a8f3f6a048c1f68cc33de643fcd06ce1dddd61e6ad52613dd93b8"
        );
        assert_eq!(
            KeyDependencySet::default().sha256().unwrap(),
            "9d8c455dd49154c24a1e0097f73ebfe2340eef215701ba1dc03f3bcd581eb37c"
        );
        assert_eq!(
            KeyDependencySet::from_set(versions().into_iter().rev().collect()).unwrap(),
            set
        );
        let mut changed = versions();
        changed[2].version = 8;
        assert_ne!(
            KeyDependencySet::new(changed).unwrap().sha256().unwrap(),
            set.sha256().unwrap()
        );

        let mut unsorted = versions();
        unsorted.swap(0, 1);
        let mut duplicate = versions();
        duplicate.insert(1, duplicate[0].clone());
        // Numeric, not textual, version order: 10 sorts after 9.
        let numeric = vec![version("f", "k", 9), version("f", "k", 10)];
        KeyDependencySet::new(numeric.clone()).unwrap();
        let mut textual = numeric;
        textual.reverse();
        for bad in [unsorted, duplicate, textual] {
            assert_eq!(
                KeyDependencySet::new(bad.clone()).unwrap_err().code,
                ErrorCode::InvalidArgument
            );
            let encoded = serde_json::to_vec(&json!({ "versions": bad })).unwrap();
            assert!(serde_json::from_slice::<KeyDependencySet>(&encoded).is_err());
        }

        let largest: Vec<_> = (1..=MAX_KEY_DEPENDENCIES as u64)
            .map(|n| version("f", "k", n))
            .collect();
        let bounded = KeyDependencySet::new(largest.clone()).unwrap();
        let encoded = serde_json::to_vec(&bounded).unwrap();
        assert_eq!(
            decode_exact::<KeyDependencySet>(&encoded, encoded.len(), "set").unwrap(),
            bounded
        );
        let mut oversized = largest;
        oversized.push(version("f", "k", MAX_KEY_DEPENDENCIES as u64 + 1));
        assert!(KeyDependencySet::new(oversized.clone()).is_err());
        assert!(KeyDependencySet::from_set(oversized.iter().cloned().collect()).is_err());
        let encoded = serde_json::to_vec(&json!({ "versions": oversized })).unwrap();
        let error = serde_json::from_slice::<KeyDependencySet>(&encoded).unwrap_err();
        assert!(
            error.to_string().contains("exceeds 4096 entries"),
            "{error}"
        );
        assert!(serde_json::from_str::<KeyDependencySet>(r#"[]"#).is_err());
        assert!(serde_json::from_str::<KeyDependencySet>(r#"{}"#).is_err());
    }

    #[test]
    fn limits_outside_one_to_256_are_rejected_not_clamped() {
        for limit in [1, 2, 255, 256] {
            request(limit, None).validate().unwrap();
        }
        for limit in [0, 257, u16::MAX] {
            let request = request(limit, None);
            assert_eq!(code(request.validate()), ErrorCode::InvalidArgument);
            // Validation never rewrites the caller's request.
            assert_eq!(request.limit, limit);
        }
        let mut value = serde_json::to_value(request(1, None)).unwrap();
        for limit in [json!(65536), json!(-1), json!(1.5), json!("1")] {
            value["limit"] = limit.clone();
            assert!(
                serde_json::from_value::<ReadKeyRetentionRequest>(value.clone()).is_err(),
                "{limit}"
            );
        }
        let mut invalid_scope = request(1, None);
        invalid_scope.scope = KeyRetentionScope::Tenant {
            tenant: String::new(),
        };
        assert!(invalid_scope.validate().is_err());
    }

    #[test]
    fn cursors_are_bound_to_scope_revision_and_epoch() {
        let current = cursor(&tenant(), entry(1, 1));
        current.require_current(&tenant(), 10, 3).unwrap();
        for other in scopes()
            .into_iter()
            .skip(1)
            .chain([KeyRetentionScope::Tenant {
                tenant: "other".into(),
            }])
        {
            assert_eq!(
                code(current.require_current(&other, 10, 3)),
                ErrorCode::InvalidArgument
            );
            let request = ReadKeyRetentionRequest {
                scope: other,
                cursor: Some(current.clone()),
                limit: 1,
            };
            assert_eq!(code(request.validate()), ErrorCode::InvalidArgument);
        }
        assert_eq!(
            code(current.require_current(&tenant(), 11, 3)),
            ErrorCode::CursorExpired
        );
        assert_eq!(
            code(current.require_current(&tenant(), 9, 3)),
            ErrorCode::CursorExpired
        );
        assert_eq!(
            code(current.require_current(&tenant(), 10, 4)),
            ErrorCode::CursorExpired
        );
        let mut malformed = current.clone();
        malformed.scope_sha256 = "C".repeat(64);
        assert_eq!(
            code(malformed.require_current(&tenant(), 10, 3)),
            ErrorCode::InvalidArgument
        );
        let mut malformed = current;
        malformed.after.key.version = 0;
        assert!(request(1, Some(malformed)).validate().is_err());
        // The scope digest is domain separated and distinct for every scope.
        let digests: BTreeSet<_> = scopes().iter().map(|s| s.sha256().unwrap()).collect();
        assert_eq!(digests.len(), scopes().len());
    }

    #[test]
    fn pages_follow_the_exact_request_order_limit_and_continuation() {
        let first = request(2, None);
        let page =
            |entries: Vec<KeyRetentionEntry>, next: Option<KeyRetentionCursor>| KeyRetentionPage {
                entries,
                next_cursor: next,
                coverage: complete(),
            };
        page(
            vec![entry(1, 1), entry(1, 2)],
            Some(cursor(&tenant(), entry(1, 2))),
        )
        .validate(&first)
        .unwrap();
        page(vec![entry(1, 1)], None).validate(&first).unwrap();
        page(vec![], None).validate(&first).unwrap();
        // A catalog reference sorts before a session reference of the same key.
        let catalog = KeyRetentionEntry {
            key: version("file", "keyring-a", 1),
            reference: references()[0].clone(),
        };
        page(vec![catalog.clone(), entry(1, 1)], None)
            .validate(&first)
            .unwrap();

        for (bad, code_expected) in [
            // More than the requested limit.
            (
                page(vec![entry(1, 1), entry(1, 2), entry(1, 3)], None),
                ErrorCode::InvalidArgument,
            ),
            // Unsorted or duplicated entries.
            (
                page(vec![entry(1, 2), entry(1, 1)], None),
                ErrorCode::InvalidArgument,
            ),
            (
                page(vec![entry(1, 1), catalog], None),
                ErrorCode::InvalidArgument,
            ),
            (
                page(vec![entry(1, 1), entry(1, 1)], None),
                ErrorCode::InvalidArgument,
            ),
            // A continuation must name the last entry and cannot be empty.
            (
                page(vec![entry(1, 1)], Some(cursor(&tenant(), entry(1, 2)))),
                ErrorCode::InvalidArgument,
            ),
            (
                page(vec![], Some(cursor(&tenant(), entry(1, 1)))),
                ErrorCode::InvalidArgument,
            ),
            (
                page(
                    vec![entry(1, 1)],
                    Some(cursor(&KeyRetentionScope::Control {}, entry(1, 1))),
                ),
                ErrorCode::InvalidArgument,
            ),
            // An invalid entry.
            (page(vec![entry(0, 1)], None), ErrorCode::InvalidArgument),
        ] {
            assert_eq!(code(bad.validate(&first)), code_expected, "{bad:?}");
        }

        let mut stale_next = cursor(&tenant(), entry(1, 1));
        stale_next.coverage_revision = 9;
        assert_eq!(
            code(page(vec![entry(1, 1)], Some(stale_next)).validate(&first)),
            ErrorCode::CursorExpired
        );

        let next = request(2, Some(cursor(&tenant(), entry(1, 2))));
        page(vec![entry(1, 3)], None).validate(&next).unwrap();
        for repeated in [entry(1, 2), entry(1, 1)] {
            assert_eq!(
                code(page(vec![repeated], None).validate(&next)),
                ErrorCode::InvalidArgument
            );
        }
        let mut changed = page(vec![entry(1, 3)], None);
        changed.coverage = KeyRetentionCoverage::Complete {
            coverage_revision: 11,
            membership_epoch: 3,
            coverage_sha256: "c".repeat(64),
        };
        assert_eq!(code(changed.validate(&next)), ErrorCode::CursorExpired);

        let oversized: Vec<_> = (1..=u128::from(MAX_KEY_RETENTION_PAGE_ENTRIES) + 1)
            .map(|session| entry(1, session))
            .collect();
        let encoded = json!({
            "entries": oversized,
            "next_cursor": null,
            "coverage": complete(),
        });
        assert!(serde_json::from_value::<KeyRetentionPage>(encoded).is_err());
        let encoded = json!({
            "entries": [entry(1, 2), entry(1, 1)],
            "next_cursor": null,
            "coverage": complete(),
        });
        assert!(serde_json::from_value::<KeyRetentionPage>(encoded).is_err());
    }

    #[test]
    fn coverage_is_bounded_ordered_and_explicitly_incomplete() {
        incomplete(missing(MAX_MISSING_KEY_DEPENDENCIES), true)
            .validate()
            .unwrap();
        incomplete(missing(1), false).validate().unwrap();
        for bad in [
            incomplete(vec![], false),
            incomplete(vec![], true),
            incomplete(missing(MAX_MISSING_KEY_DEPENDENCIES - 1), true),
            incomplete(missing(MAX_MISSING_KEY_DEPENDENCIES + 1), true),
            incomplete(missing(2).into_iter().rev().collect(), false),
            incomplete(
                vec![MissingKeyDependency::MemberUnreported { node_id: 0 }],
                false,
            ),
            incomplete(
                vec![MissingKeyDependency::ArchiveUnavailable { id: String::new() }],
                false,
            ),
            KeyRetentionCoverage::Complete {
                coverage_revision: 1,
                membership_epoch: 1,
                coverage_sha256: "not-a-digest".into(),
            },
        ] {
            assert_eq!(code(bad.validate()), ErrorCode::InvalidArgument, "{bad:?}");
        }
        let encoded = json!({
            "kind": "incomplete",
            "coverage_revision": 1,
            "membership_epoch": 1,
            "missing": missing(MAX_MISSING_KEY_DEPENDENCIES + 1),
            "truncated": true,
        });
        let error = serde_json::from_value::<KeyRetentionCoverage>(encoded).unwrap_err();
        assert!(error.to_string().contains("exceeds 64 entries"), "{error}");
        let coverage = incomplete(missing(1), false);
        assert_eq!(coverage.coverage_revision(), 10);
        assert_eq!(coverage.membership_epoch(), 3);
    }

    #[test]
    fn references_reject_nil_zero_and_malformed_identities() {
        for bad in [
            KeyReference::Catalog {
                node_id: 0,
                catalog_id: Uuid::from_u128(1),
                domain: KeyCatalogDomain::NodeControl,
            },
            KeyReference::Catalog {
                node_id: 1,
                catalog_id: Uuid::nil(),
                domain: KeyCatalogDomain::NodeControl,
            },
            KeyReference::BackupSession {
                session_id: Uuid::nil(),
            },
            KeyReference::CompletedBackup {
                backup_id: Uuid::from_u128(1),
                checkpoint_sha256: "A".repeat(64),
            },
            KeyReference::CompletedBackup {
                backup_id: Uuid::nil(),
                checkpoint_sha256: "a".repeat(64),
            },
            KeyReference::AuditArchive {
                stream_id: Uuid::nil(),
                first_sequence: 0,
            },
            KeyReference::HistoryArchive {
                archive_id: String::new(),
                object_id: "object".into(),
            },
            KeyReference::HistoryArchive {
                archive_id: "archive".into(),
                object_id: "x".repeat(257),
            },
            KeyReference::RecoveryRecord {
                operation_id: Uuid::nil(),
            },
            KeyReference::TargetJournal {
                node_id: 0,
                incarnation: Uuid::from_u128(1),
            },
            KeyReference::TargetJournal {
                node_id: 1,
                incarnation: Uuid::nil(),
            },
            KeyReference::LocalRecovery {
                operation_id: Uuid::nil(),
            },
        ] {
            assert_eq!(code(bad.validate()), ErrorCode::InvalidArgument, "{bad:?}");
        }
        let kinds: BTreeSet<_> = references().iter().map(KeyReference::kind).collect();
        assert_eq!(kinds.len(), references().len());
        assert!(references().is_sorted());
    }

    #[test]
    fn retirement_requires_complete_matching_coverage_and_bound_records() {
        let request = retirement();
        assert!(request.retires(&version("file", "keyring-a", 1)));
        assert!(!request.retires(&version("file", "keyring-a", 2)));
        assert!(!request.retires(&version("file", "keyring-b", 1)));
        assert!(!request.retires(&version("transit", "keyring-a", 1)));
        assert!(fence().rejects(&version("file", "keyring-a", 1)));
        assert!(record().retires(&version("file", "keyring-a", 1)));
        assert!(!record().retires(&version("file", "keyring-a", 2)));

        for below in [0, 1] {
            let mut bad = retirement();
            bad.retire_below_version = below;
            assert_eq!(code(bad.validate()), ErrorCode::InvalidArgument);
            assert!(bad.request_sha256().is_err());
        }
        let mut bad = retirement();
        bad.retirement_id = String::new();
        assert!(bad.validate().is_err());
        let mut bad = retirement();
        bad.identity.key_ref = String::new();
        assert!(bad.validate().is_err());
        let mut bad = retirement();
        bad.expected_coverage_sha256 = "c".repeat(63);
        assert!(bad.validate().is_err());

        request.require_coverage(&complete()).unwrap();
        let other = KeyRetentionCoverage::Complete {
            coverage_revision: 10,
            membership_epoch: 3,
            coverage_sha256: "e".repeat(64),
        };
        assert_eq!(code(request.require_coverage(&other)), ErrorCode::Conflict);
        assert_eq!(
            code(request.require_coverage(&incomplete(missing(1), false))),
            ErrorCode::Unavailable
        );

        // Every request field is bound into the fence digest.
        let mut changed = retirement();
        changed.retire_below_version = 3;
        assert_ne!(
            changed.request_sha256().unwrap(),
            retirement().request_sha256().unwrap()
        );
        let mut substituted = fence();
        substituted.request = changed;
        assert!(substituted.validate().is_err());
        let mut unfenced = fence();
        unfenced.fence_revision = 0;
        assert!(unfenced.validate().is_err());

        let mut early = record();
        early.completed_revision = early.fence.fence_revision;
        assert!(early.validate().is_err());
        let mut digest = record();
        digest.completed_coverage_sha256 = "invalid".into();
        assert!(digest.validate().is_err());
        assert!(
            KeyRetirementStatus::Aborted {
                fence: fence(),
                aborted_revision: 11,
            }
            .validate()
            .is_err()
        );
        assert!(
            KeyRetirementStatus::Completed { record: early }
                .validate()
                .is_err()
        );
    }
}
