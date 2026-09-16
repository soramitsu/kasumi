//! Transport-independent, exact JSON contracts shared by every Kasumi interface.
mod ordered_seek;
pub use ordered_seek::*;
mod security_audit;
pub use security_audit::*;
mod audit;
pub use audit::*;
mod canonical_json;
pub use canonical_json::CanonicalJsonValue;
mod canonical_keys;
pub use canonical_keys::deserialize_u64_map;
mod target;
pub use target::*;
mod authority_protocol;
pub use authority_protocol::*;
mod target_runtime_protocol;
pub use target_runtime_protocol::*;
mod recovery;
pub use recovery::*;
mod lifecycle;
pub use lifecycle::*;
mod authorization;
pub use authorization::{CredentialLiveness, RequestAuthorization};
mod credential_resource;
mod credentials;
pub use credentials::*;
mod restore_lineage;
pub use credential_resource::CredentialResource;
pub use restore_lineage::*;
mod backup;
pub use backup::*;
mod atomic;
pub use atomic::*;
mod history;
pub use history::*;
mod retirement;
pub use retirement::*;
mod custody;
pub use custody::*;
mod schema;
pub use schema::*;
mod signing;
use serde::{Deserialize, Serialize};
use serde_json::Value;
pub use signing::*;
use std::collections::{BTreeMap, BTreeSet};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Serialize, Deserialize, thiserror::Error)]
#[error("{code:?}: {message}")]
pub struct Error {
    pub code: ErrorCode,
    #[serde(deserialize_with = "Error::deserialize_message")]
    pub message: String,
    // Request-local composition state. Never accepted from or sent over a wire,
    // and never persisted in an idempotency receipt.
    #[serde(skip)]
    denial_audit_attempted: bool,
}
impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Error")
            .field("code", &self.code)
            .field("message", &self.message)
            .finish()
    }
}
impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        self.code == other.code && self.message == other.message
    }
}
impl Eq for Error {}
impl Error {
    // Keep worst-case JSON/base64 details plus percent-encoded gRPC messages
    // below common 8 KiB header budgets, including protocol framing.
    pub const MAX_MESSAGE_BYTES: usize = 512;

    /// Internal adapter composition; a new request or deserialized receipt always
    /// starts without this marker. It is not a claim that the audit write succeeded.
    #[doc(hidden)]
    pub fn denial_audit_attempted(&self) -> bool {
        self.denial_audit_attempted
    }

    #[doc(hidden)]
    pub fn mark_denial_audit_attempted(&mut self) {
        self.denial_audit_attempted = true;
    }

    fn bounded_message(mut message: String) -> String {
        if message.len() > Self::MAX_MESSAGE_BYTES {
            let mut end = Self::MAX_MESSAGE_BYTES - 3;
            while !message.is_char_boundary(end) {
                end -= 1;
            }
            // Drop the original allocation so retained receipts cannot keep
            // a large document property path alive behind a truncated string.
            let mut bounded = String::with_capacity(Self::MAX_MESSAGE_BYTES);
            bounded.push_str(&message[..end]);
            bounded.push_str("...");
            message = bounded;
        }
        message
    }

    fn deserialize_message<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<String, D::Error> {
        String::deserialize(deserializer).map(Self::bounded_message)
    }

    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: Self::bounded_message(message.into()),
            denial_audit_attempted: false,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    InvalidArgument,
    Unauthorized,
    Forbidden,
    NotFound,
    AlreadyExists,
    Conflict,
    SchemaViolation,
    QuotaExceeded,
    ResourceExhausted,
    IndexRequired,
    CursorExpired,
    Unavailable,
    UnknownOutcome,
    Corruption,
    Sealed,
    AuditUnavailable,
}

/// Constructed by the authentication boundary, never from remote operation input.
/// Embedding applications are trusted and may provide their own verified context.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestContext {
    pub authorization: RequestAuthorization,
    pub principal: String,
    pub tenant: String,
    pub scopes: BTreeSet<Action>,
    pub request_id: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Read,
    Write,
    Admin,
    Audit,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Grant {
    pub principal: String,
    pub collection: Option<String>,
    pub actions: BTreeSet<Action>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Policy {
    pub grants: Vec<Grant>,
    pub strict_read_audit: bool,
}
impl Policy {
    pub fn allows(
        &self,
        context: &RequestContext,
        collection: Option<&str>,
        action: Action,
    ) -> bool {
        context.scopes.contains(&action)
            && self.grants.iter().any(|g| {
                g.principal == context.principal
                    && g.actions.contains(&action)
                    && (g.collection.is_none() || g.collection.as_deref() == collection)
            })
    }
}

/// Default resource quota; the streaming format has no aggregate size ceiling.
pub fn default_snapshot_bytes() -> u64 {
    3 << 29
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub history: HistoryLimits,
    pub atomic: AtomicLimits,
    pub max_document_bytes: usize,
    pub max_batch_operations: usize,
    pub max_batch_bytes: usize,
    pub max_documents: u64,
    pub max_collections: usize,
    pub max_schema_bytes: usize,
    pub max_schema_activation_bytes: u64,
    pub max_retirement_bytes: u64,
    pub max_policy_grants: usize,
    pub max_logical_bytes: u64,
    pub max_snapshot_bytes: u64,
    pub max_receipts: usize,
    pub audit_retention: AuditRetentionBudget,
    pub max_query_candidates: usize,
    pub max_query_groups: usize,
    pub max_result_bytes: usize,
    pub max_page_size: usize,
    pub max_cursors: usize,
    pub max_cursor_bytes: usize,
    pub cursor_ttl_ms: u64,
    pub receipt_ttl_ms: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            atomic: AtomicLimits::default(),
            history: HistoryLimits::default(),
            max_document_bytes: 1 << 20,
            max_batch_operations: 256,
            max_batch_bytes: 8 << 20,
            max_documents: 1_000_000,
            max_collections: 128,
            max_schema_bytes: 8 << 20,
            max_schema_activation_bytes: 64 << 20,
            max_retirement_bytes: 64 << 20,
            max_policy_grants: 4096,
            max_logical_bytes: 1 << 30,
            max_snapshot_bytes: default_snapshot_bytes(),
            max_receipts: 100_000,
            audit_retention: AuditRetentionBudget::default(),
            max_query_candidates: 100_000,
            max_query_groups: 10_000,
            max_result_bytes: 8 << 20,
            max_page_size: 1000,
            max_cursors: 128,
            max_cursor_bytes: 64 << 20,
            cursor_ttl_ms: 60_000,
            receipt_ttl_ms: 86_400_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Document {
    pub id: String,
    pub version: u64,
    #[serde(serialize_with = "canonical_json::serialize")]
    pub body: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CollectionDefinition {
    pub name: String,
    pub write_mode: CollectionWriteMode,
    pub retention_class: CollectionRetentionClass,
    #[serde(serialize_with = "canonical_json::serialize")]
    pub schema: Value,
    #[serde(default)]
    pub indexes: Vec<IndexDefinition>,
    #[serde(default)]
    pub strict_read_audit: bool,
}

/// Append-only protection is enforced during ordered application, including
/// administrative callers. A collection cannot later weaken this protection.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CollectionWriteMode {
    Mutable,
    AppendOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionState {
    pub definition: CollectionDefinition,
    /// Last committed document-change revision; reads, denials and replays do
    /// not change it. Schema changes are fenced separately by schema_epoch.
    pub data_epoch: u64,
    #[serde(serialize_with = "serialize_resident_map")]
    // Leaf copy-on-write clones Arc handles, never unrelated JSON bodies.
    pub documents: imbl::OrdMap<String, std::sync::Arc<Document>>,
    #[serde(serialize_with = "serialize_resident_map")]
    pub archived_documents: imbl::OrdMap<String, std::sync::Arc<ArchivedDocument>>,
    pub archived_document_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IndexDefinition {
    pub name: String,
    pub fields: Vec<IndexField>,
    #[serde(default)]
    pub unique: bool,
    #[serde(default)]
    pub text: Option<TextIndex>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IndexField {
    pub path: String,
    pub kind: ScalarType,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScalarType {
    String,
    Number,
    Boolean,
    Decimal,
    StringArray,
    NumberArray,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TextIndex {
    pub analyzer: Analyzer,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Analyzer {
    UnicodeV1,
    EnglishV1,
    JapaneseV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Mutation {
    Put {
        collection: String,
        id: String,
        #[serde(serialize_with = "canonical_json::serialize")]
        body: Value,
        #[serde(default)]
        expected: Precondition,
    },
    Delete {
        collection: String,
        id: String,
        #[serde(default)]
        expected: Precondition,
    },
}
impl Mutation {
    pub fn target(&self) -> (&str, &str) {
        match self {
            Self::Put { collection, id, .. } | Self::Delete { collection, id, .. } => {
                (collection, id)
            }
        }
    }
    pub fn expected(&self) -> &Precondition {
        match self {
            Self::Put { expected, .. } | Self::Delete { expected, .. } => expected,
        }
    }
}
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "version", rename_all = "snake_case")]
pub enum Precondition {
    #[default]
    Any,
    Absent,
    Version(u64),
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MutationBatch {
    pub idempotency_key: String,
    pub read_set: Vec<ReadAssertion>,
    pub operations: Vec<Mutation>,
}

impl MutationBatch {
    /// Exact canonical input identity retained with the mutation outcome.
    /// Includes the original idempotency key, read set and preconditions.
    pub fn digest(&self) -> Result<String> {
        staged_digest(self).map(|(digest, _)| digest)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "kind",
    content = "version",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ReadPrecondition {
    Absent,
    Version(u64),
}

/// Read-only dependencies checked against one pre-write state, after exact
/// idempotent replay. Collection epochs fence inserts/deletes (phantoms).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReadAssertion {
    /// Trusted execution-admission time must not exceed this bound. Replicas
    /// evaluate the leader-stamped command time, never their local wall clock.
    Before {
        not_after_ms: u64,
    },
    Snapshot {
        incarnation: String,
        policy_epoch: u64,
        schema_epoch: u64,
    },
    Document {
        collection: String,
        id: String,
        expected: ReadPrecondition,
    },
    Collection {
        collection: String,
        data_epoch: u64,
    },
}

/// All nondeterministic values (identity, time, IDs) are fixed before proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Command {
    pub context: RequestContext,
    pub timestamp_ms: u64,
    pub operation: Operation,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", content = "data", rename_all = "snake_case")]
pub enum Operation {
    LifecycleControl(LifecycleControlCommand),
    ActivateSchema(SchemaChangeSet),
    PublishHistoryArchive(PublishHistoryArchive),
    Mutate(MutationBatch),
    BeginStaged(BeginStagedTransaction),
    AppendStaged(AppendStagedChunk),
    FinalizeStaged(StagedTransactionRef),
    StopStaged(StopStagedTransaction),
    CreateCollection(CollectionDefinition),
    ReplaceCollection(CollectionDefinition),
    SetPolicy(Policy),
    SetLimits(Limits),
    Suspend(bool),
    /// Terminal fence for a replaced incarnation; only restore creates a new one.
    RetireSource(PreparedRetirement),
    AbortRetirement(RetireSourceRequest),
    Audit(AuditEvent),
    MaintenanceAudit(AuditEvent),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WriteReceipt {
    pub revision: u64,
    pub versions: BTreeMap<String, u64>,
}
/// A retained outcome is meaningful only for this exact original batch digest.
/// Absence of this record is not proof that an invocation never committed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MutationReceipt {
    pub scope: MutationReceiptScope,
    pub request_digest: String,
    pub outcome: Result<WriteReceipt>,
}
/// Retain this expected namespace with the original invocation across renewals.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MutationReceiptScope {
    pub tenant: String,
    pub incarnation: String,
    pub principal: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredReceipt {
    pub scope: MutationReceiptScope,
    pub idempotency_key: String,
    pub recorded_revision: u64,
    pub request_digest: String,
    pub expires_at_ms: u64,
    pub collections: Vec<String>,
    pub outcome: Result<WriteReceipt>,
}
impl StoredReceipt {
    pub fn validate_identity(
        &self,
        key: &str,
        tenant: &str,
        genesis_revision: u64,
        maximum_revision: u64,
    ) -> Result<()> {
        validate_name(&self.scope.tenant)?;
        validate_name(&self.scope.incarnation)?;
        validate_name(&self.scope.principal)?;
        validate_name(&self.idempotency_key)?;
        validate_sha256(&self.request_digest)?;
        let (identity, _) = staged_digest(&(&self.scope.principal, &self.idempotency_key))?;
        if self.scope.tenant != tenant
            || identity != key
            || self.recorded_revision <= genesis_revision
            || self.recorded_revision > maximum_revision
            || self.expires_at_ms == 0
            || self
                .outcome
                .as_ref()
                .is_ok_and(|r| r.revision != self.recorded_revision)
        {
            return Err(Error::new(
                ErrorCode::Corruption,
                "receipt original identity or position differs",
            ));
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_id: String,
    pub principal: String,
    pub action: String,
    pub request_id: String,
    pub timestamp_ms: u64,
    pub data_revision: Option<u64>,
    pub outcome: String,
    pub collection: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantState {
    pub tenant: String,
    pub incarnation: String,
    pub revision: u64,
    /// Logical revisions stay increasing when a backup starts a new Raft history.
    pub revision_base: u64,
    pub policy_epoch: u64,
    pub schema_epoch: u64,
    pub suspended: bool,
    pub retired: bool,
    pub pending_restore: Option<PendingRestore>,
    pub restored_from: Option<FullBackupCheckpoint>,
    pub restore_lineage: Vec<RestoreLineageLink>,
    #[serde(deserialize_with = "require_explicit_option")]
    pub lifecycle_control: Option<LifecycleControlState>,
    pub target_lifecycle: imbl::OrdMap<String, TargetExecutionState>,
    pub recovery_control: RecoveryControlState,
    pub document_count: u64,
    pub logical_bytes: u64,
    pub policy: Policy,
    pub limits: Limits,
    pub collections: BTreeMap<String, CollectionState>,
    #[serde(serialize_with = "serialize_resident_map")]
    pub receipts: imbl::OrdMap<String, StoredReceipt>,
    #[serde(serialize_with = "serialize_resident_map")]
    pub staged_transactions: imbl::OrdMap<String, StagedTransaction>,
    pub active_staged_transactions: BTreeSet<String>,
    /// Exact canonical headers and point identities; uploaded chunks are separate.
    pub permanent_staged_bytes: u64,
    /// Outstanding capacity owned by active stages for counter growth and termination.
    pub reserved_staged_terminal_bytes: u64,
    pub change_feed: ChangeFeedState,
    #[serde(serialize_with = "serialize_resident_map")]
    pub history_archives: imbl::OrdMap<String, std::sync::Arc<RetainedHistoryArchive>>,
    pub history_archive_bytes: usize,
    #[serde(serialize_with = "serialize_resident_map")]
    pub schema_activations: imbl::OrdMap<String, StoredSchemaActivation>,
    pub schema_activation_bytes: u64,
    #[serde(serialize_with = "serialize_resident_map")]
    pub retirements: imbl::OrdMap<String, StoredRetirement>,
    pub retirement_bytes: u64,
    pub audit_retention: AuditRetentionState,
    pub audits: imbl::Vector<AuditEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingRestore {
    pub backup_id: String,
    pub source_revision: u64,
}

/// Hash randomization must not change snapshot identity across replicas. Sort
/// borrowed map entries while serializing, without cloning document bodies.
fn serialize_resident_map<V: Serialize + Clone, S: serde::Serializer>(
    map: &imbl::OrdMap<String, V>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    map.serialize(serializer)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Predicate {
    #[default]
    All,
    Eq {
        field: String,
        value: Value,
    },
    In {
        field: String,
        values: Vec<Value>,
    },
    Compare {
        field: String,
        comparison: Comparison,
        value: Value,
    },
    Exists {
        field: String,
        exists: bool,
    },
    Contains {
        field: String,
        value: Value,
    },
    And {
        predicates: Vec<Predicate>,
    },
    Or {
        predicates: Vec<Predicate>,
    },
    Not {
        predicate: Box<Predicate>,
    },
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Comparison {
    Lt,
    Lte,
    Gt,
    Gte,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Sort {
    pub field: String,
    pub direction: Direction,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Asc,
    Desc,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Aggregation {
    pub alias: String,
    pub function: AggregateFunction,
    pub field: Option<String>,
    pub scale: Option<i64>,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AggregateFunction {
    Count,
    Sum,
    Min,
    Max,
    Avg,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TextSearch {
    pub index: String,
    pub query: String,
    pub mode: TextMode,
    #[serde(default = "default_distance")]
    pub distance: u8,
}
fn default_distance() -> u8 {
    1
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TextMode {
    Terms,
    Phrase,
    Prefix,
    Fuzzy,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct QueryRequest {
    pub collection: String,
    #[serde(default)]
    pub filter: Predicate,
    #[serde(default)]
    pub sort: Vec<Sort>,
    #[serde(default)]
    pub projection: Vec<String>,
    #[serde(default)]
    pub aggregates: Vec<Aggregation>,
    #[serde(default)]
    pub group_by: Vec<String>,
    #[serde(default)]
    pub text: Option<TextSearch>,
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub allow_scan: bool,
}
fn default_limit() -> usize {
    100
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QueryRow {
    pub id: String,
    pub version: u64,
    pub body: Value,
    pub score: Option<f32>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QueryResponse {
    pub revision: u64,
    pub rows: Vec<QueryRow>,
    pub aggregates: Vec<Value>,
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct DocumentKey {
    pub collection: String,
    pub id: String,
}

/// A bounded, complete read from one generation. Queries cannot use cursors;
/// exceeding a requested row limit fails instead of returning a partial set.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ReadSnapshotRequest {
    pub documents: Vec<DocumentKey>,
    pub queries: Vec<QueryRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SnapshotDocument {
    pub key: DocumentKey,
    pub document: Option<Document>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SnapshotReadResponse {
    pub revision: u64,
    pub incarnation: String,
    pub policy_epoch: u64,
    pub schema_epoch: u64,
    pub collection_epochs: BTreeMap<String, u64>,
    pub documents: Vec<SnapshotDocument>,
    pub queries: Vec<QueryResponse>,
}

impl SnapshotReadResponse {
    /// Conservative serializable read set: querying a collection fences all
    /// writes in that collection. Point reads fence only their exact document.
    pub fn read_assertions(&self) -> Vec<ReadAssertion> {
        let mut result = vec![ReadAssertion::Snapshot {
            incarnation: self.incarnation.clone(),
            policy_epoch: self.policy_epoch,
            schema_epoch: self.schema_epoch,
        }];
        for row in &self.documents {
            result.push(ReadAssertion::Document {
                collection: row.key.collection.clone(),
                id: row.key.id.clone(),
                expected: row
                    .document
                    .as_ref()
                    .map_or(ReadPrecondition::Absent, |document| {
                        ReadPrecondition::Version(document.version)
                    }),
            });
        }
        for (collection, data_epoch) in &self.collection_epochs {
            result.push(ReadAssertion::Collection {
                collection: collection.clone(),
                data_epoch: *data_epoch,
            });
        }
        result
    }
}

pub fn validate_name(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 256 || value.chars().any(|c| c.is_control()) {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "name must contain 1–256 bytes without control characters",
        ));
    }
    Ok(())
}

/// First-release nullable wire fields must be present explicitly. Serde's
/// implicit missing-Option behavior is not a version migration mechanism.
pub fn require_explicit_option<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn denial_audit_marker_is_request_local_and_never_wire_controlled() {
        let plain = Error::new(ErrorCode::Forbidden, "access denied");
        let mut audited = plain.clone();
        audited.mark_denial_audit_attempted();
        assert!(audited.clone().denial_audit_attempted());
        assert_eq!(plain, audited);
        assert_eq!(format!("{plain:?}"), format!("{audited:?}"));
        let encoded = serde_json::to_value(&audited).unwrap();
        assert_eq!(
            encoded,
            serde_json::json!({"code":"FORBIDDEN","message":"access denied"})
        );
        let recovered: Error = serde_json::from_value(encoded).unwrap();
        assert!(!recovered.denial_audit_attempted());
        let injected: Error = serde_json::from_value(serde_json::json!({
            "code":"FORBIDDEN","message":"access denied","denial_audit_attempted":true
        }))
        .unwrap();
        assert!(!injected.denial_audit_attempted());
    }
    #[test]
    fn error_messages_bound_utf8_and_recovered_receipt_allocations() {
        let error = Error::new(ErrorCode::SchemaViolation, "猫".repeat(400_000));
        assert_eq!(error.code, ErrorCode::SchemaViolation);
        assert!(error.message.len() <= Error::MAX_MESSAGE_BYTES);
        assert!(error.message.ends_with("..."));
        assert!(error.message.capacity() <= Error::MAX_MESSAGE_BYTES);
        let recovered: Error = serde_json::from_value(serde_json::json!({
            "code":"SCHEMA_VIOLATION", "message":"猫".repeat(400_000)
        }))
        .unwrap();
        assert_eq!(recovered, error);
        let unchanged = Error::new(ErrorCode::UnknownOutcome, "resolve operation receipt");
        assert_eq!(unchanged.message, "resolve operation receipt");
    }
    #[test]
    fn exact_number_wire_round_trip() {
        let text = r#"{"n":900719925474099312345678901234567890.123456789}"#;
        let value: Value = serde_json::from_str(text).unwrap();
        assert_eq!(serde_json::to_string(&value).unwrap(), text);
    }
    #[test]
    fn remote_mutation_fields_are_closed() {
        assert!(
            serde_json::from_value::<MutationBatch>(
                serde_json::json!({"read_set":[],"idempotency_key":"x","operations":[],"principal":"admin"})
            )
            .is_err()
        );
    }
}
