//! Durable change feeds and verified archive contracts. All fields are v1 inputs.
use crate::{Document, Error, ErrorCode, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, sync::Arc};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryLimits {
    pub max_feed_events: usize,
    pub max_feed_bytes: usize,
    pub max_archive_segments: usize,
}
impl Default for HistoryLimits {
    fn default() -> Self {
        Self {
            max_feed_events: 100_000,
            max_feed_bytes: 128 << 20,
            max_archive_segments: 4096,
        }
    }
}

/// Operational documents cannot be moved out of their resident namespace.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CollectionRetentionClass {
    Operational,
    ArchivableHistory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeRecord {
    pub collection: String,
    pub id: String,
    /// Full immutable after-image, or None for a deletion.
    pub document: Option<Arc<Document>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeCommit {
    pub revision: u64,
    pub first_sequence: u64,
    pub records: Vec<ChangeRecord>,
    /// Exact canonical encoded records, excluding vector framing.
    pub record_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeFeedState {
    /// The next globally unique event sequence in this incarnation.
    pub next_sequence: u64,
    pub commits: imbl::OrdMap<u64, Arc<ChangeCommit>>,
    pub event_count: usize,
    pub encoded_commit_bytes: usize,
}
impl ChangeFeedState {
    pub fn empty() -> Self {
        Self {
            next_sequence: 1,
            commits: imbl::OrdMap::new(),
            event_count: 0,
            encoded_commit_bytes: 0,
        }
    }
    pub fn first_available_sequence(&self) -> u64 {
        self.commits
            .get_min()
            .map_or(self.next_sequence, |(sequence, _)| *sequence)
    }
}

/// A resumable position, never an authorization grant. Every field is checked
/// against current trusted request identity, collection scope and incarnation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChangeFeedCursor {
    pub tenant: String,
    pub incarnation: String,
    pub principal: String,
    pub collections: BTreeSet<String>,
    pub after_sequence: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ChangeFeedStart {
    /// From incarnation sequence one; yields RetentionGap if it has expired.
    Beginning,
    /// Establish a position at the currently committed head, returning no events.
    Now,
    After {
        cursor: ChangeFeedCursor,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadChangeFeed {
    pub collections: BTreeSet<String>,
    pub start: ChangeFeedStart,
    pub limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeEvent {
    pub sequence: u64,
    pub revision: u64,
    pub ordinal: usize,
    pub commit_event_count: usize,
    pub collection: String,
    pub id: String,
    pub document: Option<Arc<Document>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ChangeFeedPage {
    Events {
        revision: u64,
        first_available_sequence: u64,
        head_sequence: u64,
        events: Vec<ChangeEvent>,
        next: ChangeFeedCursor,
        caught_up: bool,
    },
    RetentionGap {
        first_available_sequence: u64,
        head_sequence: u64,
        requested_after_sequence: u64,
    },
}

pub const MAX_ARCHIVE_CHUNK_BYTES: usize = 8 << 20;
pub const MAX_ARCHIVE_CHUNKS: usize = 4096;
pub const MAX_ARCHIVE_MANIFEST_BYTES: usize = 4 << 20;
pub const MAX_ARCHIVE_DOCUMENTS: usize = 100_000;
pub const MAX_ARCHIVE_SOURCE_BYTES: usize = 64 << 20;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArchivedDocument {
    pub version: u64,
    pub archive_id: String,
    pub chunk_index: usize,
    pub document_sha256: String,
    pub document_bytes: usize,
    /// Exact declared structured index fields preserve uniqueness and candidate
    /// planning without retaining the rest of an archived document body.
    pub indexed_fields: std::collections::BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArchiveChunkDescriptor {
    pub object_id: String,
    pub ciphertext_sha256: String,
    pub plaintext_sha256: String,
    pub plaintext_bytes: usize,
    pub document_count: usize,
    pub first_id: String,
    pub last_id: String,
}

/// This is a subset of logical history and is never a full database backup.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HistoryArchiveManifest {
    pub kind: HistoryArchiveKind,
    pub archive_id: String,
    pub tenant: String,
    pub source_incarnation: String,
    pub collection: String,
    pub cutoff_revision: u64,
    pub source_schema_epoch: u64,
    pub destination: String,
    pub document_count: usize,
    pub chunks: Vec<ArchiveChunkDescriptor>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HistoryArchiveKind {
    HistorySubset,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryArchiveChunk {
    pub kind: HistoryArchiveKind,
    pub archive_id: String,
    pub source_incarnation: String,
    pub collection: String,
    pub index: usize,
    pub documents: Vec<Arc<Document>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveHistory {
    pub archive_id: String,
    pub collection: String,
    pub cutoff_revision: u64,
    /// An operator-installed destination alias, never a caller-supplied URL.
    pub destination: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishHistoryArchive {
    pub manifest: HistoryArchiveManifest,
    pub manifest_object_id: String,
    pub manifest_ciphertext_sha256: String,
    pub expected_policy_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetainedHistoryArchive {
    /// Current operator binding, distinct from immutable source provenance.
    pub storage_destination: String,
    pub manifest: HistoryArchiveManifest,
    pub manifest_object_id: String,
    pub manifest_ciphertext_sha256: String,
    pub published_revision: u64,
}

pub fn validate_sha256(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
    {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "invalid SHA-256 digest",
        ));
    }
    Ok(())
}
