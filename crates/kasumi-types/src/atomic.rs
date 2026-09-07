//! Bounded large-transaction and coherent read-lease contracts.
use crate::{Error, ErrorCode, Mutation, ReadAssertion, Result, WriteReceipt};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Mandatory first-release resource policy; no deserialization defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtomicLimits {
    pub max_operations: usize,
    pub max_read_assertions: usize,
    pub max_transaction_bytes: usize,
    pub max_active_transactions: usize,
    pub max_reserved_staging_bytes: usize,
    pub max_transaction_records: usize,
    pub max_snapshot_leases: usize,
    pub max_snapshot_lease_bytes: usize,
}

impl Default for AtomicLimits {
    fn default() -> Self {
        Self {
            max_operations: 100_000,
            max_read_assertions: 100_000,
            max_transaction_bytes: 64 << 20,
            max_active_transactions: 8,
            max_reserved_staging_bytes: 128 << 20,
            max_transaction_records: 100_000,
            max_snapshot_leases: 8,
            max_snapshot_lease_bytes: 256 << 20,
        }
    }
}

pub const MAX_STAGED_CHUNKS: usize = 512;
pub const STAGED_OUTCOME_HEADROOM: usize = 8192;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagedChunk {
    pub read_set: Vec<ReadAssertion>,
    pub operations: Vec<Mutation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StagedManifest {
    pub chunk_digests: Vec<String>,
    pub encoded_chunk_bytes: usize,
    pub operation_count: usize,
    pub read_assertion_count: usize,
    pub read_collections: BTreeSet<String>,
    pub write_collections: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeginStagedTransaction {
    pub transaction_id: String,
    pub manifest: StagedManifest,
    pub ttl_ms: u64,
}

/// Permanent stop binds the exact original Begin input. Admission assertions
/// belong to this attempt and never become its permanent identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopStagedTransaction {
    pub original: BeginStagedTransaction,
    pub admission: Vec<ReadAssertion>,
}

impl BeginStagedTransaction {
    pub fn reference(&self) -> Result<StagedTransactionRef> {
        crate::validate_name(&self.transaction_id)?;
        Ok(StagedTransactionRef {
            transaction_id: self.transaction_id.clone(),
            manifest_digest: staged_digest(&self.manifest)?.0,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagedTransactionRef {
    pub transaction_id: String,
    pub manifest_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppendStagedChunk {
    pub transaction: StagedTransactionRef,
    pub index: usize,
    pub chunk: StagedChunk,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum StagedOutcome {
    Uploading,
    Finished { outcome: Result<WriteReceipt> },
    Aborted { receipt: WriteReceipt },
    Expired { receipt: WriteReceipt },
}

impl StagedOutcome {
    pub fn resolved(&self) -> Option<Result<WriteReceipt>> {
        match self {
            Self::Uploading => None,
            Self::Finished { outcome } => Some(outcome.clone()),
            Self::Aborted { .. } => Some(Err(Error::new(
                ErrorCode::Conflict,
                "staged transaction aborted",
            ))),
            Self::Expired { .. } => Some(Err(Error::new(
                ErrorCode::Conflict,
                "staged upload expired",
            ))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagedTransactionStatus {
    pub transaction: StagedTransactionRef,
    pub manifest: StagedManifest,
    pub received_chunks: Vec<usize>,
    #[serde(deserialize_with = "required_expiry")]
    pub expires_at_ms: Option<u64>,
    pub outcome: StagedOutcome,
}

// Option records an explicitly absent lease; a missing first-release wire field
// must not silently become a never-started stop.
fn required_expiry<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<u64>, D::Error> {
    Option::<u64>::deserialize(deserializer)
}

/// Replicated internal staging state. Payloads never enter document indexes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StagedTransaction {
    pub principal: String,
    pub transaction_id: String,
    pub manifest_digest: String,
    pub manifest: StagedManifest,
    pub chunks: BTreeMap<usize, Arc<StagedChunk>>,
    /// Exact encoded chunk map contents excluding its framing braces/commas.
    pub stored_chunk_bytes: usize,
    pub uploaded_payload_bytes: usize,
    pub uploaded_operations: usize,
    pub uploaded_read_assertions: usize,
    #[serde(deserialize_with = "required_expiry")]
    pub expires_at_ms: Option<u64>,
    pub ttl_ms: u64,
    pub outcome: StagedOutcome,
}

impl StagedTransaction {
    pub fn status(&self) -> StagedTransactionStatus {
        StagedTransactionStatus {
            transaction: StagedTransactionRef {
                transaction_id: self.transaction_id.clone(),
                manifest_digest: self.manifest_digest.clone(),
            },
            manifest: self.manifest.clone(),
            received_chunks: self.chunks.keys().copied().collect(),
            expires_at_ms: self.expires_at_ms,
            outcome: self.outcome.clone(),
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self.outcome, StagedOutcome::Uploading)
    }
}

/// Canonical JSON SHA-256 and length, without a second encoded payload buffer.
pub fn staged_digest(value: &impl Serialize) -> Result<(String, usize)> {
    use sha2::{Digest, Sha256};
    struct Writer {
        digest: Sha256,
        bytes: usize,
    }
    impl std::io::Write for Writer {
        fn write(&mut self, value: &[u8]) -> std::io::Result<usize> {
            self.bytes = self
                .bytes
                .checked_add(value.len())
                .ok_or_else(|| std::io::Error::other("staging size overflow"))?;
            self.digest.update(value);
            Ok(value.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = Writer {
        digest: Sha256::new(),
        bytes: 0,
    };
    serde_json::to_writer(&mut writer, value)
        .map_err(|_| Error::new(ErrorCode::InvalidArgument, "staging encoding failed"))?;
    Ok((format!("{:x}", writer.digest.finalize()), writer.bytes))
}

impl StagedManifest {
    /// Build one immutable manifest after the caller has assembled and
    /// deduplicated its complete read set and split it into bounded chunks.
    pub fn from_chunks(chunks: &[StagedChunk]) -> Result<Self> {
        if chunks.is_empty() || chunks.len() > MAX_STAGED_CHUNKS {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "staged chunk count outside bounds",
            ));
        }
        let mut manifest = Self {
            chunk_digests: Vec::with_capacity(chunks.len()),
            encoded_chunk_bytes: 0,
            operation_count: 0,
            read_assertion_count: 0,
            read_collections: BTreeSet::new(),
            write_collections: BTreeSet::new(),
        };
        for chunk in chunks {
            let (digest, bytes) = staged_digest(chunk)?;
            manifest.chunk_digests.push(digest);
            manifest.encoded_chunk_bytes = add(manifest.encoded_chunk_bytes, bytes)?;
            manifest.operation_count = add(manifest.operation_count, chunk.operations.len())?;
            manifest.read_assertion_count =
                add(manifest.read_assertion_count, chunk.read_set.len())?;
            for assertion in &chunk.read_set {
                if let ReadAssertion::Document { collection, .. }
                | ReadAssertion::Collection { collection, .. } = assertion
                {
                    manifest.read_collections.insert(collection.clone());
                }
            }
            for mutation in &chunk.operations {
                manifest
                    .write_collections
                    .insert(mutation.target().0.into());
            }
        }
        Ok(manifest)
    }
}

fn add(previous: usize, value: usize) -> Result<usize> {
    previous
        .checked_add(value)
        .ok_or_else(|| Error::new(ErrorCode::ResourceExhausted, "staging size overflow"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenSnapshotLease {
    pub ttl_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotLease {
    pub lease_id: String,
    pub revision: u64,
    pub incarnation: String,
    pub policy_epoch: u64,
    pub schema_epoch: u64,
    pub ttl_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadSnapshotPage {
    pub lease_id: String,
    pub documents: Vec<crate::DocumentKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanSnapshotPage {
    pub lease_id: String,
    pub collection: String,
    pub after_id: Option<String>,
    pub limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotScanPage {
    pub snapshot: SnapshotLease,
    pub collection: String,
    pub data_epoch: u64,
    pub documents: Vec<crate::Document>,
    pub next_after_id: Option<String>,
}
