//! Durable, append-only Kasumi records for a Taira deployment operation.
//!
//! This crate never submits to Taira. A caller must verify each transaction and
//! object against its installed Taira endpoint before recording a phase proof,
//! and must verify the chain again before treating a recorded completion as live.
use anyhow::{Context, ensure};
use async_trait::async_trait;
use kasumi_client::{
    ClientDecodeLimits, ClientProfile, ClientResources, KasumiClientPool, SnapshotReadOptions,
};
use kasumi_transport::credentials::FileCredentialSource;
use kasumi_types::{
    Document, DocumentKey, Mutation, MutationBatch, MutationReceipt, MutationReceiptScope,
    Precondition, ReadSnapshotRequest, WriteReceipt, validate_name,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path, sync::Arc, time::Duration};
use thiserror::Error;
use tokio::time::Instant;
use uuid::Uuid;

// The maintained Iroha deployment CLI accepts retained files up to 8 MiB.
// Storage chunks keep this envelope below Kasumi's 1 MiB document ceiling.
pub const MAX_NATIVE_ARTIFACT_BYTES: usize = 8 << 20;
const INLINE_ENTRY_BYTES: usize = 128 << 10;
const CHUNK_BYTES: usize = 128 << 10;
const MAX_CHUNKS: usize = 256;
pub const REQUIRED_MAX_DOCUMENT_BYTES: usize = 384 << 10;
pub const REQUIRED_MAX_BATCH_BYTES: usize = 384 << 10;

#[derive(Debug, Error)]
pub enum JournalError {
    #[error("invalid Taira journal input: {0}")]
    Invalid(String),
    #[error("Taira journal identity or phase conflicts with an existing record")]
    Conflict,
    #[error("Taira journal is missing a preceding phase")]
    MissingPredecessor,
    #[error("Taira journal phase records are inconsistent")]
    Inconsistent,
    #[error("Kasumi rejected the exact journal mutation: {0}")]
    Rejected(String),
    #[error("Kasumi journal outcome is unknown for {0}; recover before retrying")]
    UnknownOutcome(String),
    #[error(transparent)]
    Backend(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, JournalError>;

fn invalid(message: impl Into<String>) -> JournalError {
    JournalError::Invalid(message.into())
}

fn name(value: &str, field: &str) -> Result<()> {
    validate_name(value).map_err(|_| invalid(format!("invalid {field}")))
}

fn sha256(value: &str, field: &str) -> Result<()> {
    let bytes = hex::decode(value).map_err(|_| invalid(format!("invalid {field}")))?;
    if bytes.len() != 32 || hex::encode(bytes) != value {
        return Err(invalid(format!("invalid {field}")));
    }
    Ok(())
}

fn exact_hex(value: &str, maximum: usize, field: &str) -> Result<Vec<u8>> {
    if value.is_empty() || value.len() > maximum * 2 {
        return Err(invalid(format!("invalid {field} size")));
    }
    let bytes = hex::decode(value).map_err(|_| invalid(format!("invalid {field} hex")))?;
    if bytes.is_empty() || bytes.len() > maximum || hex::encode(&bytes) != value {
        return Err(invalid(format!("invalid {field} encoding")));
    }
    Ok(bytes)
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn proof_digest(proof: &ChainProof) -> Result<String> {
    Ok(digest(
        &serde_json::to_vec(proof).map_err(anyhow::Error::from)?,
    ))
}

/// The immutable identity shared by every phase of one deployment. The Kasumi
/// scope is retained even if a credential family is renewed later.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeploymentIdentity {
    pub journal_scope: MutationReceiptScope,
    pub network: String,
    pub genesis_sha256: String,
    pub operation_id: Uuid,
    pub dataspace: String,
    pub namespace: String,
    pub signer_account: String,
    pub signer_public_key_sha256: String,
    pub request_sha256: String,
    pub artifact_sha256: String,
}

impl DeploymentIdentity {
    pub fn validate(&self) -> Result<()> {
        name(&self.journal_scope.tenant, "Kasumi tenant")?;
        name(&self.journal_scope.principal, "Kasumi principal")?;
        let incarnation = Uuid::parse_str(&self.journal_scope.incarnation)
            .map_err(|_| invalid("invalid Kasumi incarnation"))?;
        if incarnation.is_nil() || self.operation_id.is_nil() {
            return Err(invalid("nil Kasumi incarnation or deployment operation"));
        }
        name(&self.network, "network")?;
        name(&self.dataspace, "dataspace")?;
        name(&self.namespace, "namespace")?;
        name(&self.signer_account, "signer account")?;
        sha256(&self.genesis_sha256, "genesis digest")?;
        sha256(&self.signer_public_key_sha256, "signer key digest")?;
        sha256(&self.request_sha256, "request digest")?;
        sha256(&self.artifact_sha256, "artifact digest")
    }
}

/// Signed bytes are retained before broadcast. The transaction ID is the
/// installed Iroha CLI's identity; the SHA-256 independently binds these bytes.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedTransaction {
    pub transaction_id: String,
    pub signed_bytes_hex: String,
    pub signed_bytes_sha256: String,
}

impl SignedTransaction {
    pub fn validate(&self) -> Result<()> {
        name(&self.transaction_id, "transaction ID")?;
        sha256(&self.signed_bytes_sha256, "signed transaction digest")?;
        let bytes = exact_hex(
            &self.signed_bytes_hex,
            MAX_NATIVE_ARTIFACT_BYTES,
            "signed transaction",
        )?;
        if hex::encode(Sha256::digest(bytes)) != self.signed_bytes_sha256 {
            return Err(invalid("signed transaction bytes differ from their digest"));
        }
        Ok(())
    }
}

/// Exact authenticated Taira response/receipt bytes and the observed chain
/// state. This is retained evidence, not independently verified chain finality.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChainProof {
    pub transaction_id: String,
    pub block_height: u64,
    pub block_hash: String,
    pub observed_state_sha256: String,
    pub evidence_hex: String,
    pub evidence_sha256: String,
}

impl ChainProof {
    pub fn validate(&self) -> Result<()> {
        name(&self.transaction_id, "proof transaction ID")?;
        if self.block_height == 0 {
            return Err(invalid("zero proof block height"));
        }
        sha256(&self.block_hash, "proof block hash")?;
        sha256(&self.observed_state_sha256, "observed state digest")?;
        sha256(&self.evidence_sha256, "chain evidence digest")?;
        let evidence = exact_hex(
            &self.evidence_hex,
            MAX_NATIVE_ARTIFACT_BYTES,
            "chain evidence",
        )?;
        if hex::encode(Sha256::digest(evidence)) != self.evidence_sha256 {
            return Err(invalid("chain evidence differs from its digest"));
        }
        Ok(())
    }
}

/// Links the three immutable phase observations and retains the exact native
/// four-validator completion receipt. The Iroha CLI must reauthenticate it;
/// Kasumi persistence alone cannot establish finality or current chain state.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CompletionProofs {
    pub catalog_proof_sha256: String,
    pub bootstrap_proof_sha256: String,
    pub aliases_proof_sha256: String,
    pub native_receipt_name: String,
    pub native_receipt_hex: String,
    pub native_receipt_sha256: String,
}

impl CompletionProofs {
    pub fn validate(&self) -> Result<()> {
        sha256(&self.catalog_proof_sha256, "catalog proof digest")?;
        sha256(&self.bootstrap_proof_sha256, "bootstrap proof digest")?;
        sha256(&self.aliases_proof_sha256, "aliases proof digest")?;
        name(&self.native_receipt_name, "native completion receipt name")?;
        sha256(
            &self.native_receipt_sha256,
            "native completion receipt digest",
        )?;
        let bytes = exact_hex(
            &self.native_receipt_hex,
            MAX_NATIVE_ARTIFACT_BYTES,
            "native completion receipt",
        )?;
        if hex::encode(Sha256::digest(bytes)) != self.native_receipt_sha256 {
            return Err(invalid("native completion receipt differs from its digest"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhaseKind {
    Intent,
    CatalogPrepared,
    CatalogVerified,
    BootstrapPrepared,
    BootstrapVerified,
    AliasesPrepared,
    AliasesVerified,
    Completed,
}

impl PhaseKind {
    pub const ORDER: [Self; 8] = [
        Self::Intent,
        Self::CatalogPrepared,
        Self::CatalogVerified,
        Self::BootstrapPrepared,
        Self::BootstrapVerified,
        Self::AliasesPrepared,
        Self::AliasesVerified,
        Self::Completed,
    ];

    fn slug(self) -> &'static str {
        match self {
            Self::Intent => "intent",
            Self::CatalogPrepared => "catalog-prepared",
            Self::CatalogVerified => "catalog-verified",
            Self::BootstrapPrepared => "bootstrap-prepared",
            Self::BootstrapVerified => "bootstrap-verified",
            Self::AliasesPrepared => "aliases-prepared",
            Self::AliasesVerified => "aliases-verified",
            Self::Completed => "completed",
        }
    }

    fn index(self) -> usize {
        Self::ORDER.iter().position(|phase| *phase == self).unwrap()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "phase", content = "details", rename_all = "snake_case")]
pub enum DeploymentPhase {
    Intent,
    CatalogPrepared {
        signed_transaction: SignedTransaction,
    },
    CatalogVerified {
        proof: ChainProof,
    },
    BootstrapPrepared {
        signed_transaction: SignedTransaction,
    },
    BootstrapVerified {
        proof: ChainProof,
    },
    AliasesPrepared {
        signed_transaction: SignedTransaction,
    },
    AliasesVerified {
        proof: ChainProof,
    },
    Completed(Box<CompletionProofs>),
}

impl DeploymentPhase {
    pub fn kind(&self) -> PhaseKind {
        match self {
            Self::Intent => PhaseKind::Intent,
            Self::CatalogPrepared { .. } => PhaseKind::CatalogPrepared,
            Self::CatalogVerified { .. } => PhaseKind::CatalogVerified,
            Self::BootstrapPrepared { .. } => PhaseKind::BootstrapPrepared,
            Self::BootstrapVerified { .. } => PhaseKind::BootstrapVerified,
            Self::AliasesPrepared { .. } => PhaseKind::AliasesPrepared,
            Self::AliasesVerified { .. } => PhaseKind::AliasesVerified,
            Self::Completed(_) => PhaseKind::Completed,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JournalEntry {
    pub format: u32,
    pub identity: DeploymentIdentity,
    pub phase: DeploymentPhase,
}

impl JournalEntry {
    pub fn validate(&self) -> Result<()> {
        if self.format != 1 {
            return Err(invalid("unsupported journal entry format"));
        }
        self.identity.validate()?;
        match &self.phase {
            DeploymentPhase::Intent => Ok(()),
            DeploymentPhase::CatalogPrepared { signed_transaction }
            | DeploymentPhase::BootstrapPrepared { signed_transaction }
            | DeploymentPhase::AliasesPrepared { signed_transaction } => {
                signed_transaction.validate()
            }
            DeploymentPhase::CatalogVerified { proof }
            | DeploymentPhase::BootstrapVerified { proof }
            | DeploymentPhase::AliasesVerified { proof } => proof.validate(),
            DeploymentPhase::Completed(proofs) => proofs.validate(),
        }
    }

    pub fn document_id(&self) -> String {
        document_id(self.identity.operation_id, self.phase.kind())
    }

    pub fn mutation(&self, collection: &str) -> Result<MutationBatch> {
        self.validate()?;
        name(collection, "journal collection")?;
        let body = serde_json::to_value(self).map_err(anyhow::Error::from)?;
        if serde_json::to_vec(&body)
            .map_err(anyhow::Error::from)?
            .len()
            > INLINE_ENTRY_BYTES
        {
            return Err(invalid("entry requires chunked journal storage"));
        }
        Ok(MutationBatch {
            idempotency_key: self.document_id(),
            read_set: Vec::new(),
            operations: vec![Mutation::Put {
                collection: collection.to_owned(),
                id: self.document_id(),
                body,
                expected: Precondition::Absent,
            }],
        })
    }
}

/// A committed phase points only to already persisted immutable chunks. The
/// phase document is the commit marker; orphan chunks are safe to replay.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ChunkManifest {
    format: u32,
    identity: DeploymentIdentity,
    phase: String,
    payload_sha256: String,
    payload_bytes: usize,
    chunks: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ChunkDocument {
    format: u32,
    identity: DeploymentIdentity,
    phase: String,
    index: usize,
    chunks: usize,
    payload_sha256: String,
    data_hex: String,
    data_sha256: String,
}

fn chunk_id(operation_id: Uuid, phase: PhaseKind, index: usize) -> String {
    format!("{}/chunk-{index:03}", document_id(operation_id, phase))
}

fn put_batch(collection: &str, id: String, body: serde_json::Value) -> MutationBatch {
    MutationBatch {
        idempotency_key: id.clone(),
        read_set: Vec::new(),
        operations: vec![Mutation::Put {
            collection: collection.to_owned(),
            id,
            body,
            expected: Precondition::Absent,
        }],
    }
}

fn bounded_body<T: Serialize>(value: &T) -> Result<serde_json::Value> {
    let body = serde_json::to_value(value).map_err(anyhow::Error::from)?;
    if serde_json::to_vec(&body)
        .map_err(anyhow::Error::from)?
        .len()
        > REQUIRED_MAX_DOCUMENT_BYTES
    {
        return Err(invalid("journal document exceeds required Kasumi limit"));
    }
    Ok(body)
}

fn chunked_storage(
    entry: &JournalEntry,
    collection: &str,
    payload: &[u8],
) -> Result<(MutationBatch, Vec<(String, serde_json::Value)>)> {
    let phase = entry.phase.kind();
    let chunks = payload.len().div_ceil(CHUNK_BYTES);
    if chunks == 0 || chunks > MAX_CHUNKS {
        return Err(invalid("journal payload exceeds chunked storage envelope"));
    }
    let payload_sha256 = digest(payload);
    let manifest = ChunkManifest {
        format: 1,
        identity: entry.identity.clone(),
        phase: phase.slug().into(),
        payload_sha256: payload_sha256.clone(),
        payload_bytes: payload.len(),
        chunks,
    };
    let manifest_batch = put_batch(collection, entry.document_id(), bounded_body(&manifest)?);
    let mut documents = Vec::with_capacity(chunks);
    for (index, bytes) in payload.chunks(CHUNK_BYTES).enumerate() {
        let chunk = ChunkDocument {
            format: 1,
            identity: entry.identity.clone(),
            phase: phase.slug().into(),
            index,
            chunks,
            payload_sha256: payload_sha256.clone(),
            data_hex: hex::encode(bytes),
            data_sha256: digest(bytes),
        };
        documents.push((
            chunk_id(entry.identity.operation_id, phase, index),
            bounded_body(&chunk)?,
        ));
    }
    Ok((manifest_batch, documents))
}

fn document_id(operation_id: Uuid, phase: PhaseKind) -> String {
    format!("dpn-taira-v1/{operation_id}/{}", phase.slug())
}

/// Adapter boundary permits deterministic recovery tests without live services.
/// Production uses `KasumiBackend`, whose receipt method verifies the exact
/// original batch and authenticated scope through `KasumiClientPool`.
#[async_trait]
pub trait JournalBackend: Send {
    async fn mutate(
        &mut self,
        batch: &MutationBatch,
        timeout: Duration,
    ) -> anyhow::Result<WriteReceipt>;
    async fn resolve(
        &mut self,
        scope: &MutationReceiptScope,
        original: &MutationBatch,
        timeout: Duration,
    ) -> anyhow::Result<Option<MutationReceipt>>;
    async fn read_records(
        &mut self,
        collection: &str,
        ids: &[String],
        timeout: Duration,
    ) -> anyhow::Result<Vec<Option<Document>>>;
}

/// The caller must independently authenticate this binding, including its
/// profile digest. A profile cannot sign its own expected identity.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledProfileBinding {
    pub profile_sha256: String,
    pub tenant: String,
    pub incarnation: Uuid,
    pub principal: String,
    pub family_id: Uuid,
    pub collection: String,
}

impl InstalledProfileBinding {
    pub fn validate(&self) -> Result<()> {
        sha256(&self.profile_sha256, "installed profile digest")?;
        name(&self.tenant, "Kasumi tenant")?;
        name(&self.principal, "Kasumi principal")?;
        name(&self.collection, "journal collection")?;
        if self.incarnation.is_nil() || self.family_id.is_nil() {
            return Err(invalid("nil installed Kasumi identity"));
        }
        Ok(())
    }

    pub fn scope(&self) -> MutationReceiptScope {
        MutationReceiptScope {
            tenant: self.tenant.clone(),
            incarnation: self.incarnation.to_string(),
            principal: self.principal.clone(),
        }
    }
}

pub struct KasumiBackend {
    pool: KasumiClientPool,
    resources: Arc<ClientResources>,
    expected_incarnation: Uuid,
}

impl KasumiBackend {
    /// Local validation only; the first journal operation opens the TLS channel.
    pub fn from_installed_profile(path: &Path, binding: &InstalledProfileBinding) -> Result<Self> {
        binding.validate()?;
        let (profile, digest) = ClientProfile::load_with_sha256(path)?;
        if digest != binding.profile_sha256 {
            return Err(JournalError::Conflict);
        }
        profile.require_database_binding(
            &binding.tenant,
            binding.incarnation,
            &binding.principal,
            binding.family_id,
        )?;
        let config = profile.connection(false)?;
        let credential = Arc::new(FileCredentialSource::new(&profile.bearer_file)?);
        let pool = KasumiClientPool::new(BTreeMap::from([(1, config)]), credential)?;
        Ok(Self {
            pool,
            resources: ClientResources::new(128 << 20, 2).map_err(anyhow::Error::from)?,
            expected_incarnation: binding.incarnation,
        })
    }
}

#[async_trait]
impl JournalBackend for KasumiBackend {
    async fn mutate(
        &mut self,
        batch: &MutationBatch,
        timeout: Duration,
    ) -> anyhow::Result<WriteReceipt> {
        Ok(self.pool.mutate(batch, timeout).await?)
    }

    async fn resolve(
        &mut self,
        scope: &MutationReceiptScope,
        original: &MutationBatch,
        timeout: Duration,
    ) -> anyhow::Result<Option<MutationReceipt>> {
        Ok(self.pool.resolve_mutation(scope, original, timeout).await?)
    }

    async fn read_records(
        &mut self,
        collection: &str,
        ids: &[String],
        timeout: Duration,
    ) -> anyhow::Result<Vec<Option<Document>>> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .context("invalid journal read timeout")?;
        let request = ReadSnapshotRequest {
            documents: ids
                .iter()
                .map(|id| DocumentKey {
                    collection: collection.to_owned(),
                    id: id.clone(),
                })
                .collect(),
            queries: Vec::new(),
            time_bounds: None,
        };
        let options = SnapshotReadOptions {
            resources: self.resources.clone(),
            limits: ClientDecodeLimits {
                max_request_bytes: 128 << 10,
                max_wire_bytes: 8 << 20,
                max_json_bytes: 8 << 20,
                max_depth: 32,
                max_nodes: 100_000,
                max_string_bytes: 1 << 20,
                max_number_bytes: 128,
                max_rows: 8,
                max_decoded_bytes: 12 << 20,
            },
            deadline,
            expected_incarnation: self.expected_incarnation,
        };
        let response = self.pool.read_snapshot(&request, &options).await?;
        ensure!(
            response.documents.len() == ids.len(),
            "journal snapshot omitted a document"
        );
        response
            .documents
            .iter()
            .zip(ids)
            .map(|(row, id)| {
                ensure!(
                    row.key.collection == collection && row.key.id == *id,
                    "journal snapshot changed a document key"
                );
                Ok(row.document.clone())
            })
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalView {
    entries: Vec<JournalEntry>,
}

impl JournalView {
    pub fn entries(&self) -> &[JournalEntry] {
        &self.entries
    }

    /// This only reports a Kasumi record. The caller must check Taira again.
    pub fn recorded_completion(&self) -> Option<&JournalEntry> {
        self.entries
            .last()
            .filter(|entry| entry.phase.kind() == PhaseKind::Completed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppendOutcome {
    Committed,
    Recovered,
    AlreadyPresent,
}

pub struct Journal<B> {
    backend: B,
    collection: String,
    scope: MutationReceiptScope,
}

impl<B: JournalBackend> Journal<B> {
    pub fn new(backend: B, collection: String, scope: MutationReceiptScope) -> Result<Self> {
        name(&collection, "journal collection")?;
        name(&scope.tenant, "Kasumi tenant")?;
        name(&scope.principal, "Kasumi principal")?;
        let incarnation = Uuid::parse_str(&scope.incarnation)
            .map_err(|_| invalid("invalid Kasumi incarnation"))?;
        if incarnation.is_nil() {
            return Err(invalid("nil Kasumi incarnation"));
        }
        Ok(Self {
            backend,
            collection,
            scope,
        })
    }

    pub async fn read(
        &mut self,
        identity: &DeploymentIdentity,
        phase: PhaseKind,
        timeout: Duration,
    ) -> Result<Option<JournalEntry>> {
        let view = self.recover(identity, timeout).await?;
        Ok(view.entries.get(phase.index()).cloned())
    }

    async fn read_chunked(
        &mut self,
        manifest: &ChunkManifest,
        phase: PhaseKind,
        timeout: Duration,
    ) -> Result<JournalEntry> {
        if manifest.format != 1
            || manifest.phase != phase.slug()
            || manifest.chunks == 0
            || manifest.chunks > MAX_CHUNKS
            || manifest.payload_bytes <= INLINE_ENTRY_BYTES
            || manifest.payload_bytes.div_ceil(CHUNK_BYTES) != manifest.chunks
            || sha256(&manifest.payload_sha256, "chunked payload digest").is_err()
        {
            return Err(JournalError::Inconsistent);
        }
        let mut payload = Vec::with_capacity(manifest.payload_bytes);
        for start in (0..manifest.chunks).step_by(4) {
            let end = (start + 4).min(manifest.chunks);
            let ids = (start..end)
                .map(|index| chunk_id(manifest.identity.operation_id, phase, index))
                .collect::<Vec<_>>();
            let documents = self
                .backend
                .read_records(&self.collection, &ids, timeout)
                .await?;
            if documents.len() != ids.len() {
                return Err(JournalError::Inconsistent);
            }
            for (offset, (document, id)) in documents.into_iter().zip(ids).enumerate() {
                let Some(document) = document else {
                    return Err(JournalError::Inconsistent);
                };
                if document.id != id || document.version == 0 {
                    return Err(JournalError::Inconsistent);
                }
                let chunk: ChunkDocument = serde_json::from_value(document.body)
                    .map_err(|_| JournalError::Inconsistent)?;
                if chunk.format != 1
                    || chunk.identity != manifest.identity
                    || chunk.phase != manifest.phase
                    || chunk.index != start + offset
                    || chunk.chunks != manifest.chunks
                    || chunk.payload_sha256 != manifest.payload_sha256
                    || sha256(&chunk.data_sha256, "chunk digest").is_err()
                {
                    return Err(JournalError::Inconsistent);
                }
                let bytes = exact_hex(&chunk.data_hex, CHUNK_BYTES, "journal chunk")
                    .map_err(|_| JournalError::Inconsistent)?;
                if digest(&bytes) != chunk.data_sha256
                    || (chunk.index + 1 < chunk.chunks && bytes.len() != CHUNK_BYTES)
                {
                    return Err(JournalError::Inconsistent);
                }
                payload.extend(bytes);
            }
        }
        if payload.len() != manifest.payload_bytes || digest(&payload) != manifest.payload_sha256 {
            return Err(JournalError::Inconsistent);
        }
        let entry: JournalEntry =
            serde_json::from_slice(&payload).map_err(|_| JournalError::Inconsistent)?;
        if serde_json::to_vec(&entry).map_err(anyhow::Error::from)? != payload
            || entry.identity != manifest.identity
            || entry.phase.kind() != phase
        {
            return Err(JournalError::Inconsistent);
        }
        Ok(entry)
    }

    async fn append_chunk(
        &mut self,
        id: String,
        body: serde_json::Value,
        timeout: Duration,
    ) -> Result<()> {
        let existing = self
            .backend
            .read_records(&self.collection, std::slice::from_ref(&id), timeout)
            .await?;
        if let [Some(document)] = existing.as_slice() {
            return if document.id == id && document.version > 0 && document.body == body {
                Ok(())
            } else {
                Err(JournalError::Conflict)
            };
        }
        if !matches!(existing.as_slice(), [None]) {
            return Err(JournalError::Inconsistent);
        }
        let batch = put_batch(&self.collection, id.clone(), body.clone());
        let submission = self.backend.mutate(&batch, timeout).await;
        let resolution = if submission.is_err() {
            self.backend
                .resolve(&self.scope, &batch, timeout)
                .await
                .ok()
                .flatten()
        } else {
            None
        };
        if let Some(receipt) = &resolution {
            let digest = batch.digest().map_err(|_| JournalError::Inconsistent)?;
            if receipt.scope != self.scope || receipt.request_digest != digest {
                return Err(JournalError::Inconsistent);
            }
        }
        let after = self
            .backend
            .read_records(&self.collection, std::slice::from_ref(&id), timeout)
            .await
            .map_err(|_| JournalError::UnknownOutcome(id.clone()))?;
        if let Some(receipt) = resolution
            && let Err(error) = receipt.outcome
        {
            return Err(JournalError::Rejected(error.to_string()));
        }
        match after.as_slice() {
            [Some(document)]
                if document.id == id && document.version > 0 && document.body == body =>
            {
                Ok(())
            }
            [Some(_)] => Err(JournalError::Conflict),
            _ => Err(JournalError::UnknownOutcome(id)),
        }
    }

    /// Read all phase IDs in one authenticated snapshot, including absent IDs.
    pub async fn recover(
        &mut self,
        identity: &DeploymentIdentity,
        timeout: Duration,
    ) -> Result<JournalView> {
        identity.validate()?;
        if identity.journal_scope != self.scope {
            return Err(JournalError::Conflict);
        }
        let ids = PhaseKind::ORDER
            .iter()
            .map(|phase| document_id(identity.operation_id, *phase))
            .collect::<Vec<_>>();
        let documents = self
            .backend
            .read_records(&self.collection, &ids, timeout)
            .await?;
        if documents.len() != ids.len() {
            return Err(JournalError::Inconsistent);
        }
        let mut entries = Vec::new();
        let mut gap = false;
        for ((document, id), phase) in documents.iter().zip(&ids).zip(PhaseKind::ORDER) {
            match document {
                None => gap = true,
                Some(document) => {
                    if gap || document.id != *id || document.version == 0 {
                        return Err(JournalError::Inconsistent);
                    }
                    let entry: JournalEntry = if document.body.get("payload_sha256").is_some() {
                        let manifest: ChunkManifest = serde_json::from_value(document.body.clone())
                            .map_err(|_| JournalError::Inconsistent)?;
                        if manifest.identity != *identity {
                            return Err(JournalError::Conflict);
                        }
                        self.read_chunked(&manifest, phase, timeout).await?
                    } else {
                        serde_json::from_value(document.body.clone())
                            .map_err(|_| JournalError::Inconsistent)?
                    };
                    entry.validate().map_err(|_| JournalError::Inconsistent)?;
                    if entry.identity != *identity || entry.phase.kind() != phase {
                        return Err(JournalError::Conflict);
                    }
                    entries.push(entry);
                }
            }
        }
        validate_sequence(&entries)?;
        Ok(JournalView { entries })
    }

    /// Append one irreversible phase record. An unknown network outcome is
    /// resolved by the exact Kasumi receipt and an authenticated snapshot read.
    /// No Taira submission happens here.
    pub async fn append(
        &mut self,
        entry: JournalEntry,
        timeout: Duration,
    ) -> Result<AppendOutcome> {
        entry.validate()?;
        if entry.identity.journal_scope != self.scope {
            return Err(JournalError::Conflict);
        }
        let index = entry.phase.kind().index();
        let view = self.recover(&entry.identity, timeout).await?;
        if let Some(existing) = view.entries.get(index) {
            return if *existing == entry {
                Ok(AppendOutcome::AlreadyPresent)
            } else {
                Err(JournalError::Conflict)
            };
        }
        if view.entries.len() != index {
            return Err(JournalError::MissingPredecessor);
        }
        let mut proposed = view.entries;
        proposed.push(entry.clone());
        validate_sequence(&proposed)?;
        let payload = serde_json::to_vec(&entry).map_err(anyhow::Error::from)?;
        let batch = if payload.len() <= INLINE_ENTRY_BYTES {
            entry.mutation(&self.collection)?
        } else {
            let (manifest, chunks) = chunked_storage(&entry, &self.collection, &payload)?;
            for (id, body) in chunks {
                self.append_chunk(id, body, timeout).await?;
            }
            manifest
        };
        let submission = self.backend.mutate(&batch, timeout).await;
        let resolution = if submission.is_err() {
            self.backend
                .resolve(&self.scope, &batch, timeout)
                .await
                .ok()
                .flatten()
        } else {
            None
        };
        if let Some(receipt) = &resolution {
            let digest = batch.digest().map_err(|_| JournalError::Inconsistent)?;
            if receipt.scope != self.scope || receipt.request_digest != digest {
                return Err(JournalError::Inconsistent);
            }
        }
        let after = self.recover(&entry.identity, timeout);
        let after = match after.await {
            Ok(view) => view,
            Err(JournalError::Backend(_)) => {
                return Err(JournalError::UnknownOutcome(entry.document_id()));
            }
            Err(error) => return Err(error),
        };
        if let Some(receipt) = resolution
            && let Err(error) = receipt.outcome
        {
            return Err(JournalError::Rejected(error.to_string()));
        }
        match after.entries.get(index) {
            Some(existing) if *existing == entry => {
                if submission.is_ok() {
                    Ok(AppendOutcome::Committed)
                } else {
                    Ok(AppendOutcome::Recovered)
                }
            }
            Some(_) => Err(JournalError::Conflict),
            None => Err(JournalError::UnknownOutcome(entry.document_id())),
        }
    }
}

impl Journal<KasumiBackend> {
    /// The binding must come from the caller's independently authenticated
    /// runtime configuration, never from the profile being checked.
    pub fn from_installed_profile(path: &Path, binding: &InstalledProfileBinding) -> Result<Self> {
        let backend = KasumiBackend::from_installed_profile(path, binding)?;
        Self::new(backend, binding.collection.clone(), binding.scope())
    }
}

fn validate_sequence(entries: &[JournalEntry]) -> Result<()> {
    if entries.len() > PhaseKind::ORDER.len() {
        return Err(JournalError::Inconsistent);
    }
    for (index, entry) in entries.iter().enumerate() {
        if entry.phase.kind() != PhaseKind::ORDER[index] {
            return Err(JournalError::Inconsistent);
        }
    }
    for (prepared_index, verified_index) in [(1, 2), (3, 4), (5, 6)] {
        if let Some(verified) = entries.get(verified_index) {
            let signed_transaction = match &entries[prepared_index].phase {
                DeploymentPhase::CatalogPrepared { signed_transaction }
                | DeploymentPhase::BootstrapPrepared { signed_transaction }
                | DeploymentPhase::AliasesPrepared { signed_transaction } => signed_transaction,
                _ => return Err(JournalError::Inconsistent),
            };
            let proof = match &verified.phase {
                DeploymentPhase::CatalogVerified { proof }
                | DeploymentPhase::BootstrapVerified { proof }
                | DeploymentPhase::AliasesVerified { proof } => proof,
                _ => return Err(JournalError::Inconsistent),
            };
            if proof.transaction_id != signed_transaction.transaction_id {
                return Err(JournalError::Inconsistent);
            }
        }
    }
    if let Some(JournalEntry {
        phase: DeploymentPhase::Completed(proofs),
        ..
    }) = entries.get(7)
    {
        for (proof_sha256, verified_index) in [
            &proofs.catalog_proof_sha256,
            &proofs.bootstrap_proof_sha256,
            &proofs.aliases_proof_sha256,
        ]
        .into_iter()
        .zip([2, 4, 6])
        {
            let Some(verified) = entries.get(verified_index) else {
                return Err(JournalError::Inconsistent);
            };
            let retained = match &verified.phase {
                DeploymentPhase::CatalogVerified { proof }
                | DeploymentPhase::BootstrapVerified { proof }
                | DeploymentPhase::AliasesVerified { proof } => proof,
                _ => return Err(JournalError::Inconsistent),
            };
            if *proof_sha256 != proof_digest(retained)? {
                return Err(JournalError::Inconsistent);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::bail;

    #[derive(Default)]
    enum Dispatch {
        #[default]
        Normal,
        CommitThenError,
        ErrorBeforeCommit,
    }

    #[derive(Default)]
    struct FakeBackend {
        records: BTreeMap<String, Document>,
        receipts: BTreeMap<String, MutationReceipt>,
        dispatch: Dispatch,
        mutate_calls: usize,
        resolve_calls: usize,
        read_calls: usize,
        scope: Option<MutationReceiptScope>,
    }

    #[async_trait]
    impl JournalBackend for FakeBackend {
        async fn mutate(
            &mut self,
            batch: &MutationBatch,
            _timeout: Duration,
        ) -> anyhow::Result<WriteReceipt> {
            self.mutate_calls += 1;
            let digest = batch.digest()?;
            if let Some(receipt) = self.receipts.get(&batch.idempotency_key) {
                if receipt.request_digest != digest {
                    bail!("same idempotency key has different input");
                }
                return Ok(receipt.outcome.clone()?);
            }
            let dispatch = std::mem::take(&mut self.dispatch);
            if matches!(dispatch, Dispatch::ErrorBeforeCommit) {
                bail!("response lost before commit");
            }
            let [
                Mutation::Put {
                    id, body, expected, ..
                },
            ] = batch.operations.as_slice()
            else {
                bail!("test backend accepts one put");
            };
            ensure!(*expected == Precondition::Absent, "not append-only");
            ensure!(
                serde_json::to_vec(body)?.len() <= REQUIRED_MAX_DOCUMENT_BYTES,
                "document exceeds journal storage preflight"
            );
            if self.records.contains_key(id) {
                bail!("record already exists");
            }
            let receipt = WriteReceipt {
                revision: (self.records.len() + 1) as u64,
                versions: BTreeMap::from([(id.clone(), 1)]),
            };
            self.records.insert(
                id.clone(),
                Document {
                    id: id.clone(),
                    version: 1,
                    body: body.clone(),
                },
            );
            self.receipts.insert(
                batch.idempotency_key.clone(),
                MutationReceipt {
                    scope: self.scope.clone().unwrap(),
                    request_digest: digest,
                    outcome: Ok(receipt.clone()),
                },
            );
            if matches!(dispatch, Dispatch::CommitThenError) {
                bail!("response lost after commit");
            }
            Ok(receipt)
        }

        async fn resolve(
            &mut self,
            _scope: &MutationReceiptScope,
            original: &MutationBatch,
            _timeout: Duration,
        ) -> anyhow::Result<Option<MutationReceipt>> {
            self.resolve_calls += 1;
            Ok(self.receipts.get(&original.idempotency_key).cloned())
        }

        async fn read_records(
            &mut self,
            _collection: &str,
            ids: &[String],
            _timeout: Duration,
        ) -> anyhow::Result<Vec<Option<Document>>> {
            self.read_calls += 1;
            Ok(ids.iter().map(|id| self.records.get(id).cloned()).collect())
        }
    }

    fn identity() -> DeploymentIdentity {
        DeploymentIdentity {
            journal_scope: MutationReceiptScope {
                tenant: "dpn-deployments".into(),
                incarnation: Uuid::from_u128(1).to_string(),
                principal: "deploy-operator".into(),
            },
            network: "taira-testnet".into(),
            genesis_sha256: "a1".repeat(32),
            operation_id: Uuid::from_u128(2),
            dataspace: "payments".into(),
            namespace: "payments-v1".into(),
            signer_account: "operator@wonderland".into(),
            signer_public_key_sha256: "b2".repeat(32),
            request_sha256: "c3".repeat(32),
            artifact_sha256: "d4".repeat(32),
        }
    }

    fn entry(identity: &DeploymentIdentity, phase: DeploymentPhase) -> JournalEntry {
        JournalEntry {
            format: 1,
            identity: identity.clone(),
            phase,
        }
    }

    fn transaction(id: &str, bytes: &[u8]) -> SignedTransaction {
        SignedTransaction {
            transaction_id: id.into(),
            signed_bytes_hex: hex::encode(bytes),
            signed_bytes_sha256: digest(bytes),
        }
    }

    fn proof(id: &str, evidence: &[u8]) -> ChainProof {
        ChainProof {
            transaction_id: id.into(),
            block_height: 42,
            block_hash: "e5".repeat(32),
            observed_state_sha256: "f6".repeat(32),
            evidence_hex: hex::encode(evidence),
            evidence_sha256: digest(evidence),
        }
    }

    fn completion(
        catalog: ChainProof,
        bootstrap: ChainProof,
        aliases: ChainProof,
    ) -> DeploymentPhase {
        let receipt = b"native four-validator completion receipt";
        DeploymentPhase::Completed(Box::new(CompletionProofs {
            catalog_proof_sha256: proof_digest(&catalog).unwrap(),
            bootstrap_proof_sha256: proof_digest(&bootstrap).unwrap(),
            aliases_proof_sha256: proof_digest(&aliases).unwrap(),
            native_receipt_name: "completion-1234.json".into(),
            native_receipt_hex: hex::encode(receipt),
            native_receipt_sha256: digest(receipt),
        }))
    }

    fn journal(identity: &DeploymentIdentity) -> Journal<FakeBackend> {
        let backend = FakeBackend {
            scope: Some(identity.journal_scope.clone()),
            ..Default::default()
        };
        Journal::new(
            backend,
            "dpn_taira_journal".into(),
            identity.journal_scope.clone(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn same_id_replay_is_read_only_and_conflicting_payload_is_rejected() {
        let identity = identity();
        let mut journal = journal(&identity);
        let intent = entry(&identity, DeploymentPhase::Intent);
        let timeout = Duration::from_secs(1);
        assert_eq!(
            journal.append(intent.clone(), timeout).await.unwrap(),
            AppendOutcome::Committed
        );
        assert_eq!(
            journal.append(intent, timeout).await.unwrap(),
            AppendOutcome::AlreadyPresent
        );
        assert_eq!(journal.backend.mutate_calls, 1);

        let ready = entry(
            &identity,
            DeploymentPhase::CatalogPrepared {
                signed_transaction: transaction("catalog-tx", b"signed catalog transaction"),
            },
        );
        journal.append(ready, timeout).await.unwrap();
        let conflict = entry(
            &identity,
            DeploymentPhase::CatalogPrepared {
                signed_transaction: transaction("different-tx", b"different signed transaction"),
            },
        );
        assert!(matches!(
            journal.append(conflict, timeout).await,
            Err(JournalError::Conflict)
        ));
        assert_eq!(journal.backend.mutate_calls, 2);
    }

    #[tokio::test]
    async fn uncertain_commit_resolves_original_receipt_and_reads_back_record() {
        let identity = identity();
        let mut journal = journal(&identity);
        journal.backend.dispatch = Dispatch::CommitThenError;
        let intent = entry(&identity, DeploymentPhase::Intent);
        assert_eq!(
            journal
                .append(intent.clone(), Duration::from_secs(1))
                .await
                .unwrap(),
            AppendOutcome::Recovered
        );
        assert_eq!(journal.backend.resolve_calls, 1);
        assert!(journal.backend.read_calls >= 2);
        assert_eq!(
            journal
                .read(&identity, PhaseKind::Intent, Duration::from_secs(1))
                .await
                .unwrap(),
            Some(intent)
        );

        journal.backend.dispatch = Dispatch::ErrorBeforeCommit;
        let ready = entry(
            &identity,
            DeploymentPhase::CatalogPrepared {
                signed_transaction: transaction("catalog-tx", b"signed catalog transaction"),
            },
        );
        assert!(matches!(
            journal.append(ready.clone(), Duration::from_secs(1)).await,
            Err(JournalError::UnknownOutcome(_))
        ));
        assert_eq!(
            journal.append(ready, Duration::from_secs(1)).await.unwrap(),
            AppendOutcome::Committed
        );
    }

    #[tokio::test]
    async fn identity_and_phase_proofs_are_bound_to_the_original_operation() {
        let identity = identity();
        let mut journal = journal(&identity);
        let timeout = Duration::from_secs(1);
        let catalog = proof("catalog-tx", b"catalog receipt");
        let bootstrap = proof("bootstrap-tx", b"bootstrap receipt");
        let aliases = proof("aliases-tx", b"aliases receipt");
        let complete = entry(
            &identity,
            completion(catalog.clone(), bootstrap.clone(), aliases.clone()),
        );
        assert!(matches!(
            journal.append(complete.clone(), timeout).await,
            Err(JournalError::MissingPredecessor)
        ));
        journal
            .append(entry(&identity, DeploymentPhase::Intent), timeout)
            .await
            .unwrap();
        journal
            .append(
                entry(
                    &identity,
                    DeploymentPhase::CatalogPrepared {
                        signed_transaction: transaction(
                            "catalog-tx",
                            b"signed catalog transaction",
                        ),
                    },
                ),
                timeout,
            )
            .await
            .unwrap();
        let wrong_proof = entry(
            &identity,
            DeploymentPhase::CatalogVerified {
                proof: proof("other-tx", b"wrong receipt"),
            },
        );
        assert!(matches!(
            journal.append(wrong_proof, timeout).await,
            Err(JournalError::Inconsistent)
        ));
        journal
            .append(
                entry(
                    &identity,
                    DeploymentPhase::CatalogVerified {
                        proof: catalog.clone(),
                    },
                ),
                timeout,
            )
            .await
            .unwrap();
        let early_aliases = entry(
            &identity,
            DeploymentPhase::AliasesPrepared {
                signed_transaction: transaction("aliases-tx", b"signed aliases transaction"),
            },
        );
        assert!(matches!(
            journal.append(early_aliases, timeout).await,
            Err(JournalError::MissingPredecessor)
        ));
        journal
            .append(
                entry(
                    &identity,
                    DeploymentPhase::BootstrapPrepared {
                        signed_transaction: transaction(
                            "bootstrap-tx",
                            b"signed bootstrap transaction",
                        ),
                    },
                ),
                timeout,
            )
            .await
            .unwrap();
        journal
            .append(
                entry(
                    &identity,
                    DeploymentPhase::BootstrapVerified {
                        proof: bootstrap.clone(),
                    },
                ),
                timeout,
            )
            .await
            .unwrap();
        journal
            .append(
                entry(
                    &identity,
                    DeploymentPhase::AliasesPrepared {
                        signed_transaction: transaction(
                            "aliases-tx",
                            b"signed aliases transaction",
                        ),
                    },
                ),
                timeout,
            )
            .await
            .unwrap();
        let wrong_alias_proof = entry(
            &identity,
            DeploymentPhase::AliasesVerified {
                proof: proof("other-alias-tx", b"wrong alias receipt"),
            },
        );
        assert!(matches!(
            journal.append(wrong_alias_proof, timeout).await,
            Err(JournalError::Inconsistent)
        ));
        journal
            .append(
                entry(
                    &identity,
                    DeploymentPhase::AliasesVerified {
                        proof: aliases.clone(),
                    },
                ),
                timeout,
            )
            .await
            .unwrap();
        let wrong_completion = entry(
            &identity,
            completion(
                catalog.clone(),
                bootstrap.clone(),
                proof("aliases-tx", b"substituted alias receipt"),
            ),
        );
        assert!(matches!(
            journal.append(wrong_completion, timeout).await,
            Err(JournalError::Inconsistent)
        ));
        journal.append(complete.clone(), timeout).await.unwrap();
        let recovered = journal.recover(&identity, timeout).await.unwrap();
        assert_eq!(recovered.entries().len(), PhaseKind::ORDER.len());
        assert_eq!(recovered.recorded_completion(), Some(&complete));
        assert_eq!(
            journal
                .read(&identity, PhaseKind::AliasesPrepared, timeout)
                .await
                .unwrap()
                .unwrap()
                .phase,
            DeploymentPhase::AliasesPrepared {
                signed_transaction: transaction("aliases-tx", b"signed aliases transaction"),
            }
        );
        let DeploymentPhase::Completed(mut malformed_completion) = complete.phase.clone() else {
            unreachable!();
        };
        malformed_completion.native_receipt_sha256 = "00".repeat(32);
        assert!(matches!(
            malformed_completion.validate(),
            Err(JournalError::Invalid(_))
        ));

        let mut different = identity.clone();
        different.genesis_sha256 = "01".repeat(32);
        assert!(matches!(
            journal.recover(&different, timeout).await,
            Err(JournalError::Conflict)
        ));
        different = identity.clone();
        different.journal_scope.principal = "another-operator".into();
        assert!(matches!(
            journal.recover(&different, timeout).await,
            Err(JournalError::Conflict)
        ));
        let mut bad_transaction = transaction("new-tx", b"signed bytes");
        bad_transaction.signed_bytes_sha256 = "00".repeat(32);
        assert!(matches!(
            bad_transaction.validate(),
            Err(JournalError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn chunked_signed_wire_survives_ambiguous_write_and_exact_replay() {
        let identity = identity();
        let mut journal = journal(&identity);
        let timeout = Duration::from_secs(1);
        journal
            .append(entry(&identity, DeploymentPhase::Intent), timeout)
            .await
            .unwrap();
        let bytes = vec![0x5a; 180 << 10];
        let prepared = entry(
            &identity,
            DeploymentPhase::CatalogPrepared {
                signed_transaction: transaction("large-catalog-tx", &bytes),
            },
        );
        journal.backend.dispatch = Dispatch::CommitThenError;
        assert_eq!(
            journal.append(prepared.clone(), timeout).await.unwrap(),
            AppendOutcome::Committed
        );
        assert_eq!(journal.backend.resolve_calls, 1);
        assert!(journal.backend.records.len() > 3);
        let calls = journal.backend.mutate_calls;
        assert_eq!(
            journal.append(prepared.clone(), timeout).await.unwrap(),
            AppendOutcome::AlreadyPresent
        );
        assert_eq!(journal.backend.mutate_calls, calls);
        assert_eq!(
            journal
                .read(&identity, PhaseKind::CatalogPrepared, timeout)
                .await
                .unwrap(),
            Some(prepared.clone())
        );
        let conflict = entry(
            &identity,
            DeploymentPhase::CatalogPrepared {
                signed_transaction: transaction("other-catalog-tx", &bytes),
            },
        );
        assert!(matches!(
            journal.append(conflict, timeout).await,
            Err(JournalError::Conflict)
        ));
        let id = chunk_id(identity.operation_id, PhaseKind::CatalogPrepared, 0);
        journal.backend.records.get_mut(&id).unwrap().body["data_sha256"] =
            serde_json::Value::String("00".repeat(32));
        assert!(matches!(
            journal.recover(&identity, timeout).await,
            Err(JournalError::Inconsistent)
        ));
    }

    #[test]
    fn native_eight_megabyte_signed_wire_fits_chunked_kasumi_documents() {
        let identity = identity();
        let bytes = vec![0x5a; MAX_NATIVE_ARTIFACT_BYTES];
        let prepared = entry(
            &identity,
            DeploymentPhase::CatalogPrepared {
                signed_transaction: transaction("max-catalog-tx", &bytes),
            },
        );
        prepared.validate().unwrap();
        let payload = serde_json::to_vec(&prepared).unwrap();
        let (manifest, chunks) = chunked_storage(&prepared, "dpn_taira_journal", &payload).unwrap();
        assert!(chunks.len() <= MAX_CHUNKS);
        assert!(chunks.len() > 1);
        assert!(chunks.iter().all(
            |(_, body)| serde_json::to_vec(body).unwrap().len() <= REQUIRED_MAX_DOCUMENT_BYTES
        ));
        let [Mutation::Put { body, .. }] = manifest.operations.as_slice() else {
            panic!("manifest must be one absent put");
        };
        assert!(serde_json::to_vec(body).unwrap().len() <= REQUIRED_MAX_DOCUMENT_BYTES);
    }

    #[test]
    fn observed_scale_evidence_and_completion_receipt_fit_without_duplicate_proofs() {
        let identity = identity();
        let evidence = proof("catalog-tx", &vec![0x47; 176 << 10]);
        let verified = entry(
            &identity,
            DeploymentPhase::CatalogVerified {
                proof: evidence.clone(),
            },
        );
        verified.validate().unwrap();
        let verified_bytes = serde_json::to_vec(&verified).unwrap();
        let (_, verified_chunks) =
            chunked_storage(&verified, "dpn_taira_journal", &verified_bytes).unwrap();
        assert!(verified_chunks.len() > 1);

        let receipt = vec![0x52; 175_716];
        let completed = entry(
            &identity,
            DeploymentPhase::Completed(Box::new(CompletionProofs {
                catalog_proof_sha256: proof_digest(&evidence).unwrap(),
                bootstrap_proof_sha256: proof_digest(&proof("bootstrap-tx", b"bootstrap")).unwrap(),
                aliases_proof_sha256: proof_digest(&proof("aliases-tx", b"aliases")).unwrap(),
                native_receipt_name: "completion-1234.json".into(),
                native_receipt_hex: hex::encode(&receipt),
                native_receipt_sha256: digest(&receipt),
            })),
        );
        completed.validate().unwrap();
        let completed_bytes = serde_json::to_vec(&completed).unwrap();
        let (_, completed_chunks) =
            chunked_storage(&completed, "dpn_taira_journal", &completed_bytes).unwrap();
        assert!(completed_chunks.len() > 1);
        assert!(completed_chunks.iter().all(|(_, body)| {
            serde_json::to_vec(body).unwrap().len() <= REQUIRED_MAX_DOCUMENT_BYTES
        }));
    }
}
