//! Tenant-private, append-only custody of original evidence bytes.
//!
//! A manifest is published only after every immutable chunk has been durably
//! written and read back. A missing manifest hides orphan chunks. Reading a
//! manifest verifies every chunk and the complete byte digest before returning
//! data. This proves custody integrity inside the authenticated Kasumi tenant;
//! it does not verify the external evidence's signatures, finality or meaning.

use anyhow::{Context, ensure};
use async_trait::async_trait;
use kasumi_client::{
    ClientDecodeLimits, ClientProfile, ClientResources, KasumiClientPool, SnapshotReadOptions,
};
use kasumi_transport::credentials::FileCredentialSource;
use kasumi_types::{
    CollectionDefinition, CollectionRetentionClass, CollectionWriteMode, Document, DocumentKey,
    Mutation, MutationBatch, MutationReceipt, MutationReceiptScope, Precondition,
    ReadSnapshotRequest, SchemaSnapshot, WriteReceipt, validate_name,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path, sync::Arc, time::Duration};
use thiserror::Error;
use tokio::time::Instant;
use uuid::Uuid;

/// One component's upper bound. A complete external proof may require several
/// separately named components and an application-level completeness manifest.
/// Admission also checks the operator's smaller installed limit.
pub const MAX_COMPONENT_BYTES: usize = 256 << 20;
pub const CHUNK_BYTES: usize = 384 << 10;
pub const MAX_CHUNKS: usize = MAX_COMPONENT_BYTES.div_ceil(CHUNK_BYTES);
pub const REQUIRED_MAX_DOCUMENT_BYTES: usize = 896 << 10;
pub const REQUIRED_MAX_BATCH_BYTES: usize = 896 << 10;
const FORMAT: &str = "kasumi.private_evidence.v1";
const READ_GROUP: usize = 4;
const ID_FRAME: &[u8] = b"kasumi.private-evidence.id.v1\0";

#[derive(Debug, Error)]
pub enum CustodyError {
    #[error("invalid private evidence input: {0}")]
    Invalid(&'static str),
    #[error("private evidence identity or bytes conflict with retained data")]
    Conflict,
    #[error("retained private evidence is incomplete or inconsistent")]
    Inconsistent,
    #[error("Kasumi rejected the original private evidence write")]
    Rejected,
    #[error("private evidence outcome is unknown for {0}; resolve the same ID before retrying")]
    UnknownOutcome(String),
    #[error(transparent)]
    Backend(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, CustodyError>;

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn document_receipt_path(collection: &str, id: &str) -> String {
    let escape = |value: &str| value.replace('~', "~0").replace('/', "~1");
    format!("/{}/{}", escape(collection), escape(id))
}

fn exact_digest(value: &str) -> bool {
    hex::decode(value).is_ok_and(|bytes| bytes.len() == 32 && hex::encode(bytes) == value)
}

fn exact_hex(value: &str, maximum: usize) -> Result<Vec<u8>> {
    if value.is_empty() || value.len() > maximum * 2 {
        return Err(CustodyError::Inconsistent);
    }
    let bytes = hex::decode(value).map_err(|_| CustodyError::Inconsistent)?;
    if bytes.is_empty() || bytes.len() > maximum || hex::encode(&bytes) != value {
        return Err(CustodyError::Inconsistent);
    }
    Ok(bytes)
}

/// The caller obtains this scope and subject binding from independently
/// authenticated application state. A record cannot grant its own authority.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceIdentity {
    pub scope: MutationReceiptScope,
    pub evidence_id: Uuid,
    pub subject_sha256: String,
    pub purpose: String,
}

fn validate_scope(scope: &MutationReceiptScope) -> Result<()> {
    validate_name(&scope.tenant).map_err(|_| CustodyError::Invalid("tenant"))?;
    validate_name(&scope.principal).map_err(|_| CustodyError::Invalid("principal"))?;
    let incarnation =
        Uuid::parse_str(&scope.incarnation).map_err(|_| CustodyError::Invalid("incarnation"))?;
    if incarnation.is_nil() || incarnation.to_string() != scope.incarnation {
        return Err(CustodyError::Invalid("incarnation"));
    }
    Ok(())
}

impl EvidenceIdentity {
    /// Construct one permanent ID from the original stage subject and purpose.
    /// A lost reply cannot justify generating a different evidence identity.
    pub fn new(
        scope: MutationReceiptScope,
        subject_sha256: String,
        purpose: String,
    ) -> Result<Self> {
        let evidence_id = Self::derive_id(&scope, &subject_sha256, &purpose)?;
        Ok(Self {
            scope,
            evidence_id,
            subject_sha256,
            purpose,
        })
    }

    fn derive_id(
        scope: &MutationReceiptScope,
        subject_sha256: &str,
        purpose: &str,
    ) -> Result<Uuid> {
        validate_scope(scope)?;
        validate_name(purpose).map_err(|_| CustodyError::Invalid("purpose"))?;
        if !exact_digest(subject_sha256) {
            return Err(CustodyError::Invalid("subject digest"));
        }
        let mut digest = Sha256::new();
        digest.update(ID_FRAME);
        for field in [
            scope.tenant.as_str(),
            scope.incarnation.as_str(),
            scope.principal.as_str(),
            subject_sha256,
            purpose,
        ] {
            digest.update((field.len() as u64).to_be_bytes());
            digest.update(field.as_bytes());
        }
        let hash = digest.finalize();
        let mut bytes: [u8; 16] = hash[..16]
            .try_into()
            .map_err(|_| CustodyError::Invalid("identity digest"))?;
        bytes[6] = (bytes[6] & 0x0f) | 0x80; // UUID version 8: application-defined derivation.
        bytes[8] = (bytes[8] & 0x3f) | 0x80; // RFC 4122 variant.
        Ok(Uuid::from_bytes(bytes))
    }

    pub fn validate(&self) -> Result<()> {
        if self.evidence_id != Self::derive_id(&self.scope, &self.subject_sha256, &self.purpose)? {
            return Err(CustodyError::Invalid(
                "evidence ID differs from permanent subject",
            ));
        }
        Ok(())
    }

    fn manifest_id(&self) -> String {
        format!("private-evidence/{}/manifest", self.evidence_id)
    }

    fn chunk_id(&self, index: usize) -> String {
        format!("private-evidence/{}/chunk-{index:04}", self.evidence_id)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct EvidenceManifest {
    schema: String,
    identity: EvidenceIdentity,
    payload_sha256: String,
    payload_bytes: usize,
    chunks: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct EvidenceChunk {
    schema: String,
    identity: EvidenceIdentity,
    payload_sha256: String,
    index: usize,
    chunks: usize,
    data_sha256: String,
    data_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedEvidence {
    pub identity: EvidenceIdentity,
    pub sha256: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppendOutcome {
    Committed,
    Recovered,
    AlreadyPresent,
}

/// These are first-release collection definitions, not a request to create
/// them. The authorized operator must install both with sufficient tenant
/// quotas and grant only the application's specific read/write principal.
/// Strict read auditing and append-only enforcement are part of the schema.
pub fn collection_definitions(manifests: &str, chunks: &str) -> Result<[CollectionDefinition; 2]> {
    validate_name(manifests).map_err(|_| CustodyError::Invalid("manifest collection"))?;
    validate_name(chunks).map_err(|_| CustodyError::Invalid("chunk collection"))?;
    if manifests == chunks {
        return Err(CustodyError::Invalid("distinct collections required"));
    }
    let identity = serde_json::json!({
        "type":"object", "additionalProperties":false,
        "required":["scope","evidence_id","subject_sha256","purpose"],
        "properties":{
            "scope":{"type":"object", "additionalProperties":false,
                "required":["tenant","incarnation","principal"],
                "properties":{"tenant":{"type":"string"},"incarnation":{"type":"string"},"principal":{"type":"string"}}},
            "evidence_id":{"type":"string","format":"uuid"},
            "subject_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},
            "purpose":{"type":"string","minLength":1,"maxLength":256}
        }
    });
    let mut manifest_properties = serde_json::json!({
        "schema":{"const":FORMAT},
        "payload_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},
        "payload_bytes":{"type":"integer","minimum":1,"maximum":MAX_COMPONENT_BYTES},
        "chunks":{"type":"integer","minimum":1,"maximum":MAX_CHUNKS}
    });
    manifest_properties["identity"] = identity.clone();
    let mut chunk_properties = serde_json::json!({
        "schema":{"const":FORMAT},
        "payload_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},
        "index":{"type":"integer","minimum":0,"maximum":MAX_CHUNKS - 1},
        "chunks":{"type":"integer","minimum":1,"maximum":MAX_CHUNKS},
        "data_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},
        "data_hex":{"type":"string","pattern":"^[0-9a-f]+$","minLength":2,"maxLength":CHUNK_BYTES * 2}
    });
    chunk_properties["identity"] = identity;
    let definition = |name: &str, required: &[&str], properties| CollectionDefinition {
        name: name.into(),
        write_mode: CollectionWriteMode::AppendOnly,
        retention_class: CollectionRetentionClass::Operational,
        schema: serde_json::json!({
            "type":"object", "additionalProperties":false,
            "required":required, "properties":properties
        }),
        indexes: Vec::new(),
        strict_read_audit: true,
    };
    Ok([
        definition(
            manifests,
            &[
                "schema",
                "identity",
                "payload_sha256",
                "payload_bytes",
                "chunks",
            ],
            manifest_properties,
        ),
        definition(
            chunks,
            &[
                "schema",
                "identity",
                "payload_sha256",
                "index",
                "chunks",
                "data_sha256",
                "data_hex",
            ],
            chunk_properties,
        ),
    ])
}

/// Source-bound identities for the two exact definitions. The signed runtime
/// must pin these digests and provisioning must independently verify the live
/// definitions before starting the application.
pub fn collection_definition_sha256(manifests: &str, chunks: &str) -> Result<[String; 2]> {
    let definitions = collection_definitions(manifests, chunks)?;
    let digest = |definition: &CollectionDefinition| {
        serde_json::to_vec(definition)
            .map(|wire| sha256_hex(&wire))
            .map_err(|_| CustodyError::Invalid("definition encoding"))
    };
    Ok([digest(&definitions[0])?, digest(&definitions[1])?])
}

fn body<T: Serialize>(value: &T) -> Result<serde_json::Value> {
    let body = serde_json::to_value(value).map_err(|_| CustodyError::Invalid("encoding"))?;
    let encoded = serde_json::to_vec(&body).map_err(|_| CustodyError::Invalid("encoding"))?;
    if encoded.len() > REQUIRED_MAX_DOCUMENT_BYTES {
        return Err(CustodyError::Invalid("document limit"));
    }
    Ok(body)
}

fn put(collection: &str, id: String, body: serde_json::Value) -> MutationBatch {
    MutationBatch {
        idempotency_key: id.clone(),
        read_set: Vec::new(),
        operations: vec![Mutation::Put {
            collection: collection.into(),
            id,
            body,
            expected: Precondition::Absent,
        }],
    }
}

#[async_trait]
pub trait CustodyBackend: Send {
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

/// The expected profile digest and identity must come from a signed owner
/// configuration. A profile cannot authenticate itself by supplying them.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledProfileBinding {
    pub profile_sha256: String,
    pub tenant: String,
    pub incarnation: Uuid,
    pub principal: String,
    pub family_id: Uuid,
    pub manifest_collection: String,
    pub chunk_collection: String,
    pub manifest_definition_sha256: String,
    pub chunk_definition_sha256: String,
    pub max_component_bytes: usize,
}

impl InstalledProfileBinding {
    pub fn validate(&self) -> Result<()> {
        if !exact_digest(&self.profile_sha256)
            || self.incarnation.is_nil()
            || self.family_id.is_nil()
            || self.max_component_bytes == 0
            || self.max_component_bytes > MAX_COMPONENT_BYTES
        {
            return Err(CustodyError::Invalid("installed binding"));
        }
        validate_name(&self.tenant).map_err(|_| CustodyError::Invalid("tenant"))?;
        validate_name(&self.principal).map_err(|_| CustodyError::Invalid("principal"))?;
        let [manifest_digest, chunk_digest] =
            collection_definition_sha256(&self.manifest_collection, &self.chunk_collection)?;
        if self.manifest_definition_sha256 != manifest_digest
            || self.chunk_definition_sha256 != chunk_digest
        {
            return Err(CustodyError::Invalid("collection definition binding"));
        }
        Ok(())
    }

    fn scope(&self) -> MutationReceiptScope {
        MutationReceiptScope {
            tenant: self.tenant.clone(),
            incarnation: self.incarnation.to_string(),
            principal: self.principal.clone(),
        }
    }
}

/// Check an authenticated native administrative `ReadSchema` result for the
/// exact two requested collections. Deployment must perform this check with
/// its separate administrative authority before admitting application reads.
pub fn verify_installed_collection_definitions(
    snapshot: &SchemaSnapshot,
    binding: &InstalledProfileBinding,
) -> Result<()> {
    binding.validate()?;
    if snapshot.incarnation != binding.incarnation.to_string() || snapshot.collections.len() != 2 {
        return Err(CustodyError::Conflict);
    }
    for (name, expected) in [
        (
            &binding.manifest_collection,
            &binding.manifest_definition_sha256,
        ),
        (&binding.chunk_collection, &binding.chunk_definition_sha256),
    ] {
        let Some(Some(collection)) = snapshot.collections.get(name) else {
            return Err(CustodyError::Conflict);
        };
        let actual = sha256_hex(
            &serde_json::to_vec(&collection.definition)
                .map_err(|_| CustodyError::Invalid("definition encoding"))?,
        );
        if actual != *expected {
            return Err(CustodyError::Conflict);
        }
    }
    Ok(())
}

pub struct KasumiBackend {
    pool: KasumiClientPool,
    resources: Arc<ClientResources>,
    expected_incarnation: Uuid,
}

impl KasumiBackend {
    pub fn from_installed_profile(path: &Path, binding: &InstalledProfileBinding) -> Result<Self> {
        binding.validate()?;
        let (profile, digest) = ClientProfile::load_with_sha256(path)?;
        if digest != binding.profile_sha256 {
            return Err(CustodyError::Conflict);
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
impl CustodyBackend for KasumiBackend {
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
            .context("invalid custody read timeout")?;
        let request = ReadSnapshotRequest {
            documents: ids
                .iter()
                .map(|id| DocumentKey {
                    collection: collection.into(),
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
                max_rows: READ_GROUP,
                max_decoded_bytes: 12 << 20,
            },
            deadline,
            expected_incarnation: self.expected_incarnation,
        };
        let response = self.pool.read_snapshot(&request, &options).await?;
        ensure!(
            response.documents.len() == ids.len(),
            "custody snapshot omitted a document"
        );
        response
            .documents
            .iter()
            .zip(ids)
            .map(|(row, id)| {
                ensure!(
                    row.key.collection == collection && row.key.id == *id,
                    "custody snapshot changed a document key"
                );
                Ok(row.document.clone())
            })
            .collect()
    }
}

pub struct PrivateEvidenceCustody<B> {
    backend: B,
    manifest_collection: String,
    chunk_collection: String,
    scope: MutationReceiptScope,
    max_component_bytes: usize,
}

impl<B: CustodyBackend> PrivateEvidenceCustody<B> {
    pub fn new(
        backend: B,
        manifest_collection: String,
        chunk_collection: String,
        scope: MutationReceiptScope,
        max_component_bytes: usize,
    ) -> Result<Self> {
        collection_definitions(&manifest_collection, &chunk_collection)?;
        if max_component_bytes == 0 || max_component_bytes > MAX_COMPONENT_BYTES {
            return Err(CustodyError::Invalid("component limit"));
        }
        validate_scope(&scope)?;
        Ok(Self {
            backend,
            manifest_collection,
            chunk_collection,
            scope,
            max_component_bytes,
        })
    }

    fn require_identity(&self, identity: &EvidenceIdentity) -> Result<()> {
        identity.validate()?;
        if identity.scope != self.scope {
            return Err(CustodyError::Conflict);
        }
        Ok(())
    }

    fn remaining(deadline: Instant) -> Result<Duration> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(CustodyError::Backend(anyhow::anyhow!(
                "custody deadline elapsed"
            )));
        }
        Ok(remaining)
    }

    async fn one(
        &mut self,
        collection: &str,
        id: String,
        deadline: Instant,
    ) -> Result<Option<Document>> {
        let rows = self
            .backend
            .read_records(
                collection,
                std::slice::from_ref(&id),
                Self::remaining(deadline)?,
            )
            .await?;
        match rows.as_slice() {
            [document]
                if document
                    .as_ref()
                    .is_none_or(|record| record.id == id && record.version > 0) =>
            {
                Ok(document.clone())
            }
            _ => Err(CustodyError::Inconsistent),
        }
    }

    /// Read and authenticate one complete component. Missing manifests return
    /// `None`; a present manifest with any absent, replaced or altered chunk is
    /// an error. The caller must separately verify the external proof itself.
    pub async fn read(
        &mut self,
        identity: &EvidenceIdentity,
        timeout: Duration,
    ) -> Result<Option<RetainedEvidence>> {
        self.require_identity(identity)?;
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(CustodyError::Invalid("timeout"))?;
        let collection = self.manifest_collection.clone();
        let Some(document) = self
            .one(&collection, identity.manifest_id(), deadline)
            .await?
        else {
            return Ok(None);
        };
        let manifest: EvidenceManifest =
            serde_json::from_value(document.body).map_err(|_| CustodyError::Inconsistent)?;
        if manifest.schema != FORMAT
            || manifest.identity != *identity
            || manifest.payload_bytes == 0
            || manifest.payload_bytes > self.max_component_bytes
            || manifest.chunks == 0
            || manifest.chunks > MAX_CHUNKS
            || manifest.chunks != manifest.payload_bytes.div_ceil(CHUNK_BYTES)
            || !exact_digest(&manifest.payload_sha256)
        {
            return Err(CustodyError::Inconsistent);
        }
        // Do not allocate the claimed full length before any chunk exists.
        let mut payload = Vec::new();
        for start in (0..manifest.chunks).step_by(READ_GROUP) {
            let end = (start + READ_GROUP).min(manifest.chunks);
            let ids = (start..end)
                .map(|index| identity.chunk_id(index))
                .collect::<Vec<_>>();
            let rows = self
                .backend
                .read_records(&self.chunk_collection, &ids, Self::remaining(deadline)?)
                .await?;
            if rows.len() != ids.len() {
                return Err(CustodyError::Inconsistent);
            }
            for (index, (document, id)) in (start..end).zip(rows.into_iter().zip(ids)) {
                let Some(document) = document else {
                    return Err(CustodyError::Inconsistent);
                };
                if document.id != id || document.version == 0 {
                    return Err(CustodyError::Inconsistent);
                }
                let chunk: EvidenceChunk = serde_json::from_value(document.body)
                    .map_err(|_| CustodyError::Inconsistent)?;
                if chunk.schema != FORMAT
                    || chunk.identity != *identity
                    || chunk.payload_sha256 != manifest.payload_sha256
                    || chunk.index != index
                    || chunk.chunks != manifest.chunks
                    || !exact_digest(&chunk.data_sha256)
                {
                    return Err(CustodyError::Inconsistent);
                }
                let bytes = exact_hex(&chunk.data_hex, CHUNK_BYTES)?;
                if sha256_hex(&bytes) != chunk.data_sha256
                    || (index + 1 < manifest.chunks && bytes.len() != CHUNK_BYTES)
                    || payload
                        .len()
                        .checked_add(bytes.len())
                        .is_none_or(|len| len > manifest.payload_bytes)
                {
                    return Err(CustodyError::Inconsistent);
                }
                payload.try_reserve_exact(bytes.len()).map_err(|_| {
                    CustodyError::Backend(anyhow::anyhow!("custody memory unavailable"))
                })?;
                payload.extend(bytes);
            }
        }
        if payload.len() != manifest.payload_bytes
            || sha256_hex(&payload) != manifest.payload_sha256
        {
            return Err(CustodyError::Inconsistent);
        }
        Ok(Some(RetainedEvidence {
            identity: identity.clone(),
            sha256: manifest.payload_sha256,
            bytes: payload,
        }))
    }

    async fn put_exact(
        &mut self,
        collection: &str,
        id: String,
        proposed: serde_json::Value,
        deadline: Instant,
    ) -> Result<AppendOutcome> {
        if let Some(existing) = self.one(collection, id.clone(), deadline).await? {
            return if existing.body == proposed {
                Ok(AppendOutcome::AlreadyPresent)
            } else {
                Err(CustodyError::Conflict)
            };
        }
        let original = put(collection, id.clone(), proposed.clone());
        let submit = self
            .backend
            .mutate(&original, Self::remaining(deadline)?)
            .await;
        let (receipt, recovered) = match submit {
            Ok(receipt) => (receipt, false),
            Err(_) => {
                let remaining = Self::remaining(deadline)
                    .map_err(|_| CustodyError::UnknownOutcome(id.clone()))?;
                let resolution = self
                    .backend
                    .resolve(&self.scope, &original, remaining)
                    .await
                    .map_err(|_| CustodyError::UnknownOutcome(id.clone()))?
                    .ok_or_else(|| CustodyError::UnknownOutcome(id.clone()))?;
                let expected = original.digest().map_err(|_| CustodyError::Inconsistent)?;
                if resolution.scope != self.scope || resolution.request_digest != expected {
                    return Err(CustodyError::Inconsistent);
                }
                (
                    resolution.outcome.map_err(|_| CustodyError::Rejected)?,
                    true,
                )
            }
        };
        if receipt.revision == 0
            || receipt.versions
                != BTreeMap::from([(document_receipt_path(collection, &id), receipt.revision)])
        {
            return Err(CustodyError::Inconsistent);
        }
        let after = self
            .one(collection, id.clone(), deadline)
            .await
            .map_err(|_| CustodyError::UnknownOutcome(id.clone()))?;
        match after {
            Some(document) if document.body == proposed && document.version == receipt.revision => {
                if recovered {
                    Ok(AppendOutcome::Recovered)
                } else {
                    Ok(AppendOutcome::Committed)
                }
            }
            Some(document) if document.body == proposed => Err(CustodyError::Inconsistent),
            Some(_) => Err(CustodyError::Conflict),
            None => Err(CustodyError::UnknownOutcome(id)),
        }
    }

    /// Retain an exact original byte component. Each chunk uses its own
    /// permanent Kasumi mutation identity. The final manifest is the commit
    /// marker; a failed upload can resume with the same identity and bytes.
    pub async fn append(
        &mut self,
        identity: &EvidenceIdentity,
        bytes: &[u8],
        timeout: Duration,
    ) -> Result<AppendOutcome> {
        self.require_identity(identity)?;
        if bytes.is_empty() || bytes.len() > self.max_component_bytes {
            return Err(CustodyError::Invalid("component size"));
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(CustodyError::Invalid("timeout"))?;
        if let Some(existing) = self.read(identity, Self::remaining(deadline)?).await? {
            return if existing.bytes == bytes {
                Ok(AppendOutcome::AlreadyPresent)
            } else {
                Err(CustodyError::Conflict)
            };
        }
        let payload_sha256 = sha256_hex(bytes);
        let chunks = bytes.len().div_ceil(CHUNK_BYTES);
        if chunks == 0 || chunks > MAX_CHUNKS {
            return Err(CustodyError::Invalid("component chunk count"));
        }
        let mut recovered = false;
        let collection = self.chunk_collection.clone();
        for (index, part) in bytes.chunks(CHUNK_BYTES).enumerate() {
            let chunk = EvidenceChunk {
                schema: FORMAT.into(),
                identity: identity.clone(),
                payload_sha256: payload_sha256.clone(),
                index,
                chunks,
                data_sha256: sha256_hex(part),
                data_hex: hex::encode(part),
            };
            recovered |= self
                .put_exact(
                    &collection,
                    identity.chunk_id(index),
                    body(&chunk)?,
                    deadline,
                )
                .await?
                == AppendOutcome::Recovered;
        }
        let manifest = EvidenceManifest {
            schema: FORMAT.into(),
            identity: identity.clone(),
            payload_sha256,
            payload_bytes: bytes.len(),
            chunks,
        };
        let collection = self.manifest_collection.clone();
        recovered |= self
            .put_exact(
                &collection,
                identity.manifest_id(),
                body(&manifest)?,
                deadline,
            )
            .await?
            == AppendOutcome::Recovered;
        let remaining = Self::remaining(deadline)
            .map_err(|_| CustodyError::UnknownOutcome(identity.manifest_id()))?;
        let retained = self
            .read(identity, remaining)
            .await
            .map_err(|_| CustodyError::UnknownOutcome(identity.manifest_id()))?;
        if retained.as_ref().is_none_or(|record| record.bytes != bytes) {
            return Err(CustodyError::UnknownOutcome(identity.manifest_id()));
        }
        Ok(if recovered {
            AppendOutcome::Recovered
        } else {
            AppendOutcome::Committed
        })
    }
}

impl PrivateEvidenceCustody<KasumiBackend> {
    pub fn from_installed_profile(path: &Path, binding: &InstalledProfileBinding) -> Result<Self> {
        let backend = KasumiBackend::from_installed_profile(path, binding)?;
        Self::new(
            backend,
            binding.manifest_collection.clone(),
            binding.chunk_collection.clone(),
            binding.scope(),
            binding.max_component_bytes,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{bail, ensure};

    #[derive(Default)]
    enum Dispatch {
        #[default]
        Normal,
        CommitThenError,
        CommitThenErrorWithoutReceipt,
        CommitWithWrongReceipt,
        ErrorBeforeCommit,
    }

    #[derive(Default)]
    struct MemoryBackend {
        records: BTreeMap<(String, String), Document>,
        receipts: BTreeMap<String, MutationReceipt>,
        scope: Option<MutationReceiptScope>,
        dispatch: Dispatch,
        mutation_calls: usize,
    }

    #[async_trait]
    impl CustodyBackend for MemoryBackend {
        async fn mutate(
            &mut self,
            batch: &MutationBatch,
            _: Duration,
        ) -> anyhow::Result<WriteReceipt> {
            self.mutation_calls += 1;
            let digest = batch.digest()?;
            if let Some(receipt) = self.receipts.get(&batch.idempotency_key) {
                ensure!(receipt.request_digest == digest, "changed original batch");
                return Ok(receipt.outcome.clone()?);
            }
            let dispatch = std::mem::take(&mut self.dispatch);
            if matches!(dispatch, Dispatch::ErrorBeforeCommit) {
                bail!("not submitted");
            }
            let [
                Mutation::Put {
                    collection,
                    id,
                    body,
                    expected,
                },
            ] = batch.operations.as_slice()
            else {
                bail!("test backend accepts one immutable put");
            };
            ensure!(*expected == Precondition::Absent, "not append-only");
            ensure!(
                serde_json::to_vec(body)?.len() <= REQUIRED_MAX_DOCUMENT_BYTES,
                "oversized document"
            );
            let key = (collection.clone(), id.clone());
            ensure!(!self.records.contains_key(&key), "duplicate document");
            let result = WriteReceipt {
                revision: self.records.len() as u64 + 1,
                versions: BTreeMap::from([(
                    document_receipt_path(collection, id),
                    self.records.len() as u64 + 1,
                )]),
            };
            self.records.insert(
                key,
                Document {
                    id: id.clone(),
                    version: result.revision,
                    body: body.clone(),
                },
            );
            if !matches!(dispatch, Dispatch::CommitThenErrorWithoutReceipt) {
                self.receipts.insert(
                    batch.idempotency_key.clone(),
                    MutationReceipt {
                        scope: self.scope.clone().unwrap(),
                        request_digest: digest,
                        outcome: Ok(result.clone()),
                    },
                );
            }
            if matches!(
                dispatch,
                Dispatch::CommitThenError | Dispatch::CommitThenErrorWithoutReceipt
            ) {
                bail!("reply lost after commit");
            }
            if matches!(dispatch, Dispatch::CommitWithWrongReceipt) {
                return Ok(WriteReceipt {
                    revision: result.revision,
                    versions: BTreeMap::new(),
                });
            }
            Ok(result)
        }

        async fn resolve(
            &mut self,
            _: &MutationReceiptScope,
            original: &MutationBatch,
            _: Duration,
        ) -> anyhow::Result<Option<MutationReceipt>> {
            Ok(self.receipts.get(&original.idempotency_key).cloned())
        }

        async fn read_records(
            &mut self,
            collection: &str,
            ids: &[String],
            _: Duration,
        ) -> anyhow::Result<Vec<Option<Document>>> {
            Ok(ids
                .iter()
                .map(|id| self.records.get(&(collection.into(), id.clone())).cloned())
                .collect())
        }
    }

    fn identity() -> EvidenceIdentity {
        EvidenceIdentity::new(
            MutationReceiptScope {
                tenant: "mibank-bpng".into(),
                incarnation: Uuid::from_u128(1).to_string(),
                principal: "core-evidence".into(),
            },
            "ab".repeat(32),
            "retail-protocol4-executed-block".into(),
        )
        .unwrap()
    }

    fn custody() -> PrivateEvidenceCustody<MemoryBackend> {
        let id = identity();
        let backend = MemoryBackend {
            scope: Some(id.scope.clone()),
            ..MemoryBackend::default()
        };
        PrivateEvidenceCustody::new(
            backend,
            "evidence_manifests".into(),
            "evidence_chunks".into(),
            id.scope,
            2 * CHUNK_BYTES + 1,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn multi_chunk_roundtrip_replay_and_conflict() {
        let mut custody = custody();
        let id = identity();
        let data = (0..CHUNK_BYTES + 17)
            .map(|index| index as u8)
            .collect::<Vec<_>>();
        assert_eq!(
            custody.read(&id, Duration::from_secs(5)).await.unwrap(),
            None
        );
        assert_eq!(
            custody
                .append(&id, &data, Duration::from_secs(5))
                .await
                .unwrap(),
            AppendOutcome::Committed
        );
        assert_eq!(
            custody
                .read(&id, Duration::from_secs(5))
                .await
                .unwrap()
                .unwrap()
                .bytes,
            data
        );
        assert_eq!(
            custody
                .append(&id, &data, Duration::from_secs(5))
                .await
                .unwrap(),
            AppendOutcome::AlreadyPresent
        );
        let mut changed = data.clone();
        changed[0] ^= 1;
        assert!(matches!(
            custody.append(&id, &changed, Duration::from_secs(5)).await,
            Err(CustodyError::Conflict)
        ));
        assert_eq!(custody.backend.mutation_calls, 3); // two chunks, one manifest
    }

    #[tokio::test]
    async fn lost_reply_recovers_exact_receipt_and_complete_readback() {
        let mut custody = custody();
        custody.backend.dispatch = Dispatch::CommitThenError;
        let id = identity();
        assert_eq!(
            custody
                .append(&id, b"original bytes", Duration::from_secs(5))
                .await
                .unwrap(),
            AppendOutcome::Recovered
        );
        assert_eq!(
            custody
                .read(&id, Duration::from_secs(5))
                .await
                .unwrap()
                .unwrap()
                .bytes,
            b"original bytes"
        );
    }

    #[tokio::test]
    async fn visible_chunk_without_original_receipt_is_unknown() {
        let mut custody = custody();
        custody.backend.dispatch = Dispatch::CommitThenErrorWithoutReceipt;
        let id = identity();
        assert!(matches!(
            custody
                .append(&id, b"original bytes", Duration::from_secs(5))
                .await,
            Err(CustodyError::UnknownOutcome(_))
        ));
        assert_eq!(custody.backend.records.len(), 1);
        assert!(custody.backend.receipts.is_empty());
        assert!(
            custody
                .read(&id, Duration::from_secs(5))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn successful_reply_must_name_the_exact_committed_document() {
        let mut custody = custody();
        custody.backend.dispatch = Dispatch::CommitWithWrongReceipt;
        let id = identity();
        assert!(matches!(
            custody
                .append(&id, b"original bytes", Duration::from_secs(5))
                .await,
            Err(CustodyError::Inconsistent)
        ));
        assert_eq!(custody.backend.records.len(), 1);
        assert!(
            custody
                .read(&id, Duration::from_secs(5))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn uncommitted_chunk_never_publishes_manifest_and_replays_same_id() {
        let mut custody = custody();
        custody.backend.dispatch = Dispatch::ErrorBeforeCommit;
        let id = identity();
        assert!(matches!(
            custody
                .append(&id, b"evidence", Duration::from_secs(5))
                .await,
            Err(CustodyError::UnknownOutcome(_))
        ));
        assert_eq!(
            custody.read(&id, Duration::from_secs(5)).await.unwrap(),
            None
        );
        assert_eq!(
            custody
                .append(&id, b"evidence", Duration::from_secs(5))
                .await
                .unwrap(),
            AppendOutcome::Committed
        );
    }

    #[tokio::test]
    async fn present_manifest_requires_every_original_chunk() {
        let mut custody = custody();
        let id = identity();
        custody
            .append(&id, b"exact proof", Duration::from_secs(5))
            .await
            .unwrap();
        let key = (custody.chunk_collection.clone(), id.chunk_id(0));
        let original = custody.backend.records.get(&key).unwrap().clone();
        custody.backend.records.remove(&key);
        assert!(matches!(
            custody.read(&id, Duration::from_secs(5)).await,
            Err(CustodyError::Inconsistent)
        ));
        custody.backend.records.insert(key.clone(), original);
        let record = custody.backend.records.get_mut(&key).unwrap();
        record.body["data_hex"] = serde_json::json!("00");
        assert!(matches!(
            custody.read(&id, Duration::from_secs(5)).await,
            Err(CustodyError::Inconsistent)
        ));
    }

    #[tokio::test]
    async fn private_scope_and_bounded_first_release_schema() {
        let mut custody = custody();
        let mut other_scope = identity().scope;
        other_scope.principal = "other-principal".into();
        let id = EvidenceIdentity::new(
            other_scope,
            "ab".repeat(32),
            "retail-protocol4-executed-block".into(),
        )
        .unwrap();
        assert!(matches!(
            custody.append(&id, b"bytes", Duration::from_secs(5)).await,
            Err(CustodyError::Conflict)
        ));
        let definitions = collection_definitions("evidence_manifests", "evidence_chunks").unwrap();
        assert!(
            definitions
                .iter()
                .all(|definition| definition.strict_read_audit
                    && definition.write_mode == CollectionWriteMode::AppendOnly
                    && definition.retention_class == CollectionRetentionClass::Operational)
        );
        assert!(
            custody
                .append(
                    &identity(),
                    &vec![0; 2 * CHUNK_BYTES + 2],
                    Duration::from_secs(5)
                )
                .await
                .is_err()
        );
        assert_eq!(MAX_CHUNKS, MAX_COMPONENT_BYTES.div_ceil(CHUNK_BYTES));
    }

    #[test]
    fn installed_schema_accepts_maximum_chunk_and_rejects_unknown_fields() {
        let [manifest_definition, chunk_definition] =
            collection_definitions("evidence_manifests", "evidence_chunks").unwrap();
        let mut scope = identity().scope;
        scope.tenant = "t".repeat(256);
        scope.principal = "p".repeat(256);
        let id = EvidenceIdentity::new(scope, "ab".repeat(32), "e".repeat(256)).unwrap();
        let part = vec![0xa5; CHUNK_BYTES];
        let chunk = EvidenceChunk {
            schema: FORMAT.into(),
            identity: id.clone(),
            payload_sha256: sha256_hex(&part),
            index: 0,
            chunks: 1,
            data_sha256: sha256_hex(&part),
            data_hex: hex::encode(&part),
        };
        let chunk_body = body(&chunk).unwrap();
        kasumi_query::validate_document(&chunk_definition, &chunk_body).unwrap();
        assert!(serde_json::to_vec(&chunk_body).unwrap().len() <= REQUIRED_MAX_DOCUMENT_BYTES);
        let chunk_batch = put(
            &chunk_definition.name,
            identity().chunk_id(0),
            chunk_body.clone(),
        );
        assert!(kasumi_types::staged_digest(&chunk_batch).unwrap().1 <= REQUIRED_MAX_BATCH_BYTES);
        let manifest = EvidenceManifest {
            schema: FORMAT.into(),
            identity: id,
            payload_sha256: sha256_hex(&part),
            payload_bytes: part.len(),
            chunks: 1,
        };
        let manifest_body = body(&manifest).unwrap();
        kasumi_query::validate_document(&manifest_definition, &manifest_body).unwrap();
        let mut unknown = chunk_body;
        unknown["retired_decoder"] = serde_json::json!(true);
        assert!(kasumi_query::validate_document(&chunk_definition, &unknown).is_err());
    }

    #[test]
    fn installed_binding_rejects_unpinned_or_changed_collection_schema() {
        let [manifest_definition_sha256, chunk_definition_sha256] =
            collection_definition_sha256("evidence_manifests", "evidence_chunks").unwrap();
        let mut binding = InstalledProfileBinding {
            profile_sha256: "42".repeat(32),
            tenant: "mibank-bpng".into(),
            incarnation: Uuid::from_u128(1),
            principal: "core-evidence".into(),
            family_id: Uuid::from_u128(3),
            manifest_collection: "evidence_manifests".into(),
            chunk_collection: "evidence_chunks".into(),
            manifest_definition_sha256,
            chunk_definition_sha256,
            max_component_bytes: 32 << 20,
        };
        binding.validate().unwrap();
        binding.chunk_definition_sha256 = "00".repeat(32);
        assert!(binding.validate().is_err());
        binding.chunk_definition_sha256 =
            collection_definition_sha256("evidence_manifests", "evidence_chunks").unwrap()[1]
                .clone();
        binding.max_component_bytes = MAX_COMPONENT_BYTES + 1;
        assert!(binding.validate().is_err());
    }

    #[test]
    fn evidence_id_is_permanent_for_stage_scope_and_component_purpose() {
        let original = identity();
        assert_eq!(
            EvidenceIdentity::new(
                original.scope.clone(),
                original.subject_sha256.clone(),
                original.purpose.clone(),
            )
            .unwrap()
            .evidence_id,
            original.evidence_id
        );
        let changed_purpose = EvidenceIdentity::new(
            original.scope.clone(),
            original.subject_sha256.clone(),
            "retail-protocol4-finality-chain".into(),
        )
        .unwrap();
        assert_ne!(changed_purpose.evidence_id, original.evidence_id);
        let mut fabricated = original;
        fabricated.evidence_id = Uuid::from_u128(99);
        assert!(fabricated.validate().is_err());
    }

    #[test]
    fn admin_schema_result_must_match_signed_first_release_definitions() {
        let [manifest_definition, chunk_definition] =
            collection_definitions("evidence_manifests", "evidence_chunks").unwrap();
        let [manifest_definition_sha256, chunk_definition_sha256] =
            collection_definition_sha256("evidence_manifests", "evidence_chunks").unwrap();
        let binding = InstalledProfileBinding {
            profile_sha256: "42".repeat(32),
            tenant: "mibank-bpng".into(),
            incarnation: Uuid::from_u128(1),
            principal: "core-evidence".into(),
            family_id: Uuid::from_u128(3),
            manifest_collection: "evidence_manifests".into(),
            chunk_collection: "evidence_chunks".into(),
            manifest_definition_sha256,
            chunk_definition_sha256,
            max_component_bytes: 32 << 20,
        };
        let mut snapshot = SchemaSnapshot {
            incarnation: binding.incarnation.to_string(),
            revision: 10,
            policy_epoch: 2,
            schema_epoch: 3,
            collections: BTreeMap::from([
                (
                    binding.manifest_collection.clone(),
                    Some(kasumi_types::SchemaCollection {
                        definition: manifest_definition,
                        data_epoch: 1,
                        archived_document_count: 0,
                    }),
                ),
                (
                    binding.chunk_collection.clone(),
                    Some(kasumi_types::SchemaCollection {
                        definition: chunk_definition,
                        data_epoch: 1,
                        archived_document_count: 0,
                    }),
                ),
            ]),
        };
        verify_installed_collection_definitions(&snapshot, &binding).unwrap();
        snapshot
            .collections
            .get_mut(&binding.chunk_collection)
            .unwrap()
            .as_mut()
            .unwrap()
            .definition
            .strict_read_audit = false;
        assert!(verify_installed_collection_definitions(&snapshot, &binding).is_err());
        snapshot
            .collections
            .get_mut(&binding.chunk_collection)
            .unwrap()
            .as_mut()
            .unwrap()
            .definition
            .strict_read_audit = true;
        snapshot.incarnation = Uuid::from_u128(9).to_string();
        assert!(verify_installed_collection_definitions(&snapshot, &binding).is_err());
    }
}
