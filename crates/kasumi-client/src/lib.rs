//! Native protocol and typed data client, independent of server/storage internals.
//! Connection requires TLS 1.3, mTLS, an approved CA and server leaf pins. The
//! caller supplies current credentials for every request. Low-level clients do
//! not retry; installed endpoint pools retain exact operation identities and
//! pin historical reads to their originating member.

/// The connection types that [`KasumiClientConfig`] and [`Kasumi::connect`]
/// take, so that an application needs no direct `kasumi-transport` dependency.
pub use kasumi_transport::{
    CertificatePin, TlsIdentity,
    credentials::{CredentialSource, FileCredentialSource},
};
/// Every request, reply and definition type in this crate's signatures.
pub use kasumi_types as types;
use kasumi_types::{MutationBatch, WriteReceipt};
use serde::Serialize;
use std::collections::BTreeSet;
use tonic::{Request, transport::Channel};

mod literal_decode;
mod snapshot_decode;
pub use literal_decode::{
    decode_mutation_json, decode_query_json, decode_schema_change_json, decode_staged_chunk_json,
};
pub use snapshot_decode::{
    AdmittedResponse, ClientDecodeLimits, ClientResourceUsage, ClientResources, JsonReadOptions,
    SnapshotReadOptions,
};
mod credentials;
mod profile;
pub use profile::{ClientProfile, ProfileAuthorityEndpoint, ProfileTlsFiles};
mod security_audit;
pub use security_audit::VerifiedSecurityAuditArchive;
mod installed_pool;
mod lifecycle_pool;
mod recovery_pool;
mod retirement_pool;
pub use lifecycle_pool::KasumiLifecyclePool;
pub use recovery_pool::KasumiRecoveryPool;
pub use retirement_pool::KasumiRetirementPool;
mod recovery;
pub use recovery::KasumiRecoveryClient;
mod lifecycle;
pub use lifecycle::{CurrentControlTopology, CurrentControlTopologyRelease, KasumiLifecycleClient};
mod authority;
mod authority_pool;
mod control_signer;
pub use control_signer::CurrentControlSignerObservation;
mod signer_publication;
pub use signer_publication::CurrentSignerPublication;
mod data_pool;
mod mutation_receipt;
pub use authority_pool::KasumiAuthorityPool;
pub use data_pool::{KasumiClientPool, RoutedQueryPage, RoutedSnapshotLease};
pub use mutation_receipt::{
    RECEIPT_FOR_OTHER_INPUT, RECEIPT_FOR_OTHER_SCOPE, verify_mutation_receipt,
};
mod restore_lineage_proof;
mod retirement_proof;
pub use authority::KasumiAuthorityClient;
pub use restore_lineage_proof::VerifiedRestoreLineage;
pub use retirement_proof::{
    VerifiedRetirementReceipt, VerifiedRetirementResolution, VerifiedRetirementStop,
};
mod backup_proof;
mod retirement;
pub use backup_proof::VerifiedBackupCheckpoint;

mod kasumi;
pub use kasumi::{Kasumi, QueryPage, TypedDocument};

/// Everything needed to read and write data: `use kasumi_client::prelude::*;`.
///
/// ```
/// use kasumi_client::prelude::*;
///
/// // Each name that a request or batch builder takes is in the prelude.
/// let walk = QueryRequest::new("events")
///     .filter(Filter::new().eq("/tenant", "acme").gte("/at", "2026-01-01"))
///     .sort_asc("/at")
///     .sort_asc("/event_id")
///     .paging(Paging::Seek)
///     .limit(500);
/// assert_eq!(walk.page_size(), 500);
/// ```
pub mod prelude {
    pub use crate::{ClientError, Kasumi, QueryPage, TypedDocument};
    pub use kasumi_types::{
        AggregateFunction, Aggregation, CollectionDefinition, Condition, Direction, Document,
        ErrorCode, Filter, Mutation, MutationBatch, Paging, Precondition, QueryRequest,
        QueryResponse, QueryRow, ReadAssertion, ReadPrecondition, Sort, TextMode, TextSearch,
        WriteReceipt,
    };
}

pub mod proto {
    tonic::include_proto!("kasumi.v1");
}

/// Required identity of the first-release native write-receipt wire contract.
pub const NATIVE_WRITE_RECEIPT_CONTRACT: &str = "kasumi.write-receipt.v1";

/// Decode the strict current native write-receipt wire. This checks the
/// contract, canonical ordered unique paths, and applying revisions, but does
/// not match the reply to a specific request.
pub fn decode_native_write_receipt(
    response: proto::WriteReceipt,
) -> Result<WriteReceipt, ClientError> {
    mutation_receipt::decode_write_receipt(response)
}

/// Verify a native `Mutate` reply against the exact submitted batch.
/// This matches input on an authenticated connection; it is not independent
/// authentication of the server or a finality proof.
pub fn verify_submitted_mutation_receipt(
    original: &MutationBatch,
    response: proto::WriteReceipt,
) -> Result<WriteReceipt, ClientError> {
    mutation_receipt::verify_committed_write_receipt(original, response)
}

/// Classify with [`ClientError::is_transient`], [`ClientError::grpc_code`] and
/// [`ClientError::code`] rather than matching variants or raw gRPC numbers:
/// a bounded read reports every failure, a cancelled stream included, in its
/// normalized `DecodeRejected` form. New variants may be added.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClientError {
    #[error("native secure connection failed: {0}")]
    Connection(#[from] anyhow::Error),
    #[error("{}", transport_failure(.0))]
    Transport(#[from] tonic::Status),
    /// Admitted decode failures retain no peer-controlled strings or metadata after
    /// their admission owner is released. The code remains usable for routing,
    /// and `database` keeps the server's Kasumi error code when it reported one.
    #[error("{}", decode_rejection(.code, .reason, .database))]
    DecodeRejected {
        code: tonic::Code,
        reason: &'static str,
        database: Option<kasumi_types::ErrorCode>,
    },
    #[error("invalid native JSON")]
    Json(#[from] serde_json::Error),
    #[error("invalid native response: {0}")]
    InvalidResponse(&'static str),
    #[error("invalid bearer authorization")]
    Authorization,
    #[error("native request exceeds its byte limit")]
    RequestTooLarge,
}

impl ClientError {
    /// The database's own error code, when the server rejected the request.
    /// It is more specific than the gRPC status: `IndexRequired`,
    /// `CursorExpired` and `Sealed` share one gRPC code, for example, and
    /// `UnknownOutcome` means "resolve or retry the same batch", never "give up".
    pub fn code(&self) -> Option<kasumi_types::ErrorCode> {
        match self {
            Self::Transport(status) => database_code(status),
            Self::DecodeRejected { database, .. } => *database,
            _ => None,
        }
    }

    /// The gRPC status code of this failure, whichever variant carries it.
    pub fn grpc_code(&self) -> tonic::Code {
        match self {
            Self::Transport(status) => status.code(),
            Self::DecodeRejected { code, .. } => *code,
            Self::Connection(_) => tonic::Code::Unavailable,
            Self::Json(_) | Self::InvalidResponse(_) => tonic::Code::DataLoss,
            Self::Authorization => tonic::Code::Unauthenticated,
            Self::RequestTooLarge => tonic::Code::ResourceExhausted,
        }
    }

    /// Whether the same request can succeed if sent again later: the node was
    /// unreachable, opening, draining or busy, or the attempt was cut short.
    /// A write sent again must reuse its idempotency key and identical batch;
    /// `UnknownOutcome` is transient in exactly that sense. Back off between
    /// attempts: a node reopening after a restart can take minutes.
    pub fn is_transient(&self) -> bool {
        use kasumi_types::ErrorCode;
        if let Some(code) = self.code() {
            return matches!(
                code,
                ErrorCode::Unavailable | ErrorCode::UnknownOutcome | ErrorCode::ResourceExhausted
            );
        }
        matches!(
            self.grpc_code(),
            tonic::Code::Unavailable
                | tonic::Code::DeadlineExceeded
                | tonic::Code::Cancelled
                | tonic::Code::Unknown
                | tonic::Code::ResourceExhausted
        )
    }
}

#[cfg(test)]
mod classification_tests {
    use super::*;

    fn kasumi(code: kasumi_types::ErrorCode, grpc: tonic::Code) -> ClientError {
        ClientError::Transport(tonic::Status::with_details(
            grpc,
            "fixture",
            serde_json::to_vec(&kasumi_types::Error::new(code, "fixture"))
                .unwrap()
                .into(),
        ))
    }

    #[test]
    fn a_cancelled_bounded_read_is_transient_whatever_its_variant() {
        let cancelled = ClientError::DecodeRejected {
            code: tonic::Code::Cancelled,
            reason: "native transport failed",
            database: None,
        };
        assert_eq!(cancelled.grpc_code(), tonic::Code::Cancelled);
        assert!(cancelled.is_transient());
        assert!(ClientError::Connection(anyhow::anyhow!("refused")).is_transient());
        assert!(ClientError::Transport(tonic::Status::unavailable("opening")).is_transient());
    }

    #[test]
    fn the_database_code_decides_before_the_grpc_code() {
        use kasumi_types::ErrorCode;
        assert!(kasumi(ErrorCode::UnknownOutcome, tonic::Code::Aborted).is_transient());
        assert!(
            kasumi(ErrorCode::ResourceExhausted, tonic::Code::ResourceExhausted).is_transient()
        );
        assert!(!kasumi(ErrorCode::QuotaExceeded, tonic::Code::ResourceExhausted).is_transient());
        assert!(!kasumi(ErrorCode::Forbidden, tonic::Code::PermissionDenied).is_transient());
        assert!(!ClientError::Authorization.is_transient());
        assert!(!ClientError::InvalidResponse("fixture").is_transient());
    }

    #[test]
    fn a_database_answer_displays_its_code_instead_of_a_transport_failure() {
        use kasumi_types::ErrorCode;
        let rejected = kasumi(ErrorCode::IndexRequired, tonic::Code::FailedPrecondition);
        assert_eq!(
            rejected.to_string(),
            "database reported INDEX_REQUIRED: fixture"
        );
        // A bounded read keeps only the closed code, and still shows it.
        let normalized = crate::snapshot_decode::normalize(rejected);
        assert_eq!(
            normalized.to_string(),
            "database reported INDEX_REQUIRED (gRPC FailedPrecondition)"
        );
        // Without a database answer the failure is still described as local.
        let unreachable = ClientError::Transport(tonic::Status::unavailable("refused"));
        assert!(
            unreachable
                .to_string()
                .starts_with("native transport failed: "),
            "{unreachable}"
        );
        let cancelled = ClientError::DecodeRejected {
            code: tonic::Code::Cancelled,
            reason: "native transport failed",
            database: None,
        };
        assert_eq!(
            cancelled.to_string(),
            "native decode failed (Cancelled): native transport failed"
        );
    }
}

/// Kasumi statuses carry `{"code": ..., "message": ...}` in their details.
pub(crate) fn database_code(status: &tonic::Status) -> Option<kasumi_types::ErrorCode> {
    serde_json::from_slice::<kasumi_types::Error>(status.details())
        .ok()
        .map(|error| error.code)
}

/// A request the database answered with its own error reads as that answer,
/// not as a failed transport: `INDEX_REQUIRED` is the caller's to act on.
fn transport_failure(status: &tonic::Status) -> String {
    match database_code(status) {
        Some(database) => format!("database reported {database}: {}", status.message()),
        None => format!("native transport failed: {status}"),
    }
}

/// The normalized form keeps no peer text, so the database's closed code is
/// the only description of its answer and must not be left out.
fn decode_rejection(
    code: &tonic::Code,
    reason: &'static str,
    database: &Option<kasumi_types::ErrorCode>,
) -> String {
    match database {
        Some(database) => format!("database reported {database} (gRPC {code:?})"),
        None => format!("native decode failed ({code:?}): {reason}"),
    }
}

/// Operator-selected connection identity and trust. Deliberately not Debug or
/// serializable: it owns private key material. Bearer tokens are request-local.
#[derive(Clone)]
pub struct KasumiClientConfig {
    pub endpoint: String,
    pub identity: TlsIdentity,
    pub trusted_ca_pem: Vec<u8>,
    pub server_certificate_pins: BTreeSet<CertificatePin>,
}

#[derive(Clone, Debug)]
pub struct KasumiClient {
    inner: proto::kasumi_data_client::KasumiDataClient<Channel>,
    deadline: Option<tokio::time::Instant>,
    read_channel: Channel,
}

impl KasumiClient {
    pub(crate) fn set_deadline(&mut self, deadline: tokio::time::Instant) {
        self.deadline = Some(deadline);
    }

    fn authorized<T>(&self, bearer: &str, value: T) -> Result<Request<T>, ClientError> {
        let mut request = authorized(bearer, value)?;
        if let Some(deadline) = self.deadline {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(
                    tonic::Status::deadline_exceeded("native operation deadline elapsed").into(),
                );
            }
            request.set_timeout(remaining);
        }
        Ok(request)
    }

    /// Current data authority observes immutable historical commitments. This
    /// proof grants no present permission and exposes no backup/key locations.
    pub async fn read_restore_lineage(
        &mut self,
        bearer: &str,
        request: &kasumi_types::ReadRestoreLineage,
    ) -> Result<VerifiedRestoreLineage, ClientError> {
        let response = self
            .read_client()
            .read_restore_lineage(self.authorized(
                bearer,
                proto::ReadRestoreLineageRequest {
                    request_json: encode(request)?,
                },
            )?)
            .await?
            .into_inner();
        let observation: kasumi_types::RestoreLineageObservation =
            serde_json::from_slice(&response.response_json)?;
        observation
            .validate()
            .map_err(|_| ClientError::Authorization)?;
        if observation.incarnation != request.expected_incarnation
            || observation.collection != request.collection
        {
            return Err(ClientError::Authorization);
        }
        Ok(VerifiedRestoreLineage::from_verified_read(observation))
    }

    pub async fn connect(config: &KasumiClientConfig) -> Result<Self, ClientError> {
        // HTTP/2 stream admission is per connection. Keep reads independent of
        // queued mutations, while clones share this bounded connection pair.
        let connect = || {
            kasumi_transport::grpc_channel(
                &config.endpoint,
                &config.identity,
                &config.trusted_ca_pem,
                config.server_certificate_pins.clone(),
            )
        };
        let (channel, read_channel) = tokio::try_join!(connect(), connect())?;
        Ok(Self {
            deadline: None,
            read_channel,
            inner: Self::configured_client(channel),
        })
    }

    fn configured_client(channel: Channel) -> proto::kasumi_data_client::KasumiDataClient<Channel> {
        proto::kasumi_data_client::KasumiDataClient::new(channel)
            .max_encoding_message_size((8 << 20) + (64 << 10))
            .max_decoding_message_size(16 << 20)
    }

    fn read_client(&self) -> proto::kasumi_data_client::KasumiDataClient<Channel> {
        Self::configured_client(self.read_channel.clone())
    }

    pub async fn begin_staged_transaction(
        &mut self,
        bearer: &str,
        request: &kasumi_types::BeginStagedTransaction,
    ) -> Result<WriteReceipt, ClientError> {
        let response = self
            .inner
            .begin_staged_transaction(self.authorized(
                bearer,
                proto::BeginStagedTransactionRequest {
                    request_json: encode(request)?,
                },
            )?)
            .await?
            .into_inner();
        mutation_receipt::decode_write_receipt(response)
    }

    pub async fn append_staged_chunk(
        &mut self,
        bearer: &str,
        request: &kasumi_types::AppendStagedChunk,
    ) -> Result<WriteReceipt, ClientError> {
        let response = self
            .inner
            .append_staged_chunk(self.authorized(
                bearer,
                proto::AppendStagedChunkRequest {
                    request_json: encode(request)?,
                },
            )?)
            .await?
            .into_inner();
        mutation_receipt::decode_write_receipt(response)
    }

    pub async fn finalize_staged_transaction(
        &mut self,
        bearer: &str,
        request: &kasumi_types::StagedTransactionRef,
    ) -> Result<WriteReceipt, ClientError> {
        let response = self
            .inner
            .finalize_staged_transaction(self.authorized(
                bearer,
                proto::StagedTransactionReference {
                    request_json: encode(request)?,
                },
            )?)
            .await?
            .into_inner();
        mutation_receipt::decode_write_receipt(response)
    }

    pub async fn stop_staged_transaction(
        &mut self,
        bearer: &str,
        request: &kasumi_types::StopStagedTransaction,
    ) -> Result<kasumi_types::StagedTransactionStatus, ClientError> {
        let reference = request
            .original
            .reference()
            .map_err(|error| ClientError::Connection(anyhow::anyhow!(error.message)))?;
        let response = self
            .inner
            .stop_staged_transaction(self.authorized(
                bearer,
                proto::StopStagedTransactionRequest {
                    request_json: encode(request)?,
                },
            )?)
            .await?
            .into_inner();
        staged_status::decode(&response.response_json, &reference)
    }

    pub async fn staged_transaction_status(
        &mut self,
        bearer: &str,
        request: &kasumi_types::StagedTransactionRef,
    ) -> Result<kasumi_types::StagedTransactionStatus, ClientError> {
        let response = self
            .read_client()
            .staged_transaction_status(self.authorized(
                bearer,
                proto::StagedTransactionReference {
                    request_json: encode(request)?,
                },
            )?)
            .await?
            .into_inner();
        staged_status::decode(&response.response_json, request)
    }

    pub async fn close_snapshot_lease(
        &mut self,
        bearer: &str,
        lease_id: &str,
    ) -> Result<(), ClientError> {
        self.inner
            .close_snapshot_lease(self.authorized(
                bearer,
                proto::SnapshotLeaseReference {
                    lease_id: lease_id.into(),
                },
            )?)
            .await?;
        Ok(())
    }
    /// Read-only full-batch shape admission using existing Data grants. The
    /// application must carry its returned epoch assertion into actual dispatch.
    pub async fn admit_mutation_capacity(
        &mut self,
        bearer: &str,
        expected_tenant: &str,
        request: &kasumi_types::AdmitMutationCapacity,
    ) -> Result<kasumi_types::MutationCapacityAdmission, ClientError> {
        // Bound protobuf decoding before allocating a peer-controlled JSON reply.
        let mut client = self.inner.clone().max_decoding_message_size(8192);
        let response = client
            .admit_mutation_capacity(self.authorized(
                bearer,
                proto::MutationCapacityRequest {
                    request_json: encode(request)?,
                },
            )?)
            .await?
            .into_inner();
        if response.response_json.len() > 4096 {
            return Err(ClientError::InvalidResponse(
                "mutation admission reply exceeds bound",
            ));
        }
        let admitted: kasumi_types::MutationCapacityAdmission =
            serde_json::from_slice(&response.response_json)?;
        if admitted.tenant != expected_tenant
            || admitted.incarnation != request.expected_incarnation
            || admitted.policy_epoch == 0
            || admitted.schema_epoch == 0
            || admitted.batch_digest
                != request
                    .batch
                    .digest()
                    .map_err(|_| ClientError::InvalidResponse("mutation admission input digest"))?
            || !request
                .batch
                .read_set
                .contains(&admitted.snapshot_assertion())
        {
            return Err(ClientError::InvalidResponse(
                "mutation admission differs from exact input and epochs",
            ));
        }
        Ok(admitted)
    }

    pub async fn mutate(
        &mut self,
        bearer: &str,
        batch: &MutationBatch,
    ) -> Result<WriteReceipt, ClientError> {
        let response = self
            .inner
            .mutate(self.authorized(
                bearer,
                proto::MutateRequest {
                    batch_json: encode(batch)?,
                },
            )?)
            .await?
            .into_inner();
        mutation_receipt::verify_committed_write_receipt(batch, response)
    }
}

/// Connect this client to the separate administrative listener.
#[derive(Clone)]
pub struct KasumiAdminClient {
    deadline: Option<tokio::time::Instant>,
    bounded_channel: Channel,
    inner: proto::kasumi_admin_client::KasumiAdminClient<Channel>,
}
impl KasumiAdminClient {
    pub(crate) fn set_deadline(&mut self, deadline: tokio::time::Instant) {
        self.deadline = Some(deadline);
    }
    fn authorized<T>(&self, bearer: &str, value: T) -> Result<tonic::Request<T>, ClientError> {
        crate::authorized_until(bearer, value, self.deadline)
    }
    pub async fn backup_session_status(
        &mut self,
        bearer: &str,
        request: &kasumi_types::BackupSessionRequest,
    ) -> Result<kasumi_types::BackupSessionStatus, ClientError> {
        let mut wire = authorized(
            bearer,
            proto::BackupSessionJsonRequest {
                request_json: encode(request)?,
            },
        )?;
        wire.set_timeout(std::time::Duration::from_secs(300));
        let response = self.inner.backup_session_status(wire).await?.into_inner();
        let status: kasumi_types::BackupSessionStatus =
            serde_json::from_slice(&response.response_json)?;
        if status.intent.session_id != request.session_id {
            return Err(ClientError::Json(
                <serde_json::Error as serde::de::Error>::custom(
                    "backup session identity differs from original request",
                ),
            ));
        }
        Ok(status)
    }
    pub async fn abort_backup_session(
        &mut self,
        bearer: &str,
        request: &kasumi_types::AbortBackupSession,
    ) -> Result<kasumi_types::BackupSessionStatus, ClientError> {
        let mut wire = authorized(
            bearer,
            proto::BackupSessionJsonRequest {
                request_json: encode(request)?,
            },
        )?;
        wire.set_timeout(std::time::Duration::from_secs(300));
        let response = self.inner.abort_backup_session(wire).await?.into_inner();
        let status: kasumi_types::BackupSessionStatus =
            serde_json::from_slice(&response.response_json)?;
        if status.intent.session_id != request.session_id {
            return Err(ClientError::Json(
                <serde_json::Error as serde::de::Error>::custom(
                    "backup session identity differs from original request",
                ),
            ));
        }
        Ok(status)
    }
    pub async fn cleanup_backup_session(
        &mut self,
        bearer: &str,
        request: &kasumi_types::CleanupBackupSession,
    ) -> Result<kasumi_types::BackupCleanupResult, ClientError> {
        let mut wire = authorized(
            bearer,
            proto::BackupSessionJsonRequest {
                request_json: encode(request)?,
            },
        )?;
        wire.set_timeout(std::time::Duration::from_secs(300));
        let response = self.inner.cleanup_backup_session(wire).await?.into_inner();
        let result: kasumi_types::BackupCleanupResult =
            serde_json::from_slice(&response.response_json)?;
        if result.session_id != request.session_id
            || result.deleted_objects > request.max_objects as u64
        {
            return Err(ClientError::Json(
                <serde_json::Error as serde::de::Error>::custom(
                    "backup cleanup result differs from original request",
                ),
            ));
        }
        Ok(result)
    }
    /// Returns a proof only from this authenticated, pinned-mTLS administrative channel.
    pub async fn create_backup_checkpoint(
        &mut self,
        bearer: &str,
        request: &kasumi_types::CreateBackupCheckpoint,
    ) -> Result<VerifiedBackupCheckpoint, ClientError> {
        let expected_id = request.session_id;
        let mut request = authorized(
            bearer,
            proto::CreateBackupCheckpointRequest {
                request_json: encode(request)?,
            },
        )?;
        request.set_timeout(std::time::Duration::from_secs(300));
        let response = self
            .inner
            .create_backup_checkpoint(request)
            .await?
            .into_inner();
        let checkpoint: kasumi_types::FullBackupCheckpoint =
            serde_json::from_slice(&response.response_json)?;
        checkpoint.validate().map_err(|error| {
            ClientError::Json(<serde_json::Error as serde::de::Error>::custom(error))
        })?;
        if checkpoint.backup_id != expected_id {
            return Err(ClientError::Json(
                <serde_json::Error as serde::de::Error>::custom(
                    "backup checkpoint identity differs from original request",
                ),
            ));
        }
        Ok(VerifiedBackupCheckpoint::verified(checkpoint))
    }

    /// Returns a proof only from this authenticated, pinned-mTLS administrative channel.
    pub async fn verify_backup_checkpoint(
        &mut self,
        bearer: &str,
        request: &kasumi_types::VerifyBackupCheckpoint,
    ) -> Result<VerifiedBackupCheckpoint, ClientError> {
        let expected_id = request.backup_id;
        let mut request = authorized(
            bearer,
            proto::VerifyBackupCheckpointRequest {
                request_json: encode(request)?,
            },
        )?;
        request.set_timeout(std::time::Duration::from_secs(300));
        let response = self
            .inner
            .verify_backup_checkpoint(request)
            .await?
            .into_inner();
        let checkpoint: kasumi_types::FullBackupCheckpoint =
            serde_json::from_slice(&response.response_json)?;
        checkpoint.validate().map_err(|error| {
            ClientError::Json(<serde_json::Error as serde::de::Error>::custom(error))
        })?;
        if checkpoint.backup_id != expected_id {
            return Err(ClientError::Json(
                <serde_json::Error as serde::de::Error>::custom(
                    "backup checkpoint identity differs from original request",
                ),
            ));
        }
        Ok(VerifiedBackupCheckpoint::verified(checkpoint))
    }

    pub async fn activate_schema(
        &mut self,
        bearer: &str,
        request: &kasumi_types::SchemaChangeSet,
    ) -> Result<WriteReceipt, ClientError> {
        let response = self
            .inner
            .activate_schema(authorized(
                bearer,
                proto::SchemaChangeSetRequest {
                    request_json: encode(request)?,
                },
            )?)
            .await?
            .into_inner();
        mutation_receipt::decode_write_receipt(response)
    }

    pub async fn schema_activation_status(
        &mut self,
        bearer: &str,
        request: &kasumi_types::ReadSchemaActivation,
    ) -> Result<kasumi_types::SchemaActivationStatus, ClientError> {
        let response = self
            .inner
            .schema_activation_status(authorized(
                bearer,
                proto::SchemaActivationStatusRequest {
                    request_json: encode(request)?,
                },
            )?)
            .await?
            .into_inner();
        Ok(serde_json::from_slice(&response.response_json)?)
    }

    pub async fn connect(config: &KasumiClientConfig) -> Result<Self, ClientError> {
        let channel = kasumi_transport::grpc_channel(
            &config.endpoint,
            &config.identity,
            &config.trusted_ca_pem,
            config.server_certificate_pins.clone(),
        )
        .await?;
        Ok(Self {
            deadline: None,
            bounded_channel: channel.clone(),
            inner: proto::kasumi_admin_client::KasumiAdminClient::new(channel)
                .max_encoding_message_size((8 << 20) + (64 << 10))
                .max_decoding_message_size(16 << 20),
        })
    }
    pub async fn archive_history(
        &mut self,
        bearer: &str,
        request: &kasumi_types::ArchiveHistory,
    ) -> Result<WriteReceipt, ClientError> {
        let response = self
            .inner
            .archive_history(authorized(
                bearer,
                proto::ArchiveHistoryRequest {
                    request_json: encode(request)?,
                },
            )?)
            .await?
            .into_inner();
        mutation_receipt::decode_write_receipt(response)
    }
}

fn encode(value: &impl Serialize) -> Result<Vec<u8>, ClientError> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > 8 << 20 {
        return Err(ClientError::RequestTooLarge);
    }
    Ok(bytes)
}

fn authorized_until<T>(
    bearer: &str,
    value: T,
    deadline: Option<tokio::time::Instant>,
) -> Result<Request<T>, ClientError> {
    let mut request = authorized(bearer, value)?;
    if let Some(deadline) = deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(
                tonic::Status::deadline_exceeded("native operation deadline elapsed").into(),
            );
        }
        request.set_timeout(remaining);
    }
    Ok(request)
}

fn authorized<T>(bearer: &str, value: T) -> Result<Request<T>, ClientError> {
    if bearer.is_empty()
        || bearer.len() > 32_768
        || bearer.bytes().any(|byte| !byte.is_ascii_graphic())
    {
        return Err(ClientError::Authorization);
    }
    let mut request = Request::new(value);
    let mut authorization: tonic::metadata::MetadataValue<tonic::metadata::Ascii> =
        format!("Bearer {bearer}")
            .parse()
            .map_err(|_| ClientError::Authorization)?;
    // This flag preserves the wire bytes while redacting Debug and preventing
    // HTTP/2 implementations from indexing the credential in shared tables.
    authorization.set_sensitive(true);
    request
        .metadata_mut()
        .insert("authorization", authorization);
    Ok(request)
}

mod staged_status;

mod target;
pub use target::{KasumiTargetClient, TargetAcknowledgement};

#[cfg(test)]
mod authorization_tests {
    use super::*;
    #[test]
    fn bearer_wire_value_is_unchanged_while_debug_is_redacted() {
        let bearer = "synthetic-private-bearer-for-redaction-test";
        let request = authorized(bearer, ()).unwrap();
        let metadata = request.metadata().get("authorization").unwrap();
        assert_eq!(metadata.to_str().unwrap(), format!("Bearer {bearer}"));
        assert!(metadata.is_sensitive());
        for diagnostic in [
            format!("{metadata:?}"),
            format!("{:?}", request.metadata()),
            format!("{request:?}"),
        ] {
            assert!(!diagnostic.contains(bearer));
        }
        assert!(format!("{request:?}").contains("authorization"));
    }
}
