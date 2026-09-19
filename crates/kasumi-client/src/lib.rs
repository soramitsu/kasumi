//! Native protocol and typed data client, independent of server/storage internals.
//! Connection requires TLS 1.3, mTLS, an approved CA and server leaf pins. The
//! caller supplies current credentials for every request. Low-level clients do
//! not retry; installed endpoint pools retain exact operation identities and
//! pin historical reads to their originating member.

use kasumi_transport::{CertificatePin, TlsIdentity};
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
pub use lifecycle::KasumiLifecycleClient;
mod authority;
mod authority_pool;
mod control_signer;
pub use control_signer::CurrentControlSignerObservation;
mod signer_publication;
pub use signer_publication::CurrentSignerPublication;
mod data_pool;
mod mutation_receipt;
pub use authority_pool::KasumiAuthorityPool;
pub use data_pool::{
    KasumiClientPool, RoutedOrderedSeekPage, RoutedQueryPage, RoutedSnapshotLease,
};
pub use mutation_receipt::verify_mutation_receipt;
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

pub mod proto {
    tonic::include_proto!("kasumi.v1");
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("native secure connection failed: {0}")]
    Connection(#[from] anyhow::Error),
    #[error("native transport failed: {0}")]
    Transport(#[from] tonic::Status),
    /// Admitted decode failures retain no peer-controlled strings or metadata after
    /// their admission owner is released. The code remains usable for routing.
    #[error("native decode failed ({code:?}): {reason}")]
    DecodeRejected {
        code: tonic::Code,
        reason: &'static str,
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

/// Operator-selected connection identity and trust. Deliberately not Debug or
/// serializable: it owns private key material. Bearer tokens are request-local.
#[derive(Clone)]
pub struct KasumiClientConfig {
    pub endpoint: String,
    pub identity: TlsIdentity,
    pub trusted_ca_pem: Vec<u8>,
    pub server_certificate_pins: BTreeSet<CertificatePin>,
}

#[derive(Clone)]
pub struct KasumiClient {
    inner: proto::kasumi_data_client::KasumiDataClient<Channel>,
    deadline: Option<tokio::time::Instant>,
    snapshot_channel: Channel,
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
            .inner
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
        let channel = kasumi_transport::grpc_channel(
            &config.endpoint,
            &config.identity,
            &config.trusted_ca_pem,
            config.server_certificate_pins.clone(),
        )
        .await?;
        Ok(Self {
            deadline: None,
            snapshot_channel: channel.clone(),
            inner: proto::kasumi_data_client::KasumiDataClient::new(channel)
                .max_encoding_message_size((8 << 20) + (64 << 10))
                .max_decoding_message_size(16 << 20),
        })
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
        Ok(WriteReceipt {
            revision: response.revision,
            versions: response.versions.into_iter().collect(),
        })
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
        Ok(WriteReceipt {
            revision: response.revision,
            versions: response.versions.into_iter().collect(),
        })
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
        Ok(WriteReceipt {
            revision: response.revision,
            versions: response.versions.into_iter().collect(),
        })
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
            .inner
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
        Ok(WriteReceipt {
            revision: response.revision,
            versions: response.versions.into_iter().collect(),
        })
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
        Ok(WriteReceipt {
            revision: response.revision,
            versions: response.versions.into_iter().collect(),
        })
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
        Ok(WriteReceipt {
            revision: response.revision,
            versions: response.versions.into_iter().collect(),
        })
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
