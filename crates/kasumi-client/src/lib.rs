//! Native protocol and typed data client, independent of server/storage internals.
//! Connection requires TLS 1.3, mTLS, an approved CA and server leaf pins. The
//! caller supplies a current bearer token for every request. No retry or redirect is performed;
//! transport uncertainty must be resolved with the original idempotency key.

use kasumi_transport::{CertificatePin, TlsIdentity};
use kasumi_types::{
    MutationBatch, QueryRequest, QueryResponse, QueryRow, ReadSnapshotRequest,
    SnapshotReadResponse, WriteReceipt,
};
use serde::Serialize;
use std::collections::BTreeSet;
use tonic::{Request, transport::Channel};

pub mod proto {
    tonic::include_proto!("kasumi.v1");
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("native secure connection failed: {0}")]
    Connection(#[from] anyhow::Error),
    #[error("native transport failed: {0}")]
    Transport(#[from] tonic::Status),
    #[error("invalid native JSON")]
    Json(#[from] serde_json::Error),
    #[error("invalid bearer authorization")]
    Authorization,
    #[error("native request exceeds its byte limit")]
    RequestTooLarge,
}

/// Operator-selected connection identity and trust. Deliberately not Debug or
/// serializable: it owns private key material. Bearer tokens are request-local.
pub struct KasumiClientConfig {
    pub endpoint: String,
    pub identity: TlsIdentity,
    pub trusted_ca_pem: Vec<u8>,
    pub server_certificate_pins: BTreeSet<CertificatePin>,
}

#[derive(Clone)]
pub struct KasumiClient {
    inner: proto::kasumi_data_client::KasumiDataClient<Channel>,
}

impl KasumiClient {
    pub async fn read_change_feed(
        &mut self,
        bearer: &str,
        request: &kasumi_types::ReadChangeFeed,
    ) -> Result<kasumi_types::ChangeFeedPage, ClientError> {
        let response = self
            .inner
            .read_change_feed(authorized(
                bearer,
                proto::ReadChangeFeedRequest {
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
            .begin_staged_transaction(authorized(
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
            .append_staged_chunk(authorized(
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
            .finalize_staged_transaction(authorized(
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

    pub async fn abort_staged_transaction(
        &mut self,
        bearer: &str,
        request: &kasumi_types::StagedTransactionRef,
    ) -> Result<WriteReceipt, ClientError> {
        let response = self
            .inner
            .abort_staged_transaction(authorized(
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

    pub async fn staged_transaction_status(
        &mut self,
        bearer: &str,
        request: &kasumi_types::StagedTransactionRef,
    ) -> Result<kasumi_types::StagedTransactionStatus, ClientError> {
        let response = self
            .inner
            .staged_transaction_status(authorized(
                bearer,
                proto::StagedTransactionReference {
                    request_json: encode(request)?,
                },
            )?)
            .await?
            .into_inner();
        Ok(serde_json::from_slice(&response.response_json)?)
    }

    pub async fn open_snapshot_lease(
        &mut self,
        bearer: &str,
        request: &kasumi_types::OpenSnapshotLease,
    ) -> Result<kasumi_types::SnapshotLease, ClientError> {
        let response = self
            .inner
            .open_snapshot_lease(authorized(
                bearer,
                proto::OpenSnapshotLeaseRequest {
                    request_json: encode(request)?,
                },
            )?)
            .await?
            .into_inner();
        Ok(serde_json::from_slice(&response.response_json)?)
    }

    pub async fn read_snapshot_page(
        &mut self,
        bearer: &str,
        request: &kasumi_types::ReadSnapshotPage,
    ) -> Result<kasumi_types::SnapshotReadResponse, ClientError> {
        let response = self
            .inner
            .read_snapshot_page(authorized(
                bearer,
                proto::ReadSnapshotPageRequest {
                    request_json: encode(request)?,
                },
            )?)
            .await?
            .into_inner();
        Ok(serde_json::from_slice(&response.response_json)?)
    }

    pub async fn scan_snapshot_page(
        &mut self,
        bearer: &str,
        request: &kasumi_types::ScanSnapshotPage,
    ) -> Result<kasumi_types::SnapshotScanPage, ClientError> {
        let response = self
            .inner
            .scan_snapshot_page(authorized(
                bearer,
                proto::ScanSnapshotPageRequest {
                    request_json: encode(request)?,
                },
            )?)
            .await?
            .into_inner();
        Ok(serde_json::from_slice(&response.response_json)?)
    }

    pub async fn close_snapshot_lease(
        &mut self,
        bearer: &str,
        lease_id: &str,
    ) -> Result<(), ClientError> {
        self.inner
            .close_snapshot_lease(authorized(
                bearer,
                proto::SnapshotLeaseReference {
                    lease_id: lease_id.into(),
                },
            )?)
            .await?;
        Ok(())
    }
    pub async fn read_snapshot(
        &mut self,
        bearer: &str,
        request: &ReadSnapshotRequest,
    ) -> Result<SnapshotReadResponse, ClientError> {
        let response = self
            .inner
            .read_snapshot(authorized(
                bearer,
                proto::ReadSnapshotRequest {
                    request_json: encode(request)?,
                },
            )?)
            .await?
            .into_inner();
        Ok(serde_json::from_slice(&response.response_json)?)
    }

    /// Bounded ordinary query/pagination for discovery. A returned page is not
    /// a complete conditional-transaction dependency set; use coherent snapshot
    /// reads and their assertions when a write depends on query completeness.
    pub async fn query(
        &mut self,
        bearer: &str,
        request: &QueryRequest,
    ) -> Result<QueryResponse, ClientError> {
        let response = self
            .inner
            .query(authorized(
                bearer,
                proto::QueryRequest {
                    query_json: encode(request)?,
                },
            )?)
            .await?
            .into_inner();
        let rows = response
            .rows
            .into_iter()
            .map(|row| {
                let document = row.document.ok_or_else(|| {
                    ClientError::Transport(tonic::Status::data_loss(
                        "native query row is missing its document",
                    ))
                })?;
                Ok(QueryRow {
                    id: document.id,
                    version: document.version,
                    body: serde_json::from_slice(&document.body_json)?,
                    score: row.score,
                })
            })
            .collect::<Result<Vec<_>, ClientError>>()?;
        let aggregates = response
            .aggregates_json
            .into_iter()
            .map(|value| serde_json::from_slice(&value))
            .collect::<Result<Vec<_>, serde_json::Error>>()?;
        Ok(QueryResponse {
            revision: response.revision,
            rows,
            aggregates,
            cursor: response.cursor,
        })
    }

    pub async fn mutate(
        &mut self,
        bearer: &str,
        batch: &MutationBatch,
    ) -> Result<WriteReceipt, ClientError> {
        let response = self
            .inner
            .mutate(authorized(
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
    inner: proto::kasumi_admin_client::KasumiAdminClient<Channel>,
}
impl KasumiAdminClient {
    pub async fn connect(config: &KasumiClientConfig) -> Result<Self, ClientError> {
        let channel = kasumi_transport::grpc_channel(
            &config.endpoint,
            &config.identity,
            &config.trusted_ca_pem,
            config.server_certificate_pins.clone(),
        )
        .await?;
        Ok(Self {
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

fn authorized<T>(bearer: &str, value: T) -> Result<Request<T>, ClientError> {
    if bearer.is_empty()
        || bearer.len() > 32_768
        || bearer.bytes().any(|byte| !byte.is_ascii_graphic())
    {
        return Err(ClientError::Authorization);
    }
    let mut request = Request::new(value);
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {bearer}")
            .parse()
            .map_err(|_| ClientError::Authorization)?,
    );
    Ok(request)
}
