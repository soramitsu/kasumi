//! Native protobuf services. Runtime callers must bind data/admin services to
//! their respective TLS 1.3 listeners; these adapters open no sockets themselves.
use crate::{
    api::{
        DatabaseRegistry, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, decode_json, encode_json,
        mutation_release, release_response, response_owner, status,
    },
    auth::Authenticator,
};
use kasumi_types::{Operation, RequestContext, validate_name};
use std::sync::Arc;
use tonic::{Request, Response, Status};

pub use kasumi_client::proto;
use proto::*;
#[path = "rpc_lifecycle.rs"]
mod lifecycle;
#[path = "rpc_recovery.rs"]
mod recovery;
pub use recovery::NativeRecoveryControl;
#[path = "rpc_target.rs"]
mod target;
pub use lifecycle::NativeLifecycleControl;
pub use target::NativeTargetRecovery;
#[path = "rpc_authority.rs"]
mod authority;
#[path = "rpc_backup_sessions.rs"]
mod backup_sessions;
#[path = "rpc_control_signer.rs"]
mod control_signer;
#[path = "rpc_security_audit.rs"]
mod security_audit;
#[cfg(test)]
#[path = "rpc_snapshot_failure_tests.rs"]
mod snapshot_failure_tests;
#[cfg(test)]
pub(crate) use security_audit::AuditReleaseGate;
#[path = "rpc_credentials.rs"]
mod credentials;
#[path = "rpc_retirement.rs"]
mod retirement;
pub use authority::NativeAuthority;
#[cfg(test)]
#[path = "rpc_authority_tests.rs"]
mod authority_tests;
#[cfg(test)]
#[path = "rpc_lifecycle_tests.rs"]
mod lifecycle_tests;
#[cfg(test)]
#[path = "rpc_recovery_tests.rs"]
mod recovery_tests;

#[cfg(test)]
#[path = "rpc_control_signer_tests.rs"]
mod control_signer_tests;

#[derive(Clone)]
pub(crate) struct NativeData {
    registry: DatabaseRegistry,
    auth: Arc<Authenticator>,
}
#[derive(Clone)]
pub struct NativeAdmin {
    registry: DatabaseRegistry,
    auth: Arc<Authenticator>,
    failures: crate::administration::OriginalRecoveries,
    management: Option<Arc<crate::administration::Administration>>,
    telemetry: Arc<crate::observability::Telemetry>,
    control_signer: Option<Arc<crate::control_signer_runtime::ControlSignerRuntime>>,
    #[cfg(test)]
    audit_release_gate: Arc<tokio::sync::Mutex<Option<AuditReleaseGate>>>,
}

async fn verified<T>(auth: &Authenticator, request: &Request<T>) -> Result<RequestContext, Status> {
    let mut values = request.metadata().get_all("authorization").iter();
    let first = values
        .next()
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let authorization = if values.next().is_some() { "" } else { first };
    auth.authenticate(authorization).await.map_err(status)
}
async fn routed(
    registry: &DatabaseRegistry,
    auth: &Authenticator,
    context: &RequestContext,
) -> Result<Arc<kasumi_engine::Database>, Status> {
    auth.audit_result(context, registry.database(context))
        .await
        .map_err(status)
}

fn receipt(value: kasumi_types::WriteReceipt) -> WriteReceipt {
    WriteReceipt {
        revision: value.revision,
        contract: kasumi_client::NATIVE_WRITE_RECEIPT_CONTRACT.into(),
        versions: value
            .versions
            .into_iter()
            .map(|(target_path, revision)| VersionEntry {
                target_path,
                revision,
            })
            .collect(),
    }
}

#[cfg(test)]
#[test]
fn native_write_receipt_encodes_canonical_map_order_as_visible_rows() {
    let encoded = receipt(kasumi_types::WriteReceipt {
        revision: 11,
        versions: std::collections::BTreeMap::from([
            ("/rows/z".into(), 11),
            ("/rows/a".into(), 11),
        ]),
    });
    assert_eq!(
        encoded.contract,
        kasumi_client::NATIVE_WRITE_RECEIPT_CONTRACT
    );
    assert_eq!(
        encoded
            .versions
            .iter()
            .map(|entry| entry.target_path.as_str())
            .collect::<Vec<_>>(),
        vec!["/rows/a", "/rows/z"]
    );
}
/// Build the native data HTTP service with its mandatory response owner.
/// Register the returned service with tonic's router on the data TLS listener.
/// The raw protobuf handler stays inside this crate, so embedders cannot omit
/// the body/frame ownership wrapper or extract its direct protobuf responses.
///
/// ```compile_fail
/// use kasumi_server::rpc::NativeData;
/// ```
///
/// The returned HTTP service cannot be used as an unwrapped protobuf handler:
///
/// ```compile_fail
/// use kasumi_server::{
///     api::DatabaseRegistry,
///     auth::Authenticator,
///     rpc::{native_data_service, proto::kasumi_data_server::KasumiDataServer},
/// };
/// use std::sync::Arc;
///
/// fn bypass(registry: DatabaseRegistry, auth: Arc<Authenticator>) {
///     let service = native_data_service(registry, auth);
///     let unwrapped = KasumiDataServer::new(service);
///     let _router = tonic::service::Routes::new(unwrapped);
/// }
/// ```
pub fn native_data_service(
    registry: DatabaseRegistry,
    auth: Arc<Authenticator>,
) -> impl tonic::server::NamedService
+ Clone
+ Send
+ Sync
+ 'static
+ tower::Service<
    axum::http::Request<tonic::body::Body>,
    Response = axum::http::Response<tonic::body::Body>,
    Error = std::convert::Infallible,
    Future: Send + 'static,
> {
    NativeData::new(registry, auth).service()
}

impl NativeData {
    pub(crate) fn new(registry: DatabaseRegistry, auth: Arc<Authenticator>) -> Self {
        Self { registry, auth }
    }
    pub(crate) fn service(
        self,
    ) -> response_owner::AdmittedService<kasumi_data_server::KasumiDataServer<Self>> {
        response_owner::AdmittedService::new(
            kasumi_data_server::KasumiDataServer::new(self)
                .max_decoding_message_size(MAX_REQUEST_BYTES)
                .max_encoding_message_size(MAX_RESPONSE_BYTES),
        )
    }
}

#[tonic::async_trait]
impl kasumi_data_server::KasumiData for NativeData {
    async fn admit_mutation_capacity(
        &self,
        request: Request<MutationCapacityRequest>,
    ) -> Result<Response<MutationCapacityResponse>, Status> {
        let context = verified(&self.auth, &request).await?;
        let request = decode_json(&request.into_inner().request_json).map_err(status)?;
        let database = routed(&self.registry, &self.auth, &context).await?;
        let fence = self
            .auth
            .audit_result(&context, database.owned_response_fence(&context))
            .await
            .map_err(status)?;
        let result = database
            .admit_mutation_capacity(&context, request)
            .await
            .map_err(|error| self.registry.status(&context, error))?;
        response_owner::PendingReply::new(result, fence)
            .convert(|result, fence| {
                Ok(MutationCapacityResponse {
                    response_json: response_owner::encode_json(result, fence)?,
                })
            })
            .map_err(status)?
            .release(&self.auth, &context)
            .await
    }

    async fn read_change_feed(
        &self,
        request: Request<ReadChangeFeedRequest>,
    ) -> Result<Response<ReadChangeFeedResponse>, Status> {
        let context = verified(&self.auth, &request).await?;
        let request = decode_json(&request.into_inner().request_json).map_err(status)?;
        let database = routed(&self.registry, &self.auth, &context).await?;
        let fence = self
            .auth
            .audit_result(&context, database.owned_response_fence(&context))
            .await
            .map_err(status)?;
        let result = database
            .read_change_feed(&context, request)
            .await
            .map_err(|error| self.registry.status(&context, error))?;
        response_owner::PendingReply::new(result, fence)
            .convert(|result, fence| {
                Ok(ReadChangeFeedResponse {
                    response_json: response_owner::encode_json(result, fence)?,
                })
            })
            .map_err(status)?
            .release(&self.auth, &context)
            .await
    }
    async fn get(&self, request: Request<GetRequest>) -> Result<Response<GetResponse>, Status> {
        let context = verified(&self.auth, &request).await?;
        let request = request.into_inner();
        validate_name(&request.collection).map_err(status)?;
        validate_name(&request.id).map_err(status)?;
        let database = routed(&self.registry, &self.auth, &context).await?;
        let fence = self
            .auth
            .audit_result(&context, database.owned_response_fence(&context))
            .await
            .map_err(status)?;
        let result = database
            .get(&context, &request.collection, &request.id)
            .await;
        let Some(result) = result.map_err(|error| self.registry.status(&context, error))? else {
            return Ok(Response::new(
                release_response(
                    &self.auth,
                    &context,
                    fence,
                    GetResponse { document: None },
                    false,
                )
                .await
                .map_err(status)?,
            ));
        };
        response_owner::PendingReply::new(result, fence)
            .convert(|result, fence| {
                Ok(GetResponse {
                    document: Some(Document {
                        id: response_owner::clone_string(fence, &result.id)?,
                        version: result.version,
                        body_json: response_owner::encode_json(&result.body, fence)?,
                    }),
                })
            })
            .map_err(status)?
            .release(&self.auth, &context)
            .await
    }
    async fn query(
        &self,
        request: Request<QueryRequest>,
    ) -> Result<Response<QueryResponse>, Status> {
        let context = verified(&self.auth, &request).await?;
        let query = decode_json(&request.into_inner().query_json).map_err(status)?;
        let database = routed(&self.registry, &self.auth, &context).await?;
        let fence = self
            .auth
            .audit_result(&context, database.owned_response_fence(&context))
            .await
            .map_err(status)?;
        let result = database
            .query(&context, query)
            .await
            .map_err(|error| self.registry.status(&context, error))?;
        response_owner::PendingReply::new(result, fence)
            .convert(|result, fence| {
                response_owner::claim_vec::<QueryRow>(fence, result.rows.len())?;
                let mut rows = Vec::with_capacity(result.rows.len());
                for row in &result.rows {
                    rows.push(QueryRow {
                        document: Some(Document {
                            id: response_owner::clone_string(fence, &row.id)?,
                            version: row.version,
                            body_json: response_owner::encode_json(&row.body, fence)?,
                        }),
                        score: row.score,
                    });
                }
                response_owner::claim_vec::<Vec<u8>>(fence, result.aggregates.len())?;
                let mut aggregates_json = Vec::with_capacity(result.aggregates.len());
                for value in &result.aggregates {
                    aggregates_json.push(response_owner::encode_json(value, fence)?);
                }
                Ok(QueryResponse {
                    revision: result.revision,
                    rows,
                    aggregates_json,
                    cursor: result
                        .cursor
                        .as_deref()
                        .map(|cursor| response_owner::clone_string(fence, cursor))
                        .transpose()?,
                })
            })
            .map_err(status)?
            .release(&self.auth, &context)
            .await
    }
    async fn read_restore_lineage(
        &self,
        request: Request<ReadRestoreLineageRequest>,
    ) -> Result<Response<ReadRestoreLineageResponse>, Status> {
        let context = verified(&self.auth, &request).await?;
        let input = decode_json(&request.into_inner().request_json).map_err(status)?;
        let database = routed(&self.registry, &self.auth, &context).await?;
        let fence = self
            .auth
            .audit_result(&context, database.response_fence(&context))
            .await
            .map_err(status)?;
        let proof = database
            .read_restore_lineage(&context, input)
            .await
            .map_err(|error| self.registry.status(&context, error))?;
        let response = ReadRestoreLineageResponse {
            response_json: encode_json(proof.observation()).map_err(status)?,
        };
        self.auth
            .audit_result(
                &context,
                database
                    .check_restore_lineage_release(&context, &proof)
                    .await,
            )
            .await
            .map_err(status)?;
        Ok(Response::new(
            release_response(&self.auth, &context, fence, response, false)
                .await
                .map_err(status)?,
        ))
    }
    async fn read_snapshot(
        &self,
        request: Request<ReadSnapshotRequest>,
    ) -> Result<Response<ReadSnapshotResponse>, Status> {
        let context = verified(&self.auth, &request).await?;
        let snapshot = decode_json(&request.into_inner().request_json).map_err(status)?;
        let database = routed(&self.registry, &self.auth, &context).await?;
        let fence = self
            .auth
            .audit_result(&context, database.owned_response_fence(&context))
            .await
            .map_err(status)?;
        let result = database
            .read_snapshot(&context, snapshot)
            .await
            .map_err(|error| self.registry.status(&context, error))?;
        response_owner::PendingReply::new(result, fence)
            .convert(|result, fence| {
                Ok(ReadSnapshotResponse {
                    response_json: response_owner::encode_json(result, fence)?,
                })
            })
            .map_err(status)?
            .release(&self.auth, &context)
            .await
    }

    async fn mutate(
        &self,
        request: Request<MutateRequest>,
    ) -> Result<Response<WriteReceipt>, Status> {
        let context = verified(&self.auth, &request).await?;
        let batch = decode_json(&request.into_inner().batch_json).map_err(status)?;
        let database = routed(&self.registry, &self.auth, &context).await?;
        let fence = self
            .auth
            .audit_result(&context, database.response_fence(&context))
            .await
            .map_err(status)?;
        let result = database.mutate(context.clone(), batch).await;
        let result = result.map_err(|error| self.registry.status(&context, error))?;
        let response = receipt(result);
        let response = release_response(&self.auth, &context, fence, response, true)
            .await
            .map_err(status)?;
        Ok(Response::new(response))
    }
    async fn begin_staged_transaction(
        &self,
        request: Request<BeginStagedTransactionRequest>,
    ) -> Result<Response<WriteReceipt>, Status> {
        let context = verified(&self.auth, &request).await?;
        let input = decode_json(&request.into_inner().request_json).map_err(status)?;
        let database = routed(&self.registry, &self.auth, &context).await?;
        let fence = self
            .auth
            .audit_result(&context, database.response_fence(&context))
            .await
            .map_err(status)?;
        let result = database
            .begin_staged_transaction(context.clone(), input)
            .await
            .map_err(|error| self.registry.status(&context, error))?;
        let response = release_response(&self.auth, &context, fence, receipt(result), true)
            .await
            .map_err(status)?;
        Ok(Response::new(response))
    }

    async fn append_staged_chunk(
        &self,
        request: Request<AppendStagedChunkRequest>,
    ) -> Result<Response<WriteReceipt>, Status> {
        let context = verified(&self.auth, &request).await?;
        let input = decode_json(&request.into_inner().request_json).map_err(status)?;
        let database = routed(&self.registry, &self.auth, &context).await?;
        let fence = self
            .auth
            .audit_result(&context, database.response_fence(&context))
            .await
            .map_err(status)?;
        let result = database
            .append_staged_chunk(context.clone(), input)
            .await
            .map_err(|error| self.registry.status(&context, error))?;
        let response = release_response(&self.auth, &context, fence, receipt(result), true)
            .await
            .map_err(status)?;
        Ok(Response::new(response))
    }

    async fn finalize_staged_transaction(
        &self,
        request: Request<StagedTransactionReference>,
    ) -> Result<Response<WriteReceipt>, Status> {
        let context = verified(&self.auth, &request).await?;
        let input = decode_json(&request.into_inner().request_json).map_err(status)?;
        let database = routed(&self.registry, &self.auth, &context).await?;
        let fence = self
            .auth
            .audit_result(&context, database.response_fence(&context))
            .await
            .map_err(status)?;
        let result = database
            .finalize_staged_transaction(context.clone(), input)
            .await
            .map_err(|error| self.registry.status(&context, error))?;
        let response = release_response(&self.auth, &context, fence, receipt(result), true)
            .await
            .map_err(status)?;
        Ok(Response::new(response))
    }

    async fn stop_staged_transaction(
        &self,
        request: Request<StopStagedTransactionRequest>,
    ) -> Result<Response<StagedTransactionStatusResponse>, Status> {
        let context = verified(&self.auth, &request).await?;
        let input = decode_json(&request.into_inner().request_json).map_err(status)?;
        let database = routed(&self.registry, &self.auth, &context).await?;
        let fence = self
            .auth
            .audit_result(
                &context,
                database.staged_stop_response_fence(&context, &input),
            )
            .await
            .map_err(status)?;
        let result = database
            .stop_staged_transaction(context.clone(), input)
            .await
            .map_err(|error| self.registry.status(&context, error))?;
        let response = StagedTransactionStatusResponse {
            response_json: encode_json(&result).map_err(|_| {
                status(kasumi_types::Error::new(
                    kasumi_types::ErrorCode::UnknownOutcome,
                    "staged resolution encoding failed; recover the original identity",
                ))
            })?,
        };
        // An accepted stop or terminal resolution must not look like a definite
        // rejection when its final authority/deadline check withholds disclosure.
        let released = release_response(&self.auth, &context, fence, response, true).await
            .map_err(|_| status(kasumi_types::Error::new(kasumi_types::ErrorCode::UnknownOutcome,
                "staged resolution response was fenced; retry the original identity with fresh authority")))?;
        Ok(Response::new(released))
    }

    async fn staged_transaction_status(
        &self,
        request: Request<StagedTransactionReference>,
    ) -> Result<Response<StagedTransactionStatusResponse>, Status> {
        let context = verified(&self.auth, &request).await?;
        let input = decode_json(&request.into_inner().request_json).map_err(status)?;
        let database = routed(&self.registry, &self.auth, &context).await?;
        let fence = self
            .auth
            .audit_result(&context, database.response_fence(&context))
            .await
            .map_err(status)?;
        let result = database
            .staged_transaction_status(&context, &input)
            .await
            .map_err(|error| self.registry.status(&context, error))?;
        let response = StagedTransactionStatusResponse {
            response_json: encode_json(&result).map_err(status)?,
        };
        let response = release_response(&self.auth, &context, fence, response, false)
            .await
            .map_err(status)?;
        Ok(Response::new(response))
    }

    async fn open_snapshot_lease(
        &self,
        request: Request<OpenSnapshotLeaseRequest>,
    ) -> Result<Response<SnapshotLeaseResponse>, Status> {
        let context = verified(&self.auth, &request).await?;
        let input = decode_json(&request.into_inner().request_json).map_err(status)?;
        let database = routed(&self.registry, &self.auth, &context).await?;
        let mut fence = self
            .auth
            .audit_result(&context, database.response_fence(&context))
            .await
            .map_err(status)?;
        let result = database
            .open_snapshot_lease(&context, input)
            .await
            .map_err(|error| self.registry.status(&context, error))?;
        self.auth
            .audit_result(&context, fence.bind_snapshot_lease(&result.lease_id).await)
            .await
            .map_err(status)?;
        let response = SnapshotLeaseResponse {
            response_json: encode_json(&result).map_err(status)?,
        };
        let response = release_response(&self.auth, &context, fence, response, false)
            .await
            .map_err(status)?;
        Ok(Response::new(response))
    }

    async fn read_snapshot_page(
        &self,
        request: Request<ReadSnapshotPageRequest>,
    ) -> Result<Response<ReadSnapshotResponse>, Status> {
        let context = verified(&self.auth, &request).await?;
        let input: kasumi_types::ReadSnapshotPage =
            decode_json(&request.into_inner().request_json).map_err(status)?;
        let database = routed(&self.registry, &self.auth, &context).await?;
        let mut fence = self
            .auth
            .audit_result(&context, database.owned_response_fence(&context))
            .await
            .map_err(status)?;
        self.auth
            .audit_result(&context, fence.bind_snapshot_lease(&input.lease_id).await)
            .await
            .map_err(status)?;
        let result = database
            .read_snapshot_page(&context, input)
            .await
            .map_err(|error| self.registry.status(&context, error))?;
        response_owner::PendingReply::new(result, fence)
            .convert(|result, fence| {
                Ok(ReadSnapshotResponse {
                    response_json: response_owner::encode_json(result, fence)?,
                })
            })
            .map_err(status)?
            .release(&self.auth, &context)
            .await
    }

    async fn scan_snapshot_page(
        &self,
        request: Request<ScanSnapshotPageRequest>,
    ) -> Result<Response<SnapshotScanPageResponse>, Status> {
        let context = verified(&self.auth, &request).await?;
        let input: kasumi_types::ScanSnapshotPage =
            decode_json(&request.into_inner().request_json).map_err(status)?;
        let database = routed(&self.registry, &self.auth, &context).await?;
        let mut fence = self
            .auth
            .audit_result(&context, database.owned_response_fence(&context))
            .await
            .map_err(status)?;
        self.auth
            .audit_result(&context, fence.bind_snapshot_lease(&input.lease_id).await)
            .await
            .map_err(status)?;
        let result = database
            .scan_snapshot_page(&context, input)
            .await
            .map_err(|error| self.registry.status(&context, error))?;
        response_owner::PendingReply::new(result, fence)
            .convert(|result, fence| {
                Ok(SnapshotScanPageResponse {
                    response_json: response_owner::encode_json(result, fence)?,
                })
            })
            .map_err(status)?
            .release(&self.auth, &context)
            .await
    }

    async fn close_snapshot_lease(
        &self,
        request: Request<SnapshotLeaseReference>,
    ) -> Result<Response<CloseSnapshotLeaseResponse>, Status> {
        let context = verified(&self.auth, &request).await?;
        let lease_id = request.into_inner().lease_id;
        let database = routed(&self.registry, &self.auth, &context).await?;
        let fence = self
            .auth
            .audit_result(&context, database.response_fence(&context))
            .await
            .map_err(status)?;
        database
            .close_snapshot_lease(&context, &lease_id)
            .await
            .map_err(|error| self.registry.status(&context, error))?;
        let response = release_response(
            &self.auth,
            &context,
            fence,
            CloseSnapshotLeaseResponse {},
            false,
        )
        .await
        .map_err(status)?;
        Ok(Response::new(response))
    }
    async fn collections(
        &self,
        request: Request<CollectionsRequest>,
    ) -> Result<Response<CollectionsResponse>, Status> {
        let context = verified(&self.auth, &request).await?;
        let database = routed(&self.registry, &self.auth, &context).await?;
        let fence = self
            .auth
            .audit_result(&context, database.response_fence(&context))
            .await
            .map_err(status)?;
        let definitions = database.collections(&context).await;
        let definitions = definitions.map_err(|error| self.registry.status(&context, error))?;
        // Account the whole response, not just each independent schema.
        encode_json(&definitions).map_err(status)?;
        let response = CollectionsResponse {
            definitions_json: definitions
                .iter()
                .map(|definition| encode_json(definition).map_err(status))
                .collect::<Result<_, _>>()?,
        };
        let response = release_response(&self.auth, &context, fence, response, false)
            .await
            .map_err(status)?;
        Ok(Response::new(response))
    }
    async fn receipt(
        &self,
        request: Request<ReceiptRequest>,
    ) -> Result<Response<ReceiptResponse>, Status> {
        let context = verified(&self.auth, &request).await?;
        let request = request.into_inner();
        validate_name(&request.idempotency_key).map_err(status)?;
        let database = routed(&self.registry, &self.auth, &context).await?;
        let fence = self
            .auth
            .audit_result(&context, database.response_fence(&context))
            .await
            .map_err(status)?;
        let stored = database
            .operation_receipt(&context, &request.idempotency_key)
            .await;
        let stored = stored.map_err(|error| self.registry.status(&context, error))?;
        let request_digest = stored
            .as_ref()
            .map(|stored| stored.request_digest.clone())
            .unwrap_or_default();
        let scope = stored.as_ref().map(|stored| MutationReceiptScope {
            tenant: stored.scope.tenant.clone(),
            incarnation: stored.scope.incarnation.clone(),
            principal: stored.scope.principal.clone(),
        });
        let outcome = stored.map(|stored| match stored.outcome {
            Ok(value) => receipt_response::Outcome::Committed(receipt(value)),
            Err(error) => receipt_response::Outcome::Rejected(DatabaseError {
                code: serde_json::to_value(error.code)
                    .expect("error enum is serializable")
                    .as_str()
                    .unwrap()
                    .into(),
                message: error.message,
            }),
        });
        let response = ReceiptResponse {
            outcome,
            request_digest,
            scope,
        };
        let response = release_response(&self.auth, &context, fence, response, false)
            .await
            .map_err(status)?;
        Ok(Response::new(response))
    }
}

impl NativeAdmin {
    #[cfg(test)]
    pub(crate) fn audit_release_gate(&self) -> Arc<tokio::sync::Mutex<Option<AuditReleaseGate>>> {
        self.audit_release_gate.clone()
    }
    pub fn new(
        registry: DatabaseRegistry,
        auth: Arc<Authenticator>,
        failures: crate::administration::OriginalRecoveries,
    ) -> Self {
        Self {
            registry,
            auth,
            failures,
            management: None,
            telemetry: crate::observability::Telemetry::new(),
            control_signer: None,
            #[cfg(test)]
            audit_release_gate: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }
    pub fn with_management(
        mut self,
        management: Arc<crate::administration::Administration>,
    ) -> Self {
        self.management = Some(management);
        self
    }
    pub(crate) fn with_control_signer(
        mut self,
        runtime: Arc<crate::control_signer_runtime::ControlSignerRuntime>,
    ) -> Self {
        self.control_signer = Some(runtime);
        self
    }
    pub(crate) fn with_telemetry(
        mut self,
        telemetry: Arc<crate::observability::Telemetry>,
    ) -> Self {
        self.telemetry = telemetry;
        self
    }
    pub fn service(self) -> kasumi_admin_server::KasumiAdminServer<Self> {
        kasumi_admin_server::KasumiAdminServer::new(self)
            .max_decoding_message_size(MAX_REQUEST_BYTES)
            .max_encoding_message_size(MAX_RESPONSE_BYTES)
    }
    async fn database(
        &self,
        context: &RequestContext,
    ) -> Result<Arc<kasumi_engine::Database>, Status> {
        Ok(if context.tenant == crate::runtime::CONTROL_TENANT {
            let result = match &self.management {
                Some(manager) => manager.authorized_database(context).await,
                None => Err(kasumi_types::Error::new(
                    kasumi_types::ErrorCode::Forbidden,
                    "control administration requires the private runtime route",
                )),
            };
            self.auth
                .audit_result(context, result)
                .await
                .map_err(status)?
        } else {
            routed(&self.registry, &self.auth, context).await?
        })
    }

    /// Claim the original paid RPC seat before polling constructor-reaching
    /// work. A foreign status receives a native-free diagnostic only after the
    /// whole returned failure is installed in that independently retained seat.
    async fn snapshot_call<
        T: crate::administration::original_serving_runtime::RpcSnapshotOutput,
    >(
        &self,
        context: &RequestContext,
        mutation: bool,
        work: impl std::future::Future<Output = std::result::Result<T, kasumi_engine::SnapshotFailure>>,
    ) -> Result<T, Status> {
        let guard = self
            .failures
            .rpc_claim(&context.tenant)
            .await
            .map_err(|refusal| {
                let (code, message) = match refusal {
                    kasumi_store::ScratchAdmissionRefusal::Busy => (
                        kasumi_types::ErrorCode::ResourceExhausted,
                        "administrative operation custody exhausted",
                    ),
                    kasumi_store::ScratchAdmissionRefusal::Sealed => (
                        kasumi_types::ErrorCode::Unavailable,
                        "administrative operation custody closed",
                    ),
                };
                self.registry
                    .status(context, kasumi_types::Error::new(code, message))
            })?;
        match guard.run_snapshot(work).await {
            Ok(value) => Ok(value),
            Err(guard) => {
                let marker = guard.with_report(|report| {
                    use crate::administration::original_serving_runtime::CleanupEntry;
                    let observation = report.observation();
                    if observation.entry() == CleanupEntry::Returned
                        && observation.future_disposal() == CleanupEntry::Returned
                        && let Some(kasumi_engine::SnapshotFailure::Operation(original)) =
                            report.original()
                    {
                        return original.clone();
                    }
                    // A returned error, successful output, poll panic and
                    // future-disposal panic stay independently in the seat.
                    kasumi_types::Error::new(
                        if mutation {
                            kasumi_types::ErrorCode::UnknownOutcome
                        } else {
                            kasumi_types::ErrorCode::Unavailable
                        },
                        "administrative failure remains in its original admitted custody",
                    )
                });
                let marker = if mutation {
                    mutation_release::<()>(Err(marker)).unwrap_err()
                } else {
                    marker
                };
                Err(self.registry.status(context, marker))
            }
        }
    }

    async fn apply(
        &self,
        context: RequestContext,
        operation: Operation,
    ) -> Result<Response<WriteReceipt>, Status> {
        let database = self.database(&context).await?;
        let result = database.administer(context.clone(), operation).await;
        let result = result.map_err(|error| self.registry.status(&context, error))?;
        // Policy/schema/suspension operations intentionally change the epoch.
        // Capture their resulting epoch before constructing the acknowledgement.
        let fence = self
            .auth
            .audit_result(&context, database.response_fence(&context))
            .await
            .map_err(|error| status(mutation_release::<()>(Err(error)).unwrap_err()))?;
        let response = receipt(result);
        let response = release_response(&self.auth, &context, fence, response, true)
            .await
            .map_err(status)?;
        Ok(Response::new(response))
    }
}

#[tonic::async_trait]
impl kasumi_admin_server::KasumiAdmin for NativeAdmin {
    async fn control_signer_maintenance(
        &self,
        request: Request<AuthorityJsonRequest>,
    ) -> Result<Response<AuthorityJsonResponse>, Status> {
        self.control_signer_maintenance_impl(request).await
    }
    async fn security_audit_status(
        &self,
        request: Request<SecurityAuditJsonRequest>,
    ) -> Result<Response<SecurityAuditJsonResponse>, Status> {
        self.security_audit_rpc(request, security_audit::AuditOperation::Status)
            .await
    }
    async fn security_audit_export(
        &self,
        request: Request<SecurityAuditJsonRequest>,
    ) -> Result<Response<SecurityAuditJsonResponse>, Status> {
        self.security_audit_rpc(request, security_audit::AuditOperation::Export)
            .await
    }
    async fn security_audit_archives(
        &self,
        request: Request<SecurityAuditJsonRequest>,
    ) -> Result<Response<SecurityAuditJsonResponse>, Status> {
        self.security_audit_rpc(request, security_audit::AuditOperation::Archives)
            .await
    }
    async fn security_audit_verify(
        &self,
        request: Request<SecurityAuditJsonRequest>,
    ) -> Result<Response<SecurityAuditJsonResponse>, Status> {
        self.security_audit_rpc(request, security_audit::AuditOperation::Verify)
            .await
    }

    async fn create_credential(
        &self,
        request: Request<CredentialJsonRequest>,
    ) -> Result<Response<CredentialJsonResponse>, Status> {
        self.credential_rpc(request, credentials::CredentialOperation::Create)
            .await
    }
    async fn renew_credential(
        &self,
        request: Request<CredentialJsonRequest>,
    ) -> Result<Response<CredentialJsonResponse>, Status> {
        self.credential_rpc(request, credentials::CredentialOperation::Renew)
            .await
    }
    async fn revoke_credential(
        &self,
        request: Request<CredentialJsonRequest>,
    ) -> Result<Response<CredentialJsonResponse>, Status> {
        self.credential_rpc(request, credentials::CredentialOperation::Revoke)
            .await
    }
    async fn credential_status(
        &self,
        request: Request<CredentialJsonRequest>,
    ) -> Result<Response<CredentialJsonResponse>, Status> {
        self.credential_rpc(request, credentials::CredentialOperation::Status)
            .await
    }
    async fn read_custody(
        &self,
        request: Request<RetirementReference>,
    ) -> Result<Response<CustodyStatusResponse>, Status> {
        self.read_custody_rpc(request).await
    }
    async fn execute_custody(
        &self,
        request: Request<CustodyCommandRequest>,
    ) -> Result<Response<CustodyReceiptResponse>, Status> {
        self.execute_custody_rpc(request).await
    }
    async fn read_custody_receipt(
        &self,
        request: Request<CustodyCommandRequest>,
    ) -> Result<Response<CustodyReceiptResponse>, Status> {
        self.read_custody_receipt_rpc(request).await
    }

    async fn abort_retirement(
        &self,
        request: Request<RetireSourceRequest>,
    ) -> Result<Response<RetirementStatusResponse>, Status> {
        self.abort_retirement_rpc(request).await
    }
    async fn retire_source(
        &self,
        request: Request<RetireSourceRequest>,
    ) -> Result<Response<RetirementReceiptResponse>, Status> {
        self.retire_source_rpc(request).await
    }
    async fn retirement_status(
        &self,
        request: Request<RetirementReference>,
    ) -> Result<Response<RetirementStatusResponse>, Status> {
        self.retirement_status_rpc(request).await
    }
    async fn verify_retirement_receipt(
        &self,
        request: Request<RetirementReference>,
    ) -> Result<Response<RetirementReceiptResponse>, Status> {
        self.verify_retirement_receipt_rpc(request).await
    }

    async fn backup_session_status(
        &self,
        request: Request<BackupSessionJsonRequest>,
    ) -> Result<Response<BackupSessionJsonResponse>, Status> {
        self.backup_session_rpc(request, backup_sessions::SessionOperation::Status)
            .await
    }
    async fn abort_backup_session(
        &self,
        request: Request<BackupSessionJsonRequest>,
    ) -> Result<Response<BackupSessionJsonResponse>, Status> {
        self.backup_session_rpc(request, backup_sessions::SessionOperation::Abort)
            .await
    }
    async fn cleanup_backup_session(
        &self,
        request: Request<BackupSessionJsonRequest>,
    ) -> Result<Response<BackupSessionJsonResponse>, Status> {
        self.backup_session_rpc(request, backup_sessions::SessionOperation::Cleanup)
            .await
    }
    async fn create_backup_checkpoint(
        &self,
        request: Request<CreateBackupCheckpointRequest>,
    ) -> Result<Response<BackupCheckpointResponse>, Status> {
        self.telemetry
            .backup_request(0, async {
                let context = verified(&self.auth, &request).await?;
                let request: kasumi_types::CreateBackupCheckpoint =
                    decode_json(&request.into_inner().request_json).map_err(status)?;
                let database = self.database(&context).await?;
                let operation_fence = self
                    .auth
                    .audit_result(&context, database.response_fence(&context))
                    .await
                    .map_err(status)?;
                let proof = self
                    .snapshot_call(&context, true, async {
                        Box::pin(database.backup_checkpoint_named(
                            context.clone(),
                            &request.destination,
                            request.session_id,
                        ))
                        .await
                    })
                    .await?;
                let fence = self
                    .auth
                    .audit_result(
                        &context,
                        database.backup_checkpoint_response_fence(&context, &proof),
                    )
                    .await
                    .map_err(|error| status(mutation_release::<()>(Err(error)).unwrap_err()))?;
                let response = BackupCheckpointResponse {
                    response_json: encode_json(proof.checkpoint()).map_err(status)?,
                };
                self.auth
                    .audit_result(&context, fence.check())
                    .await
                    .map_err(|error| status(mutation_release::<()>(Err(error)).unwrap_err()))?;
                Ok(Response::new(
                    release_response(&self.auth, &context, operation_fence, response, true)
                        .await
                        .map_err(status)?,
                ))
            })
            .await
    }

    async fn verify_backup_checkpoint(
        &self,
        request: Request<VerifyBackupCheckpointRequest>,
    ) -> Result<Response<BackupCheckpointResponse>, Status> {
        self.telemetry
            .backup_request(1, async {
                let context = verified(&self.auth, &request).await?;
                let request: kasumi_types::VerifyBackupCheckpoint =
                    decode_json(&request.into_inner().request_json).map_err(status)?;
                let database = self.database(&context).await?;
                let operation_fence = self
                    .auth
                    .audit_result(&context, database.response_fence(&context))
                    .await
                    .map_err(status)?;
                let proof = self
                    .snapshot_call(&context, false, async {
                        Box::pin(database.verify_backup_checkpoint_named(
                            context.clone(),
                            &request.destination,
                            request.backup_id,
                        ))
                        .await
                    })
                    .await?;
                let fence = self
                    .auth
                    .audit_result(
                        &context,
                        database.backup_checkpoint_response_fence(&context, &proof),
                    )
                    .await
                    .map_err(status)?;
                let response = BackupCheckpointResponse {
                    response_json: encode_json(proof.checkpoint()).map_err(status)?,
                };
                self.auth
                    .audit_result(&context, fence.check())
                    .await
                    .map_err(status)?;
                Ok(Response::new(
                    release_response(&self.auth, &context, operation_fence, response, false)
                        .await
                        .map_err(status)?,
                ))
            })
            .await
    }

    async fn read_schema(
        &self,
        request: Request<ReadSchemaRequest>,
    ) -> Result<Response<ReadSchemaResponse>, Status> {
        let context = verified(&self.auth, &request).await?;
        let request = decode_json(&request.into_inner().request_json).map_err(status)?;
        let database = self.database(&context).await?;
        let fence = self
            .auth
            .audit_result(&context, database.response_fence(&context))
            .await
            .map_err(status)?;
        let snapshot = database
            .read_schema(&context, request)
            .await
            .map_err(|error| self.registry.status(&context, error))?;
        let response = ReadSchemaResponse {
            response_json: encode_json(&snapshot).map_err(status)?,
        };
        Ok(Response::new(
            release_response(&self.auth, &context, fence, response, false)
                .await
                .map_err(status)?,
        ))
    }

    async fn read_policy_limits(
        &self,
        request: Request<ReadPolicyLimitsRequest>,
    ) -> Result<Response<ReadPolicyLimitsResponse>, Status> {
        let context = verified(&self.auth, &request).await?;
        let request: kasumi_types::ReadPolicyLimits =
            decode_json(&request.into_inner().request_json).map_err(status)?;
        let database = self.database(&context).await?;
        let fence = self
            .auth
            .audit_result(&context, database.response_fence(&context))
            .await
            .map_err(status)?;
        let snapshot = database
            .read_policy_limits(&context, request)
            .await
            .map_err(|error| self.registry.status(&context, error))?;
        let response = ReadPolicyLimitsResponse {
            response_json: encode_json(&snapshot).map_err(status)?,
        };
        Ok(Response::new(
            release_response(&self.auth, &context, fence, response, false)
                .await
                .map_err(status)?,
        ))
    }

    async fn activate_schema(
        &self,
        request: Request<SchemaChangeSetRequest>,
    ) -> Result<Response<WriteReceipt>, Status> {
        let context = verified(&self.auth, &request).await?;
        let request: kasumi_types::SchemaChangeSet =
            decode_json(&request.into_inner().request_json).map_err(status)?;
        let database = self.database(&context).await?;
        let result = database
            .activate_schema(context.clone(), request.clone())
            .await
            .map_err(|error| self.registry.status(&context, error))?;
        let fence = self
            .auth
            .audit_result(
                &context,
                database.schema_activation_response_fence(&context, &request),
            )
            .await
            .map_err(|error| status(mutation_release::<()>(Err(error)).unwrap_err()))?;
        Ok(Response::new(
            release_response(&self.auth, &context, fence, receipt(result), true)
                .await
                .map_err(status)?,
        ))
    }

    async fn schema_activation_status(
        &self,
        request: Request<SchemaActivationStatusRequest>,
    ) -> Result<Response<SchemaActivationStatusResponse>, Status> {
        let context = verified(&self.auth, &request).await?;
        let lookup: kasumi_types::ReadSchemaActivation =
            decode_json(&request.into_inner().request_json).map_err(status)?;
        let database = self.database(&context).await?;
        let fence = self
            .auth
            .audit_result(
                &context,
                database.schema_status_response_fence(&context, &lookup),
            )
            .await
            .map_err(status)?;
        let result = database
            .schema_activation_status(&context, &lookup)
            .await
            .map_err(|error| self.registry.status(&context, error))?;
        let response = SchemaActivationStatusResponse {
            response_json: encode_json(&result).map_err(status)?,
        };
        Ok(Response::new(
            release_response(&self.auth, &context, fence, response, false)
                .await
                .map_err(status)?,
        ))
    }

    async fn archive_history(
        &self,
        request: Request<ArchiveHistoryRequest>,
    ) -> Result<Response<WriteReceipt>, Status> {
        let context = verified(&self.auth, &request).await?;
        let request = decode_json(&request.into_inner().request_json).map_err(status)?;
        let database = routed(&self.registry, &self.auth, &context).await?;
        let fence = self
            .auth
            .audit_result(&context, database.response_fence(&context))
            .await
            .map_err(status)?;
        let result = database
            .archive_history(context.clone(), request)
            .await
            .map_err(|error| self.registry.status(&context, error))?;
        Ok(Response::new(
            release_response(&self.auth, &context, fence, receipt(result), true)
                .await
                .map_err(status)?,
        ))
    }
    async fn manage(
        &self,
        request: Request<ManagementRequest>,
    ) -> Result<Response<ManagementResponse>, Status> {
        let context = verified(&self.auth, &request).await?;
        let command = decode_json(&request.into_inner().command_json).map_err(status)?;
        let manager = self
            .management
            .as_ref()
            .ok_or_else(|| Status::unavailable("runtime administration unavailable"))?;
        let mutation = !matches!(
            command,
            crate::administration::ManagementCommand::Status { .. }
        );
        let invocation = self
            .auth
            .audit_result(&context, manager.prepare(context.clone(), command))
            .await
            .map_err(status)?;
        let fence = self
            .auth
            .audit_result(&context, invocation.response_fence())
            .await
            .map_err(status)?;
        let result = invocation.execute().await;
        // Administration owns its operation denials, including nested database
        // requests. The adapter owns only its route and response fences.
        let result = result.map_err(|error| self.registry.status(&context, error))?;
        let response = ManagementResponse {
            result_json: encode_json(&result).map_err(status)?,
        };
        let release = self
            .auth
            .audit_result(&context, fence.check_release())
            .await;
        if mutation {
            mutation_release(release)
        } else {
            release
        }
        .map_err(status)?;
        Ok(Response::new(response))
    }
    async fn create_collection(
        &self,
        request: Request<CollectionDefinitionRequest>,
    ) -> Result<Response<WriteReceipt>, Status> {
        let context = verified(&self.auth, &request).await?;
        let definition = decode_json(&request.into_inner().definition_json).map_err(status)?;
        self.apply(context, Operation::CreateCollection(definition))
            .await
    }
    async fn replace_collection(
        &self,
        request: Request<CollectionDefinitionRequest>,
    ) -> Result<Response<WriteReceipt>, Status> {
        let context = verified(&self.auth, &request).await?;
        let definition = decode_json(&request.into_inner().definition_json).map_err(status)?;
        self.apply(context, Operation::ReplaceCollection(definition))
            .await
    }
    async fn set_policy(
        &self,
        request: Request<SetPolicyRequest>,
    ) -> Result<Response<WriteReceipt>, Status> {
        let context = verified(&self.auth, &request).await?;
        let policy = decode_json(&request.into_inner().policy_json).map_err(status)?;
        self.apply(context, Operation::SetPolicy(policy)).await
    }
    async fn set_limits(
        &self,
        request: Request<SetLimitsRequest>,
    ) -> Result<Response<WriteReceipt>, Status> {
        let context = verified(&self.auth, &request).await?;
        let limits = decode_json(&request.into_inner().limits_json).map_err(status)?;
        self.apply(context, Operation::SetLimits(limits)).await
    }
    async fn set_suspended(
        &self,
        request: Request<SetSuspendedRequest>,
    ) -> Result<Response<WriteReceipt>, Status> {
        let context = verified(&self.auth, &request).await?;
        self.apply(context, Operation::Suspend(request.into_inner().suspended))
            .await
    }
}
