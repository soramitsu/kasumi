//! Native protobuf services. Runtime callers must bind data/admin services to
//! their respective TLS 1.3 listeners; these adapters open no sockets themselves.
use crate::{
    api::{
        DatabaseRegistry, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, decode_json, encode_json,
        release_response, status,
    },
    auth::Authenticator,
};
use kasumi_types::{Operation, RequestContext, validate_name};
use std::sync::Arc;
use tonic::{Request, Response, Status};

pub mod proto {
    tonic::include_proto!("kasumi.v1");
}
use proto::*;

#[derive(Clone)]
pub struct NativeData {
    registry: DatabaseRegistry,
    auth: Arc<Authenticator>,
}
#[derive(Clone)]
pub struct NativeAdmin {
    registry: DatabaseRegistry,
    auth: Arc<Authenticator>,
    management: Option<Arc<crate::administration::Administration>>,
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
        versions: value.versions.into_iter().collect(),
    }
}
fn document(value: kasumi_types::Document) -> Result<Document, Status> {
    Ok(Document {
        id: value.id,
        version: value.version,
        body_json: encode_json(&value.body).map_err(status)?,
    })
}

impl NativeData {
    pub fn new(registry: DatabaseRegistry, auth: Arc<Authenticator>) -> Self {
        Self { registry, auth }
    }
    pub fn service(self) -> kasumi_data_server::KasumiDataServer<Self> {
        kasumi_data_server::KasumiDataServer::new(self)
            .max_decoding_message_size(MAX_REQUEST_BYTES)
            .max_encoding_message_size(MAX_RESPONSE_BYTES)
    }
}

#[tonic::async_trait]
impl kasumi_data_server::KasumiData for NativeData {
    async fn get(&self, request: Request<GetRequest>) -> Result<Response<Document>, Status> {
        let context = verified(&self.auth, &request).await?;
        let request = request.into_inner();
        validate_name(&request.collection).map_err(status)?;
        validate_name(&request.id).map_err(status)?;
        let database = routed(&self.registry, &self.auth, &context).await?;
        let fence = self
            .auth
            .audit_result(&context, database.response_fence(&context))
            .await
            .map_err(status)?;
        let result = database
            .get(&context, &request.collection, &request.id)
            .await;
        let result = result.map_err(|error| self.registry.status(&context, error))?;
        let response = document(result)?;
        let response = release_response(&self.auth, &context, fence, response, false)
            .await
            .map_err(status)?;
        Ok(Response::new(response))
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
            .audit_result(&context, database.response_fence(&context))
            .await
            .map_err(status)?;
        let result = database.query(&context, query).await;
        let result = result.map_err(|error| self.registry.status(&context, error))?;
        let rows = result
            .rows
            .into_iter()
            .map(|row| {
                Ok(QueryRow {
                    document: Some(document(kasumi_types::Document {
                        id: row.id,
                        version: row.version,
                        body: row.body,
                    })?),
                    score: row.score,
                })
            })
            .collect::<Result<Vec<_>, Status>>()?;
        let aggregates_json = result
            .aggregates
            .iter()
            .map(|value| encode_json(value).map_err(status))
            .collect::<Result<_, _>>()?;
        let response = QueryResponse {
            revision: result.revision,
            rows,
            aggregates_json,
            cursor: result.cursor,
        };
        let response = release_response(&self.auth, &context, fence, response, false)
            .await
            .map_err(status)?;
        Ok(Response::new(response))
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
        let outcome = stored.map(|stored| match stored {
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
        let response = ReceiptResponse { outcome };
        let response = release_response(&self.auth, &context, fence, response, false)
            .await
            .map_err(status)?;
        Ok(Response::new(response))
    }
}

impl NativeAdmin {
    pub fn new(registry: DatabaseRegistry, auth: Arc<Authenticator>) -> Self {
        Self {
            registry,
            auth,
            management: None,
        }
    }
    pub fn with_management(
        mut self,
        management: Arc<crate::administration::Administration>,
    ) -> Self {
        self.management = Some(management);
        self
    }
    pub fn service(self) -> kasumi_admin_server::KasumiAdminServer<Self> {
        kasumi_admin_server::KasumiAdminServer::new(self)
            .max_decoding_message_size(MAX_REQUEST_BYTES)
            .max_encoding_message_size(MAX_RESPONSE_BYTES)
    }
    async fn apply(
        &self,
        context: RequestContext,
        operation: Operation,
    ) -> Result<Response<WriteReceipt>, Status> {
        let database = if context.tenant == crate::runtime::CONTROL_TENANT {
            let result = match &self.management {
                Some(manager) => manager.authorized_database(&context).await,
                None => Err(kasumi_types::Error::new(
                    kasumi_types::ErrorCode::Forbidden,
                    "control administration requires the private runtime route",
                )),
            };
            self.auth
                .audit_result(&context, result)
                .await
                .map_err(status)?
        } else {
            routed(&self.registry, &self.auth, &context).await?
        };
        let result = database.administer(context.clone(), operation).await;
        let result = result.map_err(|error| self.registry.status(&context, error))?;
        // Policy/schema/suspension operations intentionally change the epoch.
        // Capture their resulting epoch before constructing the acknowledgement.
        let fence = self
            .auth
            .audit_result(&context, database.response_fence(&context))
            .await
            .map_err(status)?;
        let response = receipt(result);
        let response = release_response(&self.auth, &context, fence, response, false)
            .await
            .map_err(status)?;
        Ok(Response::new(response))
    }
}

#[tonic::async_trait]
impl kasumi_admin_server::KasumiAdmin for NativeAdmin {
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
        let fence = self
            .auth
            .audit_result(&context, manager.response_fence(&context, &command))
            .await
            .map_err(status)?;
        let result = manager.execute(context.clone(), command).await;
        // Administration owns its operation denials, including nested database
        // requests. The adapter owns only its route and response fences.
        let result = result.map_err(|error| self.registry.status(&context, error))?;
        let response = ManagementResponse {
            result_json: encode_json(&result).map_err(status)?,
        };
        self.auth
            .audit_result(&context, fence.check_release())
            .await
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
