//! Tenant routing shared by the HTTP and native adapters.
use kasumi_engine::Database;
use kasumi_types::{Error, ErrorCode, RequestContext, Result};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, RwLock},
};

pub const MAX_REQUEST_BYTES: usize = (8 << 20) + (64 << 10);
pub const MAX_RESPONSE_BYTES: usize = 16 << 20;

#[derive(Clone, Default)]
pub struct DatabaseRegistry {
    databases: Arc<RwLock<BTreeMap<String, Arc<Database>>>>,
    approved_nodes: Arc<RwLock<BTreeSet<u64>>>,
    retirement_sources:
        Arc<RwLock<BTreeMap<(String, String), kasumi_engine::InstalledRetirementSource>>>,
}

impl DatabaseRegistry {
    /// Installed source custody is retained separately from mutable data routes.
    /// This takes a typed service handle, never wire-selected keys or locations.
    pub fn install_retirement_source(
        &self,
        source: kasumi_engine::InstalledRetirementSource,
    ) -> Result<()> {
        let identity = source.identity()?;
        if identity.0.starts_with("__kasumi_") {
            return Ok(());
        }
        self.retirement_sources
            .write()
            .map_err(|_| Error::new(ErrorCode::Unavailable, "source registry unavailable"))?
            .insert(identity, source);
        Ok(())
    }
    pub fn retirement_source(
        &self,
        context: &RequestContext,
        incarnation: &str,
    ) -> Result<kasumi_engine::InstalledRetirementSource> {
        context.authorization.check_live()?;
        kasumi_types::validate_name(incarnation)?;
        if context.tenant.starts_with("__kasumi_") {
            return Err(Error::new(ErrorCode::Forbidden, "source access denied"));
        }
        self.retirement_sources
            .read()
            .map_err(|_| Error::new(ErrorCode::Unavailable, "source registry unavailable"))?
            .get(&(context.tenant.clone(), incarnation.into()))
            .cloned()
            .ok_or_else(|| Error::new(ErrorCode::Forbidden, "source access denied"))
    }
    pub(crate) fn set_approved_nodes(&self, nodes: BTreeSet<u64>) -> Result<()> {
        *self
            .approved_nodes
            .write()
            .map_err(|_| Error::new(ErrorCode::Unavailable, "routing unavailable"))? = nodes;
        Ok(())
    }
    /// A hint is advisory. Clients choose only an operator-configured endpoint
    /// for this authenticated node and retry the same idempotency key.
    pub fn leader_hint(&self, context: &RequestContext, error: &Error) -> Option<u64> {
        if !matches!(
            error.code,
            ErrorCode::Unavailable | ErrorCode::UnknownOutcome
        ) {
            return None;
        }
        let database = self.database(context).ok()?;
        let generation = database.engine().generation().ok()?;
        if !generation.state.policy.grants.iter().any(|grant| {
            grant.principal == context.principal && !grant.actions.is_disjoint(&context.scopes)
        }) {
            return None;
        }
        let leader = database
            .raft_group()
            .raft()
            .metrics()
            .borrow()
            .current_leader?;
        self.approved_nodes
            .read()
            .ok()?
            .contains(&leader)
            .then_some(leader)
    }
    pub(crate) fn status(&self, context: &RequestContext, error: Error) -> tonic::Status {
        let hint = self.leader_hint(context, &error);
        let mut status = status(error);
        if let Some(leader) = hint
            && let Ok(value) = leader.to_string().parse()
        {
            status.metadata_mut().insert("kasumi-leader-node-id", value);
        }
        status
    }

    /// Register an opened tenant; its engine, rather than caller input, supplies
    /// the routing key. Replacing a serving tenant requires an explicit removal.
    pub fn insert(&self, database: Arc<Database>) -> Result<()> {
        database.check_serving()?;
        let generation = database.engine().generation()?;
        if generation.state.retired {
            return Err(Error::new(
                ErrorCode::Sealed,
                "retired source cannot enter data routing",
            ));
        }
        let tenant = generation.state.tenant.clone();
        if tenant.starts_with("__kasumi_") {
            return Err(Error::new(
                ErrorCode::Forbidden,
                "reserved service tenants cannot be exposed through data APIs",
            ));
        }
        let mut databases = self
            .databases
            .write()
            .map_err(|_| Error::new(ErrorCode::Unavailable, "tenant registry unavailable"))?;
        if databases.contains_key(&tenant) {
            return Err(Error::new(
                ErrorCode::AlreadyExists,
                "tenant already registered",
            ));
        }
        self.install_retirement_source(kasumi_engine::InstalledRetirementSource::Serving(
            database.clone(),
        ))?;
        databases.insert(tenant, database);
        Ok(())
    }

    pub fn remove(&self, tenant: &str) -> Result<Option<Arc<Database>>> {
        Ok(self
            .databases
            .write()
            .map_err(|_| Error::new(ErrorCode::Unavailable, "tenant registry unavailable"))?
            .remove(tenant))
    }

    /// Publish one fully recovered generation after the durable control route CAS.
    /// Existing request handles remain fenced by the retired source engine.
    pub(crate) fn replace_generation(&self, expected: &str, database: Arc<Database>) -> Result<()> {
        database.check_serving()?;
        let state = database.engine().generation()?;
        if state.state.retired {
            return Err(Error::new(
                ErrorCode::Sealed,
                "retired source cannot enter data routing",
            ));
        }
        let tenant = state.state.tenant.clone();
        if tenant.starts_with("__kasumi_") {
            return Err(Error::new(ErrorCode::Forbidden, "reserved tenant"));
        }
        let mut databases = self
            .databases
            .write()
            .map_err(|_| Error::new(ErrorCode::Unavailable, "tenant registry unavailable"))?;
        let previous = databases
            .get(&tenant)
            .ok_or_else(|| Error::new(ErrorCode::Conflict, "tenant generation absent"))?;
        if previous.engine().generation()?.state.incarnation != expected {
            return Err(Error::new(ErrorCode::Conflict, "tenant generation changed"));
        }
        self.install_retirement_source(kasumi_engine::InstalledRetirementSource::Serving(
            database.clone(),
        ))?;
        databases.insert(tenant, database);
        Ok(())
    }

    /// Only a verified context selects the tenant. No data request has a tenant
    /// override, and unknown tenants do not reveal the registry's contents.
    pub fn database(&self, context: &RequestContext) -> Result<Arc<Database>> {
        if context.tenant.starts_with("__kasumi_") {
            return Err(Error::new(ErrorCode::Forbidden, "tenant access denied"));
        }
        self.databases
            .read()
            .map_err(|_| Error::new(ErrorCode::Unavailable, "tenant registry unavailable"))?
            .get(&context.tenant)
            .cloned()
            .ok_or_else(|| Error::new(ErrorCode::Forbidden, "tenant access denied"))
    }
}

pub(crate) fn decode_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err(Error::new(
            ErrorCode::ResourceExhausted,
            "request body too large",
        ));
    }
    serde_json::from_slice(bytes)
        .map_err(|_| Error::new(ErrorCode::InvalidArgument, "invalid request JSON"))
}

pub(crate) fn encode_json(value: &impl Serialize) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| Error::new(ErrorCode::Corruption, "response encoding failed"))?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(Error::new(
            ErrorCode::ResourceExhausted,
            "response too large",
        ));
    }
    Ok(bytes)
}

/// A successfully submitted mutation must not look like a rejected CAS when a
/// later policy change withholds its response. Its retained receipt is the
/// resolution path once the principal has access again.
pub(crate) fn mutation_release<T>(result: Result<T>) -> Result<T> {
    result.map_err(|error| {
        if matches!(error.code, ErrorCode::Conflict | ErrorCode::Unauthorized) {
            Error::new(
                ErrorCode::UnknownOutcome,
                "write response release was fenced; resolve or retry the same idempotency key",
            )
        } else {
            error
        }
    })
}

/// Release an already encoded adapter response only while its captured access
/// fence still holds. Database methods cannot audit a denial arising after
/// their result was returned, so this boundary owns its separate denial event.
pub(crate) async fn release_response<T>(
    auth: &crate::auth::Authenticator,
    context: &RequestContext,
    fence: impl kasumi_engine::EncodedResponseFence,
    response: T,
    mutation: bool,
) -> Result<T> {
    let release = auth.audit_result(context, fence.check()).await;
    if mutation {
        mutation_release(release)?;
    } else {
        release?;
    }
    Ok(response)
}

pub(crate) fn status(error: Error) -> tonic::Status {
    use tonic::Code;
    // Normalize even manually constructed or legacy external error values.
    let error = Error::new(error.code, error.message);
    let code = match error.code {
        ErrorCode::InvalidArgument | ErrorCode::SchemaViolation => Code::InvalidArgument,
        ErrorCode::Unauthorized => Code::Unauthenticated,
        ErrorCode::Forbidden => Code::PermissionDenied,
        ErrorCode::NotFound => Code::NotFound,
        ErrorCode::AlreadyExists => Code::AlreadyExists,
        ErrorCode::Conflict => Code::Aborted,
        ErrorCode::QuotaExceeded | ErrorCode::ResourceExhausted => Code::ResourceExhausted,
        ErrorCode::IndexRequired | ErrorCode::CursorExpired | ErrorCode::Sealed => {
            Code::FailedPrecondition
        }
        ErrorCode::Unavailable | ErrorCode::UnknownOutcome | ErrorCode::AuditUnavailable => {
            Code::Unavailable
        }
        ErrorCode::Corruption => Code::DataLoss,
    };
    // In particular, UNKNOWN_OUTCOME remains machine-readable so callers know
    // to resolve/retry their existing idempotency key instead of issuing a new one.
    let details = serde_json::to_vec(&error).unwrap_or_default();
    tonic::Status::with_details(code, error.message, details.into())
}

#[cfg(test)]
mod tests {
    include!("api_staging_tests.rs");
    include!("api_guarded_staging_tests.rs");
    include!("api_history_tests.rs");
    include!("api_schema_tests.rs");
    include!("api_backup_checkpoint_tests.rs");
    use super::*;
    use crate::{
        auth::{AuthConfig, Authenticator},
        mcp::{McpConfig, router},
        rpc::{
            NativeAdmin, NativeData,
            proto::{self, kasumi_admin_server::KasumiAdmin, kasumi_data_server::KasumiData},
        },
    };
    use axum::{
        Router,
        body::Body,
        http::{Request as HttpRequest, StatusCode},
    };
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use kasumi_store::{NodeStore, TenantStore, test_utils::LocalKeyProvider};
    use kasumi_types::{
        Action, CollectionDefinition, Grant, IndexDefinition, IndexField, Limits, Operation,
        Policy, ScalarType,
    };
    use prost::Message;
    use serde_json::{Value, json};
    use std::collections::BTreeSet;
    use tonic::{Code, Request};
    use tower::ServiceExt;

    struct Fixture {
        _dir: tempfile::TempDir,
        db: Arc<Database>,
        registry: DatabaseRegistry,
        auth: Arc<Authenticator>,
        key: EncodingKey,
        audit_store: Arc<TenantStore>,
        audit: Arc<crate::runtime::SecurityAudit>,
    }
    impl Fixture {
        async fn new() -> Self {
            let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
            let keys = serde_json::from_value(json!({"keys":[{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","use":"sig","kid":"test-key","x":URL_SAFE_NO_PAD.encode(key.public_key_raw())}]})).unwrap();
            let auth = Authenticator::with_test_keys(
                AuthConfig {
                    issuer: "https://issuer.example".into(),
                    audience: "https://kasumi.example/mcp".into(),
                    jwks_uri: "https://issuer.example/keys".into(),
                    algorithms: vec![Algorithm::EdDSA],
                    access_token_types: BTreeSet::from(["at+jwt".into()]),
                    jwks_trusted_ca_pem: None,
                },
                keys,
            )
            .await;
            let key = EncodingKey::from_ed_pem(key.serialize_pem().as_bytes()).unwrap();
            let dir = tempfile::tempdir().unwrap();
            let node = NodeStore::open(dir.path().join("node.redb")).unwrap();
            let audit_store = TenantStore::open_fixture(
                node.clone(),
                crate::runtime::SECURITY_TENANT.into(),
                Arc::new(LocalKeyProvider::new([9; 32])),
            )
            .await
            .unwrap();
            let audit = crate::runtime::SecurityAudit::open(audit_store.clone(), 10_000).unwrap();
            auth.install_audit(audit.clone()).unwrap();
            let store = TenantStore::open_fixture(
                node,
                "tenant-a".into(),
                Arc::new(LocalKeyProvider::new([3; 32])),
            )
            .await
            .unwrap();
            let actions = BTreeSet::from([Action::Read, Action::Write, Action::Admin]);
            let policy = Policy {
                grants: vec![
                    Grant {
                        principal: "person".into(),
                        collection: None,
                        actions: actions.clone(),
                    },
                    Grant {
                        principal: "reader".into(),
                        collection: Some("docs".into()),
                        actions: BTreeSet::from([Action::Read]),
                    },
                ],
                strict_read_audit: false,
            };
            let db = kasumi_engine::open_local(
                kasumi_store::test_utils::with_custody(
                    store.clone(),
                    Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32])),
                )
                .await
                .unwrap(),
                policy,
                Limits::default(),
                audit.clone(),
            )
            .await
            .unwrap();
            db.administer(
                RequestContext {
                    authorization: kasumi_types::RequestAuthorization::service_identity(),
                    principal: "person".into(),
                    tenant: "tenant-a".into(),
                    scopes: actions,
                    request_id: "bootstrap".into(),
                },
                Operation::CreateCollection(CollectionDefinition {
                    retention_class: kasumi_types::CollectionRetentionClass::Operational,
                    write_mode: kasumi_types::CollectionWriteMode::Mutable,
                    name: "docs".into(),
                    schema: json!({"type":"object"}),
                    indexes: vec![IndexDefinition {
                        name: "n".into(),
                        fields: vec![IndexField {
                            path: "/n".into(),
                            kind: ScalarType::Number,
                        }],
                        unique: false,
                        text: None,
                    }],
                    strict_read_audit: false,
                }),
            )
            .await
            .unwrap();
            let registry = DatabaseRegistry::default();
            registry.insert(db.clone()).unwrap();
            Self {
                _dir: dir,
                db,
                registry,
                auth,
                key,
                audit_store,
                audit,
            }
        }
        fn token(&self, principal: &str, tenant: &str, scope: &str) -> String {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let mut header = Header::new(Algorithm::EdDSA);
            header.kid = Some("test-key".into());
            header.typ = Some("at+jwt".into());
            format!("Bearer {}", encode(&header, &json!({"sub":principal,"tenant":tenant,"scope":scope,"iss":"https://issuer.example","aud":"https://kasumi.example/mcp","exp":now+300}), &self.key).unwrap())
        }
        fn router(&self) -> Router {
            router(
                McpConfig::new("https://kasumi.example/mcp".into()).unwrap(),
                self.registry.clone(),
                self.auth.clone(),
            )
            .unwrap()
        }
        fn data(&self) -> NativeData {
            NativeData::new(self.registry.clone(), self.auth.clone())
        }
        async fn close(&self) {
            self.db.shutdown().await.unwrap();
            self.audit.shutdown().await;
        }
    }
    fn native<T>(message: T, token: &str) -> Request<T> {
        let mut request = Request::new(message);
        request
            .metadata_mut()
            .insert("authorization", token.parse().unwrap());
        request
    }
    fn mcp_body(method: &str, mut params: Value) -> Value {
        params["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"kasumi-tests","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}});
        json!({"jsonrpc":"2.0","id":1,"method":method,"params":params})
    }
    async fn post(
        router: &Router,
        token: Option<&str>,
        body: Value,
        headers: &[(&str, &str)],
    ) -> (StatusCode, Value) {
        let method = body["method"].as_str().unwrap();
        let mut request = HttpRequest::builder()
            .method("POST")
            .uri("/mcp")
            .header("host", "kasumi.example")
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-method", method);
        if let Some(name) = body.pointer("/params/name").and_then(Value::as_str) {
            request = request.header("mcp-name", name);
        }
        if let Some(token) = token {
            request = request.header("authorization", token);
        }
        let mut request = request
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        for (key, value) in headers {
            request.headers_mut().insert(
                axum::http::HeaderName::from_bytes(key.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        let response = router.clone().oneshot(request).await.unwrap();
        let code = response.status();
        assert!(response.headers().get("mcp-session-id").is_none());
        let body = axum::body::to_bytes(response.into_body(), 32 << 20)
            .await
            .unwrap();
        (
            code,
            serde_json::from_slice(&body)
                .unwrap_or_else(|_| json!({"raw":String::from_utf8_lossy(&body)})),
        )
    }
    fn batch() -> Value {
        serde_json::from_str(r#"{"read_set":[],"idempotency_key":"write-once","operations":[{"op":"put","collection":"docs","id":"one","body":{"n":90071992547409931234567890.123456789},"expected":{"kind":"absent"}}]}"#).unwrap()
    }

    // Model the delivery boundary deterministically: run the complete adapter,
    // consume its encoded response, then lose that response before the client
    // receives it. This is not a kernel/TCP fault injector.
    fn lose_first_response(router: Router) -> Router {
        async fn intercept(
            axum::extract::State(first): axum::extract::State<Arc<std::sync::atomic::AtomicBool>>,
            request: HttpRequest<Body>,
            next: axum::middleware::Next,
        ) -> axum::response::Response {
            let response = next.run(request).await;
            if first.swap(false, std::sync::atomic::Ordering::SeqCst) {
                assert_eq!(response.status(), StatusCode::OK);
                let bytes = axum::body::to_bytes(response.into_body(), 32 << 20)
                    .await
                    .unwrap();
                assert!(!bytes.is_empty());
                axum::http::Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(Body::from(r#"{"error":"injected_response_loss"}"#))
                    .unwrap()
            } else {
                response
            }
        }
        router.layer(axum::middleware::from_fn_with_state(
            Arc::new(std::sync::atomic::AtomicBool::new(true)),
            intercept,
        ))
    }

    async fn grpc_post<M: Message>(
        router: &Router,
        method: &str,
        message: M,
        token: &str,
    ) -> (StatusCode, Vec<u8>) {
        let protobuf = message.encode_to_vec();
        let mut frame = vec![0];
        frame.extend_from_slice(&u32::try_from(protobuf.len()).unwrap().to_be_bytes());
        frame.extend_from_slice(&protobuf);
        let request = HttpRequest::builder()
            .method("POST")
            .uri(format!("/kasumi.v1.KasumiData/{method}"))
            .version(axum::http::Version::HTTP_2)
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .header("authorization", token)
            .body(Body::from(frame))
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 32 << 20)
            .await
            .unwrap();
        (status, bytes.to_vec())
    }

    fn decode_grpc<M: Message + Default>(frame: &[u8]) -> M {
        assert!(frame.len() >= 5);
        assert_eq!(frame[0], 0, "uncompressed protobuf response expected");
        assert_eq!(
            u32::from_be_bytes(frame[1..5].try_into().unwrap()) as usize,
            frame.len() - 5
        );
        M::decode(&frame[5..]).unwrap()
    }

    #[tokio::test]
    async fn native_and_mcp_lost_committed_responses_resolve_without_reapplying() {
        for mcp in [false, true] {
            let fixture = Fixture::new().await;
            let token = fixture.token("person", "tenant-a", "kasumi:read kasumi:write");
            let router = lose_first_response(if mcp {
                fixture.router()
            } else {
                tonic::service::Routes::new(fixture.data().service()).into_axum_router()
            });
            if mcp {
                let (status, response) = post(
                    &router,
                    Some(&token),
                    mcp_body(
                        "tools/call",
                        json!({"name":"kasumi_mutate","arguments":batch()}),
                    ),
                    &[],
                )
                .await;
                assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
                assert_eq!(response, json!({"error":"injected_response_loss"}));
            } else {
                let (status, response) = grpc_post(
                    &router,
                    "Mutate",
                    proto::MutateRequest {
                        batch_json: serde_json::to_vec(&batch()).unwrap(),
                    },
                    &token,
                )
                .await;
                assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
                assert_eq!(
                    serde_json::from_slice::<Value>(&response).unwrap(),
                    json!({"error":"injected_response_loss"})
                );
            }
            // The caller received only the injected failure. Resolve the
            // uncertain outcome through a separate authenticated adapter call.
            let committed = fixture.db.engine().generation().unwrap();
            let original = committed.state.collections["docs"].documents["one"].clone();
            assert_eq!(committed.state.document_count, 1);
            assert_eq!(committed.state.receipts.len(), 1);
            let expected = committed
                .state
                .receipts
                .values()
                .next()
                .unwrap()
                .outcome
                .clone()
                .unwrap();
            if mcp {
                let (status, receipt) = post(
                    &router, Some(&token),
                    mcp_body("tools/call", json!({"name":"kasumi_receipt","arguments":{"idempotency_key":"write-once"}})),
                    &[],
                ).await;
                assert_eq!(status, StatusCode::OK);
                assert_eq!(
                    receipt["result"]["structuredContent"]["Ok"],
                    serde_json::to_value(&expected).unwrap(),
                    "{receipt}"
                );
                let (status, retried) = post(
                    &router,
                    Some(&token),
                    mcp_body(
                        "tools/call",
                        json!({"name":"kasumi_mutate","arguments":batch()}),
                    ),
                    &[],
                )
                .await;
                assert_eq!(status, StatusCode::OK);
                assert_eq!(
                    retried["result"]["structuredContent"],
                    serde_json::to_value(&expected).unwrap(),
                    "{retried}"
                );
            } else {
                let (status, receipt) = grpc_post(
                    &router,
                    "Receipt",
                    proto::ReceiptRequest {
                        idempotency_key: "write-once".into(),
                    },
                    &token,
                )
                .await;
                assert_eq!(status, StatusCode::OK);
                let receipt: proto::ReceiptResponse = decode_grpc(&receipt);
                let Some(proto::receipt_response::Outcome::Committed(receipt)) = receipt.outcome
                else {
                    panic!("lost response must resolve to a committed receipt");
                };
                assert_eq!(receipt.revision, expected.revision);
                let (status, retried) = grpc_post(
                    &router,
                    "Mutate",
                    proto::MutateRequest {
                        batch_json: serde_json::to_vec(&batch()).unwrap(),
                    },
                    &token,
                )
                .await;
                assert_eq!(status, StatusCode::OK);
                assert_eq!(decode_grpc::<proto::WriteReceipt>(&retried), receipt);
            }
            let after = fixture.db.engine().generation().unwrap();
            assert_eq!(after.state.document_count, 1);
            assert_eq!(after.state.receipts.len(), 1);
            assert_eq!(after.state.collections["docs"].documents["one"], original);
            assert_eq!(
                original.body["n"].to_string(),
                "90071992547409931234567890.123456789"
            );
            fixture.close().await;
        }
    }

    #[test]
    fn native_status_bounds_worst_case_header_escaping() {
        let mut error = Error::new(ErrorCode::SchemaViolation, "");
        error.message = "\u{0001}".repeat(1 << 20);
        let status = status(error);
        assert_eq!(status.code(), Code::InvalidArgument);
        assert!(status.message().len() <= Error::MAX_MESSAGE_BYTES);
        let mut headers = axum::http::HeaderMap::new();
        status.add_header(&mut headers).unwrap();
        let size: usize = headers
            .iter()
            .map(|(name, value)| name.as_str().len() + value.len() + 32)
            .sum();
        assert!(
            size < 8 << 10,
            "encoded status headers exceed budget: {size}"
        );
        let details: Error = serde_json::from_slice(status.details()).unwrap();
        assert_eq!(details.code, ErrorCode::SchemaViolation);
        assert_eq!(details.message, status.message());
    }

    #[tokio::test]
    async fn long_schema_property_errors_match_native_mcp_and_durable_receipts() {
        let fixture = Fixture::new().await;
        let token = fixture.token(
            "person",
            "tenant-a",
            "kasumi:read kasumi:write kasumi:admin",
        );
        let admin = NativeAdmin::new(fixture.registry.clone(), fixture.auth.clone());
        admin.replace_collection(native(proto::CollectionDefinitionRequest {
            definition_json: serde_json::to_vec(&CollectionDefinition {
                retention_class: kasumi_types::CollectionRetentionClass::Operational,
                write_mode: kasumi_types::CollectionWriteMode::Mutable,
name: "docs".into(),
                schema: json!({"type":"object", "patternProperties":{".*":{"type":"integer"}}}),
                indexes: Vec::new(), strict_read_audit: false,
            }).unwrap(),
        }, &token)).await.unwrap();
        let mut object = serde_json::Map::new();
        object.insert("猫".repeat(349_500), json!("invalid"));
        let body = Value::Object(object);
        assert!(serde_json::to_vec(&body).unwrap().len() < 1 << 20);
        assert!(serde_json::to_vec(&body).unwrap().len() > (1 << 20) - 1024);
        let batch = json!({"read_set":[],"idempotency_key":"long-schema-error", "operations":[{"op":"put", "collection":"docs", "id":"bad", "body":body}]});
        let native_api = fixture.data();
        let rejected = native_api
            .mutate(native(
                proto::MutateRequest {
                    batch_json: serde_json::to_vec(&batch).unwrap(),
                },
                &token,
            ))
            .await
            .unwrap_err();
        assert_eq!(rejected.code(), Code::InvalidArgument);
        let error: Error = serde_json::from_slice(rejected.details()).unwrap();
        assert_eq!(error.code, ErrorCode::SchemaViolation);
        assert!(error.message.starts_with("/猫"));
        assert!(error.message.len() <= Error::MAX_MESSAGE_BYTES);
        let (_, response) = post(
            &fixture.router(),
            Some(&token),
            mcp_body(
                "tools/call",
                json!({"name":"kasumi_mutate", "arguments":batch}),
            ),
            &[],
        )
        .await;
        assert_eq!(response["result"]["isError"], true);
        assert_eq!(
            response["result"]["structuredContent"]["error"],
            serde_json::to_value(&error).unwrap()
        );
        let receipt = native_api
            .receipt(native(
                proto::ReceiptRequest {
                    idempotency_key: "long-schema-error".into(),
                },
                &token,
            ))
            .await
            .unwrap()
            .into_inner();
        match receipt.outcome.unwrap() {
            proto::receipt_response::Outcome::Rejected(receipt) => {
                assert_eq!(receipt.code, "SCHEMA_VIOLATION");
                assert_eq!(receipt.message, error.message);
            }
            _ => panic!("schema failure must retain a rejected receipt"),
        }
        fixture.close().await;
    }

    #[tokio::test]
    async fn native_and_mcp_share_exact_data_receipts_query_and_authorization() {
        let fixture = Fixture::new().await;
        let token = fixture.token(
            "person",
            "tenant-a",
            "kasumi:read kasumi:write kasumi:admin",
        );
        let native_api = fixture.data();
        let original = proto::MutateRequest {
            batch_json: serde_json::to_vec(&batch()).unwrap(),
        };
        // Real protobuf encoding/decoding must preserve the JSON numeric literal.
        let decoded = proto::MutateRequest::decode(original.encode_to_vec().as_slice()).unwrap();
        let written = native_api
            .mutate(native(decoded, &token))
            .await
            .unwrap()
            .into_inner();
        let router = fixture.router();
        let (status, response) = post(
            &router,
            Some(&token),
            mcp_body(
                "tools/call",
                json!({"name":"kasumi_get","arguments":{"collection":"docs","id":"one"}}),
            ),
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{response}");
        assert_eq!(
            response["result"]["structuredContent"]["body"]["n"].to_string(),
            "90071992547409931234567890.123456789"
        );
        let fetched = native_api
            .get(native(
                proto::GetRequest {
                    collection: "docs".into(),
                    id: "one".into(),
                },
                &token,
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            serde_json::from_slice::<Value>(&fetched.body_json).unwrap()["n"].to_string(),
            "90071992547409931234567890.123456789"
        );
        let (_, retried) = post(
            &router,
            Some(&token),
            mcp_body(
                "tools/call",
                json!({"name":"kasumi_mutate","arguments":batch()}),
            ),
            &[],
        )
        .await;
        assert_eq!(
            retried["result"]["structuredContent"]["revision"],
            json!(written.revision)
        );
        let receipt = native_api
            .receipt(native(
                proto::ReceiptRequest {
                    idempotency_key: "write-once".into(),
                },
                &token,
            ))
            .await
            .unwrap()
            .into_inner();
        assert!(matches!(
            receipt.outcome,
            Some(proto::receipt_response::Outcome::Committed(_))
        ));
        let query = json!({"collection":"docs","filter":{"op":"all"},"aggregates":[{"alias":"sum","function":"sum","field":"/n"}]});
        let response = native_api
            .query(native(
                proto::QueryRequest {
                    query_json: serde_json::to_vec(&query).unwrap(),
                },
                &token,
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.rows.len(), 1);
        assert_eq!(
            serde_json::from_slice::<Value>(&response.aggregates_json[0]).unwrap()["values"]["sum"],
            json!("90071992547409931234567890.123456789")
        );
        let collections = native_api
            .collections(native(proto::CollectionsRequest {}, &token))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            serde_json::from_slice::<Value>(&collections.definitions_json[0]).unwrap()["name"],
            json!("docs")
        );
        fixture.close().await;
    }

    #[tokio::test]
    async fn current_mcp_discovery_and_tool_catalog_work_without_initialize() {
        let fixture = Fixture::new().await;
        let token = fixture.token("person", "tenant-a", "kasumi:read kasumi:write");
        let router = fixture.router();
        let (code, result) = post(
            &router,
            Some(&token),
            mcp_body("server/discover", json!({})),
            &[],
        )
        .await;
        assert_eq!(code, StatusCode::OK, "{result}");
        assert_eq!(result["result"]["supportedVersions"], json!(["2026-07-28"]));
        let (code, result) = post(
            &router,
            Some(&token),
            mcp_body("tools/list", json!({})),
            &[],
        )
        .await;
        assert_eq!(code, StatusCode::OK, "{result}");
        let tools = result["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 5);
        assert!(
            !tools
                .iter()
                .any(|tool| tool["name"].as_str().unwrap().contains("admin"))
        );
        let query = tools
            .iter()
            .find(|tool| tool["name"] == "kasumi_query")
            .unwrap();
        assert!(query["inputSchema"]["$defs"]["predicate"]["oneOf"].is_array());
        assert_eq!(query["inputSchema"]["additionalProperties"], false);
        fixture.close().await;
    }

    #[tokio::test]
    async fn native_snapshot_preserves_exact_data_and_its_read_set_rejects_a_stale_commit() {
        let fixture = Fixture::new().await;
        let token = fixture.token(
            "person",
            "tenant-a",
            "kasumi:read kasumi:write kasumi:admin",
        );
        let api = fixture.data();
        api.mutate(native(
            proto::MutateRequest {
                batch_json: serde_json::to_vec(&batch()).unwrap(),
            },
            &token,
        ))
        .await
        .unwrap();
        let response = api
            .read_snapshot(native(
                proto::ReadSnapshotRequest {
                    request_json: serde_json::to_vec(
                        &json!({"documents":[{"collection":"docs","id":"one"}],"queries":[]}),
                    )
                    .unwrap(),
                },
                &token,
            ))
            .await
            .unwrap()
            .into_inner();
        let snapshot: kasumi_types::SnapshotReadResponse =
            serde_json::from_slice(&response.response_json).unwrap();
        assert_eq!(
            snapshot.documents[0].document.as_ref().unwrap().body["n"].to_string(),
            "90071992547409931234567890.123456789"
        );
        let conditional = json!({"idempotency_key":"conditional-native","read_set":snapshot.read_assertions(),"operations":[{"op":"put","collection":"docs","id":"one","body":{"n":2},"expected":{"kind":"any"}}]});
        api.mutate(native(
            proto::MutateRequest {
                batch_json: serde_json::to_vec(&conditional).unwrap(),
            },
            &token,
        ))
        .await
        .unwrap();
        let mut stale = conditional;
        stale["idempotency_key"] = json!("stale-native");
        stale["operations"][0]["id"] = json!("other");
        let error = api
            .mutate(native(
                proto::MutateRequest {
                    batch_json: serde_json::to_vec(&stale).unwrap(),
                },
                &token,
            ))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Aborted);
        fixture.close().await;
    }

    #[tokio::test]
    async fn both_adapters_reject_wrong_identity_tenant_scope_and_admin_escalation() {
        let fixture = Fixture::new().await;
        let reader = fixture.token(
            "reader",
            "tenant-a",
            "kasumi:read kasumi:write kasumi:admin",
        );
        let native_api = fixture.data();
        let error = native_api
            .mutate(native(
                proto::MutateRequest {
                    batch_json: serde_json::to_vec(&batch()).unwrap(),
                },
                &reader,
            ))
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::PermissionDenied);
        let mut forged = native(
            proto::MutateRequest {
                batch_json: serde_json::to_vec(&batch()).unwrap(),
            },
            &reader,
        );
        forged
            .metadata_mut()
            .insert("x-principal", "person".parse().unwrap());
        assert_eq!(
            native_api.mutate(forged).await.unwrap_err().code(),
            Code::PermissionDenied
        );
        let router = fixture.router();
        let (_, result) = post(
            &router,
            Some(&reader),
            mcp_body(
                "tools/call",
                json!({"name":"kasumi_mutate","arguments":batch()}),
            ),
            &[("x-principal", "person"), ("x-tenant", "tenant-b")],
        )
        .await;
        assert_eq!(result["result"]["isError"], true, "{result}");
        assert_eq!(
            result["result"]["structuredContent"]["error"]["code"],
            "FORBIDDEN"
        );
        let other_tenant = fixture.token("person", "tenant-b", "kasumi:read");
        assert_eq!(
            native_api
                .get(native(
                    proto::GetRequest {
                        collection: "docs".into(),
                        id: "one".into()
                    },
                    &other_tenant
                ))
                .await
                .unwrap_err()
                .code(),
            Code::PermissionDenied
        );
        let no_scope = fixture.token("person", "tenant-a", "");
        assert_eq!(
            native_api
                .get(native(
                    proto::GetRequest {
                        collection: "docs".into(),
                        id: "one".into()
                    },
                    &no_scope
                ))
                .await
                .unwrap_err()
                .code(),
            Code::PermissionDenied
        );
        let admin = NativeAdmin::new(fixture.registry.clone(), fixture.auth.clone());
        assert_eq!(
            admin
                .set_suspended(native(
                    proto::SetSuspendedRequest { suspended: true },
                    &reader
                ))
                .await
                .unwrap_err()
                .code(),
            Code::PermissionDenied
        );
        let mut override_batch = batch();
        override_batch["tenant"] = json!("tenant-b");
        assert_eq!(
            native_api
                .mutate(native(
                    proto::MutateRequest {
                        batch_json: serde_json::to_vec(&override_batch).unwrap()
                    },
                    &reader
                ))
                .await
                .unwrap_err()
                .code(),
            Code::InvalidArgument
        );
        fixture.close().await;
    }

    #[tokio::test]
    async fn mcp_rejects_legacy_mismatched_metadata_bad_origins_and_unauthenticated_calls() {
        let fixture = Fixture::new().await;
        let router = fixture.router();
        let token = fixture.token("person", "tenant-a", "kasumi:read");
        let request = mcp_body("tools/list", json!({}));
        assert_eq!(
            post(&router, None, request.clone(), &[]).await.0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            post(&router, Some("Bearer forged"), request.clone(), &[])
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            post(
                &router,
                Some(&token),
                request.clone(),
                &[("origin", "https://attacker.example")]
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            post(
                &router,
                Some(&token),
                request.clone(),
                &[("host", "attacker.example")]
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        let (code, result) = post(
            &router,
            Some(&token),
            request.clone(),
            &[("mcp-method", "tools/call")],
        )
        .await;
        assert_eq!(code, StatusCode::BAD_REQUEST);
        assert_eq!(result["error"]["code"], -32020);
        let mut legacy = request.clone();
        legacy["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] = json!("2025-11-25");
        let (code, result) = post(
            &router,
            Some(&token),
            legacy,
            &[("mcp-protocol-version", "2025-11-25")],
        )
        .await;
        assert_eq!(code, StatusCode::BAD_REQUEST);
        assert_eq!(result["error"]["code"], -32022);
        let mut missing = request.clone();
        missing["params"] = json!({});
        assert_eq!(
            post(&router, Some(&token), missing, &[]).await.0,
            StatusCode::BAD_REQUEST
        );
        let initialize = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2026-07-28","capabilities":{},"clientInfo":{"name":"test","version":"1"}}});
        let (_, result) = post(&router, Some(&token), initialize, &[]).await;
        assert_eq!(result["error"]["code"], -32601, "{result}");
        assert!(result.get("result").is_none());
        fixture.close().await;
    }

    #[tokio::test]
    async fn protected_resource_metadata_and_challenges_advertise_only_configured_issuer() {
        let fixture = Fixture::new().await;
        let router = fixture.router();
        let response = router
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/.well-known/oauth-protected-resource/mcp")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 65536)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["resource"], "https://kasumi.example/mcp");
        assert_eq!(
            body["authorization_servers"],
            json!(["https://issuer.example"])
        );
        let response = router
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("host", "kasumi.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers()["www-authenticate"],
            "Bearer resource_metadata=\"https://kasumi.example/.well-known/oauth-protected-resource/mcp\""
        );
        fixture.close().await;
    }

    #[tokio::test]
    async fn embedded_native_and_mcp_denials_have_one_durable_record_per_request() {
        let fixture = Fixture::new().await;
        let denials = || -> Vec<Value> {
            fixture
                .audit_store
                .scan("security.audit")
                .unwrap()
                .into_iter()
                .map(|(_, body)| serde_json::from_slice::<Value>(&body).unwrap())
                .filter(|event| {
                    matches!(
                        event["event"]["kind"].as_str(),
                        Some("access_denied" | "tenant_sealed")
                    )
                })
                .collect()
        };
        let context = RequestContext {
            authorization: kasumi_types::RequestAuthorization::service_identity(),
            principal: "reader".into(),
            tenant: "tenant-a".into(),
            scopes: BTreeSet::from([Action::Read, Action::Write]),
            request_id: "embedded-denial".into(),
        };
        let error = fixture
            .db
            .mutate(context, serde_json::from_value(batch()).unwrap())
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::Forbidden);
        assert_eq!(denials().len(), 1);
        assert_eq!(denials()[0]["event"]["request_id"], "embedded-denial");

        let token = fixture.token("reader", "tenant-a", "kasumi:read kasumi:write");
        let error = fixture
            .data()
            .mutate(native(
                proto::MutateRequest {
                    batch_json: serde_json::to_vec(&batch()).unwrap(),
                },
                &token,
            ))
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::PermissionDenied);
        assert_eq!(
            denials().len(),
            2,
            "native must not duplicate the Database audit"
        );

        let router = fixture.router();
        let (status, response) = post(
            &router,
            Some(&token),
            mcp_body(
                "tools/call",
                json!({"name":"kasumi_mutate","arguments":batch()}),
            ),
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            response["result"]["structuredContent"]["error"]["code"],
            "FORBIDDEN"
        );
        assert_eq!(
            denials().len(),
            3,
            "MCP must not duplicate the Database audit"
        );

        // These rejections originate before Database dispatch and still need
        // an adapter-owned audit, with only verified token identity recorded.
        let unknown = fixture.token("reader", "unknown-tenant", "kasumi:read");
        assert_eq!(
            fixture
                .data()
                .get(native(
                    proto::GetRequest {
                        collection: "docs".into(),
                        id: "one".into(),
                    },
                    &unknown
                ))
                .await
                .unwrap_err()
                .code(),
            Code::PermissionDenied
        );
        assert_eq!(denials().len(), 4);
        let (_, response) = post(
            &router,
            Some(&unknown),
            mcp_body(
                "tools/call",
                json!({"name":"kasumi_get","arguments":{"collection":"docs","id":"one"}}),
            ),
            &[],
        )
        .await;
        assert_eq!(
            response["result"]["structuredContent"]["error"]["code"],
            "FORBIDDEN"
        );
        assert_eq!(denials().len(), 5);
        assert!(
            denials()[3..]
                .iter()
                .all(|event| event["event"]["tenant"] == "unknown-tenant")
        );

        let (status, _) = post(
            &router,
            Some(&token),
            mcp_body("tools/list", json!({})),
            &[("host", "unapproved.example")],
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(denials().len(), 6, "SDK protocol rejection remains audited");

        fixture.db.engine().seal();
        assert_eq!(
            fixture
                .data()
                .get(native(
                    proto::GetRequest {
                        collection: "docs".into(),
                        id: "one".into(),
                    },
                    &token
                ))
                .await
                .unwrap_err()
                .code(),
            Code::FailedPrecondition
        );
        assert_eq!(
            denials().len(),
            7,
            "native predispatch response fence owns this denial"
        );
        let (_, response) = post(
            &router,
            Some(&token),
            mcp_body(
                "tools/call",
                json!({"name":"kasumi_get","arguments":{"collection":"docs","id":"one"}}),
            ),
            &[],
        )
        .await;
        assert_eq!(
            response["result"]["structuredContent"]["error"]["code"],
            "SEALED"
        );
        assert_eq!(
            denials().len(),
            8,
            "MCP predispatch response fence owns this denial"
        );
        assert!(
            denials()[6..]
                .iter()
                .all(|event| event["event"]["kind"] == "tenant_sealed")
        );
        fixture.close().await;
    }

    #[tokio::test]
    async fn shared_adapter_release_audits_a_seal_after_response_encoding() {
        for mutation in [false, true] {
            let fixture = Fixture::new().await;
            let context = RequestContext {
                authorization: kasumi_types::RequestAuthorization::service_identity(),
                principal: "person".into(),
                tenant: "tenant-a".into(),
                scopes: BTreeSet::from([Action::Read, Action::Write]),
                request_id: "encoded-response-denial".into(),
            };
            let fence = fixture.db.response_fence(&context).unwrap();
            let encoded = if mutation {
                let result = fixture
                    .db
                    .mutate(context.clone(), serde_json::from_value(batch()).unwrap())
                    .await
                    .unwrap();
                encode_json(&result).unwrap()
            } else {
                encode_json(&fixture.db.collections(&context).await.unwrap()).unwrap()
            };
            assert!(!encoded.is_empty());
            assert!(
                fixture
                    .audit_store
                    .scan("security.audit")
                    .unwrap()
                    .is_empty()
            );
            // Both native and MCP use this shared boundary after constructing
            // their payload. Seal deterministically between encoding and release.
            fixture.db.engine().seal();
            let error = release_response(&fixture.auth, &context, fence, encoded, mutation)
                .await
                .unwrap_err();
            assert_eq!(error.code, ErrorCode::Sealed);
            let records = fixture.audit_store.scan("security.audit").unwrap();
            assert_eq!(records.len(), 1);
            let event: Value = serde_json::from_slice(&records[0].1).unwrap();
            assert_eq!(event["event"]["kind"], "tenant_sealed");
            assert_eq!(event["event"]["request_id"], context.request_id);
            fixture.close().await;
        }
    }

    #[tokio::test]
    async fn encoded_response_credential_expiry_is_audited_and_preserves_committed_receipt() {
        struct Clock(std::sync::atomic::AtomicU64);
        impl kasumi_clock::LeaseClock for Clock {
            fn now(&self) -> std::time::Duration {
                std::time::Duration::from_millis(self.0.load(std::sync::atomic::Ordering::SeqCst))
            }
        }
        for mutation in [false, true] {
            let fixture = Fixture::new().await;
            let clock = Arc::new(Clock(std::sync::atomic::AtomicU64::new(0)));
            let epoch = kasumi_clock::EpochClock::new(
                clock.clone(),
                Arc::new(kasumi_clock::SystemWallClock),
            )
            .unwrap();
            let observation = epoch.observe().unwrap();
            let context = RequestContext {
                authorization: kasumi_types::RequestAuthorization::from_verified_credential(
                    observation.utc_ms() + 1000,
                    &observation,
                )
                .unwrap(),
                principal: "person".into(),
                tenant: "tenant-a".into(),
                scopes: BTreeSet::from([Action::Read, Action::Write]),
                request_id: "encoded-expiry".into(),
            };
            let fence = fixture.db.response_fence(&context).unwrap();
            let encoded = if mutation {
                encode_json(
                    &fixture
                        .db
                        .mutate(context.clone(), serde_json::from_value(batch()).unwrap())
                        .await
                        .unwrap(),
                )
                .unwrap()
            } else {
                encode_json(&fixture.db.collections(&context).await.unwrap()).unwrap()
            };
            clock.0.store(1000, std::sync::atomic::Ordering::SeqCst);
            let error = release_response(&fixture.auth, &context, fence, encoded, mutation)
                .await
                .unwrap_err();
            assert_eq!(
                error.code,
                if mutation {
                    ErrorCode::UnknownOutcome
                } else {
                    ErrorCode::Unauthorized
                }
            );
            let records = fixture.audit_store.scan("security.audit").unwrap();
            assert_eq!(records.len(), 1);
            let event: Value = serde_json::from_slice(&records[0].1).unwrap();
            assert_eq!(event["event"]["kind"], "access_denied");
            assert_eq!(event["event"]["request_id"], context.request_id);
            if mutation {
                let fresh = fixture
                    .auth
                    .authenticate(&fixture.token("person", "tenant-a", "kasumi:read kasumi:write"))
                    .await
                    .unwrap();
                let key = batch()["idempotency_key"].as_str().unwrap().to_owned();
                assert!(
                    fixture
                        .db
                        .operation_receipt(&fresh, &key)
                        .await
                        .unwrap()
                        .unwrap()
                        .is_ok()
                );
            }
            fixture.close().await;
        }
    }

    #[tokio::test]
    async fn required_service_audits_are_durable_and_exclude_unverified_identity_and_payloads() {
        let fixture = Fixture::new().await;
        let reader = fixture.token("reader", "tenant-a", "kasumi:read kasumi:write");
        let data = fixture.data();
        assert_eq!(
            data.mutate(native(
                proto::MutateRequest {
                    batch_json: serde_json::to_vec(&batch()).unwrap()
                },
                &reader
            ))
            .await
            .unwrap_err()
            .code(),
            Code::PermissionDenied
        );
        let router = fixture.router();
        assert_eq!(
            post(
                &router,
                Some("Bearer unverified-secret-token"),
                mcp_body("tools/list", json!({})),
                &[]
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        fixture.db.engine().seal();
        assert_eq!(
            data.get(native(
                proto::GetRequest {
                    collection: "docs".into(),
                    id: "private-document-id".into()
                },
                &reader
            ))
            .await
            .unwrap_err()
            .code(),
            Code::FailedPrecondition
        );
        let records = fixture.audit_store.scan("security.audit").unwrap();
        let events: Vec<Value> = records
            .iter()
            .map(|(_, body)| serde_json::from_slice(body).unwrap())
            .collect();
        assert!(
            events
                .iter()
                .any(|event| event["event"]["kind"] == "authentication_succeeded"
                    && event["event"]["principal"] == "reader")
        );
        assert!(
            events
                .iter()
                .any(|event| event["event"]["kind"] == "access_denied"
                    && event["event"]["principal"] == "reader")
        );
        assert!(
            events
                .iter()
                .any(|event| event["event"]["kind"] == "tenant_sealed"
                    && event["event"]["tenant"] == "tenant-a")
        );
        let denied = events
            .iter()
            .find(|event| event["event"]["kind"] == "authentication_denied")
            .unwrap();
        assert!(denied["event"]["principal"].is_null());
        assert!(denied["event"]["tenant"].is_null());
        let serialized = serde_json::to_string(&events).unwrap();
        for forbidden in [
            "unverified-secret-token",
            "private-document-id",
            "90071992547409931234567890",
            reader.as_str(),
        ] {
            assert!(!serialized.contains(forbidden));
        }
        // Reopening the service sink recovers the durable sequence, independently
        // of the now-sealed data tenant and its Raft log compaction.
        let reopened =
            crate::runtime::SecurityAudit::open(fixture.audit_store.clone(), 10_000).unwrap();
        reopened
            .record(crate::runtime::SecurityEvent {
                kind: crate::runtime::SecurityEventKind::NodeStarted,
                principal: None,
                tenant: None,
                request_id: "reopen-proof".into(),
                outcome: crate::runtime::SecurityOutcome::Succeeded,
            })
            .await
            .unwrap();
        assert_eq!(
            fixture.audit_store.scan("security.audit").unwrap().len(),
            events.len() + 1
        );
        fixture.close().await;
    }

    #[tokio::test]
    async fn required_audit_failure_blocks_dispatch_and_preserves_authentication_denials() {
        let fixture = Fixture::new().await;
        let token = fixture.token("person", "tenant-a", "kasumi:read kasumi:write");
        let revision = fixture.db.engine().generation().unwrap().state.revision;
        fixture.audit_store.seal();
        let error = fixture
            .data()
            .mutate(native(
                proto::MutateRequest {
                    batch_json: serde_json::to_vec(&batch()).unwrap(),
                },
                &token,
            ))
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::Unavailable);
        assert_eq!(
            serde_json::from_slice::<Value>(error.details()).unwrap()["code"],
            "AUDIT_UNAVAILABLE"
        );
        let router = fixture.router();
        assert_eq!(
            post(
                &router,
                Some(&token),
                mcp_body(
                    "tools/call",
                    json!({"name":"kasumi_mutate","arguments":batch()})
                ),
                &[]
            )
            .await
            .0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            post(
                &router,
                Some("Bearer forged"),
                mcp_body("tools/list", json!({})),
                &[]
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            fixture.db.engine().generation().unwrap().state.revision,
            revision
        );
        assert!(
            fixture.db.engine().generation().unwrap().state.collections["docs"]
                .documents
                .is_empty()
        );
        fixture.close().await;
    }

    #[tokio::test]
    async fn private_native_control_route_can_raise_a_full_audit_budget() {
        use crate::administration::{Administration, ManagedTenant};
        let fixture = Fixture::new().await;
        let tenant = crate::runtime::CONTROL_TENANT;
        let context = RequestContext {
            authorization: kasumi_types::RequestAuthorization::service_identity(),
            tenant: tenant.into(),
            principal: "person".into(),
            scopes: BTreeSet::from([Action::Admin, Action::Read, Action::Write]),
            request_id: "control-bootstrap".into(),
        };
        let policy = Policy {
            grants: vec![Grant {
                principal: "person".into(),
                collection: None,
                actions: context.scopes.clone(),
            }],
            strict_read_audit: true,
        };
        let provider = Arc::new(LocalKeyProvider::new([61; 32]));
        let store = TenantStore::open_fixture(
            NodeStore::open(fixture._dir.path().join("control.redb")).unwrap(),
            tenant.into(),
            provider.clone(),
        )
        .await
        .unwrap();
        let limits = Limits {
            max_audit_records: 1,
            ..Limits::default()
        };
        let control = kasumi_engine::open_local(
            kasumi_store::test_utils::with_custody(
                store.clone(),
                std::sync::Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32])),
            )
            .await
            .unwrap(),
            policy.clone(),
            limits,
            fixture.audit.clone(),
        )
        .await
        .unwrap();
        control
            .administer(context.clone(), Operation::SetPolicy(policy.clone()))
            .await
            .unwrap();
        assert_eq!(control.engine().generation().unwrap().state.audits.len(), 1);
        let mut config = crate::runtime::example_config();
        config.control.initial_policy = policy;
        let manager = Administration::new(
            config,
            fixture.registry.clone(),
            control.clone(),
            fixture.audit.clone(),
            None,
            vec![ManagedTenant {
                database: control.clone(),
                store,
                provider,
                custody_provider: Arc::new(LocalKeyProvider::new([241; 32])),
                bootstrap: None,
                descriptor: None,
                lease: None,
            }],
            BTreeMap::new(),
            kasumi_engine::admission::NodeAdmission::new(Default::default()).unwrap(),
            BTreeMap::new(),
            Arc::new(|_| anyhow::bail!("fixture has no installed authority credential")),
        )
        .unwrap();
        let token = fixture.token("person", tenant, "kasumi:admin kasumi:read kasumi:write");
        let limits = Limits {
            max_audit_records: 10,
            ..Limits::default()
        };
        let payload = serde_json::to_vec(&limits).unwrap();
        let bare = NativeAdmin::new(fixture.registry.clone(), fixture.auth.clone());
        assert_eq!(
            bare.set_limits(native(
                proto::SetLimitsRequest {
                    limits_json: payload.clone()
                },
                &token
            ))
            .await
            .unwrap_err()
            .code(),
            Code::PermissionDenied
        );
        let admin = bare.with_management(manager);
        let impostor = fixture.token("reader", tenant, "kasumi:admin");
        assert_eq!(
            admin
                .set_limits(native(
                    proto::SetLimitsRequest {
                        limits_json: payload.clone()
                    },
                    &impostor
                ))
                .await
                .unwrap_err()
                .code(),
            Code::PermissionDenied
        );
        admin
            .set_limits(native(
                proto::SetLimitsRequest {
                    limits_json: payload.clone(),
                },
                &token,
            ))
            .await
            .unwrap();
        assert_eq!(
            control
                .engine()
                .generation()
                .unwrap()
                .state
                .limits
                .max_audit_records,
            10
        );
        assert_eq!(control.engine().generation().unwrap().state.audits.len(), 2);
        assert_eq!(
            fixture.registry.database(&context).err().unwrap().code,
            ErrorCode::Forbidden
        );
        let security = fixture.token("person", crate::runtime::SECURITY_TENANT, "kasumi:admin");
        assert_eq!(
            admin
                .set_limits(native(
                    proto::SetLimitsRequest {
                        limits_json: payload
                    },
                    &security
                ))
                .await
                .unwrap_err()
                .code(),
            Code::PermissionDenied
        );
        control.shutdown().await.unwrap();
        fixture.close().await;
    }

    #[tokio::test]
    async fn reserved_control_and_security_tenants_are_never_data_routes() {
        let fixture = Fixture::new().await;
        for tenant in ["__kasumi_control", "__kasumi_security"] {
            let token = fixture.token("person", tenant, "kasumi:read kasumi:admin");
            let error = fixture
                .data()
                .get(native(
                    proto::GetRequest {
                        collection: "docs".into(),
                        id: "one".into(),
                    },
                    &token,
                ))
                .await
                .unwrap_err();
            assert_eq!(error.code(), Code::PermissionDenied);
        }
        fixture.close().await;
    }
}
