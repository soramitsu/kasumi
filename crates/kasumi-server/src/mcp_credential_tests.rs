use super::*;
use crate::{
    auth::{AuthConfig, AuthKeySource, RequestAuditEvent, RequestAuditKind, RequestAuditSink},
    local_auth::{LocalCredentials, initialize_signer},
};
use axum::{
    body::{Body, Bytes},
    http::Request as HttpRequest,
};
use hyper::body::{Frame, SizeHint};
use kasumi_clock::{EpochClock, LeaseClock, WallClock};
use kasumi_store::{
    NodeStore, StorageAccess, TenantStore, private_files, test_utils::LocalKeyProvider,
};
use kasumi_types::{
    CollectionDefinition, CollectionRetentionClass, CollectionWriteMode, CreateCredential,
    CredentialResource, DEFAULT_CREDENTIAL_LIFETIME_SECONDS, Grant, IssuedCredential, Limits,
    Operation, Policy, RenewCredential, RequestAuthorization,
};
use std::{
    collections::BTreeSet,
    convert::Infallible,
    future::Future,
    pin::Pin,
    sync::{Mutex, atomic::AtomicU64},
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Notify, oneshot};
use tower::ServiceExt;
use uuid::Uuid;

pub(crate) struct ReleaseGate {
    entered: Notify,
    release: Notify,
}
impl std::fmt::Debug for ReleaseGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReleaseGate").finish_non_exhaustive()
    }
}
impl ReleaseGate {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: Notify::new(),
            release: Notify::new(),
        })
    }
    pub(super) async fn wait(&self) {
        self.entered.notify_one();
        self.release.notified().await;
    }
    pub(crate) async fn entered(&self) {
        tokio::time::timeout(Duration::from_secs(10), self.entered.notified())
            .await
            .unwrap();
    }
    pub(crate) fn release(&self) {
        self.release.notify_one();
    }
}

/// Holds a tool call after its result tree is charged and before its encoded
/// SDK body is charged, so a test can take the remaining admission headroom.
#[derive(Clone)]
pub(crate) struct BodyChargeGate(pub(crate) Arc<ReleaseGate>);

struct ManualClock {
    base_ms: u64,
    elapsed_ms: AtomicU64,
}
impl LeaseClock for ManualClock {
    fn now(&self) -> Duration {
        Duration::from_millis(self.elapsed_ms.load(Ordering::SeqCst))
    }
}
impl WallClock for ManualClock {
    fn now_ms(&self) -> anyhow::Result<u64> {
        Ok(self.base_ms + self.elapsed_ms.load(Ordering::SeqCst))
    }
}
#[derive(Default)]
struct Audit(Mutex<Vec<RequestAuditEvent>>);
#[async_trait::async_trait]
impl RequestAuditSink for Audit {
    async fn record(&self, event: RequestAuditEvent) -> kasumi_types::Result<()> {
        self.0.lock().unwrap().push(event);
        Ok(())
    }
}
struct Fixture {
    auth: Arc<Authenticator>,
    credentials: Arc<LocalCredentials>,
    clock: Arc<ManualClock>,
    audit: Arc<Audit>,
    database: Arc<kasumi_engine::Database>,
    registry: DatabaseRegistry,
    security: Arc<kasumi_engine::SecurityAudit>,
    admission: Arc<kasumi_engine::admission::NodeAdmission>,
    // The admission ledger's total reservation cap.
    budget: u64,
    node: NodeStore,
    _directory: tempfile::TempDir,
}
impl Fixture {
    async fn new() -> Self {
        let directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let private = directory.path().join("private");
        private_files::create_directory(&private).unwrap();
        let signer = private.join("signer.json");
        initialize_signer(&signer).unwrap();
        let mut config = kasumi_engine::admission::AdmissionConfig {
            max_inflight_bytes: Some(256 << 20),
            ..Default::default()
        };
        let bookkeeping =
            kasumi_engine::admission::NodeAdmission::required_bookkeeping_bytes(&config).unwrap();
        config.max_inflight_bytes = Some(bookkeeping.checked_add(256 << 20).unwrap());
        // Plan the disk metadata into the cap as FixtureStorage::open does, so
        // tests know the whole ledger budget.
        let (persistent, scratch) =
            kasumi_engine::test_utils::fixture_disk_configs(&private).unwrap();
        let config = kasumi_engine::test_utils::isolated_disk_config_with_metadata(
            config,
            &persistent,
            &scratch,
        )
        .unwrap();
        let budget = config.max_inflight_bytes.unwrap();
        let physical = kasumi_engine::test_utils::FixtureStorage::with_admission(
            &persistent,
            &scratch,
            kasumi_engine::admission::NodeAdmission::new(config).unwrap(),
        )
        .unwrap();
        let admission = physical.admission.clone();
        let node = physical
            .create_new(
                private.join("persistent/node.kv"),
                kasumi_store::test_utils::NODE_STORE_ID,
            )
            .unwrap();
        let security_store = TenantStore::initialize_catalog(
            node.clone(),
            kasumi_engine::SECURITY_TENANT.into(),
            Arc::new(LocalKeyProvider::new([31; 32])),
            StorageAccess::security_audit(),
        )
        .await
        .unwrap();
        let security = kasumi_engine::SecurityAudit::initialize(
            security_store.clone(),
            Default::default(),
            admission.clone(),
        )
        .unwrap();
        let application = TenantStore::initialize_catalog_fixture(
            node.clone(),
            "tenant-a".into(),
            Arc::new(LocalKeyProvider::new([32; 32])),
        )
        .await
        .unwrap();
        let stores = kasumi_store::test_utils::initialize_custody_fixture(
            application,
            Arc::new(LocalKeyProvider::new([33; 32])),
        )
        .await
        .unwrap();
        let database = kasumi_engine::test_utils::open_fixture(
            stores,
            Policy {
                grants: vec![Grant {
                    principal: "person".into(),
                    collection: None,
                    actions: BTreeSet::from([Action::Read, Action::Write, Action::Admin]),
                }],
                strict_read_audit: false,
            },
            Limits::default(),
            security.clone(),
        )
        .await
        .unwrap();
        database
            .administer(
                Self::context(),
                Operation::CreateCollection(CollectionDefinition {
                    name: "docs".into(),
                    write_mode: CollectionWriteMode::Mutable,
                    retention_class: CollectionRetentionClass::Operational,
                    schema: json!({"type":"object"}),
                    indexes: Vec::new(),
                    strict_read_audit: false,
                }),
            )
            .await
            .unwrap();
        // Keep both signed nbf values behind real wall time; only the trusted
        // paired issuer/verifier clock advances during the deterministic test.
        let clock = Arc::new(ManualClock {
            base_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                * 1000
                - 60_000,
            elapsed_ms: AtomicU64::new(0),
        });
        let epoch = Arc::new(EpochClock::new(clock.clone(), clock.clone()).unwrap());
        let config = AuthConfig {
            issuer: "https://issuer.example/local".into(),
            audience: "https://kasumi.example/mcp".into(),
            source: AuthKeySource::Local {
                signer_file: signer.clone(),
            },
            algorithms: vec![jsonwebtoken::Algorithm::EdDSA],
            access_token_types: BTreeSet::from(["at+jwt".into()]),
        };
        let credentials = LocalCredentials::with_test_clock(
            security_store,
            signer,
            config.issuer.clone(),
            config.audience.clone(),
            epoch.clone(),
        )
        .unwrap();
        let auth = Authenticator::with_test_clock(config, epoch).unwrap();
        let audit = Arc::new(Audit::default());
        auth.install_audit(audit.clone()).unwrap();
        auth.install_local_credentials(credentials.clone()).unwrap();
        let registry = DatabaseRegistry::default();
        registry.insert(database.clone()).unwrap();
        Self {
            auth,
            credentials,
            clock,
            audit,
            database,
            registry,
            security,
            admission,
            budget,
            node,
            _directory: directory,
        }
    }
    /// The fixed workspace every database response fence retains.
    fn response_workspace(&self) -> u64 {
        let before = self.admission.snapshot().reserved_bytes;
        let fence = self.database.response_fence(&Self::context()).unwrap();
        let workspace = self.admission.snapshot().reserved_bytes - before;
        drop(fence);
        assert_eq!(self.admission.snapshot().reserved_bytes, before);
        workspace
    }
    /// Take every admission byte except `headroom` with one resident charge.
    fn reserve_all_but(&self, headroom: u64) -> kasumi_engine::admission::Reservation {
        let available = self.budget - self.admission.snapshot().reserved_bytes;
        assert!(available >= headroom, "fixture budget is below {headroom}");
        self.admission
            .reserve_resident(available - headroom)
            .unwrap()
    }
    async fn put(&self, key: &str, documents: impl IntoIterator<Item = (String, Value)>) {
        let operations = documents
            .into_iter()
            .map(|(id, body)| json!({"op":"put", "collection":"docs", "id":id, "body":body, "expected":"absent"}))
            .collect::<Vec<_>>();
        self.database
            .mutate(
                Self::context(),
                serde_json::from_value(
                    json!({"idempotency_key":key, "read_set":[], "operations":operations}),
                )
                .unwrap(),
            )
            .await
            .unwrap();
    }
    fn context() -> RequestContext {
        RequestContext {
            authorization: RequestAuthorization::service_identity(),
            principal: "person".into(),
            tenant: "tenant-a".into(),
            scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin]),
            request_id: "mcp-release-fixture".into(),
        }
    }
    fn issue(&self) -> IssuedCredential {
        self.credentials
            .create(
                CreateCredential {
                    family_id: Uuid::new_v4(),
                    principal: "person".into(),
                    tenant: "tenant-a".into(),
                    resource: CredentialResource::Database {
                        incarnation: Uuid::parse_str(
                            &self
                                .database
                                .engine()
                                .generation()
                                .unwrap()
                                .state
                                .incarnation,
                        )
                        .unwrap(),
                    },
                    scopes: BTreeSet::from([Action::Read, Action::Write]),
                    lifetime_seconds: DEFAULT_CREDENTIAL_LIFETIME_SECONDS,
                },
                "initializer",
            )
            .unwrap()
    }
    fn router(&self) -> Router {
        router(
            McpConfig::new("https://kasumi.example/mcp".into()).unwrap(),
            self.registry.clone(),
            self.auth.clone(),
        )
        .unwrap()
    }
    fn http_auth(&self) -> HttpAuth {
        HttpAuth {
            auth: self.auth.clone(),
            challenge: HeaderValue::from_static("Bearer"),
            origins: Vec::new(),
            release_gate: Arc::new(Mutex::new(None)),
        }
    }
    fn owned_response_router(&self, body: Body, mutation_dispatched: bool) -> Router {
        let body = Arc::new(Mutex::new(Some(body)));
        let database = self.database.clone();
        Router::new()
            .route(
                "/mcp",
                axum::routing::post(
                    move |axum::Extension(invocation): axum::Extension<Verified>| {
                        let body = body.lock().unwrap().take().unwrap();
                        let database = database.clone();
                        async move {
                            invocation
                                .retain_response_fence(
                                    database.owned_response_fence(&invocation.context).unwrap(),
                                )
                                .unwrap();
                            invocation
                                .mutation_dispatched
                                .store(mutation_dispatched, Ordering::Release);
                            Response::new(body)
                        }
                    },
                ),
            )
            .layer(middleware::from_fn_with_state(
                self.http_auth(),
                authenticate,
            ))
    }
    fn assert_one_denial(&self) {
        let events = self.audit.0.lock().unwrap();
        let denied = events
            .iter()
            .filter(|event| event.kind == RequestAuditKind::AccessDenied)
            .collect::<Vec<_>>();
        assert_eq!(denied.len(), 1);
        assert!(events.iter().any(
            |event| event.kind == RequestAuditKind::AuthenticationSucceeded
                && event.request_id == denied[0].request_id
        ));
    }
    async fn close(self) {
        self.database.shutdown().await.unwrap();
        self.security.shutdown().await.unwrap();
        self.node.drain_initializers().await.unwrap();
    }
}

fn request(token: &str, method: &str, params: Value) -> HttpRequest<Body> {
    let mut params = params;
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion":"2026-07-28",
        "io.modelcontextprotocol/clientInfo":{"name":"credential-release-tests","version":"1"},
        "io.modelcontextprotocol/clientCapabilities":{},
    });
    let mut request = HttpRequest::builder()
        .method("POST")
        .uri("/mcp")
        .header("host", "kasumi.example")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", method)
        .header("authorization", format!("Bearer {token}"));
    if let Some(name) = params.get("name").and_then(Value::as_str) {
        request = request.header("mcp-name", name);
    }
    request
        .body(Body::from(
            serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
                .unwrap(),
        ))
        .unwrap()
}
async fn decoded(response: Response) -> (StatusCode, Value) {
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), MAX_RESPONSE_BYTES)
        .await
        .unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

struct HeldBody {
    bytes: Option<Bytes>,
    entered: Arc<Notify>,
    waiting: oneshot::Receiver<()>,
}
impl hyper::body::Body for HeldBody {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        if self.bytes.is_none() {
            return Poll::Ready(None);
        }
        self.entered.notify_one();
        match Pin::new(&mut self.waiting).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(_) => Poll::Ready(self.bytes.take().map(|bytes| Ok(Frame::data(bytes)))),
        }
    }
    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.bytes.as_ref().map_or(0, |bytes| bytes.len() as u64))
    }
}

#[tokio::test]
async fn catalog_body_wait_rechecks_revoked_credential_before_http_release() {
    let fixture = Fixture::new().await;
    let issued = fixture.issue();
    let (parts, body) = request(&issued.token, "tools/list", json!({})).into_parts();
    let bytes = axum::body::to_bytes(body, MAX_REQUEST_BYTES).await.unwrap();
    let entered = Arc::new(Notify::new());
    let (release, waiting) = oneshot::channel();
    let request = HttpRequest::from_parts(
        parts,
        Body::new(HeldBody {
            bytes: Some(bytes),
            entered: entered.clone(),
            waiting,
        }),
    );
    let running = tokio::spawn(fixture.router().oneshot(request));
    tokio::time::timeout(Duration::from_secs(10), entered.notified())
        .await
        .unwrap();
    fixture
        .credentials
        .revoke(issued.family_id, "operator")
        .unwrap();
    release.send(()).unwrap();
    let (status, body) = decoded(running.await.unwrap().unwrap()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, json!({"error":"UNAUTHORIZED"}));
    fixture.assert_one_denial();
    fixture.close().await;
}

// Native cache capacity is independently retained by this same governor.
// Exclude only its exact provider charge from adapter allocation comparisons.
fn mcp_non_cache_reserved(fixture: &Fixture) -> u64 {
    let cache = fixture.node.cache_stats().unwrap();
    let cache_charge = cache
        .admitted_credit_bytes
        .checked_add(cache.provider_overhead_bytes)
        .unwrap();
    fixture
        .admission
        .snapshot()
        .reserved_bytes
        .checked_sub(cache_charge)
        .unwrap()
}

#[tokio::test]
async fn terminal_body_is_materialized_with_its_admission_before_credential_release() {
    let fixture = Fixture::new().await;
    let issued = fixture.issue();
    // This fixture captures authentication audit in memory; revocation writes
    // credential storage directly and dispatches no SecurityAudit job. Pause
    // only the real audit maintenance reader during this isolated census.
    let quiescent = fixture.security.quiescent_jobs_for_test().await;
    let baseline_ledger = fixture.admission.snapshot();
    assert_eq!(baseline_ledger.inflight_operations, 0);
    let baseline_cache = fixture.node.cache_stats().unwrap();
    let baseline = mcp_non_cache_reserved(&fixture);
    let entered = Arc::new(Notify::new());
    let (release, waiting) = oneshot::channel();
    let app = fixture.owned_response_router(
        Body::new(HeldBody {
            bytes: Some(Bytes::from_static(br#"{"result":"withheld plaintext"}"#)),
            entered: entered.clone(),
            waiting,
        }),
        false,
    );
    let running = tokio::spawn(app.oneshot(request(&issued.token, "tools/list", json!({}))));
    tokio::time::timeout(Duration::from_secs(10), entered.notified())
        .await
        .unwrap();
    let held_ledger = fixture.admission.snapshot();
    let held_cache = fixture.node.cache_stats().unwrap();
    assert_eq!(held_ledger.inflight_operations, 0);
    assert!(
        !running.is_finished(),
        "a lazy body escaped the final HTTP fence"
    );
    assert!(
        mcp_non_cache_reserved(&fixture) > baseline,
        "body materialization lost its response workspace reservation"
    );
    fixture
        .credentials
        .revoke(issued.family_id, "operator")
        .unwrap();
    release.send(()).unwrap();
    let (status, body) = decoded(running.await.unwrap().unwrap()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, json!({"error":"UNAUTHORIZED"}));
    eprintln!(
        "response-census terminal baseline={baseline_ledger:?} baseline_cache={baseline_cache:?} held={held_ledger:?} held_cache={held_cache:?} released={:?} released_cache={:?}",
        fixture.admission.snapshot(),
        fixture.node.cache_stats().unwrap()
    );
    assert_eq!(mcp_non_cache_reserved(&fixture), baseline);
    let released = fixture.admission.snapshot();
    assert_eq!(
        released.live_reservations,
        baseline_ledger.live_reservations
    );
    assert_eq!(released.inflight_operations, 0);
    fixture.assert_one_denial();
    drop(quiescent);
    fixture.close().await;
}

#[tokio::test]
async fn sdk_response_keeps_original_policy_epoch_until_http_release() {
    let fixture = Fixture::new().await;
    let issued = fixture.issue();
    let baseline = fixture.admission.snapshot().reserved_bytes;
    let gate = ReleaseGate::new();
    let mut pending_request = request(
        &issued.token,
        "tools/call",
        json!({
            "name":"kasumi_collections", "arguments":{},
        }),
    );
    pending_request.extensions_mut().insert(gate.clone());
    let running = tokio::spawn(fixture.router().oneshot(pending_request));
    gate.entered().await;
    assert!(fixture.admission.snapshot().reserved_bytes > baseline);
    fixture
        .database
        .administer(
            Fixture::context(),
            Operation::SetPolicy(Policy {
                grants: vec![Grant {
                    principal: "person".into(),
                    collection: None,
                    actions: BTreeSet::from([Action::Admin]),
                }],
                strict_read_audit: false,
            }),
        )
        .await
        .unwrap();
    gate.release.notify_one();
    let (status, body) = decoded(running.await.unwrap().unwrap()).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body, json!({"error":"CONFLICT"}));
    assert_eq!(fixture.admission.snapshot().reserved_bytes, baseline);
    fixture.close().await;
}

#[tokio::test]
async fn catalog_response_wait_preserves_original_expiry_after_family_renewal() {
    let fixture = Fixture::new().await;
    let issued = fixture.issue();
    assert_eq!(issued.expires_at_ms - fixture.clock.base_ms, 3_600_000);
    let gate = ReleaseGate::new();
    let mut pending_request = request(&issued.token, "tools/list", json!({}));
    pending_request.extensions_mut().insert(gate.clone());
    let running = tokio::spawn(fixture.router().oneshot(pending_request));
    gate.entered().await;
    fixture.clock.elapsed_ms.store(30_000, Ordering::SeqCst);
    let renewed = fixture
        .credentials
        .renew(
            &RenewCredential {
                family_id: issued.family_id,
                renewal_id: Uuid::new_v4(),
            },
            "person",
        )
        .unwrap();
    assert!(renewed.expires_at_ms > issued.expires_at_ms);
    fixture.clock.elapsed_ms.store(3_600_000, Ordering::SeqCst);
    let renewed_context = fixture
        .auth
        .authenticate(&format!("Bearer {}", renewed.token))
        .await
        .unwrap();
    renewed_context.authorization.check_live().unwrap();
    gate.release.notify_one();
    let (status, body) = decoded(running.await.unwrap().unwrap()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, json!({"error":"UNAUTHORIZED"}));
    fixture.assert_one_denial();
    let (status, body) = decoded(
        fixture
            .router()
            .oneshot(request(&renewed.token, "tools/list", json!({})))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body["result"]["tools"]
            .as_array()
            .is_some_and(|tools| !tools.is_empty())
    );
    fixture.close().await;
}

#[tokio::test]
async fn dispatched_mutation_response_wait_reports_unknown_outcome_after_revocation() {
    let fixture = Fixture::new().await;
    let issued = fixture.issue();
    let gate = ReleaseGate::new();
    let arguments = json!({
            "read_set":[], "idempotency_key":"original-mcp-mutation",
            "operations":[{"op":"put", "collection":"docs", "id":"one", "body":{"value":"retained"}, "expected":"absent"}],
    });
    let mut pending_request = request(
        &issued.token,
        "tools/call",
        json!({
            "name":"kasumi_mutate", "arguments":arguments,
        }),
    );
    pending_request.extensions_mut().insert(gate.clone());
    let running = tokio::spawn(fixture.router().oneshot(pending_request));
    gate.entered().await;
    let receipt = fixture
        .database
        .operation_receipt(&Fixture::context(), "original-mcp-mutation")
        .await
        .unwrap()
        .unwrap();
    assert!(receipt.outcome.is_ok());
    fixture
        .credentials
        .revoke(issued.family_id, "operator")
        .unwrap();
    gate.release.notify_one();
    let (status, body) = decoded(running.await.unwrap().unwrap()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body, json!({"error":"UNKNOWN_OUTCOME"}));
    fixture.assert_one_denial();
    let retained = fixture
        .database
        .operation_receipt(&Fixture::context(), "original-mcp-mutation")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::to_value(&receipt).unwrap(),
        serde_json::to_value(retained).unwrap()
    );
    assert_eq!(
        fixture
            .database
            .get(&Fixture::context(), "docs", "one")
            .await
            .unwrap()
            .expect("document exists")
            .body,
        json!({"value":"retained"})
    );
    // A fresh credential for the same principal/database resolves and retries
    // the original command identity; neither operation creates another write.
    let fresh = fixture.issue();
    let (status, body) = decoded(fixture.router().oneshot(request(&fresh.token, "tools/call", json!({
        "name":"kasumi_receipt", "arguments":{"idempotency_key":"original-mcp-mutation"},
    }))).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["result"]["structuredContent"],
        serde_json::to_value(&receipt).unwrap()
    );
    let (status, body) = decoded(
        fixture
            .router()
            .oneshot(request(
                &fresh.token,
                "tools/call",
                json!({
                    "name":"kasumi_mutate", "arguments":arguments,
                }),
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["result"]["structuredContent"],
        serde_json::to_value(receipt.outcome.unwrap()).unwrap()
    );
    fixture.close().await;
}

#[tokio::test]
async fn dispatched_mutation_response_keeps_original_deadline_after_family_renewal() {
    let fixture = Fixture::new().await;
    let issued = fixture.issue();
    assert_eq!(issued.expires_at_ms - fixture.clock.base_ms, 3_600_000);
    let gate = ReleaseGate::new();
    let arguments = json!({
        "read_set":[], "idempotency_key":"renewed-mcp-mutation",
        "operations":[{"op":"put", "collection":"docs", "id":"renewal", "body":{"value":"committed"}, "expected":"absent"}],
    });
    let mut pending_request = request(
        &issued.token,
        "tools/call",
        json!({"name":"kasumi_mutate", "arguments":arguments.clone()}),
    );
    pending_request.extensions_mut().insert(gate.clone());
    let running = tokio::spawn(fixture.router().oneshot(pending_request));
    gate.entered().await;
    let original = fixture
        .database
        .operation_receipt(&Fixture::context(), "renewed-mcp-mutation")
        .await
        .unwrap()
        .unwrap();
    assert!(original.outcome.is_ok());

    fixture.clock.elapsed_ms.store(30_000, Ordering::SeqCst);
    let renewed = fixture
        .credentials
        .renew(
            &RenewCredential {
                family_id: issued.family_id,
                renewal_id: Uuid::new_v4(),
            },
            "person",
        )
        .unwrap();
    assert!(renewed.expires_at_ms > issued.expires_at_ms);
    fixture.clock.elapsed_ms.store(3_600_000, Ordering::SeqCst);
    fixture
        .auth
        .authenticate(&format!("Bearer {}", renewed.token))
        .await
        .unwrap()
        .authorization
        .check_live()
        .unwrap();
    gate.release.notify_one();
    let (status, body) = decoded(running.await.unwrap().unwrap()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body, json!({"error":"UNKNOWN_OUTCOME"}));
    fixture.assert_one_denial();

    let (status, body) = decoded(
        fixture
            .router()
            .oneshot(request(
                &renewed.token,
                "tools/call",
                json!({
                    "name":"kasumi_receipt",
                    "arguments":{"idempotency_key":"renewed-mcp-mutation"},
                }),
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["result"]["structuredContent"],
        serde_json::to_value(&original).unwrap()
    );
    let (status, body) = decoded(
        fixture
            .router()
            .oneshot(request(
                &renewed.token,
                "tools/call",
                json!({"name":"kasumi_mutate", "arguments":arguments}),
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["result"]["structuredContent"],
        serde_json::to_value(original.outcome.unwrap()).unwrap()
    );
    fixture.close().await;
}

struct UnpolledStream(Option<u64>);
impl hyper::body::Body for UnpolledStream {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        panic!("unexpected streaming plaintext must never be handed to the transport")
    }
    fn size_hint(&self) -> SizeHint {
        self.0.map_or_else(SizeHint::default, SizeHint::with_exact)
    }
}

#[tokio::test]
async fn unexpected_streaming_response_is_rejected_before_body_handoff() {
    let fixture = Fixture::new().await;
    let issued = fixture.issue();
    let state = fixture.http_auth();
    for media_type in [
        None,
        Some("text/event-stream"),
        Some("Text/Event-Stream; charset=utf-8"),
    ] {
        let app = Router::new()
            .route(
                "/mcp",
                axum::routing::post(move || async move {
                    let mut response =
                        Response::new(Body::new(UnpolledStream(media_type.map(|_| 1))));
                    if let Some(media_type) = media_type {
                        response
                            .headers_mut()
                            .insert("content-type", HeaderValue::from_static(media_type));
                    }
                    response
                }),
            )
            .layer(middleware::from_fn_with_state(state.clone(), authenticate));
        let (status, body) = decoded(
            app.oneshot(request(&issued.token, "tools/list", json!({})))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body, json!({"error":"UNAVAILABLE"}));
    }
    // Empty/protocol error responses still use their original status and body.
    let app = Router::new()
        .route(
            "/mcp",
            axum::routing::post(|| async { StatusCode::ACCEPTED }),
        )
        .layer(middleware::from_fn_with_state(state, authenticate));
    let response = app
        .oneshot(request(&issued.token, "tools/list", json!({})))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert!(
        axum::body::to_bytes(response.into_body(), 1)
            .await
            .unwrap()
            .is_empty()
    );
    fixture.close().await;
}

struct DeclaredBody {
    declared: u64,
    frame: Option<std::result::Result<Frame<Bytes>, std::io::Error>>,
}
impl hyper::body::Body for DeclaredBody {
    type Data = Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Bytes>, Self::Error>>> {
        Poll::Ready(self.frame.take())
    }
    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.declared)
    }
}

#[tokio::test]
async fn terminal_body_limits_errors_and_length_mismatches_are_enforced_before_release() {
    let fixture = Fixture::new().await;
    let issued = fixture.issue();
    let baseline = fixture.admission.snapshot().reserved_bytes;
    for (body, code) in [
        (
            DeclaredBody {
                declared: 1,
                frame: Some(Ok(Frame::data(Bytes::from(vec![
                    b'x';
                    MAX_RESPONSE_BYTES + 1
                ])))),
            },
            "RESOURCE_EXHAUSTED",
        ),
        (
            DeclaredBody {
                declared: 1,
                frame: Some(Ok(Frame::data(Bytes::from_static(b"{}")))),
            },
            "UNAVAILABLE",
        ),
        (
            DeclaredBody {
                declared: 1,
                frame: Some(Err(std::io::Error::other("injected response body failure"))),
            },
            "UNAVAILABLE",
        ),
    ] {
        let response = fixture
            .owned_response_router(Body::new(body), false)
            .oneshot(request(&issued.token, "tools/list", json!({})))
            .await
            .unwrap();
        let (status, body) = decoded(response).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body, json!({"error":code}));
        assert_eq!(fixture.admission.snapshot().reserved_bytes, baseline);
    }
    // Refuse an oversized declared body without polling/allocating it.
    let response = fixture
        .owned_response_router(
            Body::new(UnpolledStream(Some(MAX_RESPONSE_BYTES as u64 + 1))),
            false,
        )
        .oneshot(request(&issued.token, "tools/list", json!({})))
        .await
        .unwrap();
    assert_eq!(
        decoded(response).await,
        (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"RESOURCE_EXHAUSTED"})
        )
    );
    // Once a mutation is dispatched, even body failure must retain uncertainty.
    let response = fixture
        .owned_response_router(
            Body::new(DeclaredBody {
                declared: 1,
                frame: Some(Err(std::io::Error::other("injected response body failure"))),
            }),
            true,
        )
        .oneshot(request(&issued.token, "tools/list", json!({})))
        .await
        .unwrap();
    assert_eq!(
        decoded(response).await,
        (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"UNKNOWN_OUTCOME"})
        )
    );
    assert_eq!(fixture.admission.snapshot().reserved_bytes, baseline);
    fixture.close().await;
}

#[tokio::test]
async fn terminal_content_length_must_match_body_before_release() {
    const ONE: &[&str] = &["1"];
    const TWO: &[&str] = &["2"];
    const DUPLICATE: &[&str] = &["2", "2"];
    let fixture = Fixture::new().await;
    let issued = fixture.issue();
    for (lengths, dispatched, expected_status, expected_body) in [
        (
            ONE,
            false,
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"UNAVAILABLE"}),
        ),
        (
            DUPLICATE,
            false,
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"UNAVAILABLE"}),
        ),
        (
            ONE,
            true,
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"UNKNOWN_OUTCOME"}),
        ),
        (TWO, false, StatusCode::OK, json!({})),
    ] {
        let app = Router::new()
            .route(
                "/mcp",
                axum::routing::post(
                    move |axum::Extension(invocation): axum::Extension<Verified>| async move {
                        invocation
                            .mutation_dispatched
                            .store(dispatched, Ordering::Release);
                        let mut response = Response::new(Body::from("{}"));
                        for value in lengths {
                            response
                                .headers_mut()
                                .append(CONTENT_LENGTH, HeaderValue::from_static(value));
                        }
                        response
                    },
                ),
            )
            .layer(middleware::from_fn_with_state(
                fixture.http_auth(),
                authenticate,
            ));
        let (status, body) = decoded(
            app.oneshot(request(&issued.token, "tools/list", json!({})))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, expected_status);
        assert_eq!(body, expected_body);
    }
    fixture.close().await;
}

#[tokio::test]
async fn sdk_terminal_transport_failure_preserves_dispatched_mutation_uncertainty() {
    let fixture = Fixture::new().await;
    let issued = fixture.issue();
    for dispatched in [false, true] {
        for failure in [
            TerminalTransportFailure::Cancelled,
            TerminalTransportFailure::UnsupportedPeerTraffic,
        ] {
            let app = Router::new()
                .route(
                    "/mcp",
                    axum::routing::post(
                        move |axum::Extension(invocation): axum::Extension<Verified>| async move {
                            invocation
                                .mutation_dispatched
                                .store(dispatched, Ordering::Release);
                            let mut response =
                                Json(json!({"must_not_escape":"SDK transport rejection"}))
                                    .into_response();
                            response.extensions_mut().insert(failure);
                            response
                        },
                    ),
                )
                .layer(middleware::from_fn_with_state(
                    fixture.http_auth(),
                    authenticate,
                ));
            let (status, body) = decoded(
                app.oneshot(request(&issued.token, "tools/list", json!({})))
                    .await
                    .unwrap(),
            )
            .await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(
                body,
                json!({"error":if dispatched { "UNKNOWN_OUTCOME" } else { "UNAVAILABLE" }})
            );
        }
    }
    fixture.close().await;
}

#[tokio::test]
async fn small_integer_query_is_refused_before_its_value_tree_under_a_tight_budget() {
    let fixture = Fixture::new().await;
    let issued = fixture.issue();
    // Half a million integers: two bytes each as JSON, but a Value slot
    // and a heap text block each once decoded. Keep a thousand documents and
    // the full page while fitting the admitted source/page/tree overlap in
    // the unchanged 256 MiB fixture budget. Each document stays below the
    // 20,000-node validation limit.
    for batch in 0..4 {
        fixture
            .put(
                &format!("zeros-{batch}"),
                (0..250).map(|index| {
                    (
                        format!("zeros-{batch}-{index}"),
                        json!({"values":vec![0u8; 500]}),
                    )
                }),
            )
            .await;
    }
    let query = json!({"collection":"docs", "allow_scan":true, "limit":1000});
    let before_source = fixture.admission.snapshot().reserved_bytes;
    let direct = fixture
        .database
        .query(
            &Fixture::context(),
            serde_json::from_value(query.clone()).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(direct.rows.len(), 1000);
    let source_charge = fixture
        .admission
        .snapshot()
        .reserved_bytes
        .checked_sub(before_source)
        .expect("live source output adds its retained query charge");
    assert!(source_charge > 0);
    let encoded = encode_json(&direct).unwrap();
    drop(direct);
    assert_eq!(fixture.admission.snapshot().reserved_bytes, before_source);
    let tree = value_tree_bytes(&encoded).unwrap();
    assert!(tree > 24 * encoded.len() as u64);

    let baseline = fixture.admission.snapshot();
    let workspace = fixture.response_workspace();
    // Measure the actual immutable source charge, including full-result/page
    // overlap. Allow all claims before decoding, then miss only the decoded
    // tree by 1 MiB. This leaves ample room for its bounded error envelope.
    let pre_decode = [
        source_charge,
        workspace,
        response_owner::owner_bytes::<kasumi_engine::AdmittedOutput<kasumi_types::QueryResponse>>()
            .unwrap(),
        response_owner::allocation_bytes(encoded.len()).unwrap(),
    ]
    .into_iter()
    .try_fold(0u64, u64::checked_add)
    .expect("fixture pre-decode claims fit u64");
    let shortage = 1u64 << 20;
    assert!(tree > shortage);
    let through_decode = pre_decode
        .checked_add(tree)
        .expect("fixture complete decode charge fits u64");
    let headroom = through_decode.checked_sub(shortage).unwrap();
    assert!(headroom > pre_decode);
    assert!(headroom < through_decode);
    let filler = fixture.reserve_all_but(headroom);
    let call = || {
        request(
            &issued.token,
            "tools/call",
            json!({"name":"kasumi_query", "arguments":query}),
        )
    };
    let (status, body) = decoded(fixture.router().oneshot(call()).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["result"]["isError"], json!(true));
    assert_eq!(
        body["result"]["structuredContent"]["error"],
        json!({
            "code":"RESOURCE_EXHAUSTED",
            "message":"MCP tool result tree exceeds the response workspace budget",
        })
    );
    let refused = fixture.admission.snapshot();
    assert!(refused.reserved_bytes <= fixture.budget);
    assert_eq!(refused.reserved_bytes, fixture.budget - headroom);
    assert_eq!(refused.inflight_operations, baseline.inflight_operations);

    // The refusal is the tree charge alone: with the headroom back, the same
    // call releases the whole result and then returns every charge.
    drop(filler);
    let (status, body) = decoded(fixture.router().oneshot(call()).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["result"]["isError"], json!(false));
    assert_eq!(
        body["result"]["structuredContent"],
        decode_output(&encoded).unwrap()
    );
    let released = fixture.admission.snapshot();
    assert_eq!(released.reserved_bytes, baseline.reserved_bytes);
    assert_eq!(released.live_reservations, baseline.live_reservations);
    fixture.close().await;
}

#[tokio::test]
async fn refused_body_charge_after_dispatch_is_unknown_outcome_resolved_by_receipt() {
    let fixture = Fixture::new().await;
    let issued = fixture.issue();
    let baseline = fixture.admission.snapshot().reserved_bytes;
    let gate = ReleaseGate::new();
    let arguments = json!({
        "read_set":[], "idempotency_key":"uncharged-mcp-mutation",
        "operations":[{"op":"put", "collection":"docs", "id":"charged", "body":{"value":"committed once"}, "expected":"absent"}],
    });
    let mut pending_request = request(
        &issued.token,
        "tools/call",
        json!({"name":"kasumi_mutate", "arguments":arguments.clone()}),
    );
    pending_request
        .extensions_mut()
        .insert(BodyChargeGate(gate.clone()));
    let running = tokio::spawn(fixture.router().oneshot(pending_request));
    gate.entered().await;
    let receipt = fixture
        .database
        .operation_receipt(&Fixture::context(), "uncharged-mcp-mutation")
        .await
        .unwrap()
        .unwrap();
    assert!(receipt.outcome.is_ok());
    let committed = fixture
        .database
        .get(&Fixture::context(), "docs", "charged")
        .await
        .unwrap()
        .expect("document exists");
    assert_eq!(committed.body, json!({"value":"committed once"}));
    let committed_version = committed.version;
    // This direct observation is separately admitted; it must not become part
    // of the pending mutation response's exact pressure census.
    drop(committed);
    // The committed result tree is charged. Nothing is left for its body,
    // nor for a tool error body in its place.
    let held = fixture.admission.snapshot().reserved_bytes;
    assert!(held > baseline);
    let filler = fixture.reserve_all_but(0);
    gate.release();
    let (status, body) = decoded(running.await.unwrap().unwrap()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body, json!({"error":"UNKNOWN_OUTCOME"}));
    // The withheld response returned its fence charges; only the filler stays.
    assert_eq!(
        fixture.admission.snapshot().reserved_bytes,
        baseline + fixture.budget - held
    );
    drop(filler);
    assert_eq!(fixture.admission.snapshot().reserved_bytes, baseline);

    // The same credential resolves the original identity; a retry of the
    // identical batch returns the original outcome without a second write.
    let (status, body) = decoded(
        fixture
            .router()
            .oneshot(request(
                &issued.token,
                "tools/call",
                json!({
                    "name":"kasumi_receipt",
                    "arguments":{"idempotency_key":"uncharged-mcp-mutation"},
                }),
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["result"]["structuredContent"],
        serde_json::to_value(&receipt).unwrap()
    );
    let (status, body) = decoded(
        fixture
            .router()
            .oneshot(request(
                &issued.token,
                "tools/call",
                json!({"name":"kasumi_mutate", "arguments":arguments}),
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["result"]["structuredContent"],
        serde_json::to_value(receipt.outcome.unwrap()).unwrap()
    );
    let retained = fixture
        .database
        .get(&Fixture::context(), "docs", "charged")
        .await
        .unwrap()
        .expect("document exists");
    assert_eq!(retained.version, committed_version);
    assert_eq!(retained.body, json!({"value":"committed once"}));
    drop(retained);
    assert_eq!(fixture.admission.snapshot().reserved_bytes, baseline);
    fixture.close().await;
}

#[tokio::test]
async fn exact_response_charges_are_retained_until_http_release() {
    let fixture = Fixture::new().await;
    let issued = fixture.issue();
    fixture
        .put(
            "held-document",
            [("held".to_owned(), json!({"values":vec![7u8; 4096]}))],
        )
        .await;
    // Auth audit is captured and this non-strict get submits no SecurityAudit
    // job. Hold maintenance quiescent through the source quote and HTTP/body
    // disposal, then release the guard before shutting down the audit writer.
    let quiescent = fixture.security.quiescent_jobs_for_test().await;
    let baseline = fixture.admission.snapshot();
    assert_eq!(baseline.inflight_operations, 0);
    let baseline_bytes = mcp_non_cache_reserved(&fixture);
    let baseline_cache = fixture.node.cache_stats().unwrap();
    let document = fixture
        .database
        .get(&Fixture::context(), "docs", "held")
        .await
        .unwrap()
        .expect("document exists");
    let source_charge = mcp_non_cache_reserved(&fixture)
        .checked_sub(baseline_bytes)
        .unwrap();
    assert!(source_charge > 0);
    assert_eq!(
        fixture.admission.snapshot().live_reservations,
        baseline.live_reservations + 1
    );
    assert_eq!(fixture.admission.snapshot().inflight_operations, 0);
    let expected_document = serde_json::to_value(document.as_ref()).unwrap();
    let source_json = encode_json(document.as_ref()).unwrap();
    let tree = value_tree_bytes(&source_json).unwrap();
    let source_buffer = response_owner::allocation_bytes(source_json.len()).unwrap();
    let source_owner =
        response_owner::owner_bytes::<kasumi_engine::AdmittedOutput<kasumi_types::Document>>()
            .unwrap();
    drop(document);
    assert_eq!(mcp_non_cache_reserved(&fixture), baseline_bytes);
    assert_eq!(
        fixture.admission.snapshot().live_reservations,
        baseline.live_reservations
    );
    let workspace = fixture.response_workspace();
    let gate = ReleaseGate::new();
    let mut pending_request = request(
        &issued.token,
        "tools/call",
        json!({"name":"kasumi_get", "arguments":{"collection":"docs", "id":"held"}}),
    );
    pending_request.extensions_mut().insert(gate.clone());
    let running = tokio::spawn(fixture.router().oneshot(pending_request));
    gate.entered().await;
    let held = fixture.admission.snapshot();
    let held_bytes = mcp_non_cache_reserved(&fixture);
    let held_cache = fixture.node.cache_stats().unwrap();
    gate.release();
    let response = running.await.unwrap().unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let delivered_cache = fixture.node.cache_stats().unwrap();
    let body = axum::body::to_bytes(response.into_body(), MAX_RESPONSE_BYTES)
        .await
        .unwrap();
    let decoded: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(decoded["result"]["structuredContent"], expected_document);
    eprintln!(
        "response-census exact baseline={baseline:?} baseline_cache={baseline_cache:?} held={held:?} held_cache={held_cache:?} delivered={:?} delivered_cache={:?} workspace={workspace} source_charge={source_charge} source_owner={source_owner} source_buffer={source_buffer} tree={tree} sdk_body={} terminal_body={}",
        fixture.admission.snapshot(),
        fixture.node.cache_stats().unwrap(),
        encoded_body_bytes(body.len()),
        materialization_bytes(body.len()).unwrap()
    );
    // The point source has its own retained reservation. The adapter's second
    // entry owns the source wrapper, JSON buffer, decoded tree, SDK envelope
    // and terminal materialized body/owner through the final emitted bytes.
    let expected_charge = [
        source_charge,
        source_owner,
        workspace,
        source_buffer,
        tree,
        encoded_body_bytes(body.len()),
        materialization_bytes(body.len()).unwrap(),
    ]
    .into_iter()
    .try_fold(0u64, u64::checked_add)
    .unwrap();
    assert_eq!(
        held_bytes.checked_sub(baseline_bytes).unwrap(),
        expected_charge
    );
    assert_eq!(held.live_reservations, baseline.live_reservations + 2);
    assert_eq!(held.inflight_operations, baseline.inflight_operations);
    assert_eq!(mcp_non_cache_reserved(&fixture), held_bytes);
    assert_eq!(
        fixture.admission.snapshot().live_reservations,
        held.live_reservations
    );
    assert_eq!(fixture.node.cache_stats().unwrap(), delivered_cache);
    drop(body);
    let released = fixture.admission.snapshot();
    eprintln!(
        "response-census exact-final released={released:?} released_cache={:?}",
        fixture.node.cache_stats().unwrap()
    );
    assert_eq!(mcp_non_cache_reserved(&fixture), baseline_bytes);
    assert_eq!(fixture.node.cache_stats().unwrap(), delivered_cache);
    assert_eq!(
        released.live_reservations,
        held.live_reservations.checked_sub(2).unwrap()
    );
    assert_eq!(released.inflight_operations, 0);
    assert_eq!(released.live_reservations, baseline.live_reservations);
    drop(quiescent);
    fixture.close().await;
}
