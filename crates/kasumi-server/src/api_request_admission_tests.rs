/// A request body that records whether it was read, sends `first` if given,
/// and then never finishes.
struct StalledBody {
    polled: Arc<std::sync::atomic::AtomicBool>,
    first: Option<axum::body::Bytes>,
}
impl StalledBody {
    fn body(first: Option<Vec<u8>>) -> (Body, Arc<std::sync::atomic::AtomicBool>) {
        let polled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let body = Body::new(Self {
            polled: polled.clone(),
            first: first.map(Into::into),
        });
        (body, polled)
    }
}
impl hyper::body::Body for StalledBody {
    type Data = axum::body::Bytes;
    type Error = std::convert::Infallible;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<std::result::Result<hyper::body::Frame<Self::Data>, Self::Error>>>
    {
        self.polled.store(true, std::sync::atomic::Ordering::SeqCst);
        match self.first.take() {
            Some(first) => std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(first)))),
            None => std::task::Poll::Pending,
        }
    }
}

fn admitted_native(fixture: &Fixture, read_timeout: std::time::Duration) -> Router {
    let admission = crate::request_admission::RequestAdmission::native(
        fixture.physical.admission.clone(),
        fixture.auth.clone(),
    )
    .with_read_timeout(read_timeout);
    tonic::service::Routes::new(fixture.data().service())
        .into_axum_router()
        .layer(axum::middleware::from_fn_with_state(
            admission,
            crate::request_admission::admit,
        ))
}

fn grpc_request(method: &str, token: Option<&str>, body: Body) -> HttpRequest<Body> {
    let mut request = HttpRequest::builder()
        .method("POST")
        .uri(format!("/kasumi.v1.KasumiData/{method}"))
        .version(axum::http::Version::HTTP_2)
        .header("content-type", "application/grpc")
        .header("te", "trailers");
    if let Some(token) = token {
        request = request.header("authorization", token);
    }
    request.body(body).unwrap()
}

/// The five-byte gRPC prefix of an uncompressed message of `bytes`.
fn grpc_prefix(bytes: u64) -> Vec<u8> {
    let mut prefix = vec![0];
    prefix.extend_from_slice(&u32::try_from(bytes).unwrap().to_be_bytes());
    prefix
}

fn grpc_code(response: &axum::response::Response) -> Option<Code> {
    response
        .headers()
        .get("grpc-status")
        .map(|code| Code::from_bytes(code.as_bytes()))
}

/// A fixture whose whole admission budget is below the charge of one
/// maximum request, so that request can never be admitted.
async fn small_budget_fixture() -> Fixture {
    let config = kasumi_engine::admission::AdmissionConfig::default();
    let bookkeeping =
        kasumi_engine::admission::NodeAdmission::required_bookkeeping_bytes(&config).unwrap();
    let budget = 200 << 20;
    assert!(crate::request_admission::quote(MAX_REQUEST_BYTES as u64) > budget);
    Fixture::new_with_admission(kasumi_engine::admission::AdmissionConfig {
        max_inflight_bytes: Some(bookkeeping + budget),
        ..config
    })
    .await
}

#[tokio::test]
async fn native_bearer_is_verified_before_any_body_byte_is_read() {
    let fixture = Fixture::new().await;
    let router = admitted_native(&fixture, std::time::Duration::from_secs(60));
    let (body, polled) = StalledBody::body(None);
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        router
            .clone()
            .oneshot(grpc_request("Get", Some("Bearer invalid"), body)),
    )
    .await
    .expect("an invalid bearer is refused without waiting for its body")
    .unwrap();
    assert_eq!(grpc_code(&response), Some(Code::Unauthenticated));
    assert!(!polled.load(std::sync::atomic::Ordering::SeqCst));
    // A verified bearer reaches its handler, which reuses the verified context.
    let token = fixture.token("person", "tenant-a", "kasumi:read");
    let (status, response) = grpc_post(
        &router,
        "Get",
        proto::GetRequest {
            collection: "docs".into(),
            id: "absent".into(),
        },
        &token,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        decode_grpc::<proto::GetResponse>(&response)
            .document
            .is_none()
    );
    fixture.close().await;
}

#[tokio::test]
async fn native_message_is_charged_from_its_prefix_before_its_body_arrives() {
    let fixture = Fixture::new().await;
    let admission = fixture.physical.admission.clone();
    let router = admitted_native(&fixture, std::time::Duration::from_secs(60));
    let token = fixture.token("person", "tenant-a", "kasumi:read kasumi:write");
    let baseline = admission.snapshot().reserved_bytes;
    // Only the prefix of a 1 MiB message arrives.
    let declared = 1 << 20;
    let charge = crate::request_admission::wire_quote(declared + 5);
    let (body, _) = StalledBody::body(Some(grpc_prefix(declared)));
    let pending = tokio::spawn(
        router
            .clone()
            .oneshot(grpc_request("Mutate", Some(&token), body)),
    );
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while admission.snapshot().reserved_bytes < baseline + charge {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("encoded storage is charged from the prefix before collecting the mutation");
    // A cancelled request releases its charge.
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while admission.snapshot().reserved_bytes >= baseline + charge {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the cancelled request's charge is released");
    fixture.close().await;
}

#[tokio::test]
async fn native_message_beyond_the_budget_is_refused_before_buffering() {
    let fixture = small_budget_fixture().await;
    let router = admitted_native(&fixture, std::time::Duration::from_secs(60));
    let token = fixture.token("person", "tenant-a", "kasumi:read kasumi:write");
    let baseline = fixture.physical.admission.snapshot().reserved_bytes;
    let (body, _) = StalledBody::body(Some(grpc_prefix(MAX_REQUEST_BYTES as u64)));
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        router
            .clone()
            .oneshot(grpc_request("Query", Some(&token), body)),
    )
    .await
    .expect("refused from its prefix, without waiting for the message")
    .unwrap();
    assert_eq!(grpc_code(&response), Some(Code::ResourceExhausted));
    drop(response);
    assert!(
        fixture.physical.admission.snapshot().reserved_bytes
            < baseline + crate::request_admission::quote(1 << 20)
    );
    // A request that fits is still served.
    let (status, response) = grpc_post(
        &router,
        "Get",
        proto::GetRequest {
            collection: "docs".into(),
            id: "absent".into(),
        },
        &token,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        decode_grpc::<proto::GetResponse>(&response)
            .document
            .is_none()
    );
    fixture.close().await;
}

#[tokio::test]
async fn native_mutation_admits_flat_strings_but_refuses_dense_trees_before_decoding() {
    let fixture = small_budget_fixture().await;
    let entered = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let handler_entered = entered.clone();
    let router = Router::new()
        .route(
            "/kasumi.v1.KasumiData/Mutate",
            axum::routing::post(move |body: Body| {
                let entered = handler_entered.clone();
                async move {
                    entered.store(true, std::sync::atomic::Ordering::SeqCst);
                    let bytes = axum::body::to_bytes(body, MAX_REQUEST_BYTES + 5)
                        .await
                        .unwrap();
                    let request = proto::MutateRequest::decode(&bytes[5..]).unwrap();
                    let batch: kasumi_types::MutationBatch =
                        decode_json(&request.batch_json).unwrap();
                    assert_eq!(batch.operations.len(), 1);
                    StatusCode::NO_CONTENT
                }
            }),
        )
        .layer(axum::middleware::from_fn_with_state(
            crate::request_admission::RequestAdmission::native(
                fixture.physical.admission.clone(),
                fixture.auth.clone(),
            ),
            crate::request_admission::admit,
        ));
    let token = fixture.token("person", "tenant-a", "kasumi:write");
    for (dense, body) in [
        (false, json!({"proof":"a".repeat(1 << 20)})),
        (true, json!({"values":vec![0u8; 1 << 19]})),
    ] {
        entered.store(false, std::sync::atomic::Ordering::SeqCst);
        let message = proto::MutateRequest {
            batch_json: serde_json::to_vec(&json!({
                "idempotency_key":"shape", "read_set":[],
                "operations":[{"op":"put", "collection":"docs", "id":"shape",
                    "body":body, "expected":"absent"}],
            }))
            .unwrap(),
        }
        .encode_to_vec();
        let mut framed = grpc_prefix(message.len() as u64);
        framed.extend_from_slice(&message);
        let response = router
            .clone()
            .oneshot(grpc_request("Mutate", Some(&token), Body::from(framed)))
            .await
            .unwrap();
        if dense {
            assert_eq!(grpc_code(&response), Some(Code::ResourceExhausted));
            assert!(!entered.load(std::sync::atomic::Ordering::SeqCst));
        } else {
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            assert!(entered.load(std::sync::atomic::Ordering::SeqCst));
        }
    }
    fixture.close().await;
}

#[tokio::test]
async fn stalled_native_body_fails_at_its_read_deadline() {
    let fixture = Fixture::new().await;
    let router = admitted_native(&fixture, std::time::Duration::from_millis(200));
    let token = fixture.token("person", "tenant-a", "kasumi:read kasumi:write");
    let (body, _) = StalledBody::body(Some(grpc_prefix(100)));
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        router.oneshot(grpc_request("Mutate", Some(&token), body)),
    )
    .await
    .expect("the read deadline ends a body that never finishes")
    .unwrap();
    assert_eq!(grpc_code(&response), Some(Code::Unavailable));
    assert!(
        response.headers()["grpc-message"]
            .to_str()
            .unwrap()
            .contains("deadline")
    );
    fixture.close().await;
}

#[tokio::test]
async fn mcp_body_is_charged_only_after_authentication_and_before_reading() {
    let fixture = small_budget_fixture().await;
    let router = routes(
        McpConfig::new("https://kasumi.example/mcp".into()).unwrap(),
        fixture.registry.clone(),
        fixture.auth.clone(),
        Some(fixture.physical.admission.clone()),
    )
    .unwrap();
    let token = fixture.token("person", "tenant-a", "kasumi:read kasumi:write");
    let declared = |token: Option<&str>| {
        let (body, polled) = StalledBody::body(None);
        let mut request = HttpRequest::builder()
            .method("POST")
            .uri("/mcp")
            .header("host", "kasumi.example")
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-method", "tools/list")
            .header("content-length", MAX_REQUEST_BYTES.to_string());
        if let Some(token) = token {
            request = request.header("authorization", token);
        }
        (request.body(body).unwrap(), polled)
    };
    let (anonymous, polled) = declared(None);
    let response = router.clone().oneshot(anonymous).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(!polled.load(std::sync::atomic::Ordering::SeqCst));
    let (oversized, polled) = declared(Some(&token));
    let response = router.clone().oneshot(oversized).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!polled.load(std::sync::atomic::Ordering::SeqCst));
    let body = axum::body::to_bytes(response.into_body(), 1 << 10)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap(),
        json!({"error":"RESOURCE_EXHAUSTED"})
    );
    // A request that fits is still served.
    let (status, _) = post(
        &router,
        Some(&token),
        mcp_body("tools/list", json!({})),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    fixture.close().await;
}
