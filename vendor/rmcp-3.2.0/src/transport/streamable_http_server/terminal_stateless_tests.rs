use super::*;
use crate::model::{CustomRequest, ListToolsResult, PaginatedRequestParams, ServerRequest};
use futures::{FutureExt, executor::block_on};
use serde_json::{Value, json};
use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Clone, Copy)]
enum Behavior {
    Complete,
    CancelComplete,
    Hold,
    Panic,
    Notify,
    Request,
    QueuedNotification,
}
#[derive(Default)]
struct Observed {
    entered: AtomicUsize,
    dropped: AtomicUsize,
    cancellation: Mutex<Option<CancellationToken>>,
}
struct HandlerGuard(Arc<Observed>);
impl Drop for HandlerGuard {
    fn drop(&mut self) {
        self.0.dropped.fetch_add(1, Ordering::SeqCst);
    }
}
#[derive(Clone)]
struct Handler {
    behavior: Behavior,
    observed: Arc<Observed>,
}
#[derive(Clone)]
struct Identity(&'static str);
impl crate::ServerHandler for Handler {
    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Borrowed(&[ProtocolVersion::V_2026_07_28])
    }
    async fn list_tools(
        &self,
        _: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let _guard = HandlerGuard(self.observed.clone());
        self.observed.entered.fetch_add(1, Ordering::SeqCst);
        *self.observed.cancellation.lock().unwrap() = Some(context.ct.clone());
        assert_eq!(context.id, RequestId::String("original-id".into()));
        assert_eq!(
            context.protocol_version(),
            Some(ProtocolVersion::V_2026_07_28)
        );
        assert_eq!(context.client_info().unwrap().name, "inline-client");
        assert_eq!(
            context
                .extensions
                .get::<http::request::Parts>()
                .unwrap()
                .extensions
                .get::<Identity>()
                .unwrap()
                .0,
            "verified-principal"
        );
        assert!(crate::service::in_request_handler_scope());
        match self.behavior {
            Behavior::Complete => {}
            Behavior::CancelComplete => context.ct.cancel(),
            Behavior::Hold => std::future::pending::<()>().await,
            Behavior::Panic => panic!("actual terminal handler panic"),
            Behavior::Notify => {
                let _ = context.peer.notify_tool_list_changed().await;
            }
            Behavior::Request => {
                let _ = context
                    .peer
                    .send_request(ServerRequest::CustomRequest(CustomRequest::new(
                        "unsupported/request",
                        None,
                    )))
                    .await;
            }
            Behavior::QueuedNotification => {
                context.peer.try_cancel_request(RequestId::Number(99), None)
            }
        }
        Ok(ListToolsResult::default())
    }
}
fn config() -> StreamableHttpServerConfig {
    StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_json_response(true)
        .with_stateless_protocol_metadata_required(true)
        .with_allowed_hosts(["kasumi.example"])
        .with_allowed_origins(["https://client.example"])
        .with_max_request_body_bytes(4096)
}
fn service(
    behavior: Behavior,
) -> (
    StreamableHttpService<Handler, NeverSessionManager>,
    Arc<Observed>,
) {
    let observed = Arc::new(Observed::default());
    let handler = Handler {
        behavior,
        observed: observed.clone(),
    };
    (
        StreamableHttpService::new_terminal_stateless(move || Ok(handler.clone()), config())
            .unwrap(),
        observed,
    )
}
fn message() -> Value {
    json!({"jsonrpc":"2.0", "id":"original-id", "method":"tools/list", "params":{"_meta":{
        "io.modelcontextprotocol/protocolVersion":"2026-07-28",
        "io.modelcontextprotocol/clientInfo":{"name":"inline-client", "version":"1"},
        "io.modelcontextprotocol/clientCapabilities":{},
    }}})
}
fn request(message: Value) -> Request<Full<Bytes>> {
    let mut request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("host", "kasumi.example")
        .header("origin", "https://client.example")
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/list")
        .body(Full::new(Bytes::from(
            serde_json::to_vec(&message).unwrap(),
        )))
        .unwrap();
    request
        .extensions_mut()
        .insert(Identity("verified-principal"));
    request
}
fn decode(response: BoxResponse) -> Value {
    serde_json::from_slice(&block_on(response.into_body().collect()).unwrap().to_bytes()).unwrap()
}

#[test]
fn terminal_stateless_runs_without_any_tokio_runtime_and_preserves_context() {
    // Any SDK tokio::spawn path would panic: there is deliberately no runtime.
    let (service, observed) = service(Behavior::Complete);
    let response = block_on(service.handle(request(message())));
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "application/json");
    assert_eq!(decode(response)["id"], "original-id");
    assert_eq!(observed.entered.load(Ordering::SeqCst), 1);
    assert_eq!(observed.dropped.load(Ordering::SeqCst), 1);
}

#[test]
fn dropping_http_future_drops_actual_handler_and_cancels_its_context() {
    let (service, observed) = service(Behavior::Hold);
    let mut request = Box::pin(service.handle(request(message())));
    assert!(
        request
            .as_mut()
            .poll(&mut Context::from_waker(std::task::Waker::noop()))
            .is_pending()
    );
    assert_eq!(observed.entered.load(Ordering::SeqCst), 1);
    assert_eq!(observed.dropped.load(Ordering::SeqCst), 0);
    drop(request);
    assert_eq!(observed.dropped.load(Ordering::SeqCst), 1);
    assert!(
        observed
            .cancellation
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .is_cancelled()
    );
}

#[test]
fn serving_cancellation_withholds_response_and_drops_actual_handler() {
    let (service, observed) = service(Behavior::Hold);
    let mut pending = Box::pin(service.handle(request(message())));
    assert!(
        pending
            .as_mut()
            .poll(&mut Context::from_waker(std::task::Waker::noop()))
            .is_pending()
    );
    service.config.cancellation_token.cancel();
    let response = block_on(pending);
    assert_eq!(
        response.extensions().get::<TerminalTransportFailure>(),
        Some(&TerminalTransportFailure::Cancelled)
    );
    assert_eq!(observed.dropped.load(Ordering::SeqCst), 1);
}

#[test]
fn cancellation_in_the_handlers_final_poll_cannot_release_success() {
    let (service, observed) = service(Behavior::CancelComplete);
    let response = block_on(service.handle(request(message())));
    assert_eq!(
        response.extensions().get::<TerminalTransportFailure>(),
        Some(&TerminalTransportFailure::Cancelled)
    );
    assert_eq!(observed.dropped.load(Ordering::SeqCst), 1);
}

#[test]
fn handler_panic_reaches_actual_http_owner_without_detached_join_error() {
    let (service, observed) = service(Behavior::Panic);
    let outcome =
        block_on(std::panic::AssertUnwindSafe(service.handle(request(message()))).catch_unwind());
    assert!(outcome.is_err());
    assert_eq!(observed.dropped.load(Ordering::SeqCst), 1);
    assert!(
        observed
            .cancellation
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .is_cancelled()
    );
}

#[test]
fn outbound_requests_notifications_and_same_poll_enqueue_are_explicitly_rejected() {
    for behavior in [
        Behavior::Notify,
        Behavior::Request,
        Behavior::QueuedNotification,
    ] {
        let (service, observed) = service(behavior);
        let response = block_on(service.handle(request(message())));
        assert_eq!(response.status(), http::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.extensions().get::<TerminalTransportFailure>(),
            Some(&TerminalTransportFailure::UnsupportedPeerTraffic)
        );
        assert!(decode(response).get("error").is_some());
        assert_eq!(observed.dropped.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn terminal_constructor_and_config_mutation_cannot_enable_spawned_transport() {
    let handler = Handler {
        behavior: Behavior::Panic,
        observed: Arc::default(),
    };
    assert!(
        StreamableHttpService::new_terminal_stateless(
            move || Ok(handler.clone()),
            StreamableHttpServerConfig::default()
        )
        .is_err()
    );
    for change in 0..6 {
        let (mut service, observed) = service(Behavior::Panic);
        match change {
            0 => service.config.legacy_session_mode = true,
            1 => service.config.json_response = false,
            2 => service.config.stateless_protocol_metadata_required = false,
            3 => service.config.allowed_hosts.clear(),
            4 => service.config.max_request_body_bytes = 0,
            _ => {
                service = service.clone();
                service.config.legacy_session_mode = true;
            }
        }
        let response = block_on(service.handle(request(message())));
        assert_eq!(
            response.extensions().get::<TerminalTransportFailure>(),
            Some(&TerminalTransportFailure::InvalidConfiguration)
        );
        assert_eq!(observed.entered.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn inherited_headers_origin_protocol_and_body_limits_reject_before_dispatch() {
    for change in 0..7 {
        let (service, observed) = service(Behavior::Panic);
        let mut body = message();
        if change == 5 {
            body["params"]["_meta"]
                .as_object_mut()
                .unwrap()
                .remove("io.modelcontextprotocol/clientCapabilities");
        }
        if change == 6 {
            body["padding"] = json!("x".repeat(4097));
        }
        let mut request = request(body);
        match change {
            0 => {
                request
                    .headers_mut()
                    .insert("host", "attacker.example".parse().unwrap());
            }
            1 => {
                request
                    .headers_mut()
                    .insert("origin", "https://attacker.example".parse().unwrap());
            }
            2 => {
                request
                    .headers_mut()
                    .insert("mcp-method", "tools/call".parse().unwrap());
            }
            3 => {
                request.headers_mut().remove("mcp-protocol-version");
            }
            4 => {
                request
                    .headers_mut()
                    .insert("content-type", "text/plain".parse().unwrap());
            }
            _ => {}
        }
        let response = block_on(service.handle(request));
        assert!(
            response.status().is_client_error(),
            "case {change}: {}",
            response.status()
        );
        assert_eq!(observed.entered.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn asynchronous_inbound_messages_are_rejected_instead_of_acknowledged_and_dropped() {
    for message in [
        json!({"jsonrpc":"2.0", "method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0", "id":4, "result":{}}),
        json!({"jsonrpc":"2.0", "id":4, "error":{"code":-32603,"message":"failure"}}),
    ] {
        let (service, observed) = service(Behavior::Panic);
        let mut request = request(message);
        request.headers_mut().remove("mcp-method");
        let response = block_on(service.handle(request));
        assert!(response.status().is_client_error());
        assert_eq!(observed.entered.load(Ordering::SeqCst), 0);
    }
}
