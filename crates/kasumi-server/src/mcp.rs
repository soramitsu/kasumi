//! MCP 2026-07-28 over the official Rust SDK's stateless HTTP transport.
#[cfg(test)]
use crate::api::encode_json;
use crate::{
    api::{DatabaseRegistry, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, response_owner},
    auth::Authenticator,
};
use axum::{
    Json, Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderValue, StatusCode, header::CONTENT_LENGTH},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use http_body_util::BodyExt;
use hyper::body::{Body as _, Bytes};
use kasumi_types::{
    Action, Error, ErrorCode, MutationBatch, QueryRequest, RequestContext, validate_name,
};
use rmcp::{
    RoleServer, ServerHandler,
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, ErrorData, Implementation,
        InitializeRequestParams, InitializeResult, JsonRpcResponse, JsonRpcVersion2_0,
        ListToolsResult, PaginatedRequestParams, ProtocolVersion, RequestId, ServerCapabilities,
        ServerInfo, Tool, ToolAnnotations,
    },
    service::RequestContext as McpRequestContext,
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, TerminalTransportFailure,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    borrow::Cow,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};

#[cfg(test)]
#[path = "mcp_credential_tests.rs"]
mod credential_tests;
#[cfg(test)]
pub(crate) use credential_tests::{BodyChargeGate, ReleaseGate};

#[cfg(test)]
fn release_gate_slot() -> Arc<Mutex<Option<Arc<ReleaseGate>>>> {
    Arc::new(Mutex::new(None))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpConfig {
    pub public_url: String,
    pub allowed_hosts: Vec<String>,
    /// Empty means browser-origin requests are forbidden, not unchecked.
    pub allowed_origins: Vec<String>,
    #[cfg(test)]
    #[serde(skip, default = "release_gate_slot")]
    pub(crate) release_gate: Arc<Mutex<Option<Arc<ReleaseGate>>>>,
}

impl McpConfig {
    pub fn new(public_url: String) -> anyhow::Result<Self> {
        let url = resource_url(&public_url)?;
        let authority = &url[url::Position::BeforeHost..url::Position::AfterPort];
        Ok(Self {
            public_url,
            allowed_hosts: vec![authority.to_owned()],
            allowed_origins: Vec::new(),
            #[cfg(test)]
            release_gate: release_gate_slot(),
        })
    }
    fn validate(&self) -> anyhow::Result<()> {
        resource_url(&self.public_url)?;
        anyhow::ensure!(
            !self.allowed_hosts.is_empty(),
            "MCP allowed_hosts must be explicit"
        );
        for host in &self.allowed_hosts {
            let authority: axum::http::uri::Authority = host.parse()?;
            anyhow::ensure!(
                !authority.host().is_empty() && !host.contains(['@', '*']),
                "invalid allowed Host"
            );
        }
        for origin in &self.allowed_origins {
            normalized_origin(origin)?;
        }
        Ok(())
    }
}

fn resource_url(text: &str) -> anyhow::Result<reqwest::Url> {
    let url = reqwest::Url::parse(text)?;
    anyhow::ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/mcp",
        "MCP public_url must be an HTTPS /mcp URL without credentials, query, or fragment"
    );
    Ok(url)
}
fn normalized_origin(text: &str) -> anyhow::Result<String> {
    let url = reqwest::Url::parse(text)?;
    anyhow::ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none(),
        "MCP browser origins must be HTTPS origins"
    );
    Ok(url.origin().ascii_serialization())
}

#[derive(Clone)]
struct Verified {
    context: RequestContext,
    mutation_dispatched: Arc<AtomicBool>,
    source_output: Arc<Mutex<Option<response_owner::ReplyOwner>>>,
    response_fence: Arc<Mutex<Option<kasumi_engine::ResponseFence<'static>>>>,
    // A tool reply that could not be charged. The HTTP boundary replaces the
    // SDK body with a fixed-size rejection carrying this error.
    withheld: Arc<Mutex<Option<Error>>>,
}
impl Verified {
    fn new(context: RequestContext) -> Self {
        Self {
            context,
            mutation_dispatched: Arc::new(AtomicBool::new(false)),
            source_output: Arc::new(Mutex::new(None)),
            response_fence: Arc::new(Mutex::new(None)),
            withheld: Arc::new(Mutex::new(None)),
        }
    }
    fn release_error(&self, error: Error) -> Error {
        if self.mutation_dispatched.load(Ordering::Acquire) {
            Error::new(
                ErrorCode::UnknownOutcome,
                "MCP mutation response was withheld; resolve or retry the same idempotency key",
            )
        } else {
            error
        }
    }
    fn retain_response_fence(
        &self,
        fence: kasumi_engine::ResponseFence<'static>,
    ) -> kasumi_types::Result<()> {
        let mut retained = self
            .response_fence
            .lock()
            .map_err(|_| Error::new(ErrorCode::Unavailable, "MCP request ownership unavailable"))?;
        if retained.is_some() {
            return Err(Error::new(
                ErrorCode::Unavailable,
                "MCP request already owns a response",
            ));
        }
        *retained = Some(fence);
        Ok(())
    }
    fn take_response_fence(
        &self,
    ) -> kasumi_types::Result<Option<kasumi_engine::ResponseFence<'static>>> {
        let mut retained = self
            .response_fence
            .lock()
            .map_err(|_| Error::new(ErrorCode::Unavailable, "MCP request ownership unavailable"))?;
        Ok(retained.take())
    }
    fn has_response_fence(&self) -> kasumi_types::Result<bool> {
        let retained = self
            .response_fence
            .lock()
            .map_err(|_| Error::new(ErrorCode::Unavailable, "MCP request ownership unavailable"))?;
        Ok(retained.is_some())
    }
    /// Charge response materialization to the retained database fence before
    /// allocating it. The charge lasts until HTTP release drops the fence.
    fn retain_response_bytes(
        &self,
        bytes: u64,
        exhausted: &'static str,
    ) -> kasumi_types::Result<()> {
        let mut retained = self
            .response_fence
            .lock()
            .map_err(|_| Error::new(ErrorCode::Unavailable, "MCP request ownership unavailable"))?;
        let fence = retained.as_mut().ok_or_else(|| {
            Error::new(ErrorCode::Unavailable, "MCP response workspace unavailable")
        })?;
        fence.retain_response_bytes(bytes).map_err(|error| {
            if error.code == ErrorCode::ResourceExhausted {
                Error::new(ErrorCode::ResourceExhausted, exhausted)
            } else {
                error
            }
        })
    }
    fn retain_output<T: Send + Sync + 'static>(
        &self,
        value: kasumi_engine::AdmittedOutput<T>,
    ) -> kasumi_types::Result<Arc<kasumi_engine::AdmittedOutput<T>>> {
        self.retain_response_bytes(
            response_owner::owner_bytes::<kasumi_engine::AdmittedOutput<T>>()?,
            "MCP source output owner exceeds response workspace",
        )?;
        let mut retained = self
            .source_output
            .lock()
            .map_err(|_| Error::new(ErrorCode::Unavailable, "MCP source ownership unavailable"))?;
        if retained.is_some() {
            return Err(Error::new(
                ErrorCode::Unavailable,
                "MCP source output already retained",
            ));
        }
        let value = Arc::new(value);
        *retained = Some(response_owner::ReplyOwner::new(value.clone()));
        Ok(value)
    }
    fn take_source_output(&self) -> kasumi_types::Result<Option<response_owner::ReplyOwner>> {
        Ok(self
            .source_output
            .lock()
            .map_err(|_| Error::new(ErrorCode::Unavailable, "MCP source ownership unavailable"))?
            .take())
    }
    fn encode_output(&self, value: &impl Serialize) -> kasumi_types::Result<Vec<u8>> {
        let mut retained = self.response_fence.lock().map_err(|_| {
            Error::new(ErrorCode::Unavailable, "MCP response workspace unavailable")
        })?;
        let fence = retained.as_mut().ok_or_else(|| {
            Error::new(ErrorCode::Unavailable, "MCP response workspace unavailable")
        })?;
        response_owner::encode_json(value, fence)
    }
    fn withhold(&self, error: Error) {
        // A poisoned slot still withholds; the boundary reports it unavailable.
        if let Ok(mut withheld) = self.withheld.lock() {
            *withheld = Some(error);
        }
    }
    fn take_withheld(&self) -> kasumi_types::Result<Option<Error>> {
        let mut withheld = self
            .withheld
            .lock()
            .map_err(|_| Error::new(ErrorCode::Unavailable, "MCP request ownership unavailable"))?;
        Ok(withheld.take())
    }
}
#[derive(Clone)]
struct HttpAuth {
    auth: Arc<Authenticator>,
    challenge: HeaderValue,
    origins: Vec<String>,
    #[cfg(test)]
    release_gate: Arc<Mutex<Option<Arc<ReleaseGate>>>>,
}

async fn authenticate(State(state): State<HttpAuth>, mut request: Request, next: Next) -> Response {
    let origins = request.headers().get_all("origin");
    let mut origins = origins.iter();
    if let Some(origin) = origins.next() {
        let valid = origin
            .to_str()
            .ok()
            .and_then(|value| normalized_origin(value).ok())
            .is_some_and(|value| state.origins.contains(&value));
        if origins.next().is_some() || !valid {
            state.auth.anonymous_denial().await;
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error":"invalid_origin"})),
            )
                .into_response();
        }
    }
    let values = request.headers().get_all("authorization");
    let mut values = values.iter();
    let authorization = values.next().and_then(|value| value.to_str().ok());
    let authorization = if values.next().is_some() {
        ""
    } else {
        authorization.unwrap_or("")
    };
    let context = state.auth.authenticate(authorization).await;
    match context {
        Ok(context) => {
            let invocation = Verified::new(context.clone());
            request.extensions_mut().insert(invocation.clone());
            #[cfg(test)]
            let gate = request
                .extensions()
                .get::<Arc<ReleaseGate>>()
                .cloned()
                .or_else(|| {
                    state
                        .release_gate
                        .lock()
                        .ok()
                        .and_then(|mut gate| gate.take())
                });
            let mut owned = MaterializedReply {
                response: next.run(request).await,
                bytes: Bytes::new(),
                source: None,
                fence: None,
            };
            owned.source = match invocation.take_source_output() {
                Ok(source) => source,
                Err(error) => return rejected(&state, invocation.release_error(error)),
            };
            owned.fence = match invocation.take_response_fence() {
                Ok(fence) => fence,
                Err(error) => return rejected(&state, invocation.release_error(error)),
            };
            match invocation.take_withheld() {
                Ok(None) => {}
                Ok(Some(error)) | Err(error) => {
                    return rejected(&state, invocation.release_error(error));
                }
            }
            if owned
                .response
                .extensions()
                .get::<TerminalTransportFailure>()
                .is_some()
            {
                return rejected(
                    &state,
                    invocation.release_error(Error::new(
                        ErrorCode::Unavailable,
                        "MCP terminal transport withheld the response",
                    )),
                );
            }
            if owned.response.status() == StatusCode::FORBIDDEN {
                let _ = state
                    .auth
                    .audit_result::<()>(
                        &context,
                        Err(Error::new(ErrorCode::Forbidden, "request access denied")),
                    )
                    .await;
            }
            // The SDK body may suspend even with an exact size hint. Own every
            // byte before the final fence, retaining the handler's original
            // policy epoch and admitted workspace across SDK serialization.
            let owned = match owned.materialize().await {
                Ok(owned) => owned,
                Err(error) => return rejected(&state, invocation.release_error(error)),
            };
            #[cfg(test)]
            if let Some(gate) = gate {
                gate.wait().await;
            }
            // Discovery and protocol errors have no database fence, but still
            // reuse the original credential deadline and live family guard.
            let release = match &owned.fence {
                Some(fence) => fence.check(),
                None => context.authorization.check_live(),
            };
            let release = state.auth.audit_result(&context, release).await;
            if let Err(error) = release {
                return rejected(&state, invocation.release_error(error));
            }
            match owned.into_response() {
                Ok(response) => response,
                Err(error) => rejected(&state, invocation.release_error(error)),
            }
        }
        Err(error) => rejected(&state, error),
    }
}

// The SDK body and its materialized copy must drop before the source and fence,
// including while the materialization future is cancelled or unwinds.
struct MaterializedReply {
    response: Response,
    bytes: Bytes,
    source: Option<response_owner::ReplyOwner>,
    fence: Option<kasumi_engine::ResponseFence<'static>>,
}
struct McpCustody {
    _source: Option<response_owner::ReplyOwner>,
    _fence: kasumi_engine::ResponseFence<'static>,
}
fn materialization_bytes(length: usize) -> kasumi_types::Result<u64> {
    response_owner::allocation_bytes(length)?
        .checked_add(response_owner::owner_bytes::<McpCustody>()?)
        .ok_or_else(|| {
            Error::new(
                ErrorCode::ResourceExhausted,
                "MCP output allocation overflow",
            )
        })
}
impl MaterializedReply {
    async fn materialize(mut self) -> kasumi_types::Result<Self> {
        let response = &self.response;
        // rmcp may fall back to SSE after an intermediate handler message. No
        // streaming response is supported, including one with a declared length.
        let streaming = response
            .headers()
            .get_all("content-type")
            .iter()
            .any(|value| {
                value.to_str().map_or(true, |value| {
                    value.split(';').next().is_some_and(|media_type| {
                        media_type.trim().eq_ignore_ascii_case("text/event-stream")
                    })
                })
            });
        let length = response.body().size_hint().exact();
        if streaming || length.is_none() {
            return Err(Error::new(
                ErrorCode::Unavailable,
                "MCP requires a terminal response before release",
            ));
        }
        if length.is_some_and(|length| length > MAX_RESPONSE_BYTES as u64) {
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                "MCP response exceeds byte limit",
            ));
        }
        // An explicit wire length is part of the terminal response. Reject a
        // conflicting or ambiguous value before the final credential check, since
        // HTTP framing could otherwise truncate a fully materialized body.
        let mut declared_lengths = response.headers().get_all(CONTENT_LENGTH).iter();
        if let Some(declared) = declared_lengths.next()
            && (declared_lengths.next().is_some()
                || declared
                    .to_str()
                    .ok()
                    .and_then(|value| value.parse::<u64>().ok())
                    != length)
        {
            return Err(Error::new(
                ErrorCode::Unavailable,
                "MCP terminal response content length conflicts with body",
            ));
        }
        let length = length.expect("checked terminal length") as usize;
        if let Some(fence) = &mut self.fence {
            fence.retain_response_bytes(materialization_bytes(length)?)?;
        }
        // A terminal body can still contain many frames. Copy into one pre-admitted
        // exact-capacity buffer instead of collecting an unbounded frame directory.
        let mut bytes = Vec::with_capacity(length);
        let mut body = std::mem::replace(self.response.body_mut(), Body::empty());
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|_| {
                Error::new(
                    ErrorCode::Unavailable,
                    "MCP terminal response could not be materialized",
                )
            })?;
            if let Ok(data) = frame.into_data() {
                if data.len() > MAX_RESPONSE_BYTES - bytes.len() {
                    return Err(Error::new(
                        ErrorCode::ResourceExhausted,
                        "MCP response exceeds byte limit",
                    ));
                }
                if data.len() > length - bytes.len() {
                    return Err(Error::new(
                        ErrorCode::Unavailable,
                        "MCP terminal response length changed during materialization",
                    ));
                }
                bytes.extend_from_slice(&data);
            }
        }
        if bytes.len() != length {
            return Err(Error::new(
                ErrorCode::Unavailable,
                "MCP terminal response length changed during materialization",
            ));
        }
        self.bytes = Bytes::from(bytes);
        Ok(self)
    }
    fn into_response(mut self) -> kasumi_types::Result<Response> {
        let bytes = std::mem::take(&mut self.bytes);
        let bytes = match self.fence.take() {
            Some(fence) => {
                let owner = response_owner::ReplyOwner::new(McpCustody {
                    _source: self.source.take(),
                    _fence: fence,
                });
                self.response.extensions_mut().insert(owner.clone());
                response_owner::owned_bytes(bytes, owner)
            }
            None if self.source.is_some() => {
                return Err(Error::new(
                    ErrorCode::Unavailable,
                    "MCP source output lost its response fence",
                ));
            }
            None => bytes,
        };
        *self.response.body_mut() = Body::from(bytes);
        Ok(self.response)
    }
}

fn rejected(state: &HttpAuth, error: Error) -> Response {
    let code = match error.code {
        ErrorCode::Unavailable
        | ErrorCode::AuditUnavailable
        | ErrorCode::UnknownOutcome
        | ErrorCode::ResourceExhausted
        | ErrorCode::Sealed => StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::Conflict => StatusCode::CONFLICT,
        ErrorCode::Forbidden => StatusCode::FORBIDDEN,
        _ => StatusCode::UNAUTHORIZED,
    };
    let mut response = (code, Json(json!({"error":error.code}))).into_response();
    response
        .headers_mut()
        .insert("www-authenticate", state.challenge.clone());
    response
        .headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
    response
}

/// Returns routes only. The runtime must serve this router through TLS 1.3.
pub fn router(
    config: McpConfig,
    registry: DatabaseRegistry,
    auth: Arc<Authenticator>,
) -> anyhow::Result<Router> {
    config.validate()?;
    let metadata = auth.protected_resource_metadata(&config.public_url);
    let resource = resource_url(&config.public_url)?;
    let metadata_url = format!(
        "{}/.well-known/oauth-protected-resource/mcp",
        resource.origin().ascii_serialization()
    );
    let state = HttpAuth {
        auth,
        challenge: HeaderValue::from_str(&format!("Bearer resource_metadata=\"{metadata_url}\""))?,
        origins: config
            .allowed_origins
            .iter()
            .map(|origin| normalized_origin(origin))
            .collect::<anyhow::Result<_>>()?,
        #[cfg(test)]
        release_gate: config.release_gate.clone(),
    };
    let sdk_config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_stateless_protocol_metadata_required(true)
        .with_json_response(true)
        .with_allowed_hosts(config.allowed_hosts)
        .with_allowed_origins(state.origins.clone())
        .with_max_request_body_bytes(MAX_REQUEST_BYTES);
    let handler_auth = state.auth.clone();
    let service = StreamableHttpService::new_terminal_stateless(
        move || {
            Ok(KasumiMcp {
                registry: registry.clone(),
                auth: handler_auth.clone(),
            })
        },
        sdk_config,
    )?;
    let protected = Router::new()
        .route_service("/mcp", service)
        .route_layer(middleware::from_fn_with_state(state, authenticate));
    let metadata_again = metadata.clone();
    Ok(protected
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            get(move || async move { Json(metadata) }),
        )
        .route(
            "/.well-known/oauth-protected-resource",
            get(move || async move { Json(metadata_again) }),
        ))
}

#[derive(Clone)]
struct KasumiMcp {
    registry: DatabaseRegistry,
    auth: Arc<Authenticator>,
}

fn verified(context: &McpRequestContext<RoleServer>) -> Result<Verified, ErrorData> {
    context
        .extensions
        .get::<axum::http::request::Parts>()
        .and_then(|parts| parts.extensions.get::<Verified>())
        .cloned()
        .ok_or_else(|| ErrorData::internal_error("verified request identity unavailable", None))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GetArguments {
    collection: String,
    id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptArguments {
    idempotency_key: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyArguments {}

fn arguments<T: serde::de::DeserializeOwned>(value: Value) -> kasumi_types::Result<T> {
    serde_json::from_value(value)
        .map_err(|_| Error::new(ErrorCode::InvalidArgument, "invalid tool arguments"))
}
fn output(invocation: &Verified, value: &impl Serialize) -> kasumi_types::Result<Value> {
    // Bound the structured data before constructing the final protocol envelope.
    let bytes = invocation.encode_output(value)?;
    // Small scalars take far more memory as a Value tree than as JSON text.
    // Charge the whole tree before decoding any of it.
    invocation.retain_response_bytes(
        value_tree_bytes(&bytes)?,
        "MCP tool result tree exceeds the response workspace budget",
    )?;
    decode_output(&bytes)
}
fn decode_output(bytes: &[u8]) -> kasumi_types::Result<Value> {
    serde_json::from_slice(bytes)
        .map_err(|_| Error::new(ErrorCode::Corruption, "tool result encoding failed"))
}

// Value tree charges are workspace estimates, not allocator accounting. Each
// heap block is rounded up to the allocation quantum and carries one more
// quantum for its header and small size-class slack.
const HEAP_QUANTUM: u64 = 16;
// serde_json refuses deeper nesting, so no decodable output exceeds it.
const MAX_TREE_DEPTH: usize = 128;
const VALUE_BYTES: u64 = std::mem::size_of::<Value>() as u64;
// std's B-tree nodes hold at most 11 entries and 12 edges beside a parent
// link and lengths. Every node except the root holds at least 5 entries.
const MAP_NODE_BYTES: u64 = (11 * (std::mem::size_of::<String>() + std::mem::size_of::<Value>())
    + 12 * std::mem::size_of::<usize>()
    + 16) as u64;

fn heap_block(bytes: u64) -> u64 {
    bytes
        .div_ceil(HEAP_QUANTUM)
        .saturating_add(1)
        .saturating_mul(HEAP_QUANTUM)
}

/// Upper bound of the memory `serde_json::from_slice::<Value>` holds while it
/// decodes `bytes`: the returned tree plus its transient parse buffers. This
/// is one allocation-free pass over already bounded output. Output it cannot
/// delimit fails like undecodable output; anything it accepts but serde_json
/// rejects is still refused by the decode that follows the charge.
fn value_tree_bytes(bytes: &[u8]) -> kasumi_types::Result<u64> {
    #[derive(Clone, Copy, PartialEq)]
    enum Next {
        Value,
        ValueOrClose,
        Key,
        KeyOrClose,
        Colon,
        CommaOrClose,
        End,
    }
    let malformed = || Error::new(ErrorCode::Corruption, "tool result encoding failed");
    // Each open container: (is an object, entries so far).
    let mut open = [(false, 0u64); MAX_TREE_DEPTH];
    let mut depth = 0;
    let mut next = Next::Value;
    // The root Value is returned inline; everything else is a heap block.
    let mut total = VALUE_BYTES;
    let mut longest_token = 0u64;
    let mut largest_array = 0u64;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if matches!(byte, b' ' | b'\t' | b'\n' | b'\r') {
            index += 1;
            continue;
        }
        let mut completed = false;
        match (next, byte) {
            (Next::ValueOrClose | Next::CommaOrClose, b']') if depth > 0 && !open[depth - 1].0 => {
                depth -= 1;
                let elements = open[depth].1;
                if elements > 0 {
                    // Vec::push grows from four slots by doubling.
                    let capacity = elements.next_power_of_two().max(4);
                    total = total.saturating_add(heap_block(capacity.saturating_mul(VALUE_BYTES)));
                    largest_array = largest_array.max(capacity);
                }
                index += 1;
                completed = true;
            }
            (Next::KeyOrClose | Next::CommaOrClose, b'}') if depth > 0 && open[depth - 1].0 => {
                depth -= 1;
                let entries = open[depth].1;
                if entries > 0 {
                    total = total.saturating_add(
                        (entries / 5 + 1).saturating_mul(heap_block(MAP_NODE_BYTES)),
                    );
                }
                index += 1;
                completed = true;
            }
            (Next::Value | Next::ValueOrClose, b'[' | b'{') => {
                if depth == MAX_TREE_DEPTH {
                    return Err(malformed());
                }
                let object = byte == b'{';
                open[depth] = (object, 0);
                depth += 1;
                next = if object {
                    Next::KeyOrClose
                } else {
                    Next::ValueOrClose
                };
                index += 1;
            }
            (Next::Value | Next::ValueOrClose | Next::Key | Next::KeyOrClose, b'"') => {
                let mut end = index + 1;
                loop {
                    match bytes.get(end) {
                        Some(b'"') => break,
                        Some(b'\\') => end += 2,
                        Some(_) => end += 1,
                        None => return Err(malformed()),
                    }
                }
                // Decoded text is never longer than its escaped form. An
                // empty String does not allocate.
                let length = (end - index - 1) as u64;
                if length > 0 {
                    total = total.saturating_add(heap_block(length));
                }
                longest_token = longest_token.max(length);
                index = end + 1;
                if matches!(next, Next::Key | Next::KeyOrClose) {
                    open[depth - 1].1 += 1;
                    next = Next::Colon;
                } else {
                    completed = true;
                }
            }
            (Next::Value | Next::ValueOrClose, b'-' | b'0'..=b'9') => {
                let end = bytes[index..]
                    .iter()
                    .position(|byte| {
                        !matches!(byte, b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E')
                    })
                    .map_or(bytes.len(), |length| index + length);
                // Arbitrary-precision numbers keep their text: integers as
                // exact digits, others in a doubling parse buffer of 16+ bytes.
                let length = (end - index) as u64;
                total = total.saturating_add(heap_block(length.saturating_mul(2).max(16)));
                longest_token = longest_token.max(length);
                index = end;
                completed = true;
            }
            (Next::Value | Next::ValueOrClose, b't' | b'f' | b'n') => {
                let literal: &[u8] = match byte {
                    b't' => b"true",
                    b'f' => b"false",
                    _ => b"null",
                };
                if !bytes[index..].starts_with(literal) {
                    return Err(malformed());
                }
                index += literal.len();
                completed = true;
            }
            (Next::Colon, b':') => {
                next = Next::Value;
                index += 1;
            }
            (Next::CommaOrClose, b',') => {
                next = if open[depth - 1].0 {
                    Next::Key
                } else {
                    Next::Value
                };
                index += 1;
            }
            _ => return Err(malformed()),
        }
        if completed {
            if depth == 0 {
                next = Next::End;
            } else {
                if !open[depth - 1].0 {
                    open[depth - 1].1 += 1;
                }
                next = Next::CommaOrClose;
            }
        }
    }
    if next != Next::End {
        return Err(malformed());
    }
    // One at a time during decoding: the escape scratch buffer, two number
    // parse buffers, and the buffer a growing array replaces.
    let transient = heap_block(longest_token.saturating_mul(2))
        .saturating_add(heap_block(longest_token.saturating_mul(2).max(16)).saturating_mul(2))
        .saturating_add(heap_block((largest_array / 2).saturating_mul(VALUE_BYTES)));
    Ok(total.saturating_add(transient))
}

/// rmcp encodes a counted envelope with `serde_json::to_vec`: a buffer that
/// starts at 128 bytes and doubles. Its final allocation stays below twice
/// the envelope, and the buffer replaced by its last growth below the envelope.
fn encoded_body_bytes(envelope: usize) -> u64 {
    heap_block((envelope as u64).saturating_mul(3).max(128))
}

// Count the exact JSON-RPC envelope, including escaped request IDs, without
// allocating a second output buffer. An inbound ID is already bounded by the
// HTTP request limit; a large ID reduces the available result budget. Returns
// the result with its exact encoded envelope length.
fn bounded_tool_result(
    value: Value,
    is_error: bool,
    id: &RequestId,
) -> kasumi_types::Result<(CallToolResult, usize)> {
    let mut result = if is_error {
        CallToolResult::error(Vec::new())
    } else {
        CallToolResult::success(Vec::new())
    };
    result.structured_content = Some(value);
    struct Counter {
        bytes: usize,
        exceeded: bool,
    }
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > MAX_RESPONSE_BYTES.saturating_sub(self.bytes) {
                self.exceeded = true;
                return Err(std::io::Error::other("MCP response exceeds byte limit"));
            }
            self.bytes += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter {
        bytes: 0,
        exceeded: false,
    };
    let response = JsonRpcResponse {
        jsonrpc: JsonRpcVersion2_0,
        id: id.clone(),
        result: &result,
    };
    if serde_json::to_writer(&mut counter, &response).is_err() {
        return Err(Error::new(
            if counter.exceeded {
                ErrorCode::ResourceExhausted
            } else {
                ErrorCode::Corruption
            },
            "MCP response cannot be encoded within its byte limit",
        ));
    }
    Ok((result, counter.bytes))
}

impl KasumiMcp {
    async fn execute(
        &self,
        db: &kasumi_engine::Database,
        name: &str,
        invocation: &Verified,
        args: Value,
    ) -> kasumi_types::Result<Value> {
        let context = invocation.context.clone();
        match name {
            "kasumi_collections" => {
                let _: EmptyArguments = arguments(args)?;
                output(invocation, &db.collections(&context).await?)
            }
            "kasumi_get" => {
                let args: GetArguments = arguments(args)?;
                validate_name(&args.collection)?;
                validate_name(&args.id)?;
                let result = invocation
                    .retain_output(db.get(&context, &args.collection, &args.id).await?)?;
                output(invocation, result.as_ref())
            }
            "kasumi_query" => {
                let args: QueryRequest = arguments(args)?;
                let result = invocation.retain_output(db.query(&context, args).await?)?;
                output(invocation, result.as_ref())
            }
            "kasumi_mutate" => {
                let args: MutationBatch = arguments(args)?;
                invocation
                    .mutation_dispatched
                    .store(true, Ordering::Release);
                output(invocation, &db.mutate(context, args).await?)
                    .map_err(|error| invocation.release_error(error))
            }
            "kasumi_receipt" => {
                let args: ReceiptArguments = arguments(args)?;
                validate_name(&args.idempotency_key)?;
                output(
                    invocation,
                    &db.operation_receipt(&context, &args.idempotency_key)
                        .await?,
                )
            }
            _ => Err(Error::new(ErrorCode::InvalidArgument, "unknown tool")),
        }
    }
}

impl ServerHandler for KasumiMcp {
    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Owned(vec![ProtocolVersion::V_2026_07_28])
    }
    async fn initialize(
        &self,
        _: InitializeRequestParams,
        _: McpRequestContext<RoleServer>,
    ) -> Result<InitializeResult, ErrorData> {
        Err(ErrorData::method_not_found::<
            rmcp::model::InitializeResultMethod,
        >())
    }
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_protocol_version(ProtocolVersion::V_2026_07_28)
            .with_server_info(Implementation::new("kasumi", env!("CARGO_PKG_VERSION")))
            .with_instructions("Use collection discovery, exact JSON queries, and atomic idempotent mutations. Identity and tenant are determined by the access token. Administration uses the separate native admin service.")
    }
    fn get_tool(&self, name: &str) -> Option<Tool> {
        tools().iter().find(|tool| tool.name == name).cloned()
    }
    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        context: McpRequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let context = verified(&context)?.context;
        if request.is_some_and(|request| request.cursor.is_some()) {
            return Err(ErrorData::invalid_params(
                "tool catalog has no pagination cursor",
                None,
            ));
        }
        let result = ListToolsResult {
            tools: tools()
                .iter()
                .filter(|tool| {
                    context.scopes.contains(&if matches!(
                        tool.name.as_ref(),
                        "kasumi_mutate" | "kasumi_receipt"
                    ) {
                        Action::Write
                    } else {
                        Action::Read
                    })
                })
                .cloned()
                .collect(),
            ..Default::default()
        };
        Ok(result)
    }
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: McpRequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        if self.get_tool(&request.name).is_none() {
            return Err(ErrorData::invalid_params("unknown tool", None));
        }
        let response_id = context.id.clone();
        let invocation = verified(&context)?;
        let identity = invocation.context.clone();
        let args = Value::Object(request.arguments.unwrap_or_default());
        #[cfg(test)]
        let body_charge_gate = context
            .extensions
            .get::<axum::http::request::Parts>()
            .and_then(|parts| parts.extensions.get::<BodyChargeGate>())
            .cloned();
        let result = async {
            let db = self
                .auth
                .audit_result(&identity, self.registry.database(&identity))
                .await?;
            let fence = self
                .auth
                .audit_result(&identity, db.owned_response_fence(&identity))
                .await?;
            invocation.retain_response_fence(fence)?;
            // Argument validation/encoding produce protocol or resource errors.
            // Request denials from the Database itself are already durable.
            let value = self.execute(&db, &request.name, &invocation, args).await?;
            // Current MCP supports structured output directly. A text copy
            // would escape large JSON again and can triple its wire size.
            let (result, envelope) = bounded_tool_result(value, false, &response_id)
                .map_err(|error| invocation.release_error(error))?;
            #[cfg(test)]
            if let Some(gate) = &body_charge_gate {
                gate.0.wait().await;
            }
            // The SDK encodes the counted envelope after this handler returns.
            invocation
                .retain_response_bytes(
                    encoded_body_bytes(envelope),
                    "MCP response body exceeds the response workspace budget",
                )
                .map_err(|error| invocation.release_error(error))?;
            Ok(result)
        }
        .await;
        // Preserve coverage for any adapter-originated execution rejection;
        // nested Database/fence denials carry a private audit-attempt marker.
        let result = self.auth.audit_result(&identity, result).await;
        Ok(match result {
            Ok(response) => response,
            Err(error) => {
                let leader_node_id = self.registry.leader_hint(&identity, &error);
                let (result, envelope) = bounded_tool_result(
                    json!({"error":error,"leader_node_id":leader_node_id}),
                    true,
                    &response_id,
                )
                .map_err(|_| ErrorData::internal_error("MCP error response exceeds limit", None))?;
                // Without a database fence, the request failed before database
                // admission: like an SDK protocol error, its reply is a bounded
                // error plus the request's own ID. Otherwise charge the body,
                // or withhold the reply behind a fixed-size HTTP rejection.
                let charged = invocation.has_response_fence().and_then(|fenced| {
                    if fenced {
                        invocation.retain_response_bytes(
                            encoded_body_bytes(envelope),
                            "MCP error body exceeds the response workspace budget",
                        )
                    } else {
                        Ok(())
                    }
                });
                if let Err(error) = charged {
                    invocation.withhold(error);
                    return Err(ErrorData::internal_error("MCP response withheld", None));
                }
                result
            }
        }
        .into())
    }
}

fn object(properties: Value, required: Value) -> Value {
    json!({"type":"object","properties":properties,"required":required,"additionalProperties":false})
}
fn tools() -> &'static Vec<Tool> {
    static TOOLS: OnceLock<Vec<Tool>> = OnceLock::new();
    TOOLS.get_or_init(|| {
        let name = json!({"type":"string","minLength":1,"maxLength":256});
        let pointer = json!({"type":"string","maxLength":1024,"description":"JSON Pointer; number fields use exact JSON numbers, decimal fields use decimal strings"});
        let scalar = json!({"type":["string","number","boolean","null"]});
        let predicate_ref = json!({"$ref":"#/$defs/predicate"});
        let mut alternatives = vec![object(json!({"op":{"const":"all"}}), json!(["op"]))];
        for op in ["eq","contains"] { alternatives.push(object(json!({"op":{"const":op},"field":pointer,"value":scalar}),json!(["op","field","value"]))); }
        alternatives.push(object(json!({"op":{"const":"in"},"field":pointer,"values":{"type":"array","items":scalar,"maxItems":256}}),json!(["op","field","values"])));
        alternatives.push(object(json!({"op":{"const":"compare"},"field":pointer,"comparison":{"enum":["lt","lte","gt","gte"]},"value":scalar}),json!(["op","field","comparison","value"])));
        alternatives.push(object(json!({"op":{"const":"exists"},"field":pointer,"exists":{"type":"boolean"}}),json!(["op","field","exists"])));
        for op in ["and","or"] { alternatives.push(object(json!({"op":{"const":op},"predicates":{"type":"array","items":predicate_ref,"maxItems":256}}),json!(["op","predicates"]))); }
        alternatives.push(object(json!({"op":{"const":"not"},"predicate":predicate_ref}),json!(["op","predicate"])));
        let sort = object(json!({"field":pointer,"direction":{"enum":["asc","desc"]}}),json!(["field","direction"]));
        let aggregate = object(json!({"alias":name,"function":{"enum":["count","sum","min","max","avg"]},"field":pointer,"scale":{"type":"integer","minimum":0,"maximum":1000}}),json!(["alias","function"]));
        let text = object(json!({"index":name,"query":{"type":"string","maxLength":4096},"mode":{"enum":["terms","phrase","prefix","fuzzy"]},"distance":{"type":"integer","minimum":0,"maximum":2,"default":1}}),json!(["index","query","mode"]));
        let mut query = object(json!({"collection":name,"filter":predicate_ref,"sort":{"type":"array","items":sort,"maxItems":8},"projection":{"type":"array","items":pointer,"maxItems":64},"aggregates":{"type":"array","items":aggregate,"maxItems":16},"group_by":{"type":"array","items":pointer,"maxItems":8},"text":text,"limit":{"type":"integer","minimum":1,"maximum":1000,"default":100},"cursor":{"type":"string"},"allow_scan":{"type":"boolean","default":false}}),json!(["collection"]));
        query["$defs"] = json!({"predicate":{"oneOf":alternatives}});
        let precondition = json!({"oneOf":[object(json!({"kind":{"enum":["any","absent"]}}),json!(["kind"])),object(json!({"kind":{"const":"version"},"version":{"type":"integer","minimum":0}}),json!(["kind","version"]))]});
        let put = object(json!({"op":{"const":"put"},"collection":name,"id":name,"body":{"type":"object"},"expected":precondition}),json!(["op","collection","id","body"]));
        let delete = object(json!({"op":{"const":"delete"},"collection":name,"id":name,"expected":precondition}),json!(["op","collection","id"]));
        let read_expected = json!({"oneOf":[object(json!({"kind":{"const":"absent"}}),json!(["kind"])),object(json!({"kind":{"const":"version"},"version":{"type":"integer","minimum":0}}),json!(["kind","version"]))]});
        let read_assertion = json!({"oneOf":[
            object(json!({"kind":{"const":"before"},"not_after_ms":{"type":"integer","minimum":0}}),json!(["kind","not_after_ms"])),
            object(json!({"kind":{"const":"not_before"},"not_before_ms":{"type":"integer","minimum":0}}),json!(["kind","not_before_ms"])),
            object(json!({"kind":{"const":"snapshot"},"incarnation":name,"policy_epoch":{"type":"integer","minimum":0},"schema_epoch":{"type":"integer","minimum":0}}),json!(["kind","incarnation","policy_epoch","schema_epoch"])),
            object(json!({"kind":{"const":"document"},"collection":name,"id":name,"expected":read_expected}),json!(["kind","collection","id","expected"])),
            object(json!({"kind":{"const":"collection"},"collection":name,"data_epoch":{"type":"integer","minimum":0}}),json!(["kind","collection","data_epoch"]))
        ]});
        let mutate = object(json!({"idempotency_key":name,"read_set":{"type":"array","maxItems":512,"items":read_assertion},"operations":{"type":"array","minItems":1,"maxItems":256,"items":{"oneOf":[put,delete]}}}),json!(["idempotency_key","read_set","operations"]));
        vec![
            make_tool("kasumi_collections","Discover authorized collection schemas and declared indexes.",object(json!({}),json!([])),true),
            make_tool("kasumi_get","Read one document by collection/id after a read barrier.",object(json!({"collection":name,"id":name}),json!(["collection","id"])),true),
            make_tool("kasumi_query","Query an immutable snapshot. Use declared typed JSON Pointer fields; averages require a scale. Continue pages with the same query and returned cursor.",query,true),
            make_tool("kasumi_mutate","Apply one atomic tenant batch with schema, CAS, uniqueness and quotas. Reuse the same idempotency key and identical batch after UNKNOWN_OUTCOME.",mutate,false),
            make_tool("kasumi_receipt","Resolve this principal's retained mutation receipt; null means no receipt is currently available.",object(json!({"idempotency_key":name}),json!(["idempotency_key"])),true),
        ]
    })
}
fn make_tool(
    name: &'static str,
    description: &'static str,
    schema: Value,
    read_only: bool,
) -> Tool {
    let mut tool = Tool::new(
        name,
        description,
        schema
            .as_object()
            .expect("tool schema is an object")
            .clone(),
    );
    let mut annotations = ToolAnnotations::default();
    annotations.read_only_hint = Some(read_only);
    annotations.destructive_hint = Some(!read_only);
    annotations.idempotent_hint = Some(true);
    annotations.open_world_hint = Some(false);
    tool.annotations = Some(annotations);
    tool
}

#[cfg(test)]
mod response_tests {
    use super::*;

    #[test]
    fn quoted_payload_stays_within_wire_limit_without_redundant_text_copy() {
        let rows:Vec<_>=(0..7).map(|id|json!({"id":id.to_string(),"version":1,"body":{"value":"\"".repeat((512<<10)-128)}})).collect();
        assert!(serde_json::to_vec(&rows[0]["body"]).unwrap().len() < 1 << 20);
        let exact: Value = serde_json::from_str("90071992547409931234567890").unwrap();
        let value = json!({"revision":1,"rows":rows,"aggregates":[{"exact":exact}],"cursor":null});
        assert!(serde_json::to_vec(&value).unwrap().len() < 8 << 20);
        let id = RequestId::Number(1);
        let old = CallToolResult::structured(value.clone());
        assert!(
            serde_json::to_vec(&JsonRpcResponse {
                jsonrpc: JsonRpcVersion2_0,
                id: id.clone(),
                result: old
            })
            .unwrap()
            .len()
                > MAX_RESPONSE_BYTES
        );
        let (result, envelope) = bounded_tool_result(value.clone(), false, &id).unwrap();
        assert!(result.content.is_empty());
        let bytes = serde_json::to_vec(&JsonRpcResponse {
            jsonrpc: JsonRpcVersion2_0,
            id,
            result,
        })
        .unwrap();
        assert_eq!(bytes.len(), envelope);
        assert!(bytes.len() <= MAX_RESPONSE_BYTES);
        let decoded: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded["result"]["structuredContent"], value);
        assert!(
            String::from_utf8(bytes)
                .unwrap()
                .contains("90071992547409931234567890")
        );
    }

    #[test]
    fn literal_marker_keys_survive_tool_output_and_typed_arguments() {
        let body = json!({
            "raw":{"$serde_json::private::RawValue":"not JSON"},
            "number":{"$serde_json::private::Number":"7"}
        });
        let document = kasumi_types::Document {
            id: "first".into(),
            version: 1,
            body: body.clone(),
        };
        let encoded = encode_json(&document).unwrap();
        assert!(value_tree_bytes(&encoded).unwrap() > encoded.len() as u64);
        let value = decode_output(&encoded).unwrap();
        assert_eq!(value["body"], body);
        let typed: kasumi_types::Document = arguments(value.clone()).unwrap();
        assert_eq!(typed, document);
        let (response, _) = bounded_tool_result(value, false, &RequestId::Number(1)).unwrap();
        let encoded = serde_json::to_vec(&response).unwrap();
        let observed: Value = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(observed["structuredContent"]["body"], body);
    }

    #[test]
    fn envelope_accounting_includes_large_request_ids_and_bounds_errors() {
        let id = RequestId::String(std::sync::Arc::from("i".repeat(MAX_REQUEST_BYTES - 128)));
        let value = json!({"value":"x".repeat((8<<20)-128)});
        assert_eq!(
            bounded_tool_result(value, false, &id).unwrap_err().code,
            ErrorCode::ResourceExhausted
        );
        let (result, envelope) = bounded_tool_result(
            json!({"error":{"code":"RESOURCE_EXHAUSTED","message":"bounded"}}),
            true,
            &id,
        )
        .unwrap();
        assert!(result.content.is_empty());
        assert_eq!(result.is_error, Some(true));
        let bytes = serde_json::to_vec(&JsonRpcResponse {
            jsonrpc: JsonRpcVersion2_0,
            id,
            result,
        })
        .unwrap();
        assert_eq!(bytes.len(), envelope);
        assert!(bytes.len() <= MAX_RESPONSE_BYTES);
        // The SDK body charge covers its doubling buffer and the one replaced.
        assert!(encoded_body_bytes(envelope) >= 3 * envelope as u64);
        assert!(encoded_body_bytes(0) >= 128);
    }

    #[test]
    fn value_tree_bound_charges_small_scalars_far_beyond_their_encoding() {
        let integers = encode_json(&vec![0u8; 1 << 20]).unwrap();
        let bound = value_tree_bytes(&integers).unwrap();
        // Every integer owns one Value slot and one heap text block.
        assert!(bound >= (1 << 20) * (VALUE_BYTES + HEAP_QUANTUM));
        assert!(bound > 32 * integers.len() as u64);
        // Each map entry lives in a B-tree node, not only in its text.
        let map = br#"{"a":1}"#;
        assert!(value_tree_bytes(map).unwrap() >= MAP_NODE_BYTES + VALUE_BYTES);
        // Empty containers and strings allocate nothing beyond the root.
        assert!(value_tree_bytes(br#"[]"#).unwrap() < value_tree_bytes(br#"[0]"#).unwrap());
        assert!(value_tree_bytes(br#""""#).unwrap() < value_tree_bytes(br#""a""#).unwrap());
    }

    #[test]
    fn value_tree_bound_accepts_decodable_output_and_rejects_malformed_output() {
        let nested = format!(
            "{}0{}",
            "[".repeat(MAX_TREE_DEPTH - 1),
            "]".repeat(MAX_TREE_DEPTH - 1)
        );
        for accepted in [
            "null",
            " true ",
            "false",
            "-0.5e+10",
            "90071992547409931234567890",
            r#""quoted \" \\ \u0041""#,
            r#"{"":{},"a":[],"b":[1,{"c":null}],"$serde_json::private::Number":"7"}"#,
            "[ 1 , [ 2 ] , { \"k\" : \"v\" } ]",
            nested.as_str(),
        ] {
            let bytes = accepted.as_bytes();
            serde_json::from_slice::<Value>(bytes).unwrap();
            assert!(
                value_tree_bytes(bytes).unwrap() >= VALUE_BYTES,
                "{accepted}"
            );
        }
        let too_deep = format!(
            "{}{}",
            "[".repeat(MAX_TREE_DEPTH + 1),
            "]".repeat(MAX_TREE_DEPTH + 1)
        );
        for rejected in [
            "",
            "[",
            "]",
            "[1,]",
            "[1 2]",
            r#"{"a"}"#,
            r#"{"a":1,}"#,
            r#"{1:2}"#,
            r#"{"a":1]"#,
            r#"["a"}"#,
            r#""unterminated"#,
            "tru",
            "nul",
            "1 2",
            "{} {}",
            too_deep.as_str(),
        ] {
            assert!(serde_json::from_slice::<Value>(rejected.as_bytes()).is_err());
            assert_eq!(
                value_tree_bytes(rejected.as_bytes()).unwrap_err().code,
                ErrorCode::Corruption,
                "{rejected}"
            );
        }
    }
}
