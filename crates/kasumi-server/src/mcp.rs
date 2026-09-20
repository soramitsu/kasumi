//! MCP 2026-07-28 over the official Rust SDK's stateless HTTP transport.
use crate::{
    api::{DatabaseRegistry, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, encode_json},
    auth::Authenticator,
};
use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use hyper::body::Body as _;
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
        StreamableHttpServerConfig, StreamableHttpService, session::never::NeverSessionManager,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpConfig {
    pub public_url: String,
    pub allowed_hosts: Vec<String>,
    /// Empty means browser-origin requests are forbidden, not unchecked.
    pub allowed_origins: Vec<String>,
}

impl McpConfig {
    pub fn new(public_url: String) -> anyhow::Result<Self> {
        let url = resource_url(&public_url)?;
        let authority = &url[url::Position::BeforeHost..url::Position::AfterPort];
        Ok(Self {
            public_url,
            allowed_hosts: vec![authority.to_owned()],
            allowed_origins: Vec::new(),
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
    response_fence: Arc<Mutex<Option<kasumi_engine::ResponseFence<'static>>>>,
}
impl Verified {
    fn new(context: RequestContext) -> Self {
        Self {
            context,
            mutation_dispatched: Arc::new(AtomicBool::new(false)),
            response_fence: Arc::new(Mutex::new(None)),
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
}
#[derive(Clone)]
struct HttpAuth {
    auth: Arc<Authenticator>,
    challenge: HeaderValue,
    origins: Vec<String>,
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
                .get::<Arc<credential_tests::ReleaseGate>>()
                .cloned();
            let response = next.run(request).await;
            let fence = match invocation.take_response_fence() {
                Ok(fence) => fence,
                Err(error) => return rejected(&state, invocation.release_error(error)),
            };
            if response.status() == StatusCode::FORBIDDEN {
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
            let response = match materialize_response(response).await {
                Ok(response) => response,
                Err(error) => return rejected(&state, invocation.release_error(error)),
            };
            #[cfg(test)]
            if let Some(gate) = gate {
                gate.wait().await;
            }
            // Discovery and protocol errors have no database fence, but still
            // reuse the original credential deadline and live family guard.
            let release = match &fence {
                Some(fence) => fence.check(),
                None => context.authorization.check_live(),
            };
            let release = state.auth.audit_result(&context, release).await;
            if let Err(error) = release {
                return rejected(&state, invocation.release_error(error));
            }
            response
        }
        Err(error) => rejected(&state, error),
    }
}

async fn materialize_response(response: Response) -> kasumi_types::Result<Response> {
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
    let (parts, body) = response.into_parts();
    let bytes = to_bytes(body, MAX_RESPONSE_BYTES).await.map_err(|error| {
        use std::error::Error as _;
        let exceeded = error
            .source()
            .is_some_and(|source| source.is::<http_body_util::LengthLimitError>());
        Error::new(
            if exceeded {
                ErrorCode::ResourceExhausted
            } else {
                ErrorCode::Unavailable
            },
            "MCP terminal response could not be materialized",
        )
    })?;
    if length != Some(bytes.len() as u64) {
        return Err(Error::new(
            ErrorCode::Unavailable,
            "MCP terminal response length changed during materialization",
        ));
    }
    Ok(Response::from_parts(parts, Body::from(bytes)))
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
    };
    let sdk_config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_stateless_protocol_metadata_required(true)
        .with_json_response(true)
        .with_allowed_hosts(config.allowed_hosts)
        .with_allowed_origins(state.origins.clone())
        .with_max_request_body_bytes(MAX_REQUEST_BYTES);
    let handler_auth = state.auth.clone();
    let service = StreamableHttpService::new(
        move || {
            Ok(KasumiMcp {
                registry: registry.clone(),
                auth: handler_auth.clone(),
            })
        },
        Arc::new(NeverSessionManager::default()),
        sdk_config,
    );
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
fn output(value: &impl Serialize) -> kasumi_types::Result<Value> {
    // Bound the structured data before constructing the final protocol envelope.
    let bytes = encode_json(value)?;
    serde_json::from_slice(&bytes)
        .map_err(|_| Error::new(ErrorCode::Corruption, "tool result encoding failed"))
}

// Count the exact JSON-RPC envelope, including escaped request IDs, without
// allocating a second output buffer. An inbound ID is already bounded by the
// HTTP request limit; a large ID reduces the available result budget.
fn bounded_tool_result(
    value: Value,
    is_error: bool,
    id: &RequestId,
) -> kasumi_types::Result<CallToolResult> {
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
    Ok(result)
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
                output(&db.collections(&context).await?)
            }
            "kasumi_get" => {
                let args: GetArguments = arguments(args)?;
                validate_name(&args.collection)?;
                validate_name(&args.id)?;
                output(&db.get(&context, &args.collection, &args.id).await?)
            }
            "kasumi_query" => {
                let args: QueryRequest = arguments(args)?;
                output(&db.query(&context, args).await?)
            }
            "kasumi_mutate" => {
                let args: MutationBatch = arguments(args)?;
                invocation
                    .mutation_dispatched
                    .store(true, Ordering::Release);
                output(&db.mutate(context, args).await?)
                    .map_err(|error| invocation.release_error(error))
            }
            "kasumi_receipt" => {
                let args: ReceiptArguments = arguments(args)?;
                validate_name(&args.idempotency_key)?;
                output(
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
            bounded_tool_result(value, false, &response_id)
                .map_err(|error| invocation.release_error(error))
        }
        .await;
        // Preserve coverage for any adapter-originated execution rejection;
        // nested Database/fence denials carry a private audit-attempt marker.
        let result = self.auth.audit_result(&identity, result).await;
        Ok(match result {
            Ok(response) => response,
            Err(error) => {
                let leader_node_id = self.registry.leader_hint(&identity, &error);
                bounded_tool_result(
                    json!({"error":error,"leader_node_id":leader_node_id}),
                    true,
                    &response_id,
                )
                .map_err(|_| ErrorData::internal_error("MCP error response exceeds limit", None))?
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
        let result = bounded_tool_result(value.clone(), false, &id).unwrap();
        assert!(result.content.is_empty());
        let bytes = serde_json::to_vec(&JsonRpcResponse {
            jsonrpc: JsonRpcVersion2_0,
            id,
            result,
        })
        .unwrap();
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
        let value = output(&document).unwrap();
        assert_eq!(value["body"], body);
        let typed: kasumi_types::Document = arguments(value.clone()).unwrap();
        assert_eq!(typed, document);
        let response = bounded_tool_result(value, false, &RequestId::Number(1)).unwrap();
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
        let result = bounded_tool_result(
            json!({"error":{"code":"RESOURCE_EXHAUSTED","message":"bounded"}}),
            true,
            &id,
        )
        .unwrap();
        assert!(result.content.is_empty());
        assert_eq!(result.is_error, Some(true));
        assert!(
            serde_json::to_vec(&JsonRpcResponse {
                jsonrpc: JsonRpcVersion2_0,
                id,
                result
            })
            .unwrap()
            .len()
                <= MAX_RESPONSE_BYTES
        );
    }
}
