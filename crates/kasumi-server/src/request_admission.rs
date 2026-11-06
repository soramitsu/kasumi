//! Admission of client request bodies before they are buffered. Tonic and the
//! MCP SDK hold a whole message before its handler runs, and decoding its JSON
//! then multiplies its size. Mutation bodies first reserve bounded encoded
//! storage, then their JSON structure is inspected before the decoder runs.
//! Other requests reserve the conservative expansion from their declared size.
//! Charges remain through the handler, and every body has a read deadline.
use crate::{
    api::MAX_REQUEST_BYTES,
    auth::{Authenticator, ConnectionAuthentications},
};
use axum::{
    Json,
    body::Body,
    extract::{Request, State},
    http::{
        StatusCode,
        header::{CONTENT_LENGTH, CONTENT_TYPE},
    },
    middleware::Next,
    response::{IntoResponse, Response},
};
use hyper::body::{Bytes, Frame, SizeHint};
use kasumi_engine::admission::{NodeAdmission, Reservation};
use kasumi_query::QueryWorkspace;
use kasumi_types::{Error, ErrorCode, RequestContext};
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

/// Conservative decoded workspace per wire byte, including allocator slack
/// and transient vector growth. Tiny, nested objects are more expensive than
/// number arrays: each five-byte object wrapper can allocate a whole B-tree
/// node (over 700 bytes), even though it holds only one property. The bound
/// also covers the wire buffer and typed request alongside that value tree.
pub(crate) const DECODE_EXPANSION: u64 = 256;
/// Headers, extensions and decoder state of one request.
const REQUEST_OVERHEAD_BYTES: u64 = 16 << 10;
/// A client sends its whole body within this time, which even a maximum
/// request meets at about 140 KiB/s. A body trickled in or never finished
/// would otherwise hold its admission and stream slot without bound.
pub(crate) const BODY_READ_TIMEOUT: Duration = Duration::from_secs(60);
const GRPC_PREFIX_BYTES: usize = 5;

/// The admission charge for a request of `bytes`.
pub(crate) fn quote(bytes: u64) -> u64 {
    bytes
        .saturating_mul(DECODE_EXPANSION)
        .saturating_add(REQUEST_OVERHEAD_BYTES)
}

/// Encoded frame collection, its last growth allocation, Tonic's message
/// buffer and the protobuf bytes field, including capacity/allocator slack.
pub(crate) fn wire_quote(bytes: u64) -> u64 {
    bytes
        .saturating_mul(8)
        .saturating_add(REQUEST_OVERHEAD_BYTES)
}

/// Only the exact single-field, single-message encoding takes the structural
/// path. Legal alternatives (unknown/duplicate fields or nonminimal varints)
/// keep the conservative quote before Tonic interprets them.
fn mutation_json(bytes: &[u8]) -> Option<&[u8]> {
    if bytes.first() != Some(&0) {
        return None;
    }
    let length = u32::from_be_bytes(bytes.get(1..5)?.try_into().ok()?) as usize;
    let message = bytes.get(GRPC_PREFIX_BYTES..)?;
    if length != message.len() || message.first() != Some(&10) {
        return None;
    }
    let mut length = 0usize;
    for (index, &byte) in message.get(1..)?.iter().take(5).enumerate() {
        if index == 4 && byte > 15 {
            return None;
        }
        length |= usize::from(byte & 127) << (7 * index);
        if byte < 128 {
            if index > 0 && byte == 0 {
                return None;
            }
            let start = index + 2;
            return (start.checked_add(length)? == message.len()).then(|| &message[start..]);
        }
    }
    None
}

fn mutation_quote(bytes: &[u8]) -> Result<u64, Error> {
    let Some(json) = mutation_json(bytes) else {
        return Ok(quote(bytes.len() as u64));
    };
    wire_quote(bytes.len() as u64)
        .checked_add(kasumi_engine::admission::json_decode_workspace(json)?)
        .ok_or_else(|| Error::new(ErrorCode::ResourceExhausted, "request workspace overflow"))
}

struct InspectedMutation {
    // Retire the allocation before its last reservation, including an unclaimed
    // blocking-task result after the HTTP future has been cancelled.
    bytes: Bytes,
    workspace: Arc<Mutex<Reservation>>,
}
impl InspectedMutation {
    fn inspect(self) -> Result<Self, Error> {
        let required = mutation_quote(&self.bytes)?;
        self.workspace
            .lock()
            .map_err(|_| Error::new(ErrorCode::Unavailable, "request admission unavailable"))?
            .ensure_peak(required)
            .map_err(exhausted)?;
        Ok(self)
    }
}

#[derive(Clone)]
pub(crate) struct RequestAdmission {
    admission: Arc<NodeAdmission>,
    /// Native listeners verify the bearer here, before reading any body.
    auth: Option<Arc<Authenticator>>,
    read_timeout: Duration,
}
impl RequestAdmission {
    /// A native gRPC listener: authenticate, then admit the body.
    pub(crate) fn native(admission: Arc<NodeAdmission>, auth: Arc<Authenticator>) -> Self {
        Self {
            admission,
            auth: Some(auth),
            read_timeout: BODY_READ_TIMEOUT,
        }
    }
    /// A listener whose own middleware has already authenticated the bearer.
    pub(crate) fn authenticated(admission: Arc<NodeAdmission>) -> Self {
        Self {
            admission,
            auth: None,
            read_timeout: BODY_READ_TIMEOUT,
        }
    }
    #[cfg(test)]
    pub(crate) fn with_read_timeout(mut self, read_timeout: Duration) -> Self {
        self.read_timeout = read_timeout;
        self
    }
}

/// A bearer the listener verified before reading the request body. Handlers
/// reuse it instead of authenticating (and auditing) the same bearer again.
#[derive(Clone)]
pub(crate) struct Authenticated {
    auth: Arc<Authenticator>,
    context: RequestContext,
}
impl Authenticated {
    /// The verified context, if `auth` is the authenticator that verified it.
    pub(crate) fn context(&self, auth: &Authenticator) -> Option<&RequestContext> {
        std::ptr::eq(Arc::as_ptr(&self.auth), auth).then_some(&self.context)
    }
}

/// The one native method a credential authenticates after it has expired:
/// the listener verifies the presented credential with
/// `Authenticator::verify_recovery` instead of as a bearer.
pub(crate) const RECOVER_CREDENTIAL_PATH: &str = "/kasumi.v1.KasumiAdmin/RecoverCredential";

/// An expired credential the listener verified for online recovery before
/// reading the request body. Only the recovery method reads it; it is never
/// an `Authenticated` bearer.
#[derive(Clone)]
pub(crate) struct RecoveryAuthenticated {
    auth: Arc<Authenticator>,
    recovery: crate::auth::VerifiedRecovery,
}
impl RecoveryAuthenticated {
    /// The verified recovery, if `auth` is the authenticator that verified it.
    pub(crate) fn recovery(&self, auth: &Authenticator) -> Option<&crate::auth::VerifiedRecovery> {
        std::ptr::eq(Arc::as_ptr(&self.auth), auth).then_some(&self.recovery)
    }
}

pub(crate) async fn admit(
    State(state): State<RequestAdmission>,
    mut request: Request,
    next: Next,
) -> Response {
    let grpc = request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/grpc"));
    let mutation = grpc && request.uri().path() == "/kasumi.v1.KasumiData/Mutate";
    if let Some(auth) = &state.auth {
        let values = request.headers().get_all("authorization");
        let mut values = values.iter();
        let first = values.next().and_then(|value| value.to_str().ok());
        let authorization = if values.next().is_some() {
            ""
        } else {
            first.unwrap_or("")
        };
        if grpc && request.uri().path() == RECOVER_CREDENTIAL_PATH {
            let client_certificate = request
                .extensions()
                .get::<crate::tls::AuthenticatedTlsPeer>()
                .and_then(crate::tls::AuthenticatedTlsPeer::certificate_pin);
            match auth
                .verify_recovery(authorization, client_certificate)
                .await
            {
                Ok(recovery) => {
                    request.extensions_mut().insert(RecoveryAuthenticated {
                        auth: auth.clone(),
                        recovery,
                    });
                }
                Err(error) => return refused(grpc, error),
            }
        } else {
            // A TLS connection records each token's first success and counts
            // the rest; other callers record every success.
            let connection = request
                .extensions()
                .get::<Arc<ConnectionAuthentications>>()
                .cloned();
            let authenticated = match &connection {
                Some(connection) => auth.authenticate_on(authorization, connection).await,
                None => auth.authenticate(authorization).await,
            };
            match authenticated {
                Ok(context) => {
                    request.extensions_mut().insert(Authenticated {
                        auth: auth.clone(),
                        context,
                    });
                }
                Err(error) => return refused(grpc, error),
            }
        }
    }
    // A gRPC message adds its five-byte length prefix to the request limit.
    let limit = MAX_REQUEST_BYTES as u64 + if grpc { GRPC_PREFIX_BYTES as u64 } else { 0 };
    let mut lengths = request.headers().get_all(CONTENT_LENGTH).iter();
    let declared = match (lengths.next(), lengths.next()) {
        (Some(length), None) => length
            .to_str()
            .ok()
            .and_then(|length| length.parse::<u64>().ok()),
        _ => None,
    };
    if declared.is_some_and(|bytes| bytes > limit) {
        return refused(grpc, too_large());
    }
    let charged = if mutation {
        wire_quote(declared.unwrap_or(0))
    } else {
        quote(declared.unwrap_or(0))
    };
    let workspace = match state.admission.reserve_waiting(charged, None) {
        Ok(reservation) => Arc::new(Mutex::new(reservation)),
        Err(error) => return refused(grpc, exhausted(error)),
    };
    let mut request = request.map(|body| {
        Body::new(AdmittedBody {
            inner: body,
            workspace: workspace.clone(),
            charged,
            received: 0,
            declared,
            limit,
            prefix: grpc.then_some(([0; GRPC_PREFIX_BYTES], 0)),
            raw_only: mutation,
            deadline: Box::pin(tokio::time::sleep(state.read_timeout)),
            ended: false,
        })
    });
    if mutation {
        let (parts, body) = request.into_parts();
        let bytes = match axum::body::to_bytes(body, limit as usize).await {
            Ok(bytes) => bytes,
            Err(error) => return body_failure(error),
        };
        // The blocking inspector owns both the encoded allocation and its
        // charge even if the HTTP caller disappears. No DTO is constructed
        // until its complete structural workspace has been admitted.
        let inspecting = InspectedMutation {
            bytes,
            workspace: workspace.clone(),
        };
        let inspected = tokio::task::spawn_blocking(move || inspecting.inspect()).await;
        let bytes = match inspected {
            Ok(Ok(inspected)) => inspected.bytes,
            Ok(Err(error)) => return refused(grpc, error),
            Err(_) => {
                return refused(
                    grpc,
                    Error::new(ErrorCode::Unavailable, "request inspection failed"),
                );
            }
        };
        request = Request::from_parts(parts, Body::from(bytes));
    }
    let response = next.run(request).await;
    // The handler has returned, and with it every value decoded from the body.
    drop(workspace);
    response
}

fn body_failure(error: axum::Error) -> Response {
    let mut cause: &(dyn std::error::Error + 'static) = &error;
    loop {
        if let Some(status) = cause.downcast_ref::<tonic::Status>() {
            return status.clone().into_http();
        }
        match cause.source() {
            Some(source) => cause = source,
            None => {
                return refused(
                    true,
                    Error::new(ErrorCode::Unavailable, "request body read failed"),
                );
            }
        }
    }
}

fn too_large() -> Error {
    Error::new(ErrorCode::ResourceExhausted, "request body too large")
}
fn exhausted(error: Error) -> Error {
    if error.code == ErrorCode::ResourceExhausted {
        Error::new(
            ErrorCode::ResourceExhausted,
            "request body exceeds the node's decode admission",
        )
    } else {
        error
    }
}
fn refused(grpc: bool, error: Error) -> Response {
    if grpc {
        return crate::api::status(error).into_http();
    }
    let status = match error.code {
        ErrorCode::Unauthorized => StatusCode::UNAUTHORIZED,
        ErrorCode::Forbidden => StatusCode::FORBIDDEN,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    };
    (status, Json(serde_json::json!({"error":error.code}))).into_response()
}

/// Charges each body frame before passing it on, and fails the body at its
/// read deadline. The decoder sees the failure as the request's status.
struct AdmittedBody {
    inner: Body,
    workspace: Arc<Mutex<Reservation>>,
    charged: u64,
    received: u64,
    /// Content-Length, or once complete the gRPC message's own prefix.
    declared: Option<u64>,
    limit: u64,
    /// The gRPC length prefix and how much of it has arrived.
    prefix: Option<([u8; GRPC_PREFIX_BYTES], usize)>,
    raw_only: bool,
    deadline: Pin<Box<tokio::time::Sleep>>,
    ended: bool,
}
impl AdmittedBody {
    fn admit(&mut self, data: &[u8]) -> Result<(), Error> {
        self.received = self.received.saturating_add(data.len() as u64);
        if let Some((prefix, filled)) = &mut self.prefix
            && *filled < GRPC_PREFIX_BYTES
        {
            let copied = data.len().min(GRPC_PREFIX_BYTES - *filled);
            prefix[*filled..*filled + copied].copy_from_slice(&data[..copied]);
            *filled += copied;
            if *filled == GRPC_PREFIX_BYTES {
                let length = u32::from_be_bytes([prefix[1], prefix[2], prefix[3], prefix[4]]);
                self.declared = Some(GRPC_PREFIX_BYTES as u64 + u64::from(length));
            }
        }
        let bytes = self.received.max(self.declared.unwrap_or(0));
        if bytes > self.limit {
            return Err(too_large());
        }
        let quote = if self.raw_only {
            wire_quote(bytes)
        } else {
            quote(bytes)
        };
        if quote > self.charged {
            self.workspace
                .lock()
                .map_err(|_| Error::new(ErrorCode::Unavailable, "request admission unavailable"))?
                .ensure_peak(quote)
                .map_err(exhausted)?;
            self.charged = quote;
        }
        Ok(())
    }
    fn failure(error: Error) -> axum::Error {
        axum::Error::new(crate::api::status(error))
    }
}
impl hyper::body::Body for AdmittedBody {
    type Data = Bytes;
    type Error = axum::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, axum::Error>>> {
        let this = &mut *self;
        if this.ended {
            return Poll::Ready(None);
        }
        let timeout = || {
            Self::failure(Error::new(
                ErrorCode::Unavailable,
                "request body read deadline elapsed",
            ))
        };
        if this.deadline.is_elapsed() {
            return Poll::Ready(Some(Err(timeout())));
        }
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref()
                    && let Err(error) = this.admit(data)
                {
                    return Poll::Ready(Some(Err(Self::failure(error))));
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(None) => {
                this.ended = true;
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(error))),
            // Wake at the deadline even if no further frame ever arrives.
            Poll::Pending => match this.deadline.as_mut().poll(cx) {
                Poll::Ready(()) => Poll::Ready(Some(Err(timeout()))),
                Poll::Pending => Poll::Pending,
            },
        }
    }
    fn is_end_stream(&self) -> bool {
        self.ended || self.inner.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    fn frame(message: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0];
        bytes.extend_from_slice(&(message.len() as u32).to_be_bytes());
        bytes.extend_from_slice(message);
        bytes
    }

    #[tokio::test]
    async fn completed_mutation_inspection_keeps_its_charge_until_output_retirement() {
        let admission = NodeAdmission::new(Default::default()).unwrap();
        let baseline = admission.snapshot().reserved_bytes;
        let bytes: Bytes = frame(
            &crate::rpc::proto::MutateRequest {
                batch_json: br#"{"proof":"retained"}"#.to_vec(),
            }
            .encode_to_vec(),
        )
        .into();
        let required = mutation_quote(&bytes).unwrap();
        let inspecting = InspectedMutation {
            workspace: Arc::new(Mutex::new(
                admission
                    .reserve_waiting(wire_quote(bytes.len() as u64), None)
                    .unwrap(),
            )),
            bytes,
        };
        // No HTTP owner remains. A completed but unclaimed result still owns
        // the encoded body and must retain its reservation until retirement.
        let worker = tokio::task::spawn_blocking(move || inspecting.inspect());
        tokio::time::timeout(Duration::from_secs(10), async {
            while !worker.is_finished() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(admission.snapshot().reserved_bytes, baseline + required);
        drop(worker);
        assert_eq!(admission.snapshot().reserved_bytes, baseline);
    }

    #[test]
    fn mutation_structure_path_requires_one_canonical_uncompressed_message() {
        let message = crate::rpc::proto::MutateRequest {
            batch_json: b"{}".to_vec(),
        }
        .encode_to_vec();
        let encoded = frame(&message);
        assert_eq!(mutation_json(&encoded), Some(b"{}".as_slice()));
        let mut compressed = encoded.clone();
        compressed[0] = 1;
        let mut duplicate = message.clone();
        duplicate.extend_from_slice(&message);
        let mut unknown = message.clone();
        unknown.extend_from_slice(&[16, 1]);
        let mut trailing = encoded.clone();
        trailing.extend_from_slice(&encoded);
        for alternative in [
            compressed,
            frame(&duplicate),
            frame(&unknown),
            frame(&[10, 130, 0, b'{', b'}']),
            frame(&[10, 255, 255, 255, 255, 16]),
            frame(&[10, 3, b'{', b'}']),
            trailing,
            encoded[..encoded.len() - 1].to_vec(),
        ] {
            assert!(mutation_json(&alternative).is_none(), "{alternative:?}");
            assert_eq!(
                mutation_quote(&alternative).unwrap(),
                quote(alternative.len() as u64)
            );
        }
    }
}
