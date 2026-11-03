//! Admission of client request bodies before they are buffered. Tonic and the
//! MCP SDK hold a whole message before its handler runs, and decoding its JSON
//! then multiplies its size. Each request on a client listener charges its
//! declared size times that expansion to the node's admission before a body
//! byte reaches the decoder, keeps the charge until its handler returns, and
//! must finish sending its body before a read deadline.
use crate::{api::MAX_REQUEST_BYTES, auth::Authenticator};
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
    if let Some(auth) = &state.auth {
        let values = request.headers().get_all("authorization");
        let mut values = values.iter();
        let first = values.next().and_then(|value| value.to_str().ok());
        let authorization = if values.next().is_some() {
            ""
        } else {
            first.unwrap_or("")
        };
        match auth.authenticate(authorization).await {
            Ok(context) => {
                request.extensions_mut().insert(Authenticated {
                    auth: auth.clone(),
                    context,
                });
            }
            Err(error) => return refused(grpc, error),
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
    let charged = quote(declared.unwrap_or(0));
    let workspace = match state.admission.reserve_waiting(charged, None) {
        Ok(reservation) => Arc::new(Mutex::new(reservation)),
        Err(error) => return refused(grpc, exhausted(error)),
    };
    let request = request.map(|body| {
        Body::new(AdmittedBody {
            inner: body,
            workspace: workspace.clone(),
            charged,
            received: 0,
            declared,
            limit,
            prefix: grpc.then_some(([0; GRPC_PREFIX_BYTES], 0)),
            deadline: Box::pin(tokio::time::sleep(state.read_timeout)),
            ended: false,
        })
    });
    let response = next.run(request).await;
    // The handler has returned, and with it every value decoded from the body.
    drop(workspace);
    response
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
        let quote = quote(bytes);
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
