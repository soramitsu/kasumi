//! Retain admitted service output through adapter encoding and transport frames.
use super::{MAX_RESPONSE_BYTES, status};
use axum::http;
use hyper::body::{Body, Bytes, Frame, SizeHint};
use kasumi_engine::{AdmittedOutput, ResponseFence};
use kasumi_types::{Error, ErrorCode, RequestContext, Result};
use serde::Serialize;
use std::{
    any::Any,
    future::Future,
    mem::size_of,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

fn overflow() -> Error {
    Error::new(
        ErrorCode::ResourceExhausted,
        "response allocation size overflow",
    )
}
fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).ok_or_else(overflow)
}

/// Explicit allocation policy slack, not an allocator-internal or RSS census.
pub(crate) fn allocation_bytes(requested: usize) -> Result<u64> {
    if requested == 0 {
        return Ok(0);
    }
    let bytes = requested.checked_next_power_of_two().ok_or_else(overflow)?;
    add(u64::try_from(bytes).map_err(|_| overflow())?, 64)
}
pub(crate) fn claim_vec<T>(fence: &mut ResponseFence<'_>, count: usize) -> Result<()> {
    fence.retain_response_bytes(allocation_bytes(
        count.checked_mul(size_of::<T>()).ok_or_else(overflow)?,
    )?)
}
pub(crate) fn clone_string(fence: &mut ResponseFence<'_>, value: &str) -> Result<String> {
    fence.retain_response_bytes(allocation_bytes(value.len())?)?;
    Ok(value.to_owned())
}

pub(crate) fn encoded_len(value: &impl Serialize) -> Result<usize> {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .filter(|n| *n <= MAX_RESPONSE_BYTES)
                .ok_or_else(|| std::io::Error::other("response exceeds byte limit"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, value).map_err(|_| {
        Error::new(
            ErrorCode::ResourceExhausted,
            "response cannot be encoded within its byte limit",
        )
    })?;
    Ok(counter.0)
}

/// Count and admit the exact destination capacity before serializing a buffer.
pub(crate) fn encode_json(
    value: &impl Serialize,
    fence: &mut ResponseFence<'_>,
) -> Result<Vec<u8>> {
    let len = encoded_len(value)?;
    fence.retain_response_bytes(allocation_bytes(len)?)?;
    let mut bytes = Vec::with_capacity(len);
    serialize_fixed(value, &mut bytes, len)?;
    Ok(bytes)
}

fn serialize_fixed(value: &impl Serialize, bytes: &mut Vec<u8>, len: usize) -> Result<()> {
    struct Fixed<'a> {
        bytes: &'a mut Vec<u8>,
        limit: usize,
    }
    impl std::io::Write for Fixed<'_> {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            if data.len() > self.limit.saturating_sub(self.bytes.len()) {
                return Err(std::io::Error::other("response changed after sizing"));
            }
            self.bytes.extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(
        Fixed {
            bytes: &mut *bytes,
            limit: len,
        },
        value,
    )
    .map_err(|_| Error::new(ErrorCode::Corruption, "response encoding failed"))?;
    if bytes.len() != len {
        return Err(Error::new(
            ErrorCode::Corruption,
            "response encoding changed after sizing",
        ));
    }
    Ok(())
}

/// Covers the concrete owner plus Arc metadata. The separate 4096-byte policy
/// allowance covers one http::Extensions map (initial four-bucket table, its
/// boxed map and boxed ReplyOwner), tonic's boxed EncodeBody and RetainedBody,
/// response/trailer HeaderMaps, BytesMut's shared-buffer header, MCP's extra
/// Arc<Arc<AdmittedOutput<T>>>, and Bytes::from_owner's refcount/OwnedFrame box. Those
/// are fixed-count allocations on these pinned unary/terminal paths, not a
/// promise for arbitrary streaming or allocator-internal overhead. Unary native
/// output yields one data frame; MCP emits one materialized body. Byte clones
/// share that frame's owner allocation.
pub(crate) fn owner_bytes<T>() -> Result<u64> {
    add(
        allocation_bytes(
            size_of::<T>()
                .checked_add(2 * size_of::<usize>())
                .ok_or_else(overflow)?,
        )?,
        4096,
    )
}

#[derive(Clone)]
pub(crate) struct ReplyOwner {
    _owner: Arc<dyn Any + Send + Sync>,
}
impl ReplyOwner {
    pub(crate) fn new<T: Any + Send + Sync>(value: T) -> Self {
        Self {
            _owner: Arc::new(value),
        }
    }
}

/// Original typed output remains owned, rather than being extracted or cloned.
pub(crate) struct PendingReply<T> {
    source: AdmittedOutput<T>,
    fence: ResponseFence<'static>,
}
impl<T: Send + Sync + 'static> PendingReply<T> {
    pub(crate) fn new(source: AdmittedOutput<T>, fence: ResponseFence<'static>) -> Self {
        Self { source, fence }
    }
    pub(crate) fn convert<U>(
        mut self,
        convert: impl FnOnce(&T, &mut ResponseFence<'_>) -> Result<U>,
    ) -> Result<NativeReply<T, U>> {
        let response = convert(self.source.as_ref(), &mut self.fence)?;
        Ok(NativeReply {
            response,
            pending: self,
        })
    }
}
pub(crate) struct NativeReply<T, U> {
    response: U,
    pending: PendingReply<T>,
}
impl<T: Send + Sync + 'static, U: prost::Message> NativeReply<T, U> {
    pub(crate) async fn release(
        mut self,
        auth: &crate::auth::Authenticator,
        context: &RequestContext,
    ) -> std::result::Result<tonic::Response<U>, tonic::Status> {
        let len = self.response.encoded_len();
        if len > MAX_RESPONSE_BYTES {
            return Err(status(Error::new(
                ErrorCode::ResourceExhausted,
                "native response exceeds byte limit",
            )));
        }
        let framed = len.checked_add(5).ok_or_else(|| status(overflow()))?;
        // Tonic 0.14 starts with an 8KiB BytesMut. Doubling growth can hold
        // old+new allocations together; account that separately from the
        // protobuf representation and the still-owned source JSON tree.
        let growth = framed.checked_mul(2).ok_or_else(|| status(overflow()))?;
        let codec = add(
            allocation_bytes(growth.max(8192)).map_err(status)?,
            allocation_bytes(framed.max(8192)).map_err(status)?,
        )
        .map_err(status)?;
        self.pending
            .fence
            .retain_response_bytes(
                add(codec, owner_bytes::<PendingReply<T>>().map_err(status)?).map_err(status)?,
            )
            .map_err(status)?;
        auth.audit_result(context, self.pending.fence.check())
            .await
            .map_err(status)?;
        let owner = ReplyOwner::new(self.pending);
        let mut response = tonic::Response::new(self.response);
        response.extensions_mut().insert(owner);
        Ok(response)
    }
}

struct OwnedFrame {
    bytes: Bytes,
    _owner: ReplyOwner,
}
impl AsRef<[u8]> for OwnedFrame {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}
pub(crate) fn owned_bytes(bytes: Bytes, owner: ReplyOwner) -> Bytes {
    Bytes::from_owner(OwnedFrame {
        bytes,
        _owner: owner,
    })
}

struct RetainedBody {
    body: tonic::body::Body,
    owner: ReplyOwner,
}
impl Body for RetainedBody {
    type Data = Bytes;
    type Error = tonic::Status;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Bytes>, Self::Error>>> {
        let owner = self.owner.clone();
        Pin::new(&mut self.body).poll_frame(cx).map(|frame| {
            frame.map(|frame| frame.map(|frame| frame.map_data(|bytes| owned_bytes(bytes, owner))))
        })
    }
    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

/// Mandatory NativeData wrapper: HTTP parts, body and each emitted frame share
/// ownership, so independently detaching any of them preserves the charge.
#[derive(Clone)]
pub struct AdmittedService<S> {
    inner: S,
}
impl<S> AdmittedService<S> {
    pub(crate) fn new(inner: S) -> Self {
        Self { inner }
    }
}
impl<S: tonic::server::NamedService> tonic::server::NamedService for AdmittedService<S> {
    const NAME: &'static str = S::NAME;
}
impl<S, B> tower::Service<http::Request<B>> for AdmittedService<S>
where
    S: tower::Service<http::Request<B>, Response = http::Response<tonic::body::Body>>,
    S::Future: Unpin,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = AdmittedFuture<S::Future>;
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<std::result::Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }
    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        AdmittedFuture {
            inner: self.inner.call(request),
        }
    }
}
pub struct AdmittedFuture<F> {
    inner: F,
}
impl<F, E> Future for AdmittedFuture<F>
where
    F: Future<Output = std::result::Result<http::Response<tonic::body::Body>, E>> + Unpin,
{
    type Output = F::Output;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.inner).poll(cx).map(|response| {
            response.map(|mut response| {
                if let Some(owner) = response.extensions().get::<ReplyOwner>().cloned() {
                    let body = std::mem::replace(response.body_mut(), tonic::body::Body::empty());
                    *response.body_mut() = tonic::body::Body::new(RetainedBody { body, owner });
                }
                response
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changed_serializer_cannot_grow_the_admitted_destination() {
        struct Changing(std::cell::Cell<bool>);
        impl Serialize for Changing {
            fn serialize<S: serde::Serializer>(
                &self,
                serializer: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                serializer.serialize_str(if self.0.replace(true) {
                    "a longer second pass"
                } else {
                    "x"
                })
            }
        }
        let value = Changing(std::cell::Cell::new(false));
        let len = encoded_len(&value).unwrap();
        assert_eq!(len, 3);
        // Even spare allocator capacity cannot authorize more than the census.
        let mut bytes = Vec::with_capacity(128);
        let capacity = bytes.capacity();
        assert_eq!(
            serialize_fixed(&value, &mut bytes, len).unwrap_err().code,
            ErrorCode::Corruption
        );
        assert!(bytes.len() <= len);
        assert_eq!(bytes.capacity(), capacity);
        let mut exact = Vec::with_capacity(len);
        let capacity = exact.capacity();
        assert_eq!(
            serialize_fixed(&value, &mut exact, len).unwrap_err().code,
            ErrorCode::Corruption
        );
        assert_eq!(exact.capacity(), capacity);
    }

    #[test]
    fn pinned_unary_fixed_wrapper_inventory_fits_policy_allowance() {
        use crate::rpc::proto::{QueryResponse, ReadSnapshotResponse, SnapshotScanPageResponse};
        fn codec_size<T>() -> usize {
            // tokio_stream 0.1.19 Once<T> contains exactly Option<T>; using the
            // same field as the surrogate and an extra word bounds layout slack.
            size_of::<
                tonic::codec::EncodeBody<
                    tonic_prost::ProstEncoder<T>,
                    Option<std::result::Result<T, tonic::Status>>,
                >,
            >() + size_of::<usize>()
        }
        let codec = [
            codec_size::<QueryResponse>(),
            codec_size::<ReadSnapshotResponse>(),
            codec_size::<SnapshotScanPageResponse>(),
        ]
        .into_iter()
        .max()
        .unwrap();
        let arc_metadata = 2 * size_of::<usize>();
        // http 1.5.0: fresh response HeaderMap has 8 index slots and 6 entries;
        // success trailers request 3 entries (4 index slots). Bucket fields are
        // HeaderName, HeaderValue, u16 hash and Option<two usize links>.
        let header_bucket =
            size_of::<http::HeaderName>() + size_of::<http::HeaderValue>() + 4 * size_of::<usize>();
        let requests = [
            codec,
            size_of::<RetainedBody>(),
            size_of::<OwnedFrame>() + arc_metadata,
            size_of::<std::collections::HashMap<std::any::TypeId, Box<dyn Any + Send + Sync>>>(),
            4 * (size_of::<std::any::TypeId>() + size_of::<Box<dyn Any + Send + Sync>>()) + 16,
            size_of::<ReplyOwner>(),
            6 * header_bucket,
            8 * 2 * size_of::<u16>(),
            3 * header_bucket,
            4 * 2 * size_of::<u16>(),
            // bytes 1.12 shared allocation header and MCP erased extra Arc.
            4 * size_of::<usize>(),
            size_of::<Arc<AdmittedOutput<kasumi_types::QueryResponse>>>() + arc_metadata,
            // tonic success Status backing contains code/message/details/metadata.
            size_of::<http::HeaderMap>()
                + size_of::<String>()
                + size_of::<Bytes>()
                + 4 * size_of::<usize>(),
        ];
        let total: u64 = requests
            .into_iter()
            .map(|bytes| allocation_bytes(bytes).unwrap())
            .sum();
        assert!(
            total <= 4096,
            "pinned fixed wrappers require {total} policy bytes"
        );
    }
}
