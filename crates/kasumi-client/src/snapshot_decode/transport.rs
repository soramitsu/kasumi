//! Snapshot-only framing. HTTP/2/TLS frames and headers are already allocated
//! when this adapter sees them; this bounds bytes admitted into tonic, not RSS.
use super::resources::{Call, invalid};
use crate::{ClientError, proto};
use bytes::{Buf, Bytes};
use http_body::{Body as _, Frame};
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tonic::{
    Status,
    body::Body,
    codec::{BufferSettings, Codec, DecodeBuf, Decoder, EncodeBuf, Encoder},
    transport::Channel,
};
use tower_service::Service;

pub(super) struct Wire {
    pub bytes: Bytes,
    pub call: Call,
}
struct SnapshotCodec {
    call: Call,
}
struct SnapshotEncoder {
    inner: tonic_prost::ProstEncoder<proto::ReadSnapshotRequest>,
    _call: Call,
}
struct SnapshotDecoder {
    call: Call,
    seen: bool,
}
impl Codec for SnapshotCodec {
    type Encode = proto::ReadSnapshotRequest;
    type Decode = Wire;
    type Encoder = SnapshotEncoder;
    type Decoder = SnapshotDecoder;
    fn encoder(&mut self) -> Self::Encoder {
        SnapshotEncoder {
            inner: tonic_prost::ProstEncoder::new(BufferSettings::new(1024, 1024)),
            _call: self.call.clone(),
        }
    }
    fn decoder(&mut self) -> Self::Decoder {
        SnapshotDecoder {
            call: self.call.clone(),
            seen: false,
        }
    }
}
impl Encoder for SnapshotEncoder {
    type Item = proto::ReadSnapshotRequest;
    type Error = Status;
    fn encode(&mut self, value: Self::Item, output: &mut EncodeBuf<'_>) -> Result<(), Status> {
        self.inner.encode(value, output)
    }
    fn buffer_settings(&self) -> BufferSettings {
        BufferSettings::new(1024, 1024)
    }
}
impl Decoder for SnapshotDecoder {
    type Item = Wire;
    type Error = Status;
    fn decode(&mut self, input: &mut DecodeBuf<'_>) -> Result<Option<Wire>, Status> {
        if self.seen {
            return Err(Status::data_loss("extra snapshot response message"));
        }
        self.seen = true;
        self.call.check().map_err(status)?;
        Ok(Some(Wire {
            bytes: envelope(input, self.call.limits.max_json_bytes)?,
            call: self.call.clone(),
        }))
    }

    fn buffer_settings(&self) -> BufferSettings {
        BufferSettings::new(1024, 1024)
    }
}
fn envelope(input: &mut impl Buf, maximum: usize) -> Result<Bytes, Status> {
    if !input.has_remaining() || input.get_u8() != 10 {
        return Err(Status::data_loss("invalid snapshot envelope"));
    }
    let mut length = 0u64;
    let mut shift = 0;
    loop {
        if !input.has_remaining() || shift >= 64 {
            return Err(Status::data_loss("invalid snapshot length"));
        }
        let byte = input.get_u8();
        if shift == 63 && byte > 1 {
            return Err(Status::data_loss("snapshot length overflow"));
        }
        length |= u64::from(byte & 127) << shift;
        if byte < 128 {
            if shift != 0 && byte == 0 {
                return Err(Status::data_loss("noncanonical snapshot length"));
            }
            break;
        }
        shift += 7;
    }
    if length > maximum as u64 || length != input.remaining() as u64 {
        return Err(Status::resource_exhausted(
            "snapshot JSON envelope exceeds its bounds",
        ));
    }
    Ok(input.copy_to_bytes(length as usize))
}

fn status(error: ClientError) -> Status {
    match error {
        ClientError::Transport(status) => status,
        ClientError::SnapshotRejected { code, reason } => Status::new(code, reason),
        _ => Status::data_loss("invalid admitted snapshot response"),
    }
}

struct OwnedBody {
    body: Body,
    _call: Call,
}
impl http_body::Body for OwnedBody {
    type Data = Bytes;
    type Error = Status;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Status>>> {
        Pin::new(&mut self.body).poll_frame(cx)
    }
    // Keep the owner even for an empty body until tonic drops this wrapper.
}
#[derive(Default)]
struct Framing {
    header: [u8; 5],
    header_len: usize,
    remaining: Option<usize>,
    complete: bool,
}
impl Framing {
    fn accept(&mut self, mut bytes: &[u8], maximum: usize) -> Result<(), Status> {
        while !bytes.is_empty() {
            if self.complete {
                return Err(Status::data_loss("extra snapshot response bytes"));
            }
            if self.header_len < 5 {
                let take = (5 - self.header_len).min(bytes.len());
                self.header[self.header_len..self.header_len + take]
                    .copy_from_slice(&bytes[..take]);
                self.header_len += take;
                bytes = &bytes[take..];
                if self.header_len != 5 {
                    continue;
                }
                if self.header[0] != 0 {
                    return Err(Status::data_loss(
                        "compressed snapshot response is unsupported",
                    ));
                }
                let length = u32::from_be_bytes(self.header[1..5].try_into().unwrap()) as usize;
                if length > maximum {
                    return Err(Status::resource_exhausted(
                        "snapshot message exceeds its byte limit",
                    ));
                }
                self.remaining = Some(length);
                self.complete = length == 0;
            }
            let remaining = self.remaining.as_mut().unwrap();
            let take = (*remaining).min(bytes.len());
            *remaining -= take;
            bytes = &bytes[take..];
            self.complete = *remaining == 0;
        }
        Ok(())
    }
}
fn metadata_bytes(headers: &http::HeaderMap) -> Result<usize, Status> {
    let mut bytes = 0usize;
    for (key, value) in headers {
        bytes = bytes
            .checked_add(key.as_str().len())
            .and_then(|v| v.checked_add(value.len()))
            .and_then(|v| v.checked_add(64))
            .ok_or_else(|| Status::resource_exhausted("snapshot metadata overflow"))?;
    }
    if bytes > 64 << 10 {
        return Err(Status::resource_exhausted(
            "snapshot metadata exceeds its limit",
        ));
    }
    Ok(bytes)
}
struct CheckedBody {
    body: Body,
    call: Call,
    framing: Framing,
    metadata: usize,
    failed: bool,
}
impl http_body::Body for CheckedBody {
    type Data = Bytes;
    type Error = Status;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Status>>> {
        if self.failed {
            return Poll::Ready(None);
        }
        let result = match self.call.check().map_err(status) {
            Err(error) => Err(error),
            Ok(()) => match Pin::new(&mut self.body).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Ready(Some(Err(error))) => Err(error),
                Poll::Ready(Some(Ok(frame))) => {
                    let maximum = self.call.limits.max_wire_bytes;
                    if let Some(data) = frame.data_ref() {
                        self.framing.accept(data, maximum).map(|()| frame)
                    } else if let Some(trailers) = frame.trailers_ref() {
                        metadata_bytes(trailers).and_then(|size| {
                            self.metadata = self.metadata.checked_add(size).ok_or_else(|| {
                                Status::resource_exhausted("snapshot metadata overflow")
                            })?;
                            if self.metadata > 64 << 10 {
                                return Err(Status::resource_exhausted(
                                    "snapshot metadata exceeds its limit",
                                ));
                            }
                            Ok(frame)
                        })
                    } else {
                        Err(Status::data_loss("unexpected snapshot body frame"))
                    }
                }
            },
        };
        if result.is_err() {
            self.failed = true;
        }
        Poll::Ready(Some(result))
    }
}
#[derive(Clone)]
struct SnapshotService {
    channel: Channel,
    call: Call,
}
type ChannelError = <Channel as Service<http::Request<Body>>>::Error;
impl Service<http::Request<Body>> for SnapshotService {
    type Response = http::Response<Body>;
    type Error = ChannelError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, ChannelError>> + Send>>;
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), ChannelError>> {
        self.channel.poll_ready(cx)
    }
    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        let call = self.call.clone();
        let request = request.map(|body| {
            Body::new(OwnedBody {
                body,
                _call: call.clone(),
            })
        });
        let future = self.channel.call(request);
        Box::pin(async move {
            let response = future.await?;
            Ok(admit_response(response, call))
        })
    }
}

fn admit_response(response: http::Response<Body>, call: Call) -> http::Response<Body> {
    let metadata = match metadata_bytes(response.headers()) {
        Ok(metadata) => metadata,
        Err(error) => {
            // Tonic may inspect initial grpc-status before polling its body.
            drop(response);
            let mut rejected = http::Response::new(Body::new(ErrorBody {
                error: Some(error),
                _call: call,
            }));
            rejected.headers_mut().insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("application/grpc"),
            );
            return rejected;
        }
    };
    response.map(|body| {
        Body::new(CheckedBody {
            body,
            call,
            framing: Framing::default(),
            metadata,
            failed: false,
        })
    })
}

struct ErrorBody {
    error: Option<Status>,
    _call: Call,
}
impl http_body::Body for ErrorBody {
    type Data = Bytes;
    type Error = Status;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Status>>> {
        Poll::Ready(self.error.take().map(Err))
    }
}
pub(super) async fn receive(
    channel: Channel,
    mut request: tonic::Request<proto::ReadSnapshotRequest>,
    path: &'static str,
    call: Call,
) -> Result<Wire, ClientError> {
    let result = async {
        call.check()?;
        request.set_timeout(
            call.deadline
                .saturating_duration_since(tokio::time::Instant::now()),
        );
        let mut client = tonic::client::Grpc::new(SnapshotService {
            channel,
            call: call.clone(),
        })
        .max_encoding_message_size(
            call.limits
                .max_request_bytes
                .checked_add(16)
                .ok_or_else(|| invalid("snapshot request overflow"))?,
        )
        .max_decoding_message_size(call.limits.max_wire_bytes);
        client
            .ready()
            .await
            .map_err(|_| Status::unavailable("snapshot channel unavailable"))?;
        let result = client
            .unary(
                request,
                http::uri::PathAndQuery::from_static(path),
                SnapshotCodec { call: call.clone() },
            )
            .await?;
        call.check()?;
        Ok(result.into_inner())
    }
    .await;
    result.map_err(super::normalize)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn framing_rejects_declared_size_compression_and_second_message_before_forwarding() {
        let mut framing = Framing::default();
        framing.accept(&[0, 0], 3).unwrap();
        framing.accept(&[0, 0, 3, 10], 3).unwrap();
        framing.accept(&[1, b'x'], 3).unwrap();
        assert!(framing.accept(&[0], 3).is_err());
        assert!(Framing::default().accept(&[0, 0, 0, 0, 4], 3).is_err());
        assert!(Framing::default().accept(&[1, 0, 0, 0, 0], 3).is_err());
        assert!(Framing::default().accept(&[0, 0, 0, 0, 0, 0], 3).is_err());
    }
    #[test]
    fn bounded_envelope_rejects_duplicate_and_noncanonical_fields() {
        assert_eq!(
            envelope(&mut Bytes::from_static(&[10, 1, b'x']), 1).unwrap(),
            Bytes::from_static(b"x")
        );
        for bytes in [
            &[10, 1, b'x', 10, 1, b'y'][..],
            &[10, 129, 0, b'x'],
            &[10, 2, b'x', b'y'],
            &[18, 1, b'x'],
        ] {
            assert!(envelope(&mut Bytes::copy_from_slice(bytes), 1).is_err());
        }
    }
    #[tokio::test]
    async fn oversized_initial_status_headers_are_removed_before_tonic_can_decode_them() {
        let options = crate::SnapshotReadOptions {
            resources: crate::ClientResources::new(1 << 30, 1).unwrap(),
            limits: crate::SnapshotDecodeLimits::default(),
            deadline: tokio::time::Instant::now() + std::time::Duration::from_secs(30),
            expected_incarnation: uuid::Uuid::new_v4(),
        };
        let call = options.admit().unwrap();
        let mut original = http::Response::new(Body::empty());
        original
            .headers_mut()
            .insert("grpc-status", http::HeaderValue::from_static("13"));
        original.headers_mut().insert(
            "grpc-message",
            http::HeaderValue::from_str(&"x".repeat(64 << 10)).unwrap(),
        );
        let admitted = admit_response(original, call);
        assert!(!admitted.headers().contains_key("grpc-status"));
        assert!(!admitted.headers().contains_key("grpc-message"));
        let mut body = admitted.into_body();
        let frame = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
            .await
            .unwrap();
        assert_eq!(frame.unwrap_err().code(), tonic::Code::ResourceExhausted);
        drop(body);
        assert_eq!(options.resources.usage().accounted_bytes, 0);
    }
}
