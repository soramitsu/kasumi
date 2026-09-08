//! Defensive native snapshot admission, separate from server-side resource limits.
mod request;
mod resources;
mod semantic;
mod tokens;
mod transport;
use crate::{ClientError, KasumiClient, proto};
use kasumi_types::{
    OpenSnapshotLease, ReadSnapshotPage, ReadSnapshotRequest, ScanSnapshotPage, SnapshotLease,
    SnapshotReadResponse, SnapshotScanPage,
};
pub use resources::{
    AdmittedSnapshot, ClientResourceUsage, ClientResources, SnapshotDecodeLimits,
    SnapshotReadOptions,
};
pub(crate) use resources::{Call, normalize};
use resources::{exhausted, invalid};
use semantic::Expected;
use serde::Serialize;
use std::io::Write;

fn encode(request: &impl Serialize, call: &Call) -> Result<Vec<u8>, ClientError> {
    struct Output<'a> {
        bytes: Vec<u8>,
        maximum: usize,
        call: &'a Call,
    }
    impl Write for Output<'_> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.call
                .check()
                .map_err(|_| std::io::Error::other("snapshot request deadline elapsed"))?;
            let next = self
                .bytes
                .len()
                .checked_add(bytes.len())
                .ok_or_else(|| std::io::Error::other("snapshot request overflow"))?;
            if next > self.maximum {
                return Err(std::io::Error::other(
                    "snapshot request exceeds its admitted limit",
                ));
            }
            if next > self.bytes.capacity() {
                let capacity = self
                    .bytes
                    .capacity()
                    .max(1024)
                    .saturating_mul(2)
                    .max(next)
                    .min(self.maximum);
                self.bytes
                    .try_reserve_exact(capacity - self.bytes.len())
                    .map_err(|_| std::io::Error::other("snapshot request allocation failed"))?;
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    request::admit(request, call)?;
    let mut output = Output {
        bytes: Vec::new(),
        maximum: call.limits.max_request_bytes,
        call,
    };
    let result = serde_json::to_writer(&mut output, request);
    call.check()?;
    result.map_err(|_| exhausted())?;
    Ok(output.bytes)
}

use std::sync::Arc;
pub(crate) struct Prepared {
    request_json: Vec<u8>,
    expected: Expected,
    path: &'static str,
    // Retain the original metadata/request owner even when a cancelled attempt
    // still owns a body or decode worker and a new attempt is separately admitted.
    _owner: Call,
}
fn prepared(input: Vec<u8>, expected: Expected, path: &'static str, call: &Call) -> Arc<Prepared> {
    Arc::new(Prepared {
        request_json: input,
        expected,
        path,
        _owner: call.clone(),
    })
}
pub(crate) fn prepare_open(
    request: &OpenSnapshotLease,
    call: &Call,
) -> Result<Arc<Prepared>, ClientError> {
    let input = encode(request, call)?;
    if request.ttl_ms == 0 {
        return Err(invalid("empty snapshot lease lifetime"));
    }
    Ok(prepared(
        input,
        Expected::Open {
            ttl_ms: request.ttl_ms,
        },
        "/kasumi.v1.KasumiData/OpenSnapshotLease",
        call,
    ))
}
pub(crate) fn prepare_read(
    request: &ReadSnapshotRequest,
    call: &Call,
) -> Result<Arc<Prepared>, ClientError> {
    let input = encode(request, call)?;
    Ok(prepared(
        input,
        Expected::read(request, call)?,
        "/kasumi.v1.KasumiData/ReadSnapshot",
        call,
    ))
}
pub(crate) fn prepare_points(
    lease: &AdmittedSnapshot<SnapshotLease>,
    documents: &[kasumi_types::DocumentKey],
    call: &Call,
) -> Result<Arc<Prepared>, ClientError> {
    #[derive(Serialize)]
    struct Request<'a> {
        lease_id: &'a str,
        documents: &'a [kasumi_types::DocumentKey],
    }
    if documents.len() > call.limits.max_rows {
        return Err(exhausted());
    }
    let input = encode(
        &Request {
            lease_id: &lease.lease_id,
            documents,
        },
        call,
    )?;
    if documents
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        != documents.len()
    {
        return Err(invalid("duplicate requested snapshot point"));
    }
    Ok(prepared(
        input,
        Expected::Read {
            points: documents.to_vec(),
            queries: vec![],
            lease: Some((**lease).clone()),
        },
        "/kasumi.v1.KasumiData/ReadSnapshotPage",
        call,
    ))
}
pub(crate) fn prepare_scan(
    lease: &AdmittedSnapshot<SnapshotLease>,
    collection: &str,
    after_id: Option<&str>,
    limit: usize,
    call: &Call,
) -> Result<Arc<Prepared>, ClientError> {
    #[derive(Serialize)]
    struct Request<'a> {
        lease_id: &'a str,
        collection: &'a str,
        after_id: Option<&'a str>,
        limit: usize,
    }
    if limit == 0 || limit > call.limits.max_rows {
        return Err(exhausted());
    }
    let input = encode(
        &Request {
            lease_id: &lease.lease_id,
            collection,
            after_id,
            limit,
        },
        call,
    )?;
    Ok(prepared(
        input,
        Expected::Scan {
            lease: (**lease).clone(),
            collection: collection.to_owned(),
            after: after_id.map(str::to_owned),
            limit,
        },
        "/kasumi.v1.KasumiData/ScanSnapshotPage",
        call,
    ))
}
impl KasumiClient {
    pub async fn open_snapshot_lease(
        &mut self,
        bearer: &str,
        request: &OpenSnapshotLease,
        options: &SnapshotReadOptions,
    ) -> Result<AdmittedSnapshot<SnapshotLease>, ClientError> {
        let call = options.admit()?;
        self.snapshot_prepared(bearer, prepare_open(request, &call)?, call)
            .await
    }
    pub async fn read_snapshot(
        &mut self,
        bearer: &str,
        request: &ReadSnapshotRequest,
        options: &SnapshotReadOptions,
    ) -> Result<AdmittedSnapshot<SnapshotReadResponse>, ClientError> {
        let call = options.admit()?;
        self.snapshot_prepared(bearer, prepare_read(request, &call)?, call)
            .await
    }
    pub async fn read_snapshot_page(
        &mut self,
        bearer: &str,
        lease: &AdmittedSnapshot<SnapshotLease>,
        request: &ReadSnapshotPage,
        options: &SnapshotReadOptions,
    ) -> Result<AdmittedSnapshot<SnapshotReadResponse>, ClientError> {
        let call = options.admit()?;
        if request.lease_id != lease.lease_id {
            return Err(invalid(
                "snapshot point request differs from its original lease",
            ));
        }
        self.snapshot_prepared(
            bearer,
            prepare_points(lease, &request.documents, &call)?,
            call,
        )
        .await
    }
    pub async fn scan_snapshot_page(
        &mut self,
        bearer: &str,
        lease: &AdmittedSnapshot<SnapshotLease>,
        request: &ScanSnapshotPage,
        options: &SnapshotReadOptions,
    ) -> Result<AdmittedSnapshot<SnapshotScanPage>, ClientError> {
        let call = options.admit()?;
        if request.lease_id != lease.lease_id {
            return Err(invalid("snapshot scan differs from admitted lease"));
        }
        self.snapshot_prepared(
            bearer,
            prepare_scan(
                lease,
                &request.collection,
                request.after_id.as_deref(),
                request.limit,
                &call,
            )?,
            call,
        )
        .await
    }
    pub(crate) async fn snapshot_prepared<T: SnapshotOutput>(
        &mut self,
        bearer: &str,
        prepared: Arc<Prepared>,
        call: Call,
    ) -> Result<AdmittedSnapshot<T>, ClientError> {
        let mut waiter = call.waiter();
        call.check()?;
        let request = self
            .authorized(
                bearer,
                proto::ReadSnapshotRequest {
                    request_json: prepared.request_json.clone(),
                },
            )
            .map_err(normalize)?;
        let wire = tokio::time::timeout_at(
            call.deadline,
            transport::receive(
                self.snapshot_channel.clone(),
                request,
                prepared.path,
                call.clone(),
            ),
        )
        .await
        .map_err(|_| resources::deadline())??;
        let worker = decode_wire(wire, prepared);
        let response = tokio::time::timeout_at(call.deadline, worker)
            .await
            .map_err(|_| resources::deadline())?
            .map_err(|_| invalid("snapshot decode worker failed"))??;
        call.check()?;
        waiter.finished = true;
        Ok(response)
    }
}

pub(crate) trait SnapshotOutput: Send + Sync + 'static {
    fn from_decoded(value: semantic::Decoded) -> Result<Self, ClientError>
    where
        Self: Sized;
}
macro_rules! output {
    ($ty:ty, $variant:ident) => {
        impl SnapshotOutput for $ty {
            fn from_decoded(value: semantic::Decoded) -> Result<Self, ClientError> {
                match value {
                    semantic::Decoded::$variant(value) => Ok(value),
                    _ => Err(invalid("snapshot response kind differs")),
                }
            }
        }
    };
}
output!(SnapshotLease, Lease);
output!(SnapshotReadResponse, Read);
output!(SnapshotScanPage, Scan);

fn decode_wire<T: SnapshotOutput>(
    wire: transport::Wire,
    prepared: Arc<Prepared>,
) -> tokio::task::JoinHandle<Result<AdmittedSnapshot<T>, ClientError>> {
    tokio::task::spawn_blocking(move || {
        let result = (|| {
            tokens::admit(&wire.bytes, &wire.call)?;
            let decoded = prepared.expected.decode(&wire.bytes, &wire.call)?;
            wire.call.check()?;
            let value = T::from_decoded(decoded)?;
            wire.call.check()?;
            Ok::<_, ClientError>(AdmittedSnapshot::new(value, &wire.call))
        })();
        result.map_err(normalize)
    })
}

#[cfg(test)]
mod tests;
