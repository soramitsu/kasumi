//! SDK-owned literal byte boundaries, independent of a caller's Cargo patches.
mod inputs;
mod json;
mod wire;
use crate::{
    AdmittedResponse, ClientError, JsonReadOptions, KasumiAdminClient, KasumiClient, proto,
    snapshot_decode::{
        self,
        resources::{Call, exhausted, invalid, normalize},
        tokens, transport,
    },
};
use kasumi_types::*;
use std::sync::Arc;

enum Kind {
    Query {
        request: QueryRequest,
        revision: Option<u64>,
    },
    Feed(ReadChangeFeed),
    Schema(ReadSchema),
    Audit(SecurityAuditExportRequest),
}
pub(crate) struct Prepared {
    input: Vec<u8>,
    kind: Kind,
    path: &'static str,
    _owner: Call,
}
impl Prepared {
    pub(crate) fn query(&self) -> &QueryRequest {
        match &self.kind {
            Kind::Query { request, .. } => request,
            _ => unreachable!("internal query handle"),
        }
    }
    fn format(&self) -> transport::Format {
        match self.kind {
            Kind::Query { .. } => transport::Format::QueryProtobuf,
            _ => transport::Format::JsonEnvelope,
        }
    }
}
pub(crate) fn prepare_query(
    request: &QueryRequest,
    revision: Option<u64>,
    call: &Call,
) -> Result<Arc<Prepared>, ClientError> {
    let input = snapshot_decode::encode(request, call)?;
    if request.limit == 0 || request.limit > call.limits.max_rows {
        return Err(exhausted());
    }
    Ok(Arc::new(Prepared {
        input,
        kind: Kind::Query {
            request: request.clone(),
            revision,
        },
        path: "/kasumi.v1.KasumiData/Query",
        _owner: call.clone(),
    }))
}
pub(crate) fn prepare_query_page(
    request: &QueryRequest,
    cursor: &str,
    revision: u64,
    call: &Call,
) -> Result<Arc<Prepared>, ClientError> {
    #[derive(serde::Serialize)]
    struct Borrowed<'a> {
        collection: &'a str,
        filter: &'a Predicate,
        sort: &'a [Sort],
        projection: &'a [String],
        aggregates: &'a [Aggregation],
        group_by: &'a [String],
        text: &'a Option<TextSearch>,
        limit: usize,
        cursor: Option<&'a str>,
        allow_scan: bool,
    }
    let input = snapshot_decode::encode(
        &Borrowed {
            collection: &request.collection,
            filter: &request.filter,
            sort: &request.sort,
            projection: &request.projection,
            aggregates: &request.aggregates,
            group_by: &request.group_by,
            text: &request.text,
            limit: request.limit,
            cursor: Some(cursor),
            allow_scan: request.allow_scan,
        },
        call,
    )?;
    if request.limit == 0 || request.limit > call.limits.max_rows {
        return Err(exhausted());
    }
    // Clone only after admitting the complete replacement cursor/request.
    let mut original = request.clone();
    original.cursor = Some(cursor.to_owned());
    Ok(Arc::new(Prepared {
        input,
        kind: Kind::Query {
            request: original,
            revision: Some(revision),
        },
        path: "/kasumi.v1.KasumiData/Query",
        _owner: call.clone(),
    }))
}
pub(crate) enum Decoded {
    Query(QueryResponse),
    Feed(ChangeFeedPage),
    Schema(SchemaSnapshot),
    Audit(SecurityAuditPage),
}
pub(crate) trait Output: Send + Sync + 'static {
    fn take(decoded: Decoded) -> Result<Self, ClientError>
    where
        Self: Sized;
}
macro_rules! output {
    ($ty:ty,$variant:ident) => {
        impl Output for $ty {
            fn take(decoded: Decoded) -> Result<Self, ClientError> {
                match decoded {
                    Decoded::$variant(v) => Ok(v),
                    _ => Err(invalid("native response kind differs")),
                }
            }
        }
    };
}
output!(QueryResponse, Query);
output!(ChangeFeedPage, Feed);
output!(SchemaSnapshot, Schema);
output!(SecurityAuditPage, Audit);
fn decode<T: Output>(bytes: &[u8], prepared: &Prepared, call: &Call) -> Result<T, ClientError> {
    let value = if let Kind::Query { request, revision } = &prepared.kind {
        Decoded::Query(wire::query(bytes, request, *revision, call)?)
    } else {
        if matches!(prepared.kind, Kind::Audit(_)) && bytes.len() > MAX_SECURITY_AUDIT_PAGE_BYTES {
            return Err(exhausted());
        }
        tokens::admit(bytes, call)?;
        let raw: &serde_json::value::RawValue = serde_json::from_slice(bytes)?;
        match &prepared.kind {
            Kind::Feed(request) => Decoded::Feed(json::feed(raw, request, call)?),
            Kind::Schema(request) => Decoded::Schema(json::schema(raw, request, call)?),
            Kind::Audit(request) => Decoded::Audit(json::audit(raw, request, call)?),
            Kind::Query { .. } => unreachable!(),
        }
    };
    call.check()?;
    T::take(value)
}
async fn execute<T: Output>(
    channel: tonic::transport::Channel,
    bearer: &str,
    prepared: Arc<Prepared>,
    call: Call,
) -> Result<AdmittedResponse<T>, ClientError> {
    let mut waiter = call.waiter();
    call.check()?;
    let request = crate::authorized(
        bearer,
        proto::ReadSnapshotRequest {
            request_json: prepared.input.clone(),
        },
    )
    .map_err(normalize)?;
    let wire = tokio::time::timeout_at(
        call.deadline,
        transport::receive(
            channel,
            request,
            prepared.path,
            prepared.format(),
            call.clone(),
        ),
    )
    .await
    .map_err(|_| snapshot_decode::resources::deadline())??;
    let worker = tokio::task::spawn_blocking(move || {
        let result = (|| {
            let value = decode::<T>(&wire.bytes, &prepared, &wire.call)?;
            wire.call.check()?;
            Ok(AdmittedResponse::new(value, &wire.call))
        })();
        result.map_err(normalize)
    });
    let response = tokio::time::timeout_at(call.deadline, worker)
        .await
        .map_err(|_| snapshot_decode::resources::deadline())?
        .map_err(|_| invalid("native decode worker failed"))??;
    call.check()?;
    waiter.finished = true;
    Ok(response)
}
impl KasumiClient {
    /// Ordinary query results are not a complete conditional-write dependency
    /// set. Use coherent snapshot reads when writes depend on completeness.
    pub async fn query(
        &mut self,
        bearer: &str,
        request: &QueryRequest,
        options: &JsonReadOptions,
    ) -> Result<AdmittedResponse<QueryResponse>, ClientError> {
        let call = options.admit()?;
        self.query_prepared(bearer, prepare_query(request, None, &call)?, call)
            .await
    }
    pub(crate) async fn query_prepared(
        &mut self,
        bearer: &str,
        prepared: Arc<Prepared>,
        call: Call,
    ) -> Result<AdmittedResponse<QueryResponse>, ClientError> {
        execute(self.snapshot_channel.clone(), bearer, prepared, call).await
    }
    pub async fn read_change_feed(
        &mut self,
        bearer: &str,
        request: &ReadChangeFeed,
        options: &JsonReadOptions,
    ) -> Result<AdmittedResponse<ChangeFeedPage>, ClientError> {
        let call = options.admit()?;
        let input = snapshot_decode::encode(request, &call)?;
        if request.limit == 0 || request.limit > call.limits.max_rows {
            return Err(exhausted());
        }
        let prepared = Arc::new(Prepared {
            input,
            kind: Kind::Feed(request.clone()),
            path: "/kasumi.v1.KasumiData/ReadChangeFeed",
            _owner: call.clone(),
        });
        execute(self.snapshot_channel.clone(), bearer, prepared, call).await
    }
}
impl KasumiAdminClient {
    pub async fn read_schema(
        &mut self,
        bearer: &str,
        request: &ReadSchema,
        options: &JsonReadOptions,
    ) -> Result<AdmittedResponse<SchemaSnapshot>, ClientError> {
        let call = options.admit()?;
        let input = snapshot_decode::encode(request, &call)?;
        if request.collections.len() > call.limits.max_rows {
            return Err(exhausted());
        }
        let prepared = Arc::new(Prepared {
            input,
            kind: Kind::Schema(request.clone()),
            path: "/kasumi.v1.KasumiAdmin/ReadSchema",
            _owner: call.clone(),
        });
        execute(self.bounded_channel.clone(), bearer, prepared, call).await
    }
    pub async fn export_security_audit(
        &mut self,
        bearer: &str,
        request: &SecurityAuditExportRequest,
        options: &JsonReadOptions,
    ) -> Result<AdmittedResponse<SecurityAuditPage>, ClientError> {
        let call = options.admit()?;
        request
            .validate()
            .map_err(|_| invalid("invalid audit export request"))?;
        let input = snapshot_decode::encode(request, &call)?;
        if usize::from(request.limit) > call.limits.max_rows {
            return Err(exhausted());
        }
        let prepared = Arc::new(Prepared {
            input,
            kind: Kind::Audit(request.clone()),
            path: "/kasumi.v1.KasumiAdmin/SecurityAuditExport",
            _owner: call.clone(),
        });
        execute(self.bounded_channel.clone(), bearer, prepared, call).await
    }
}

/// Parse an application's canonical JSON intent before sending/digesting it.
/// Application-created Values and stock Serde decoding remain caller-owned.
pub async fn decode_mutation_json(
    bytes: &[u8],
    options: &JsonReadOptions,
) -> Result<AdmittedResponse<MutationBatch>, ClientError> {
    input(bytes, options, inputs::mutation_batch).await
}
pub async fn decode_staged_chunk_json(
    bytes: &[u8],
    options: &JsonReadOptions,
) -> Result<AdmittedResponse<StagedChunk>, ClientError> {
    input(bytes, options, inputs::staged_chunk).await
}
pub async fn decode_query_json(
    bytes: &[u8],
    options: &JsonReadOptions,
) -> Result<AdmittedResponse<QueryRequest>, ClientError> {
    input(bytes, options, inputs::query).await
}
pub async fn decode_schema_change_json(
    bytes: &[u8],
    options: &JsonReadOptions,
) -> Result<AdmittedResponse<SchemaChangeSet>, ClientError> {
    input(bytes, options, inputs::schema_change).await
}
async fn input<T: Send + Sync + 'static>(
    bytes: &[u8],
    options: &JsonReadOptions,
    build: fn(&serde_json::value::RawValue, &Call) -> Result<T, ClientError>,
) -> Result<AdmittedResponse<T>, ClientError> {
    let call = options.admit()?;
    let mut waiter = call.waiter();
    if bytes.len() > call.limits.max_request_bytes || bytes.len() > call.limits.max_json_bytes {
        return Err(exhausted());
    }
    let bytes = bytes.to_vec();
    let owner = call.clone();
    let worker = tokio::task::spawn_blocking(move || {
        let result = (|| {
            tokens::admit(&bytes, &owner)?;
            let raw: &serde_json::value::RawValue = serde_json::from_slice(&bytes)?;
            let value = build(raw, &owner)?;
            owner.check()?;
            Ok(AdmittedResponse::new(value, &owner))
        })();
        result.map_err(normalize)
    });
    let result = tokio::time::timeout_at(call.deadline, worker)
        .await
        .map_err(|_| snapshot_decode::resources::deadline())?
        .map_err(|_| invalid("native input decode worker failed"))??;
    call.check()?;
    waiter.finished = true;
    Ok(result)
}

#[cfg(test)]
mod tests;
