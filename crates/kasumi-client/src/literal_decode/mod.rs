//! SDK-owned literal byte boundaries, independent of a caller's Cargo patches.
mod inputs;
mod json;
mod ordered_seek;
mod wire;
use crate::{
    AdmittedResponse, ClientError, JsonReadOptions, KasumiAdminClient, KasumiClient, proto,
    snapshot_decode::{
        self,
        resources::{Call, exhausted, invalid, normalize},
        tokens, transport,
    },
};
use kasumi_types::{
    Aggregation, ChangeFeedPage, MAX_POLICY_LIMITS_SNAPSHOT_BYTES, MAX_SECURITY_AUDIT_PAGE_BYTES,
    MutationBatch, OrderedSeekRequest, OrderedSeekResponse, PolicyLimitsSnapshot, Predicate,
    QueryRequest, QueryResponse, ReadChangeFeed, ReadPolicyLimits, ReadSchema, SchemaChangeSet,
    SchemaSnapshot, SecurityAuditExportRequest, SecurityAuditPage, Sort, StagedChunk, TextSearch,
};
use std::sync::Arc;

enum Kind {
    OrderedSeek {
        request: OrderedSeekRequest,
        digest: String,
    },
    Query {
        request: QueryRequest,
        revision: Option<u64>,
    },
    Feed(ReadChangeFeed),
    Schema(ReadSchema),
    PolicyLimits(ReadPolicyLimits),
    Audit(SecurityAuditExportRequest),
}
pub(crate) struct Prepared {
    input: Vec<u8>,
    kind: Kind,
    path: &'static str,
    _owner: Call,
}
impl Prepared {
    pub(crate) fn ordered_seek(&self) -> &OrderedSeekRequest {
        match &self.kind {
            Kind::OrderedSeek { request, .. } => request,
            _ => unreachable!("internal ordered seek handle"),
        }
    }
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
pub(crate) fn prepare_ordered_seek(
    request: &OrderedSeekRequest,
    call: &Call,
) -> Result<Arc<Prepared>, ClientError> {
    prepare_ordered_seek_page(request, request.continuation.as_ref(), call)
}
pub(crate) fn prepare_ordered_seek_page(
    request: &OrderedSeekRequest,
    continuation: Option<&kasumi_types::OrderedSeekContinuation>,
    call: &Call,
) -> Result<Arc<Prepared>, ClientError> {
    use sha2::{Digest, Sha256};
    #[derive(serde::Serialize)]
    struct Borrowed<'a> {
        collection: &'a str,
        index: &'a str,
        prefix: &'a [serde_json::Value],
        lower: &'a Option<kasumi_types::OrderedSeekBound>,
        upper: &'a Option<kasumi_types::OrderedSeekBound>,
        direction: kasumi_types::Direction,
        limit: usize,
        continuation: Option<&'a kasumi_types::OrderedSeekContinuation>,
    }
    let mut borrowed = Borrowed {
        collection: &request.collection,
        index: &request.index,
        prefix: &request.prefix,
        lower: &request.lower,
        upper: &request.upper,
        direction: request.direction,
        limit: request.limit,
        continuation,
    };
    let input = snapshot_decode::encode(&borrowed, call)?;
    if request.limit == 0 || request.limit > call.limits.max_rows || request.limit > 1000 {
        return Err(exhausted());
    }
    borrowed.continuation = None;
    let digest = hex::encode(Sha256::digest(snapshot_decode::encode(&borrowed, call)?));
    if continuation.is_some_and(|c| c.request_sha256 != digest) {
        return Err(ClientError::DecodeRejected {
            code: tonic::Code::InvalidArgument,
            reason: "ordered seek continuation request differs",
        });
    }
    // Both original request and replacement cursor have passed this call's
    // actual limits before any retained typed clone is allocated.
    let mut original = request.clone();
    original.continuation = continuation.cloned();
    Ok(Arc::new(Prepared {
        input,
        kind: Kind::OrderedSeek {
            request: original,
            digest,
        },
        path: "/kasumi.v1.KasumiData/OrderedSeek",
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
    OrderedSeek(OrderedSeekResponse),
    Query(QueryResponse),
    Feed(ChangeFeedPage),
    Schema(SchemaSnapshot),
    PolicyLimits(PolicyLimitsSnapshot),
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
output!(OrderedSeekResponse, OrderedSeek);
output!(ChangeFeedPage, Feed);
output!(SchemaSnapshot, Schema);
output!(PolicyLimitsSnapshot, PolicyLimits);
output!(SecurityAuditPage, Audit);
fn decode<T: Output>(bytes: &[u8], prepared: &Prepared, call: &Call) -> Result<T, ClientError> {
    let value = if let Kind::Query { request, revision } = &prepared.kind {
        Decoded::Query(wire::query(bytes, request, *revision, call)?)
    } else {
        if matches!(prepared.kind, Kind::Audit(_)) && bytes.len() > MAX_SECURITY_AUDIT_PAGE_BYTES {
            return Err(exhausted());
        }
        if matches!(prepared.kind, Kind::PolicyLimits(_))
            && bytes.len() > MAX_POLICY_LIMITS_SNAPSHOT_BYTES
        {
            return Err(exhausted());
        }
        tokens::admit(bytes, call)?;
        let raw: &serde_json::value::RawValue = serde_json::from_slice(bytes)?;
        match &prepared.kind {
            Kind::OrderedSeek { request, digest } => {
                Decoded::OrderedSeek(ordered_seek::decode(raw, request, digest, call)?)
            }
            Kind::Feed(request) => Decoded::Feed(json::feed(raw, request, call)?),
            Kind::Schema(request) => Decoded::Schema(json::schema(raw, request, call)?),
            Kind::PolicyLimits(request) => {
                Decoded::PolicyLimits(json::policy_limits(raw, request, call)?)
            }
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
    /// Bounded unique-index discovery, with exact source identity on continuation.
    /// Conditional effects must still reread selected records and range guards.
    pub async fn ordered_seek(
        &mut self,
        bearer: &str,
        request: &OrderedSeekRequest,
        options: &JsonReadOptions,
    ) -> Result<AdmittedResponse<OrderedSeekResponse>, ClientError> {
        let call = options.admit()?;
        self.ordered_seek_prepared(bearer, prepare_ordered_seek(request, &call)?, call)
            .await
    }
    pub(crate) async fn ordered_seek_prepared(
        &mut self,
        bearer: &str,
        prepared: Arc<Prepared>,
        call: Call,
    ) -> Result<AdmittedResponse<OrderedSeekResponse>, ClientError> {
        execute(self.snapshot_channel.clone(), bearer, prepared, call).await
    }
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
    pub async fn read_policy_limits(
        &mut self,
        bearer: &str,
        request: &ReadPolicyLimits,
        options: &JsonReadOptions,
    ) -> Result<AdmittedResponse<PolicyLimitsSnapshot>, ClientError> {
        let call = options.admit()?;
        let input = snapshot_decode::encode(request, &call)?;
        let prepared = Arc::new(Prepared {
            input,
            kind: Kind::PolicyLimits(request.clone()),
            path: "/kasumi.v1.KasumiAdmin/ReadPolicyLimits",
            _owner: call.clone(),
        });
        execute(self.bounded_channel.clone(), bearer, prepared, call).await
    }
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
