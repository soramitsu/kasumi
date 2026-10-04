//! Seek paging: each page is read straight from a unique index, after the last
//! row of the previous page. Cursors are stateless tokens, so nothing is kept
//! between pages; a continuation instead proves that its source is unchanged.
use super::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A seek page's continuation. Clients treat the encoded token as opaque.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SeekCursor {
    /// The first page's revision, which every later page reports.
    pub(super) revision: u64,
    /// Digest of everything the walk depends on besides its rows.
    pub(super) source: String,
    /// Index key of the last row returned.
    pub(super) after: Vec<Value>,
}

impl SeekCursor {
    pub(super) fn decode(token: &str) -> Result<Self> {
        let invalid = || {
            Error::new(
                ErrorCode::InvalidArgument,
                "invalid seek cursor; resubmit the query without it",
            )
        };
        serde_json::from_slice(&hex::decode(token).map_err(|_| invalid())?).map_err(|_| invalid())
    }

    pub(super) fn encode(&self) -> Result<String> {
        serde_json::to_vec(self)
            .map(hex::encode)
            .map_err(|_| Error::new(ErrorCode::InvalidArgument, "seek cursor encoding failed"))
    }
}

/// The query, collection contents and indexes, policy and schema that a seek
/// walk reads. Any change ends the walk: its later pages could otherwise skip
/// or repeat rows relative to the first page's revision.
fn source_digest(state: &TenantState, request: &QueryRequest, revision: u64) -> Result<String> {
    let collection = state
        .collections
        .get(&request.collection)
        .ok_or_else(|| Error::new(ErrorCode::NotFound, "collection not found"))?;
    let identity = serde_json::to_vec(&(
        &state.tenant,
        &state.incarnation,
        revision,
        collection.data_epoch,
        state.policy_epoch,
        state.schema_epoch,
        &collection.definition.indexes,
        query_digest(request)?,
    ))
    .map_err(|_| Error::new(ErrorCode::InvalidArgument, "query encoding failed"))?;
    Ok(hex::encode(Sha256::digest(identity)))
}

fn expired() -> Error {
    Error::new(
        ErrorCode::CursorExpired,
        "seek cursor no longer matches: the query or its collection changed since the first page; start a new seek from the last row read",
    )
}

/// One seek page of `request` from `generation`, with its continuation.
pub(super) fn seek_page(
    generation: &Arc<crate::Generation>,
    request: &QueryRequest,
    cancellation: &QueryCancellation,
    memory: &mut QueryMemory<Reservation>,
) -> Result<QueryResponse> {
    cancellation.check()?;
    let state = &generation.state;
    // Digest construction and cursor parsing precede row assembly. Reserve
    // their provisional encoded-size workspace before allocating either;
    // retain the allowance with the worker through output destruction.
    let definition = state
        .collections
        .get(&request.collection)
        .ok_or_else(|| Error::new(ErrorCode::NotFound, "collection not found"))?;
    memory.reserve(query_input_workspace(
        &(
            request,
            &definition.definition.indexes,
            &state.tenant,
            &state.incarnation,
        ),
        4,
    )?)?;
    let cursor = request
        .cursor
        .as_deref()
        .map(SeekCursor::decode)
        .transpose()?;
    let revision = cursor
        .as_ref()
        .map_or(state.revision, |cursor| cursor.revision);
    let source = source_digest(state, request, revision)?;
    if let Some(cursor) = &cursor
        && (cursor.revision == 0 || cursor.revision > state.revision || cursor.source != source)
    {
        return Err(expired());
    }
    let page = generation
        .indexes
        .seek_page(
            &generation.document_source(&request.collection)?,
            request,
            cursor.as_ref().map(|cursor| cursor.after.as_slice()),
            &state.limits,
            &|after| {
                // Borrow the key for an exact size without allocating a token.
                #[derive(Serialize)]
                struct CursorView<'a> {
                    revision: u64,
                    source: &'a str,
                    after: &'a [Value],
                }
                crate::accounting::encoded_len(&CursorView {
                    revision,
                    source: &source,
                    after,
                })?
                .checked_mul(2)
                .ok_or_else(query_workspace_overflow)
            },
            cancellation,
            memory,
        )
        .map_err(ReadFailure::into_query_error)?;
    // Restored documents may have version zero. The first page's revision
    // remains the upper bound for every row a continuation returns.
    if page.rows.iter().any(|row| row.version > revision) {
        return Err(expired());
    }
    let cursor = match page.last_key {
        Some(after) => {
            let cursor = SeekCursor {
                revision,
                source,
                after,
            };
            // The JSON text and its hex token.
            let json = crate::accounting::encoded_len(&cursor)?;
            memory.reserve(
                kasumi_query::vec_bytes::<u8>(json)?
                    .checked_add(kasumi_query::vec_bytes::<u8>(
                        json.checked_mul(2).ok_or_else(query_workspace_overflow)?,
                    )?)
                    .ok_or_else(query_workspace_overflow)?,
            )?;
            Some(cursor.encode()?)
        }
        None => None,
    };
    Ok(QueryResponse {
        revision,
        rows: page.rows,
        aggregates: Vec::new(),
        cursor,
    })
}

#[cfg(test)]
#[path = "query_seek_tests.rs"]
mod tests;
