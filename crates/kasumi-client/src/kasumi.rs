//! The high-level data client: one cloneable handle with defaults for
//! credentials, decode budgets and deadlines.
//!
//! ```no_run
//! # async fn example() -> Result<(), kasumi_client::ClientError> {
//! use kasumi_client::prelude::*;
//! use serde_json::json;
//!
//! let db = Kasumi::from_profile("/var/lib/kasumi/profiles/default.json").await?;
//! db.mutate(&MutationBatch::new().insert("invoices", "inv-1", json!({"status": "open", "amount": 42})))
//!     .await?;
//! let invoice = db.get("invoices", "inv-1").await?;
//! let open = db
//!     .query(
//!         &QueryRequest::new("invoices")
//!             .filter(Filter::new().eq("/status", "open").gte("/amount", 10))
//!             .sort_desc("/amount")
//!             .limit(20),
//!     )
//!     .await?;
//! for row in open.rows() {
//!     println!("{} {}", row.id, row.body);
//! }
//! # Ok(()) }
//! ```
//!
//! Responses are decoded under the SDK's bounded admission and then handed to
//! the application as ordinary owned values. The low-level [`KasumiClient`]
//! remains available for callers that retain admitted responses directly.
use crate::{
    AdmittedResponse, ClientDecodeLimits, ClientError, ClientProfile, ClientResources,
    JsonReadOptions, KasumiClient, KasumiClientConfig,
};
use kasumi_transport::credentials::{CredentialSource, FileCredentialSource, token};
use kasumi_types::{
    CollectionDefinition, Document, ErrorCode, MutationBatch, QueryRequest, QueryResponse,
    QueryRow, WriteReceipt,
};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::{path::Path, sync::Arc, time::Duration};
use tokio::time::Instant;

/// Calls that may decode concurrently through one handle and its clones.
const CONCURRENT_CALLS: u64 = 256;

/// A connected data client. Clones share one connection and decode budget.
#[derive(Clone)]
pub struct Kasumi {
    client: KasumiClient,
    credential: Arc<dyn CredentialSource>,
    resources: Arc<ClientResources>,
    limits: ClientDecodeLimits,
    timeout: Duration,
}

/// A document body decoded into an application type.
#[derive(Debug, Clone, PartialEq)]
pub struct TypedDocument<T> {
    pub id: String,
    pub version: u64,
    pub body: T,
}

/// One page of query results. Continue with [`Kasumi::next_page`].
#[derive(Debug, Clone)]
pub struct QueryPage {
    query: QueryRequest,
    response: QueryResponse,
}

impl Kasumi {
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

    /// Connect with an installed client profile: its endpoint, TLS identity,
    /// trusted CA, server pin and renewable bearer file. The bearer file is
    /// reread for every operation, so credential renewal needs no reconnect.
    /// Mutation retries retain that operation's credential snapshot.
    pub async fn from_profile(path: impl AsRef<Path>) -> Result<Self, ClientError> {
        let profile = ClientProfile::load(path.as_ref())?;
        let config = profile.connection(false)?;
        let credential = FileCredentialSource::new(&profile.bearer_file)?;
        Self::connect(&config, credential).await
    }

    /// Connect with explicit TLS settings and a bearer token source, such as
    /// `FileCredentialSource` or a closure returning the current token.
    pub async fn connect(
        config: &KasumiClientConfig,
        credential: impl CredentialSource + 'static,
    ) -> Result<Self, ClientError> {
        let limits = ClientDecodeLimits::default();
        Ok(Self {
            client: KasumiClient::connect(config).await?,
            credential: Arc::new(credential),
            resources: budget(&limits)?,
            limits,
            timeout: Self::DEFAULT_TIMEOUT,
        })
    }

    /// Deadline for each call, including decoding.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Replace the per-call response bounds and their shared budget.
    pub fn with_decode_limits(mut self, limits: ClientDecodeLimits) -> Result<Self, ClientError> {
        self.resources = budget(&limits)?;
        self.limits = limits;
        Ok(self)
    }

    /// The low-level client, for snapshots, leases and staged transactions.
    pub fn client(&self) -> KasumiClient {
        self.client.clone()
    }

    fn options(&self) -> Result<JsonReadOptions, ClientError> {
        Ok(JsonReadOptions {
            resources: self.resources.clone(),
            limits: self.limits,
            deadline: deadline(self.timeout)?,
        })
    }

    fn bearer(&self) -> Result<zeroize::Zeroizing<String>, ClientError> {
        token(self.credential.as_ref()).map_err(|_| ClientError::Authorization)
    }

    /// Authorized collections with their schemas and declared indexes.
    pub async fn collections(&self) -> Result<Vec<CollectionDefinition>, ClientError> {
        let response = self
            .client
            .clone()
            .collections(&self.bearer()?, &self.options()?)
            .await?;
        Ok(Vec::clone(&response))
    }

    /// Read one document; `None` when it does not exist.
    pub async fn get(&self, collection: &str, id: &str) -> Result<Option<Document>, ClientError> {
        let response = self
            .client
            .clone()
            .get(&self.bearer()?, collection, id, &self.options()?)
            .await?;
        Ok(response.map(|document| Document::clone(&document)))
    }

    /// Read one document and deserialize its body.
    pub async fn get_as<T: DeserializeOwned>(
        &self,
        collection: &str,
        id: &str,
    ) -> Result<Option<TypedDocument<T>>, ClientError> {
        self.get(collection, id)
            .await?
            .map(|document| typed(document.id, document.version, document.body))
            .transpose()
    }

    /// Run a query and return its first page.
    pub async fn query(&self, query: &QueryRequest) -> Result<QueryPage, ClientError> {
        let response = self
            .client
            .clone()
            .query(&self.bearer()?, query, &self.options()?)
            .await?;
        Ok(QueryPage::new(query.clone(), &response))
    }

    /// The page after `page`, or `None` at the end. Pages continue the
    /// original snapshot; an expired cursor reports `ErrorCode::CursorExpired`.
    pub async fn next_page(&self, page: &QueryPage) -> Result<Option<QueryPage>, ClientError> {
        let Some(cursor) = page.response.cursor.as_deref() else {
            return Ok(None);
        };
        let options = self.options()?;
        let call = options.admit()?;
        let prepared = crate::literal_decode::prepare_query_page(
            &page.query,
            cursor,
            page.response.revision,
            &call,
        )?;
        let response = self
            .client
            .clone()
            .query_prepared(&self.bearer()?, prepared, call)
            .await?;
        Ok(Some(QueryPage::new(page.query.clone(), &response)))
    }

    /// Every row of a row query, following cursors to the end of its snapshot.
    /// Aggregate queries are rejected; use [`Self::query`] and
    /// [`QueryPage::aggregates`] for those. The collected rows are owned by the
    /// application and can exceed the per-page decode budget.
    pub async fn query_all(&self, query: &QueryRequest) -> Result<Vec<QueryRow>, ClientError> {
        if query.is_aggregate() {
            return Err(ClientError::DecodeRejected {
                code: tonic::Code::InvalidArgument,
                reason: "query_all requires a row query; use query for aggregates",
                database: None,
            });
        }
        let mut page = self.query(query).await?;
        let mut rows = Vec::new();
        loop {
            let next = self.next_page(&page).await?;
            rows.append(&mut page.response.rows);
            match next {
                Some(next) => page = next,
                None => return Ok(rows),
            }
        }
    }

    /// Create one document that must not exist yet.
    pub async fn insert(
        &self,
        collection: &str,
        id: &str,
        body: impl Into<Value>,
    ) -> Result<WriteReceipt, ClientError> {
        self.mutate(&MutationBatch::new().insert(collection, id, body))
            .await
    }

    /// Create or overwrite one document.
    pub async fn upsert(
        &self,
        collection: &str,
        id: &str,
        body: impl Into<Value>,
    ) -> Result<WriteReceipt, ClientError> {
        self.mutate(&MutationBatch::new().upsert(collection, id, body))
            .await
    }

    /// Overwrite one document only if it is still at `version`.
    pub async fn replace(
        &self,
        collection: &str,
        id: &str,
        body: impl Into<Value>,
        version: u64,
    ) -> Result<WriteReceipt, ClientError> {
        self.mutate(&MutationBatch::new().replace(collection, id, body, version))
            .await
    }

    /// Merge an RFC 7396 patch into one existing document.
    pub async fn patch(
        &self,
        collection: &str,
        id: &str,
        patch: impl Into<Value>,
    ) -> Result<WriteReceipt, ClientError> {
        self.mutate(&MutationBatch::new().patch(collection, id, patch))
            .await
    }

    /// Delete one document if it exists.
    pub async fn delete(&self, collection: &str, id: &str) -> Result<WriteReceipt, ClientError> {
        self.mutate(&MutationBatch::new().delete(collection, id))
            .await
    }

    /// Apply an atomic batch. An uncertain outcome (`UnknownOutcome` or
    /// `Unavailable`) is resolved by resending the identical batch, which
    /// carries the same idempotency key, until the call's deadline; the
    /// database applies it at most once. An error after a dispatch, including
    /// a deadline, can still hide a commit: resend the same batch later rather
    /// than building a new one.
    pub async fn mutate(&self, batch: &MutationBatch) -> Result<WriteReceipt, ClientError> {
        let deadline = deadline(self.timeout)?;
        // The idempotency receipt belongs to the original principal. A source
        // rotation must not change authority between attempts of this batch.
        let bearer = self.bearer()?;
        let mut delay = Duration::from_millis(50);
        loop {
            let mut client = self.client.clone();
            client.set_deadline(deadline);
            let result = tokio::time::timeout_at(deadline, client.mutate(&bearer, batch))
                .await
                .map_err(|_| crate::snapshot_decode::resources::deadline())?;
            match result {
                Err(error) if uncertain(&error) && Instant::now() + delay < deadline => {
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_secs(1));
                }
                result => return result,
            }
        }
    }
}

fn deadline(timeout: Duration) -> Result<Instant, ClientError> {
    if timeout.is_zero() {
        return Err(crate::snapshot_decode::resources::deadline());
    }
    Instant::now()
        .checked_add(timeout)
        .ok_or_else(crate::snapshot_decode::resources::deadline)
}

/// Retrying the identical batch is safe only for outcomes that may not have
/// applied yet; definite rejections such as `Conflict` are returned.
fn uncertain(error: &ClientError) -> bool {
    match error.code() {
        Some(code) => matches!(code, ErrorCode::UnknownOutcome | ErrorCode::Unavailable),
        None => {
            matches!(error, ClientError::Transport(status) if status.code() == tonic::Code::Unavailable)
        }
    }
}

/// Room for `CONCURRENT_CALLS` in-flight decodes. Each call's charge ends when
/// its response is handed to the application as owned values.
fn budget(limits: &ClientDecodeLimits) -> Result<Arc<ClientResources>, ClientError> {
    let bytes = limits
        .accounted_bytes()?
        .checked_mul(CONCURRENT_CALLS)
        .ok_or(ClientError::RequestTooLarge)?;
    ClientResources::new(bytes, CONCURRENT_CALLS as usize)
}

fn typed<T: DeserializeOwned>(
    id: String,
    version: u64,
    body: Value,
) -> Result<TypedDocument<T>, ClientError> {
    Ok(TypedDocument {
        id,
        version,
        body: serde_json::from_value(body)?,
    })
}

impl QueryPage {
    fn new(query: QueryRequest, response: &AdmittedResponse<QueryResponse>) -> Self {
        Self {
            query,
            response: QueryResponse::clone(response),
        }
    }

    pub fn rows(&self) -> &[QueryRow] {
        &self.response.rows
    }

    /// Aggregate queries: `{"group": {...}, "values": {alias: value}}` entries.
    pub fn aggregates(&self) -> &[Value] {
        &self.response.aggregates
    }

    /// The data revision this page (and every continuation) reads.
    pub fn revision(&self) -> u64 {
        self.response.revision
    }

    pub fn has_more(&self) -> bool {
        self.response.cursor.is_some()
    }

    /// Deserialize every row body, for example into a struct matching `select`.
    pub fn decode<T: DeserializeOwned>(&self) -> Result<Vec<TypedDocument<T>>, ClientError> {
        self.response
            .rows
            .iter()
            .map(|row| typed(row.id.clone(), row.version, row.body.clone()))
            .collect()
    }

    pub fn into_rows(self) -> Vec<QueryRow> {
        self.response.rows
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_bounds_return_errors_without_panicking() {
        assert!(deadline(Duration::ZERO).is_err());
        assert!(deadline(Duration::MAX).is_err());
        assert!(deadline(Kasumi::DEFAULT_TIMEOUT).is_ok());
    }

    #[test]
    fn only_possibly_unapplied_outcomes_are_resent() {
        let status = |code: tonic::Code, details: &str| {
            ClientError::Transport(tonic::Status::with_details(
                code,
                "peer",
                bytes::Bytes::from(details.as_bytes().to_vec()),
            ))
        };
        for (error, expected) in [
            (
                status(
                    tonic::Code::Unavailable,
                    r#"{"code":"UNKNOWN_OUTCOME","message":"resolve"}"#,
                ),
                true,
            ),
            (
                status(
                    tonic::Code::Unavailable,
                    r#"{"code":"UNAVAILABLE","message":"leader"}"#,
                ),
                true,
            ),
            (status(tonic::Code::Unavailable, ""), true),
            (
                status(
                    tonic::Code::Aborted,
                    r#"{"code":"CONFLICT","message":"version differs"}"#,
                ),
                false,
            ),
            (
                status(
                    tonic::Code::Unavailable,
                    r#"{"code":"AUDIT_UNAVAILABLE","message":"audit"}"#,
                ),
                false,
            ),
            (ClientError::Authorization, false),
        ] {
            assert_eq!(uncertain(&error), expected, "{error}");
        }
    }

    #[test]
    fn pages_decode_rows_into_application_types() {
        #[derive(serde::Deserialize, Debug, PartialEq)]
        struct Invoice {
            amount: u64,
        }
        let page = QueryPage {
            query: QueryRequest::new("invoices"),
            response: QueryResponse {
                revision: 3,
                rows: vec![QueryRow {
                    id: "inv-1".into(),
                    version: 2,
                    body: serde_json::json!({"amount": 42}),
                    score: None,
                }],
                aggregates: vec![],
                cursor: None,
            },
        };
        assert!(!page.has_more());
        assert_eq!(
            page.decode::<Invoice>().unwrap(),
            vec![TypedDocument {
                id: "inv-1".into(),
                version: 2,
                body: Invoice { amount: 42 },
            }]
        );
        assert!(budget(&ClientDecodeLimits::default()).is_ok());
    }
}
