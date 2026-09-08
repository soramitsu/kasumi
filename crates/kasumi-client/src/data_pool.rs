//! Installed native endpoint routing. Historical pages carry their originating
//! member in an opaque SDK handle; retry cannot turn them into a fresh snapshot.
use crate::{ClientError, KasumiClient, KasumiClientConfig};
use kasumi_transport::credentials::{CredentialSource, token};
use kasumi_types::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    pin::Pin,
    sync::Arc,
    time::Duration,
};
use tokio::time::Instant;

type Reply<'a, T> = Pin<Box<dyn Future<Output = std::result::Result<T, ClientError>> + Send + 'a>>;
type NativeResult<T> = std::result::Result<T, ClientError>;

#[derive(Clone)]
pub struct KasumiClientPool {
    installation: uuid::Uuid,
    endpoints: BTreeMap<u64, KasumiClientConfig>,
    clients: BTreeMap<u64, KasumiClient>,
    credential: Arc<dyn CredentialSource>,
    preferred: u64,
}
/// The returned cursor is valid only on this originating member. No Deserialize
/// constructor exists, and moving a page to another pool is rejected.
#[derive(Clone)]
pub struct RoutedQueryPage {
    installation: uuid::Uuid,
    member: u64,
    query: QueryRequest,
    response: QueryResponse,
}
impl RoutedQueryPage {
    pub fn response(&self) -> &QueryResponse {
        &self.response
    }
    pub fn member(&self) -> u64 {
        self.member
    }
}
#[derive(Clone)]
pub struct RoutedSnapshotLease {
    installation: uuid::Uuid,
    member: u64,
    lease: SnapshotLease,
}
impl RoutedSnapshotLease {
    pub fn lease(&self) -> &SnapshotLease {
        &self.lease
    }
    pub fn member(&self) -> u64 {
        self.member
    }
}
impl KasumiClientPool {
    pub fn new(
        endpoints: BTreeMap<u64, KasumiClientConfig>,
        credential: Arc<dyn CredentialSource>,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !endpoints.is_empty() && endpoints.len() <= 64 && !endpoints.contains_key(&0),
            "native pool requires one to 64 installed member IDs"
        );
        let mut origins = BTreeSet::new();
        let certificate = endpoints
            .values()
            .next()
            .unwrap()
            .identity
            .certificate_pin();
        for config in endpoints.values() {
            let url = url::Url::parse(&config.endpoint)?;
            anyhow::ensure!(
                url.scheme() == "https"
                    && url.host_str().is_some()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none()
                    && url.path() == "/"
                    && !config.server_certificate_pins.is_empty()
                    && config.identity.certificate_pin() == certificate
                    && origins.insert(url.to_string()),
                "invalid or duplicate native member endpoint"
            );
        }
        Ok(Self {
            installation: uuid::Uuid::new_v4(),
            preferred: *endpoints.keys().next().unwrap(),
            endpoints,
            clients: BTreeMap::new(),
            credential,
        })
    }
    async fn request<T, F>(
        &mut self,
        pinned: Option<u64>,
        replay: bool,
        timeout: Duration,
        mut dispatch: F,
    ) -> NativeResult<(u64, T)>
    where
        T: Send,
        F: for<'a> FnMut(&'a mut KasumiClient, &'a str) -> Reply<'a, T>,
    {
        if timeout.is_zero() {
            return Err(deadline());
        }
        let end = Instant::now().checked_add(timeout).ok_or_else(deadline)?;
        // One atomic credential snapshot belongs to this entire finite operation.
        // Renewal is observed by the next invocation, never by an endpoint retry.
        let bearer = token(self.credential.as_ref()).map_err(|_| ClientError::Authorization)?;
        let mut members = if let Some(member) = pinned {
            if !self.endpoints.contains_key(&member) {
                return Err(ClientError::Authorization);
            }
            vec![member]
        } else {
            let mut members: Vec<_> = self.endpoints.keys().copied().collect();
            let index = members.iter().position(|id| *id == self.preferred).unwrap();
            members.rotate_left(index);
            members
        };
        loop {
            for member in &members {
                let remaining = end.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(deadline());
                }
                let attempt_end = Instant::now()
                    + remaining.min((timeout / members.len() as u32).max(Duration::from_millis(1)));
                let mut dispatched = false;
                let result = tokio::time::timeout_at(attempt_end, async {
                    if let std::collections::btree_map::Entry::Vacant(entry) =
                        self.clients.entry(*member)
                    {
                        let client = KasumiClient::connect(&self.endpoints[member])
                            .await
                            .map_err(|_| {
                                ClientError::Transport(tonic::Status::unavailable(
                                    "installed data member connection failed",
                                ))
                            })?;
                        entry.insert(client);
                    }
                    dispatched = true;
                    let client = self.clients.get_mut(member).unwrap();
                    client.set_deadline(end);
                    dispatch(client, &bearer).await
                })
                .await;
                match result {
                    Ok(Ok(reply)) => {
                        self.preferred = *member;
                        return Ok((*member, reply));
                    }
                    Ok(Err(error)) if retryable(&error) && (!dispatched || replay) => {
                        self.clients.remove(member);
                    }
                    Err(_) if !dispatched || replay => {
                        self.clients.remove(member);
                    }
                    Err(_) => return Err(deadline()),
                    Ok(Err(error)) => return Err(error),
                }
            }
            let remaining = end.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(deadline());
            }
            tokio::time::sleep(remaining.min(Duration::from_millis(25))).await;
            if pinned.is_none() {
                members.rotate_left(1);
            }
        }
    }
    /// Exact replay includes the original idempotency key, body and read set;
    /// the database resolves its durable receipt or reports a real conflict.
    pub async fn mutate(
        &mut self,
        batch: &MutationBatch,
        timeout: Duration,
    ) -> NativeResult<WriteReceipt> {
        self.request(None, true, timeout, |client, token| {
            let batch = batch.clone();
            Box::pin(async move { client.mutate(token, &batch).await })
        })
        .await
        .map(|(_, reply)| reply)
    }
    pub async fn begin_staged_transaction(
        &mut self,
        request: &BeginStagedTransaction,
        timeout: Duration,
    ) -> NativeResult<WriteReceipt> {
        self.request(None, true, timeout, |client, token| {
            let request = request.clone();
            Box::pin(async move { client.begin_staged_transaction(token, &request).await })
        })
        .await
        .map(|(_, reply)| reply)
    }
    pub async fn append_staged_chunk(
        &mut self,
        request: &AppendStagedChunk,
        timeout: Duration,
    ) -> NativeResult<WriteReceipt> {
        self.request(None, true, timeout, |client, token| {
            let request = request.clone();
            Box::pin(async move { client.append_staged_chunk(token, &request).await })
        })
        .await
        .map(|(_, reply)| reply)
    }
    pub async fn finalize_staged_transaction(
        &mut self,
        request: &StagedTransactionRef,
        timeout: Duration,
    ) -> NativeResult<WriteReceipt> {
        self.request(None, true, timeout, |client, token| {
            let request = request.clone();
            Box::pin(async move { client.finalize_staged_transaction(token, &request).await })
        })
        .await
        .map(|(_, reply)| reply)
    }
    pub async fn stop_staged_transaction(
        &mut self,
        request: &StopStagedTransaction,
        timeout: Duration,
    ) -> NativeResult<StagedTransactionStatus> {
        self.request(None, true, timeout, |client, token| {
            let request = request.clone();
            Box::pin(async move { client.stop_staged_transaction(token, &request).await })
        })
        .await
        .map(|(_, reply)| reply)
    }
    pub async fn staged_transaction_status(
        &mut self,
        request: &StagedTransactionRef,
        timeout: Duration,
    ) -> NativeResult<StagedTransactionStatus> {
        self.request(None, true, timeout, |client, token| {
            let request = request.clone();
            Box::pin(async move { client.staged_transaction_status(token, &request).await })
        })
        .await
        .map(|(_, reply)| reply)
    }
    pub async fn read_snapshot(
        &mut self,
        request: &ReadSnapshotRequest,
        timeout: Duration,
    ) -> NativeResult<SnapshotReadResponse> {
        self.request(None, true, timeout, |client, token| {
            let request = request.clone();
            Box::pin(async move { client.read_snapshot(token, &request).await })
        })
        .await
        .map(|(_, reply)| reply)
    }
    pub async fn query(
        &mut self,
        query: &QueryRequest,
        timeout: Duration,
    ) -> NativeResult<RoutedQueryPage> {
        if query.cursor.is_some() {
            return Err(tonic::Status::invalid_argument(
                "continue historical pages with their routed page handle",
            )
            .into());
        }
        let (member, response) = self
            .request(None, true, timeout, |client, token| {
                let query = query.clone();
                Box::pin(async move { client.query(token, &query).await })
            })
            .await?;
        Ok(RoutedQueryPage {
            installation: self.installation,
            member,
            query: query.clone(),
            response,
        })
    }
    pub async fn next_query_page(
        &mut self,
        page: &RoutedQueryPage,
        timeout: Duration,
    ) -> NativeResult<RoutedQueryPage> {
        self.require_installation(page.installation)?;
        let mut query = page.query.clone();
        query.cursor = Some(
            page.response
                .cursor
                .clone()
                .ok_or_else(|| tonic::Status::invalid_argument("query has no next page"))?,
        );
        let (member, response) = self
            .request(Some(page.member), true, timeout, |client, token| {
                let query = query.clone();
                Box::pin(async move { client.query(token, &query).await })
            })
            .await?;
        Ok(RoutedQueryPage {
            installation: self.installation,
            member,
            query,
            response,
        })
    }
    /// An uncertain lease-creation response is returned to the caller. A retry
    /// cannot silently create a different historical snapshot on another node.
    pub async fn open_snapshot_lease(
        &mut self,
        request: &OpenSnapshotLease,
        timeout: Duration,
    ) -> NativeResult<RoutedSnapshotLease> {
        let (member, lease) = self
            .request(None, false, timeout, |client, token| {
                let request = request.clone();
                Box::pin(async move { client.open_snapshot_lease(token, &request).await })
            })
            .await?;
        Ok(RoutedSnapshotLease {
            installation: self.installation,
            member,
            lease,
        })
    }
    pub async fn read_snapshot_page(
        &mut self,
        lease: &RoutedSnapshotLease,
        documents: &[DocumentKey],
        timeout: Duration,
    ) -> NativeResult<SnapshotReadResponse> {
        self.require_installation(lease.installation)?;
        self.request(Some(lease.member), true, timeout, |client, token| {
            let request = ReadSnapshotPage {
                lease_id: lease.lease.lease_id.clone(),
                documents: documents.to_vec(),
            };
            Box::pin(async move { client.read_snapshot_page(token, &request).await })
        })
        .await
        .map(|(_, reply)| reply)
    }
    pub async fn scan_snapshot_page(
        &mut self,
        lease: &RoutedSnapshotLease,
        collection: &str,
        after_id: Option<&str>,
        limit: usize,
        timeout: Duration,
    ) -> NativeResult<SnapshotScanPage> {
        self.require_installation(lease.installation)?;
        self.request(Some(lease.member), true, timeout, |client, token| {
            let request = ScanSnapshotPage {
                lease_id: lease.lease.lease_id.clone(),
                collection: collection.to_owned(),
                after_id: after_id.map(str::to_owned),
                limit,
            };
            Box::pin(async move { client.scan_snapshot_page(token, &request).await })
        })
        .await
        .map(|(_, reply)| reply)
    }
    pub async fn close_snapshot_lease(
        &mut self,
        lease: &RoutedSnapshotLease,
        timeout: Duration,
    ) -> NativeResult<()> {
        self.require_installation(lease.installation)?;
        self.request(Some(lease.member), true, timeout, |client, token| {
            let id = lease.lease.lease_id.clone();
            Box::pin(async move { client.close_snapshot_lease(token, &id).await })
        })
        .await
        .map(|(_, reply)| reply)
    }
    fn require_installation(&self, expected: uuid::Uuid) -> NativeResult<()> {
        if self.installation != expected {
            return Err(tonic::Status::invalid_argument(
                "historical snapshot belongs to another endpoint pool",
            )
            .into());
        }
        Ok(())
    }
}
fn deadline() -> ClientError {
    tonic::Status::deadline_exceeded("installed native operation deadline elapsed; resolve uncertain writes with the original batch").into()
}
fn retryable(error: &ClientError) -> bool {
    matches!(error, ClientError::Transport(status) if matches!(status.code(), tonic::Code::Unavailable | tonic::Code::DeadlineExceeded | tonic::Code::Unknown | tonic::Code::Cancelled))
}
