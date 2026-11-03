//! Installed routes are the only routing authority. An invocation snapshots its
//! credential once and keeps one suspend-aware deadline across every member.
use crate::{ClientError, KasumiClientConfig};
use kasumi_clock::{LeaseClock, SystemLeaseClock};
use kasumi_transport::credentials::{CredentialSource, token};
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    pin::Pin,
    sync::Arc,
    time::Duration,
};
use tokio::time::Instant;

pub(crate) type Reply<'a, T> = Pin<Box<dyn Future<Output = Result<T, ClientError>> + Send + 'a>>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Dispatch {
    Retry,
    Once,
    Resolve,
}

pub(crate) trait RoutedClient: Clone + Send + 'static {
    type Context: Clone + Send + 'static;
    fn connect(
        config: &KasumiClientConfig,
        context: Self::Context,
    ) -> impl Future<Output = Result<Self, ClientError>> + Send;
    fn set_deadline(&mut self, deadline: Instant);
}

/// One attempt's share of the time left. The members not yet tried in this
/// pass split it evenly, so time a fast failure leaves goes to the rest.
pub(crate) fn attempt_slice(remaining: Duration, untried: usize) -> Duration {
    (remaining / untried.max(1) as u32)
        .max(Duration::from_millis(1))
        .min(remaining)
}

/// Installed member clients, kept across attempts and invocations. A connect
/// that outlives its attempt keeps running, so a handshake slower than one
/// slice completes for a later attempt instead of restarting every time.
pub(crate) struct Connections<C: RoutedClient> {
    endpoints: BTreeMap<u64, KasumiClientConfig>,
    context: C::Context,
    clients: BTreeMap<u64, C>,
    connecting: BTreeMap<u64, Connecting<C>>,
}
struct Connecting<C>(tokio::task::JoinHandle<Result<C, ClientError>>);
impl<C> Drop for Connecting<C> {
    fn drop(&mut self) {
        self.0.abort();
    }
}
pub(crate) enum Connected<'a, C> {
    Ready(&'a mut C),
    /// Still connecting when the attempt ended; a later attempt resumes it.
    Pending,
    Failed,
}
impl<C: RoutedClient> Clone for Connections<C> {
    /// The clone shares established clients but starts its own connects.
    fn clone(&self) -> Self {
        Self {
            endpoints: self.endpoints.clone(),
            context: self.context.clone(),
            clients: self.clients.clone(),
            connecting: BTreeMap::new(),
        }
    }
}
impl<C: RoutedClient> Connections<C> {
    pub(crate) fn new(endpoints: BTreeMap<u64, KasumiClientConfig>, context: C::Context) -> Self {
        Self {
            endpoints,
            context,
            clients: BTreeMap::new(),
            connecting: BTreeMap::new(),
        }
    }
    pub(crate) fn members(&self) -> Vec<u64> {
        self.endpoints.keys().copied().collect()
    }
    pub(crate) fn contains(&self, member: u64) -> bool {
        self.endpoints.contains_key(&member)
    }
    /// The member's client, waiting for its connect until `end` at most.
    pub(crate) async fn client(&mut self, member: u64, end: Instant) -> Connected<'_, C> {
        if !self.clients.contains_key(&member) {
            let connecting = self.connecting.entry(member).or_insert_with(|| {
                let config = self.endpoints[&member].clone();
                let context = self.context.clone();
                Connecting(tokio::spawn(
                    async move { C::connect(&config, context).await },
                ))
            });
            let Ok(connected) = tokio::time::timeout_at(end, &mut connecting.0).await else {
                return Connected::Pending;
            };
            self.connecting.remove(&member);
            match connected {
                Ok(Ok(client)) => {
                    self.clients.insert(member, client);
                }
                Ok(Err(_)) | Err(_) => return Connected::Failed,
            }
        }
        Connected::Ready(self.clients.get_mut(&member).unwrap())
    }
    /// Forget a client whose attempt got no answer in time. Its connection may
    /// be stalled; a member that answered, even with an error, keeps its client.
    pub(crate) fn discard(&mut self, member: u64) {
        self.clients.remove(&member);
    }
}

#[derive(Clone)]
pub(crate) struct InstalledPool<C: RoutedClient> {
    connections: Connections<C>,
    credential: Arc<dyn CredentialSource>,
    preferred: u64,
}

impl<C: RoutedClient> InstalledPool<C> {
    pub(crate) fn new(
        endpoints: BTreeMap<u64, KasumiClientConfig>,
        context: C::Context,
        credential: Arc<dyn CredentialSource>,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !endpoints.is_empty() && endpoints.len() <= 64 && !endpoints.contains_key(&0),
            "recovery routing requires one to 64 installed nonzero member IDs"
        );
        let certificate = endpoints
            .values()
            .next()
            .unwrap()
            .identity
            .certificate_pin();
        let mut origins = BTreeSet::new();
        for config in endpoints.values() {
            let url = url::Url::parse(&config.endpoint)?;
            anyhow::ensure!(
                config.endpoint.len() <= 2048
                    && url.scheme() == "https"
                    && url.host_str().is_some()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none()
                    && url.path() == "/"
                    && (1..=8).contains(&config.server_certificate_pins.len())
                    && config.identity.certificate_pin() == certificate
                    && origins.insert(url.to_string()),
                "invalid or duplicate installed recovery member"
            );
        }
        Ok(Self {
            preferred: *endpoints.keys().next().unwrap(),
            connections: Connections::new(endpoints, context),
            credential,
        })
    }

    pub(crate) fn with_credential(mut self, credential: Arc<dyn CredentialSource>) -> Self {
        self.credential = credential;
        self
    }

    pub(crate) async fn request<T, F>(
        &mut self,
        timeout: Duration,
        replay: bool,
        dispatch: F,
    ) -> Result<T, ClientError>
    where
        T: Send,
        F: for<'a> FnMut(&'a mut C, &'a str) -> Reply<'a, T>,
    {
        self.request_with_probe(timeout, replay, |_, _| Box::pin(async { Ok(()) }), dispatch)
            .await
    }

    pub(crate) async fn request_with_probe<T, F, P>(
        &mut self,
        timeout: Duration,
        replay: bool,
        mut probe: P,
        dispatch: F,
    ) -> Result<T, ClientError>
    where
        T: Send,
        F: for<'a> FnMut(&'a mut C, &'a str) -> Reply<'a, T>,
        P: for<'a> FnMut(&'a mut C, &'a str) -> Reply<'a, ()>,
    {
        self.request_inner(
            timeout,
            if replay {
                Dispatch::Retry
            } else {
                Dispatch::Once
            },
            |client, bearer| {
                let observation = probe(client, bearer);
                Box::pin(async move { observation.await.map(|()| None) })
            },
            dispatch,
        )
        .await
    }

    /// A fresh, linearizable receipt observation selects a leader before the
    /// sole effect dispatch. After ambiguity, only the original receipt is
    /// observed; even a fresh absence cannot authorize another dispatch.
    pub(crate) async fn request_with_resolution<T, F, P>(
        &mut self,
        timeout: Duration,
        observe: P,
        dispatch: F,
    ) -> Result<T, ClientError>
    where
        T: Send,
        F: for<'a> FnMut(&'a mut C, &'a str) -> Reply<'a, T>,
        P: for<'a> FnMut(&'a mut C, &'a str) -> Reply<'a, Option<T>>,
    {
        self.request_inner(timeout, Dispatch::Resolve, observe, dispatch)
            .await
    }

    async fn request_inner<T, F, P>(
        &mut self,
        timeout: Duration,
        policy: Dispatch,
        mut probe: P,
        mut dispatch: F,
    ) -> Result<T, ClientError>
    where
        T: Send,
        F: for<'a> FnMut(&'a mut C, &'a str) -> Reply<'a, T>,
        P: for<'a> FnMut(&'a mut C, &'a str) -> Reply<'a, Option<T>>,
    {
        let mut budget = RequestDeadline::new(timeout, Arc::new(SystemLeaseClock))?;
        // Renewal is a new logical invocation, never a failover side effect.
        let bearer = token(self.credential.as_ref()).map_err(|_| ClientError::Authorization)?;
        budget.remaining()?;
        let mut members = self.connections.members();
        let preferred = members.iter().position(|id| *id == self.preferred).unwrap();
        members.rotate_left(preferred);
        let mut attempted = false;
        // A dispatched effect failed without a definite outcome. A later probe
        // or dispatch refusal cannot rule it out.
        let mut uncertain = false;
        loop {
            for (tried, member) in members.iter().enumerate() {
                let remaining = budget.remaining()?;
                let attempt_end = Instant::now()
                    .checked_add(attempt_slice(remaining, members.len() - tried))
                    .ok_or_else(deadline)?;
                let mut dispatched = false;
                // Only an attempt that ran out of time without an answer drops
                // its client; a member that answered keeps its connection.
                let mut elapsed = false;
                let result = match self.connections.client(*member, attempt_end).await {
                    Connected::Pending => Err(deadline()),
                    Connected::Failed => Err(ClientError::Transport(tonic::Status::unavailable(
                        "installed recovery member connection failed",
                    ))),
                    Connected::Ready(client) => {
                        async {
                            let probe_end = Instant::now()
                                .checked_add(budget.remaining()?)
                                .ok_or_else(deadline)?;
                            client.set_deadline(probe_end);
                            let Ok(observation) = tokio::time::timeout_at(
                                attempt_end.min(probe_end),
                                probe(client, &bearer),
                            )
                            .await
                            else {
                                elapsed = true;
                                return Err(deadline());
                            };
                            if let Some(reply) = observation? {
                                return Ok(Some(reply));
                            }
                            // The original receipt is still absent here. Even a
                            // fresh absence cannot authorize a second effect.
                            if policy == Dispatch::Resolve && attempted {
                                return Ok(None);
                            }
                            let remaining = budget.remaining()?;
                            let operation_end =
                                Instant::now().checked_add(remaining).ok_or_else(deadline)?;
                            let dispatch_end = if policy == Dispatch::Retry {
                                attempt_end.min(operation_end)
                            } else {
                                operation_end
                            };
                            if dispatch_end <= Instant::now() {
                                return Err(deadline());
                            }
                            client.set_deadline(operation_end);
                            dispatched = true;
                            attempted = true;
                            match tokio::time::timeout_at(dispatch_end, dispatch(client, &bearer))
                                .await
                            {
                                Ok(reply) => reply.map(Some),
                                Err(_) => {
                                    elapsed = true;
                                    Err(deadline())
                                }
                            }
                        }
                        .await
                    }
                };
                budget.remaining()?;
                match result {
                    Ok(Some(reply)) => {
                        self.preferred = *member;
                        return Ok(reply);
                    }
                    Ok(None) => {}
                    Err(error) if retryable(&error) => {
                        if elapsed {
                            self.connections.discard(*member);
                        }
                        // Resume has a work limit, not an invocation command ID.
                        // Ambiguity must return to its owner without a second dispatch.
                        if dispatched && policy == Dispatch::Once {
                            return Err(error);
                        }
                        uncertain |= dispatched;
                    }
                    Err(error) if uncertain => return Err(crate::kasumi::unresolved(&error)),
                    Err(error) => return Err(error),
                }
            }
            tokio::time::sleep(budget.remaining()?.min(Duration::from_millis(25))).await;
        }
    }
}

struct RequestDeadline {
    clock: Arc<dyn LeaseClock>,
    last: Duration,
    end: Duration,
    local_end: Instant,
}
impl RequestDeadline {
    fn new(timeout: Duration, clock: Arc<dyn LeaseClock>) -> Result<Self, ClientError> {
        if timeout.is_zero() {
            return Err(deadline());
        }
        let last = clock.now();
        let end = last.checked_add(timeout).ok_or_else(deadline)?;
        let local_end = Instant::now().checked_add(timeout).ok_or_else(deadline)?;
        Ok(Self {
            clock,
            last,
            end,
            local_end,
        })
    }
    fn remaining(&mut self) -> Result<Duration, ClientError> {
        let now = self.clock.now();
        if now < self.last {
            self.end = Duration::ZERO;
            return Err(deadline());
        }
        self.last = now;
        let remaining = self
            .end
            .saturating_sub(now)
            .min(self.local_end.saturating_duration_since(Instant::now()));
        if remaining.is_zero() {
            return Err(deadline());
        }
        Ok(remaining)
    }
}
fn deadline() -> ClientError {
    tonic::Status::deadline_exceeded("installed recovery operation deadline elapsed").into()
}
fn retryable(error: &ClientError) -> bool {
    matches!(error, ClientError::Transport(status) if matches!(status.code(),
        tonic::Code::Unavailable | tonic::Code::DeadlineExceeded | tonic::Code::Unknown | tonic::Code::Cancelled))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};
    #[derive(Clone)]
    struct Probe {
        member: u64,
        deadline: Option<Instant>,
    }
    #[derive(Clone, Default)]
    struct Members {
        unavailable: BTreeSet<u64>,
        /// Connect latency of slow members.
        slow: BTreeMap<u64, Duration>,
        connects: Arc<Mutex<Vec<u64>>>,
    }
    impl Members {
        fn unavailable(members: impl IntoIterator<Item = u64>) -> Self {
            Self {
                unavailable: members.into_iter().collect(),
                ..Self::default()
            }
        }
        fn connects(&self, member: u64) -> usize {
            let connects = self.connects.lock().unwrap();
            connects.iter().filter(|id| **id == member).count()
        }
    }
    impl RoutedClient for Probe {
        type Context = Members;
        async fn connect(
            config: &KasumiClientConfig,
            members: Self::Context,
        ) -> Result<Self, ClientError> {
            let member: u64 = url::Url::parse(&config.endpoint)
                .unwrap()
                .port()
                .unwrap()
                .into();
            members.connects.lock().unwrap().push(member);
            if let Some(latency) = members.slow.get(&member) {
                tokio::time::sleep(*latency).await;
            }
            if members.unavailable.contains(&member) {
                return Err(tonic::Status::unavailable("offline").into());
            }
            Ok(Self {
                member,
                deadline: None,
            })
        }
        fn set_deadline(&mut self, deadline: Instant) {
            self.deadline = Some(deadline);
        }
    }
    fn endpoints() -> BTreeMap<u64, KasumiClientConfig> {
        // Public test fixture key. This identity never opens a production listener.
        let identity = kasumi_transport::TlsIdentity::from_pem(
            include_bytes!("installed-pool-test-cert.pem"),
            include_bytes!("installed-pool-test-key.pem"),
        )
        .unwrap();
        (1..=3)
            .map(|id| {
                (
                    id,
                    KasumiClientConfig {
                        endpoint: format!("https://localhost:{id}"),
                        server_certificate_pins: BTreeSet::from([identity.certificate_pin()]),
                        identity: identity.clone(),
                        trusted_ca_pem: vec![],
                    },
                )
            })
            .collect()
    }
    fn pool(members: Members, loads: Arc<AtomicU64>) -> InstalledPool<Probe> {
        InstalledPool::new(
            endpoints(),
            members,
            Arc::new(move || {
                let generation = loads.fetch_add(1, Ordering::SeqCst);
                Ok(format!("opaque-{generation}").into())
            }),
        )
        .unwrap()
    }
    #[tokio::test]
    async fn failover_keeps_one_credential_and_original_request_until_the_next_invocation() {
        let loads = Arc::new(AtomicU64::new(0));
        let mut pool = pool(Members::default(), loads.clone());
        let calls = Arc::new(Mutex::new(Vec::new()));
        let operation = uuid::Uuid::new_v4();
        for generation in 0..2 {
            let calls = calls.clone();
            let reply = pool
                .request(Duration::from_secs(1), true, |client, bearer| {
                    let calls = calls.clone();
                    Box::pin(async move {
                        assert!(client.deadline.unwrap() > Instant::now());
                        assert!(
                            client.deadline.unwrap() <= Instant::now() + Duration::from_secs(1)
                        );
                        calls
                            .lock()
                            .unwrap()
                            .push((client.member, bearer.to_owned(), operation));
                        if client.member == 1 {
                            return Err(tonic::Status::unavailable("election").into());
                        }
                        Ok(operation)
                    })
                })
                .await
                .unwrap();
            assert_eq!(reply, operation);
            assert_eq!(loads.load(Ordering::SeqCst), generation + 1);
        }
        assert_eq!(
            *calls.lock().unwrap(),
            vec![
                (1, "opaque-0".into(), operation),
                (2, "opaque-0".into(), operation),
                (2, "opaque-1".into(), operation)
            ]
        );
    }
    #[tokio::test]
    async fn ambiguous_resume_never_redispatches_but_connection_failure_can_select_another_member()
    {
        let loads = Arc::new(AtomicU64::new(0));
        let mut pool = pool(Members::unavailable([1]), loads.clone());
        let dispatched = Arc::new(Mutex::new(Vec::new()));
        let seen = dispatched.clone();
        let result: Result<(), ClientError> = pool
            .request(Duration::from_secs(1), false, |client, _| {
                let seen = seen.clone();
                Box::pin(async move {
                    seen.lock().unwrap().push(client.member);
                    Err(tonic::Status::unavailable("acknowledgement lost after dispatch").into())
                })
            })
            .await;
        assert!(result.is_err());
        assert_eq!(*dispatched.lock().unwrap(), vec![2]);
        assert_eq!(loads.load(Ordering::SeqCst), 1);
    }
    #[tokio::test]
    async fn leader_probe_fails_over_without_a_second_resume_or_a_new_credential() {
        let loads = Arc::new(AtomicU64::new(0));
        let mut pool = pool(Members::default(), loads.clone());
        let probes = Arc::new(Mutex::new(Vec::new()));
        let dispatches = Arc::new(Mutex::new(Vec::new()));
        let seen_probes = probes.clone();
        let seen_dispatches = dispatches.clone();
        let result: Result<(), ClientError> = pool
            .request_with_probe(
                Duration::from_secs(1),
                false,
                |client, bearer| {
                    let seen = seen_probes.clone();
                    Box::pin(async move {
                        seen.lock()
                            .unwrap()
                            .push((client.member, bearer.to_owned()));
                        if client.member == 1 {
                            return Err(tonic::Status::unavailable("not the leader").into());
                        }
                        Ok(())
                    })
                },
                |client, bearer| {
                    let seen = seen_dispatches.clone();
                    Box::pin(async move {
                        seen.lock()
                            .unwrap()
                            .push((client.member, bearer.to_owned()));
                        Err(tonic::Status::unavailable("lost acknowledgement").into())
                    })
                },
            )
            .await;
        assert!(result.is_err());
        assert_eq!(
            *probes.lock().unwrap(),
            vec![(1, "opaque-0".into()), (2, "opaque-0".into())]
        );
        assert_eq!(*dispatches.lock().unwrap(), vec![(2, "opaque-0".into())]);
        assert_eq!(loads.load(Ordering::SeqCst), 1);
    }
    #[tokio::test]
    async fn stalled_dispatch_expires_without_credential_reload_or_second_resume() {
        let loads = Arc::new(AtomicU64::new(0));
        let mut pool = pool(Members::default(), loads.clone());
        let calls = Arc::new(AtomicU64::new(0));
        let seen = calls.clone();
        let result: Result<(), ClientError> = tokio::time::timeout(
            Duration::from_secs(1),
            pool.request(Duration::from_millis(40), false, |_, _| {
                seen.fetch_add(1, Ordering::SeqCst);
                Box::pin(std::future::pending())
            }),
        )
        .await
        .expect("original invocation must finish");
        assert!(
            matches!(result, Err(ClientError::Transport(status)) if status.code() == tonic::Code::DeadlineExceeded)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(loads.load(Ordering::SeqCst), 1);
    }
    #[tokio::test]
    async fn receipt_resolution_selects_leader_then_resolves_without_redispatch_or_renewal() {
        let loads = Arc::new(AtomicU64::new(0));
        let mut pool = pool(Members::default(), loads.clone());
        let committed = Arc::new(AtomicU64::new(0));
        let calls = Arc::new(Mutex::new(Vec::new()));
        let observed = calls.clone();
        let effect = committed.clone();
        let observation = committed.clone();
        let original = uuid::Uuid::new_v4();
        let end = Instant::now() + Duration::from_secs(1);
        let result = pool
            .request_with_resolution(
                Duration::from_secs(1),
                |client, bearer| {
                    let calls = observed.clone();
                    let committed = observation.clone();
                    Box::pin(async move {
                        assert_eq!(bearer, "opaque-0");
                        assert!(client.deadline.unwrap() <= end + Duration::from_millis(1));
                        calls.lock().unwrap().push(("read", client.member));
                        if client.member == 1 {
                            return Err(tonic::Status::unavailable("follower").into());
                        }
                        Ok((committed.load(Ordering::SeqCst) == 1).then_some(original))
                    })
                },
                |client, bearer| {
                    let calls = calls.clone();
                    let committed = effect.clone();
                    Box::pin(async move {
                        assert_eq!(bearer, "opaque-0");
                        calls.lock().unwrap().push(("write", client.member));
                        assert_eq!(committed.fetch_add(1, Ordering::SeqCst), 0);
                        Err(tonic::Status::unknown("committed reply lost").into())
                    })
                },
            )
            .await
            .unwrap();
        assert_eq!(result, original);
        assert_eq!(
            *calls.lock().unwrap(),
            vec![("read", 1), ("read", 2), ("write", 2), ("read", 3)]
        );
        assert_eq!(loads.load(Ordering::SeqCst), 1);
    }
    #[tokio::test]
    async fn absent_receipt_after_ambiguity_never_authorizes_another_effect() {
        let loads = Arc::new(AtomicU64::new(0));
        let mut pool = pool(Members::default(), loads.clone());
        let effects = Arc::new(AtomicU64::new(0));
        let reads = Arc::new(AtomicU64::new(0));
        let result: Result<(), ClientError> = pool
            .request_with_resolution(
                Duration::from_millis(40),
                |_, _| {
                    reads.fetch_add(1, Ordering::SeqCst);
                    Box::pin(async { Ok(None) })
                },
                |_, _| {
                    effects.fetch_add(1, Ordering::SeqCst);
                    Box::pin(async { Err(tonic::Status::unknown("outcome lost").into()) })
                },
            )
            .await;
        assert!(
            matches!(result, Err(ClientError::Transport(status)) if status.code() == tonic::Code::DeadlineExceeded)
        );
        assert_eq!(effects.load(Ordering::SeqCst), 1);
        assert!(reads.load(Ordering::SeqCst) >= 3);
        assert_eq!(loads.load(Ordering::SeqCst), 1);
    }
    #[tokio::test]
    async fn absent_receipt_keeps_the_answering_members_connections() {
        let members = Members::default();
        let mut pool = pool(members.clone(), Arc::new(AtomicU64::new(0)));
        let reads = Arc::new(AtomicU64::new(0));
        let result: Result<(), ClientError> = pool
            .request_with_resolution(
                Duration::from_millis(300),
                |_, _| {
                    reads.fetch_add(1, Ordering::SeqCst);
                    Box::pin(async { Ok(None) })
                },
                |_, _| Box::pin(async { Err(tonic::Status::unknown("outcome lost").into()) }),
            )
            .await;
        assert!(
            matches!(result, Err(ClientError::Transport(status)) if status.code() == tonic::Code::DeadlineExceeded)
        );
        // Every member reported the absence several times over one connection
        // each, rather than reconnecting after every 25 ms pass.
        assert!(reads.load(Ordering::SeqCst) >= 6);
        assert_eq!(*members.connects.lock().unwrap(), vec![1, 2, 3]);
    }
    #[tokio::test]
    async fn answering_member_keeps_its_connection_across_passes() {
        let members = Members::unavailable([2, 3]);
        let mut pool = pool(members.clone(), Arc::new(AtomicU64::new(0)));
        let calls = Arc::new(AtomicU64::new(0));
        let reply = pool
            .request(Duration::from_secs(5), true, |client, _| {
                let call = calls.fetch_add(1, Ordering::SeqCst);
                let member = client.member;
                Box::pin(async move {
                    assert_eq!(member, 1);
                    if call < 2 {
                        return Err(tonic::Status::unavailable("election").into());
                    }
                    Ok(call)
                })
            })
            .await
            .unwrap();
        assert_eq!(reply, 2);
        assert_eq!(members.connects(1), 1);
    }
    #[tokio::test]
    async fn stalled_attempt_reconnects_its_member() {
        let members = Members::unavailable([2, 3]);
        let mut pool = pool(members.clone(), Arc::new(AtomicU64::new(0)));
        let calls = Arc::new(AtomicU64::new(0));
        pool.request(Duration::from_secs(3), true, |_, _| {
            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                return Box::pin(std::future::pending());
            }
            Box::pin(async { Ok(()) })
        })
        .await
        .unwrap();
        assert_eq!(members.connects(1), 2);
    }
    #[tokio::test]
    async fn connect_slower_than_its_slice_completes_for_a_later_pass() {
        // The first pass gives member 1 a third of the time, less than its
        // handshake; a restarted connect would never finish within a slice.
        let members = Members {
            unavailable: BTreeSet::from([2, 3]),
            slow: BTreeMap::from([(1, Duration::from_millis(1500))]),
            ..Members::default()
        };
        let mut pool = pool(members.clone(), Arc::new(AtomicU64::new(0)));
        let member = pool
            .request(Duration::from_secs(3), true, |client, _| {
                let member = client.member;
                Box::pin(async move { Ok(member) })
            })
            .await
            .unwrap();
        assert_eq!(member, 1);
        assert_eq!(members.connects(1), 1);
    }
    #[test]
    fn attempt_slices_split_the_time_left_among_untried_members() {
        let second = Duration::from_secs(1);
        assert_eq!(attempt_slice(3 * second, 3), second);
        // Time a fast failure left over goes to the members after it.
        assert_eq!(attempt_slice(3 * second, 2), 3 * second / 2);
        assert_eq!(attempt_slice(3 * second, 1), 3 * second);
        assert_eq!(
            attempt_slice(Duration::from_micros(10), 64),
            Duration::from_micros(10)
        );
        assert_eq!(
            attempt_slice(Duration::from_millis(30), 64),
            Duration::from_millis(1)
        );
    }
    #[test]
    fn uninstalled_origins_and_missing_pins_are_rejected_before_credentials_are_loaded() {
        for change in 0..4 {
            let loads = Arc::new(AtomicU64::new(0));
            let seen = loads.clone();
            let mut members = endpoints();
            match change {
                0 => members.get_mut(&1).unwrap().endpoint = "http://localhost:1".into(),
                1 => members.get_mut(&2).unwrap().endpoint = members[&1].endpoint.clone(),
                2 => members.get_mut(&1).unwrap().server_certificate_pins.clear(),
                _ => {
                    let member = members.remove(&1).unwrap();
                    members.insert(0, member);
                }
            }
            let result = InstalledPool::<Probe>::new(
                members,
                Members::default(),
                Arc::new(move || {
                    seen.fetch_add(1, Ordering::SeqCst);
                    Ok("opaque".to_owned().into())
                }),
            );
            assert!(result.is_err());
            assert_eq!(loads.load(Ordering::SeqCst), 0);
        }
    }
    struct Clock(AtomicU64);
    impl LeaseClock for Clock {
        fn now(&self) -> Duration {
            Duration::from_millis(self.0.load(Ordering::SeqCst))
        }
    }
    #[test]
    fn suspend_and_clock_regression_cannot_extend_an_invocation() {
        let clock = Arc::new(Clock(AtomicU64::new(100)));
        let mut deadline = RequestDeadline::new(Duration::from_secs(60), clock.clone()).unwrap();
        clock.0.store(60_100, Ordering::SeqCst);
        assert!(deadline.remaining().is_err());
        clock.0.store(100, Ordering::SeqCst);
        assert!(deadline.remaining().is_err());
        let mut deadline = RequestDeadline::new(Duration::from_secs(60), clock.clone()).unwrap();
        clock.0.store(99, Ordering::SeqCst);
        assert!(deadline.remaining().is_err());
        clock.0.store(100, Ordering::SeqCst);
        assert!(deadline.remaining().is_err());
    }
    #[test]
    fn authority_and_response_failures_do_not_change_routes() {
        for code in [
            tonic::Code::Aborted,
            tonic::Code::Unauthenticated,
            tonic::Code::PermissionDenied,
            tonic::Code::InvalidArgument,
            tonic::Code::FailedPrecondition,
        ] {
            assert!(!retryable(&tonic::Status::new(code, "rejected").into()));
        }
        assert!(!retryable(&ClientError::Authorization));
        assert!(!retryable(&ClientError::InvalidResponse(
            "untrusted response"
        )));
        assert!(retryable(
            &tonic::Status::unavailable("leader changed").into()
        ));
    }
}
