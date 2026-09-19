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

pub(crate) trait RoutedClient: Clone + Send {
    type Context: Clone + Send;
    fn connect(
        config: &KasumiClientConfig,
        context: Self::Context,
    ) -> impl Future<Output = Result<Self, ClientError>> + Send;
    fn set_deadline(&mut self, deadline: Instant);
}

#[derive(Clone)]
pub(crate) struct InstalledPool<C: RoutedClient> {
    endpoints: BTreeMap<u64, KasumiClientConfig>,
    clients: BTreeMap<u64, C>,
    context: C::Context,
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
            endpoints,
            clients: BTreeMap::new(),
            context,
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
        mut dispatch: F,
    ) -> Result<T, ClientError>
    where
        T: Send,
        F: for<'a> FnMut(&'a mut C, &'a str) -> Reply<'a, T>,
        P: for<'a> FnMut(&'a mut C, &'a str) -> Reply<'a, ()>,
    {
        let mut budget = RequestDeadline::new(timeout, Arc::new(SystemLeaseClock))?;
        // Renewal is a new logical invocation, never a failover side effect.
        let bearer = token(self.credential.as_ref()).map_err(|_| ClientError::Authorization)?;
        budget.remaining()?;
        let mut members: Vec<_> = self.endpoints.keys().copied().collect();
        let preferred = members.iter().position(|id| *id == self.preferred).unwrap();
        members.rotate_left(preferred);
        loop {
            for member in &members {
                let remaining = budget.remaining()?;
                let slice =
                    remaining.min((timeout / members.len() as u32).max(Duration::from_millis(1)));
                let attempt_end = Instant::now().checked_add(slice).ok_or_else(deadline)?;
                let mut dispatched = false;
                let result = async {
                    if !self.clients.contains_key(member) {
                        let client = tokio::time::timeout_at(
                            attempt_end,
                            C::connect(&self.endpoints[member], self.context.clone()),
                        )
                        .await
                        .map_err(|_| deadline())?
                        .map_err(|_| {
                            ClientError::Transport(tonic::Status::unavailable(
                                "installed recovery member connection failed",
                            ))
                        })?;
                        budget.remaining()?;
                        self.clients.insert(*member, client);
                    }
                    let probe_end = Instant::now()
                        .checked_add(budget.remaining()?)
                        .ok_or_else(deadline)?;
                    let client = self.clients.get_mut(member).unwrap();
                    client.set_deadline(probe_end);
                    tokio::time::timeout_at(attempt_end.min(probe_end), probe(client, &bearer))
                        .await
                        .map_err(|_| deadline())??;
                    let remaining = budget.remaining()?;
                    let operation_end =
                        Instant::now().checked_add(remaining).ok_or_else(deadline)?;
                    let dispatch_end = if replay {
                        attempt_end.min(operation_end)
                    } else {
                        operation_end
                    };
                    if dispatch_end <= Instant::now() {
                        return Err(deadline());
                    }
                    let client = self.clients.get_mut(member).unwrap();
                    client.set_deadline(operation_end);
                    dispatched = true;
                    tokio::time::timeout_at(dispatch_end, dispatch(client, &bearer))
                        .await
                        .map_err(|_| deadline())?
                }
                .await;
                budget.remaining()?;
                match result {
                    Ok(reply) => {
                        self.preferred = *member;
                        return Ok(reply);
                    }
                    Err(error) if retryable(&error) => {
                        self.clients.remove(member);
                        // Resume has a work limit, not an invocation command ID.
                        // Ambiguity must return to its owner without a second dispatch.
                        if dispatched && !replay {
                            return Err(error);
                        }
                    }
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
    impl RoutedClient for Probe {
        type Context = BTreeSet<u64>;
        async fn connect(
            config: &KasumiClientConfig,
            unavailable: Self::Context,
        ) -> Result<Self, ClientError> {
            let member: u64 = url::Url::parse(&config.endpoint)
                .unwrap()
                .port()
                .unwrap()
                .into();
            if unavailable.contains(&member) {
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
    fn pool(unavailable: BTreeSet<u64>, loads: Arc<AtomicU64>) -> InstalledPool<Probe> {
        InstalledPool::new(
            endpoints(),
            unavailable,
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
        let mut pool = pool(BTreeSet::new(), loads.clone());
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
        let mut pool = pool(BTreeSet::from([1]), loads.clone());
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
        let mut pool = pool(BTreeSet::new(), loads.clone());
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
        let mut pool = pool(BTreeSet::new(), loads.clone());
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
                BTreeSet::new(),
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
