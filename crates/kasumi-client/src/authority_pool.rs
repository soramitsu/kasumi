//! Bounded failover across operator-installed authority members. A peer response
//! never supplies a new URL or trust root. Retries retain the original opaque
//! lease attempt and each operation has one deadline across all connections.
use crate::{ClientError, KasumiAuthorityClient, KasumiClientConfig};
use kasumi_serving::{
    AuthorityCommand, AuthorityTrust, LeaseAttempt, LeaseDiscovery, ServingIdentity,
    SignedAuthorityReceipt, VerifiedLease,
};
use kasumi_transport::credentials::{CredentialSource, token};
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    pin::Pin,
    sync::Arc,
    time::Duration,
};
use tokio::time::Instant;

type Reply<'a, T> = Pin<Box<dyn Future<Output = Result<T, ClientError>> + Send + 'a>>;

#[derive(Clone)]
pub struct KasumiAuthorityPool {
    endpoints: BTreeMap<u64, KasumiClientConfig>,
    clients: BTreeMap<u64, KasumiAuthorityClient>,
    trust: AuthorityTrust,
    credential: Arc<dyn CredentialSource>,
    preferred: u64,
}
impl KasumiAuthorityPool {
    pub fn new(
        endpoints: BTreeMap<u64, KasumiClientConfig>,
        trust: AuthorityTrust,
        credential: Arc<dyn CredentialSource>,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !endpoints.is_empty() && endpoints.len() <= 64 && !endpoints.contains_key(&0),
            "authority requires one to 64 installed nonzero member IDs"
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
                "invalid or duplicate authority member endpoint"
            );
        }
        Ok(Self {
            preferred: *endpoints.keys().next().unwrap(),
            endpoints,
            clients: BTreeMap::new(),
            trust,
            credential,
        })
    }

    /// Reuse installed transport routes with an independently selected current
    /// credential source, for example separate node and administrative roles.
    pub fn with_credential(mut self, credential: Arc<dyn CredentialSource>) -> Self {
        self.credential = credential;
        self
    }

    async fn request<T, F>(&mut self, timeout: Duration, mut dispatch: F) -> Result<T, ClientError>
    where
        T: Send,
        F: for<'a> FnMut(&'a mut KasumiAuthorityClient, &'a str) -> Reply<'a, T>,
    {
        if timeout.is_zero() {
            return Err(deadline());
        }
        let deadline_at = Instant::now().checked_add(timeout).ok_or_else(deadline)?;
        let mut members: Vec<_> = self.endpoints.keys().copied().collect();
        let index = members.iter().position(|id| *id == self.preferred).unwrap();
        members.rotate_left(index);
        loop {
            for member in &members {
                let remaining = deadline_at.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(deadline());
                }
                // An unreachable first member cannot monopolize the operation.
                let attempt_end = Instant::now()
                    + remaining.min((timeout / members.len() as u32).max(Duration::from_millis(1)));
                let result = tokio::time::timeout_at(attempt_end, async {
                    if let std::collections::btree_map::Entry::Vacant(entry) =
                        self.clients.entry(*member)
                    {
                        let client = KasumiAuthorityClient::connect(
                            &self.endpoints[member],
                            self.trust.clone(),
                        )
                        .await
                        .map_err(|_| {
                            ClientError::Transport(tonic::Status::unavailable(
                                "installed authority member connection failed",
                            ))
                        })?;
                        entry.insert(client);
                    }
                    let bearer =
                        token(self.credential.as_ref()).map_err(|_| ClientError::Authorization)?;
                    dispatch(self.clients.get_mut(member).unwrap(), &bearer).await
                })
                .await;
                match result {
                    Ok(Ok(reply)) => {
                        self.preferred = *member;
                        return Ok(reply);
                    }
                    Ok(Err(error)) if retryable(&error) => {
                        self.clients.remove(member);
                    }
                    Err(_) => {
                        self.clients.remove(member);
                    }
                    Ok(Err(error)) => return Err(error),
                }
            }
            let remaining = deadline_at.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(deadline());
            }
            tokio::time::sleep(remaining.min(Duration::from_millis(25))).await;
        }
    }

    pub async fn acquire_lifecycle(
        &mut self,
        request: &kasumi_serving::LifecycleAttempt,
        timeout: Duration,
    ) -> Result<kasumi_serving::VerifiedLifecycleLease, ClientError> {
        self.request(timeout, |client, token| {
            let request = request.clone();
            Box::pin(async move { client.acquire_lifecycle(token, &request).await })
        })
        .await
    }
    pub async fn execute_lifecycle(
        &mut self,
        request: &kasumi_serving::LifecycleAuthorityRequest,
        timeout: Duration,
    ) -> Result<kasumi_serving::SignedLifecycleAuthorityReceipt, ClientError> {
        self.request(timeout, |client, token| {
            let request = request.clone();
            Box::pin(async move { client.execute_lifecycle(token, &request).await })
        })
        .await
    }
    pub async fn read_lifecycle_receipt(
        &mut self,
        request: &kasumi_serving::LifecycleAuthorityReference,
        timeout: Duration,
    ) -> Result<Option<kasumi_serving::SignedLifecycleAuthorityReceipt>, ClientError> {
        self.request(timeout, |client, token| {
            let request = request.clone();
            Box::pin(async move { client.read_lifecycle_receipt(token, &request).await })
        })
        .await
    }
    pub async fn verify_control_stop(
        &mut self,
        request: &kasumi_types::ControlEpochStop,
        timeout: Duration,
    ) -> Result<kasumi_types::SignedControlEpochStop, ClientError> {
        self.request(timeout, |client, token| {
            let request = request.clone();
            Box::pin(async move { client.verify_control_stop(token, &request).await })
        })
        .await
    }
    pub async fn verify_target_stop(
        &mut self,
        request: &kasumi_serving::TargetStopReference,
        timeout: Duration,
    ) -> Result<kasumi_serving::VerifiedTargetStop, ClientError> {
        self.request(timeout, |client, token| {
            let request = request.clone();
            Box::pin(async move { client.verify_target_stop(token, &request).await })
        })
        .await
    }
    pub async fn discover_lease(
        &mut self,
        request: &LeaseDiscovery,
        timeout: Duration,
    ) -> Result<ServingIdentity, ClientError> {
        self.request(timeout, |client, token| {
            let request = request.clone();
            Box::pin(async move { client.discover_lease(token, &request).await })
        })
        .await
    }
    pub async fn acquire_lease(
        &mut self,
        attempt: &LeaseAttempt,
        timeout: Duration,
    ) -> Result<VerifiedLease, ClientError> {
        self.request(timeout, |client, token| {
            // Clone retains the same clock anchor, boot and attempt nonce.
            let attempt = attempt.clone();
            Box::pin(async move { client.acquire_lease(token, &attempt).await })
        })
        .await
    }
    pub async fn execute(
        &mut self,
        command: &AuthorityCommand,
        timeout: Duration,
    ) -> Result<SignedAuthorityReceipt, ClientError> {
        self.request(timeout, |client, token| {
            let command = command.clone();
            Box::pin(async move {
                if let Some(receipt) = client
                    .receipt(token, &command.tenant, command.command_id)
                    .await?
                {
                    if receipt.receipt.command != command {
                        return Err(anyhow::anyhow!(
                            "authority command identity conflicts with committed receipt"
                        )
                        .into());
                    }
                    return Ok(receipt);
                }
                client.execute(token, &command).await
            })
        })
        .await
    }
    pub async fn receipt(
        &mut self,
        tenant: &str,
        command_id: uuid::Uuid,
        timeout: Duration,
    ) -> Result<Option<SignedAuthorityReceipt>, ClientError> {
        self.request(timeout, |client, token| {
            let tenant = tenant.to_owned();
            Box::pin(async move { client.receipt(token, &tenant, command_id).await })
        })
        .await
    }
}
fn deadline() -> ClientError {
    tonic::Status::deadline_exceeded("installed authority operation deadline elapsed").into()
}
fn retryable(error: &ClientError) -> bool {
    match error {
        ClientError::Connection(_) => false,
        ClientError::Transport(status) => matches!(
            status.code(),
            tonic::Code::Unavailable
                | tonic::Code::DeadlineExceeded
                | tonic::Code::Unknown
                | tonic::Code::Aborted
                | tonic::Code::Cancelled
        ),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authorization_and_proof_errors_are_not_failover_signals() {
        for code in [
            tonic::Code::Unauthenticated,
            tonic::Code::PermissionDenied,
            tonic::Code::InvalidArgument,
            tonic::Code::FailedPrecondition,
        ] {
            assert!(!retryable(&ClientError::Transport(tonic::Status::new(
                code, "rejected"
            ))));
        }
        assert!(!retryable(&ClientError::Authorization));
        assert!(retryable(&ClientError::Transport(
            tonic::Status::unavailable("leader changed")
        )));
    }
}
