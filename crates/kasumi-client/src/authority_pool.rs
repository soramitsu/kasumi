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
    pub async fn observe_control_signer(
        &mut self,
        request: &kasumi_serving::ControlSignerRequest,
        timeout: Duration,
    ) -> Result<crate::CurrentControlSignerObservation, ClientError> {
        let anchor = kasumi_clock::EpochClock::system()?.observe()?;
        let reply = self
            .request(timeout, |client, token| {
                let request = request.clone();
                Box::pin(async move { client.observe_control_signer_wire(token, &request).await })
            })
            .await?;
        crate::CurrentControlSignerObservation::from_current_response(reply, anchor)
    }
    pub async fn maintenance(
        &mut self,
        request: &kasumi_serving::AuthorityMaintenanceRequest,
        timeout: Duration,
    ) -> Result<kasumi_serving::AuthorityMaintenanceResponse, ClientError> {
        self.request(timeout, |client, token| {
            let request = request.clone();
            Box::pin(async move { client.maintenance(token, &request).await })
        })
        .await
    }

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
        // One atomic credential snapshot belongs to this entire finite operation.
        // Renewal is observed by the next invocation, never by an endpoint retry.
        let bearer = token(self.credential.as_ref()).map_err(|_| ClientError::Authorization)?;
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
                    let client = self.clients.get_mut(member).unwrap();
                    client.set_deadline(deadline_at);
                    dispatch(client, &bearer).await
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
    /// A lifecycle acceptance or epoch stop is dispatched at most once in this
    /// invocation. After an ambiguous effect response, only an exact signed
    /// receipt can resolve the result; a missing receipt cannot authorize a
    /// second effect on another installed member.
    pub async fn execute_lifecycle(
        &mut self,
        request: &kasumi_serving::LifecycleAuthorityRequest,
        timeout: Duration,
    ) -> Result<kasumi_serving::SignedLifecycleAuthorityReceipt, ClientError> {
        if timeout.is_zero() {
            return Err(deadline());
        }
        let reference = request.reference();
        let partition = match request {
            kasumi_serving::LifecycleAuthorityRequest::AcceptIntent(signed) => {
                signed.observation.authority_partition.partition
            }
            kasumi_serving::LifecycleAuthorityRequest::StopEpoch(signed) => {
                signed.observation.stop.authority_partition.partition
            }
        };
        // A historical receipt does not bypass verification of this invocation's
        // installed Control proof. Fresh observation signatures are verification
        // input; the digest binds the immutable lifecycle command identity.
        self.trust
            .manifest()
            .verify_lifecycle_request(partition, request)?;
        let request_sha256 = request.digest()?;
        let deadline_at = Instant::now().checked_add(timeout).ok_or_else(deadline)?;
        let bearer = token(self.credential.as_ref()).map_err(|_| ClientError::Authorization)?;
        let mut members: Vec<_> = self.endpoints.keys().copied().collect();
        let index = members.iter().position(|id| *id == self.preferred).unwrap();
        members.rotate_left(index);
        let mut dispatched = false;
        loop {
            for member in &members {
                let remaining = deadline_at.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(if dispatched {
                        unresolved_lifecycle()
                    } else {
                        deadline()
                    });
                }
                let slice =
                    remaining.min((timeout / members.len() as u32).max(Duration::from_millis(1)));
                let attempt_end =
                    deadline_at.min(Instant::now().checked_add(slice).ok_or_else(deadline)?);
                if !self.clients.contains_key(member) {
                    let connection = tokio::time::timeout_at(
                        attempt_end,
                        KasumiAuthorityClient::connect(&self.endpoints[member], self.trust.clone()),
                    )
                    .await;
                    match connection {
                        Ok(Ok(client)) => {
                            self.clients.insert(*member, client);
                        }
                        Ok(Err(_)) | Err(_) => continue,
                    }
                }
                let observation = {
                    let client = self.clients.get_mut(member).unwrap();
                    client.set_deadline(deadline_at);
                    tokio::time::timeout_at(
                        attempt_end,
                        client.read_lifecycle_receipt(&bearer, &reference),
                    )
                    .await
                };
                match observation {
                    Ok(Ok(Some(receipt))) => {
                        if receipt.receipt.request_sha256 != request_sha256 {
                            return Err(authority_outcome_status(
                                tonic::Code::Aborted,
                                kasumi_types::ErrorCode::Conflict,
                                "lifecycle issuer identity conflicts with committed receipt",
                            ));
                        }
                        self.preferred = *member;
                        return Ok(receipt);
                    }
                    Ok(Ok(None)) => {}
                    Ok(Err(error)) => {
                        self.clients.remove(member);
                        if !retryable(&error) {
                            return Err(if dispatched {
                                unresolved_lifecycle()
                            } else {
                                error
                            });
                        }
                        continue;
                    }
                    Err(_) => {
                        self.clients.remove(member);
                        continue;
                    }
                }
                if dispatched || attempt_end <= Instant::now() {
                    continue;
                }
                let effect = {
                    let client = self.clients.get_mut(member).unwrap();
                    client.set_deadline(deadline_at);
                    // Cancellation can make a sent request's outcome unknowable.
                    dispatched = true;
                    tokio::time::timeout_at(attempt_end, client.execute_lifecycle(&bearer, request))
                        .await
                };
                match effect {
                    Ok(Ok(receipt)) => {
                        self.preferred = *member;
                        return Ok(receipt);
                    }
                    Ok(Err(_)) | Err(_) => {
                        self.clients.remove(member);
                    }
                }
            }
            let remaining = deadline_at.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(if dispatched {
                    unresolved_lifecycle()
                } else {
                    deadline()
                });
            }
            tokio::time::sleep(remaining.min(Duration::from_millis(25))).await;
        }
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
    /// The first polled Execute is the only effect dispatch in this invocation.
    /// Subsequent failover resolves only its exact signed receipt, even when an
    /// installed member currently reports absence. This remains true after a
    /// transport timeout or a non-success status from the attempted effect.
    pub async fn execute(
        &mut self,
        command: &AuthorityCommand,
        timeout: Duration,
    ) -> Result<SignedAuthorityReceipt, ClientError> {
        if timeout.is_zero() {
            return Err(deadline());
        }
        command.validate().map_err(|_| {
            ClientError::Transport(tonic::Status::invalid_argument("invalid authority command"))
        })?;
        let deadline_at = Instant::now().checked_add(timeout).ok_or_else(deadline)?;
        // One credential and one installed member set belong to this invocation.
        let bearer = token(self.credential.as_ref()).map_err(|_| ClientError::Authorization)?;
        let mut members: Vec<_> = self.endpoints.keys().copied().collect();
        let index = members.iter().position(|id| *id == self.preferred).unwrap();
        members.rotate_left(index);
        let mut dispatched = false;
        loop {
            for member in &members {
                let remaining = deadline_at.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(if dispatched {
                        unresolved_command()
                    } else {
                        deadline()
                    });
                }
                let slice =
                    remaining.min((timeout / members.len() as u32).max(Duration::from_millis(1)));
                let attempt_end =
                    deadline_at.min(Instant::now().checked_add(slice).ok_or_else(deadline)?);
                if !self.clients.contains_key(member) {
                    let connection = tokio::time::timeout_at(
                        attempt_end,
                        KasumiAuthorityClient::connect(&self.endpoints[member], self.trust.clone()),
                    )
                    .await;
                    match connection {
                        Ok(Ok(client)) => {
                            self.clients.insert(*member, client);
                        }
                        Ok(Err(_)) | Err(_) => {
                            continue;
                        }
                    }
                }
                let observation = {
                    let client = self.clients.get_mut(member).unwrap();
                    client.set_deadline(deadline_at);
                    tokio::time::timeout_at(
                        attempt_end,
                        client.receipt(&bearer, &command.tenant, command.command_id),
                    )
                    .await
                };
                match observation {
                    Ok(Ok(Some(receipt))) => {
                        if receipt.receipt.command != *command {
                            return Err(authority_outcome_status(
                                tonic::Code::Aborted,
                                kasumi_types::ErrorCode::Conflict,
                                "authority command identity conflicts with committed receipt",
                            ));
                        }
                        self.preferred = *member;
                        return Ok(receipt);
                    }
                    Ok(Ok(None)) => {}
                    Ok(Err(error)) => {
                        self.clients.remove(member);
                        if !retryable(&error) {
                            return Err(if dispatched {
                                unresolved_command()
                            } else {
                                error
                            });
                        }
                        continue;
                    }
                    Err(_) => {
                        self.clients.remove(member);
                        continue;
                    }
                }
                if dispatched || attempt_end <= Instant::now() {
                    continue;
                }
                let effect = {
                    let client = self.clients.get_mut(member).unwrap();
                    client.set_deadline(deadline_at);
                    // Conservatively mark the effect before polling its future.
                    // Cancellation can make a sent request's outcome unknowable.
                    dispatched = true;
                    tokio::time::timeout_at(attempt_end, client.execute(&bearer, command)).await
                };
                match effect {
                    Ok(Ok(receipt)) => {
                        self.preferred = *member;
                        return Ok(receipt);
                    }
                    Ok(Err(_)) | Err(_) => {
                        self.clients.remove(member);
                    }
                }
            }
            let remaining = deadline_at.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(if dispatched {
                    unresolved_command()
                } else {
                    deadline()
                });
            }
            tokio::time::sleep(remaining.min(Duration::from_millis(25))).await;
        }
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
fn authority_outcome_status(
    code: tonic::Code,
    error_code: kasumi_types::ErrorCode,
    message: &'static str,
) -> ClientError {
    let error = kasumi_types::Error::new(error_code, message);
    let details = serde_json::to_vec(&error).unwrap_or_default();
    tonic::Status::with_details(code, message, details.into()).into()
}
fn unresolved_command() -> ClientError {
    authority_outcome_status(
        tonic::Code::Unavailable,
        kasumi_types::ErrorCode::UnknownOutcome,
        "original authority command remains unresolved; read exact receipt",
    )
}
fn unresolved_lifecycle() -> ClientError {
    authority_outcome_status(
        tonic::Code::Unavailable,
        kasumi_types::ErrorCode::UnknownOutcome,
        "original lifecycle issuer effect remains unresolved; read exact receipt",
    )
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
                | tonic::Code::Cancelled
        ),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unresolved_command_has_the_authority_unknown_outcome_detail() {
        let ClientError::Transport(status) = unresolved_command() else {
            panic!("unresolved command needs a transport status");
        };
        assert_eq!(status.code(), tonic::Code::Unavailable);
        let error: kasumi_types::Error = serde_json::from_slice(status.details()).unwrap();
        assert_eq!(error.code, kasumi_types::ErrorCode::UnknownOutcome);
    }

    #[test]
    fn unresolved_lifecycle_has_the_authority_unknown_outcome_detail() {
        let ClientError::Transport(status) = unresolved_lifecycle() else {
            panic!("unresolved lifecycle effect needs a transport status");
        };
        assert_eq!(status.code(), tonic::Code::Unavailable);
        let error: kasumi_types::Error = serde_json::from_slice(status.details()).unwrap();
        assert_eq!(error.code, kasumi_types::ErrorCode::UnknownOutcome);
    }

    #[test]
    fn authorization_and_proof_errors_are_not_failover_signals() {
        for code in [
            tonic::Code::Aborted,
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
