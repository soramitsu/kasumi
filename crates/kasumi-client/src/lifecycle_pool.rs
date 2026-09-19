use crate::KasumiLifecycleClient;
use crate::{
    ClientError, KasumiClientConfig,
    installed_pool::{InstalledPool, RoutedClient},
};
use kasumi_serving::{ControlTrust, VerifiedControlChange, VerifiedControlIntent};
use kasumi_transport::credentials::CredentialSource;
use kasumi_types::*;
use std::{collections::BTreeMap, sync::Arc, time::Duration};

#[derive(Clone)]
pub struct KasumiLifecyclePool {
    inner: InstalledPool<KasumiLifecycleClient>,
    incarnation: uuid::Uuid,
}
impl RoutedClient for KasumiLifecycleClient {
    type Context = ControlTrust;
    async fn connect(
        config: &KasumiClientConfig,
        context: Self::Context,
    ) -> std::result::Result<Self, ClientError> {
        KasumiLifecycleClient::connect(config, context).await
    }
    fn set_deadline(&mut self, deadline: tokio::time::Instant) {
        KasumiLifecycleClient::set_deadline(self, deadline);
    }
}
impl KasumiLifecyclePool {
    pub fn with_credential(self, credential: Arc<dyn CredentialSource>) -> Self {
        Self {
            inner: self.inner.with_credential(credential),
            incarnation: self.incarnation,
        }
    }
    pub fn new(
        endpoints: BTreeMap<u64, KasumiClientConfig>,
        trust: ControlTrust,
        credential: Arc<dyn CredentialSource>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            incarnation: trust.root().control_incarnation,
            inner: InstalledPool::new(endpoints, trust, credential)?,
        })
    }
    pub async fn execute(
        &mut self,
        request: &LifecycleControlCommand,
        timeout: Duration,
    ) -> std::result::Result<WriteReceipt, ClientError> {
        let reference = ReadLifecycleStatus {
            command_id: command_id(request),
            expected_incarnation: self.incarnation,
        };
        self.inner
            .request_with_resolution(
                timeout,
                |client, bearer| {
                    let reference = reference.clone();
                    let request = request.clone();
                    Box::pin(async move {
                        match client.read_status(bearer, &reference).await {
                            Ok(status) => resolved(&request, &status),
                            // The initial installation has no status object yet.
                            // This endpoint has still performed its quorum barrier.
                            Err(ClientError::Transport(status))
                                if matches!(request, LifecycleControlCommand::Install { .. })
                                    && status.code() == tonic::Code::NotFound =>
                            {
                                Ok(None)
                            }
                            Err(error) => Err(error),
                        }
                    })
                },
                |client, bearer| {
                    let request = request.clone();
                    Box::pin(async move { client.execute(bearer, &request).await })
                },
            )
            .await
    }
    pub async fn observe_intent(
        &mut self,
        id: uuid::Uuid,
        timeout: Duration,
    ) -> std::result::Result<VerifiedControlIntent, ClientError> {
        self.inner
            .request(timeout, true, |client, bearer| {
                Box::pin(async move { client.observe_intent(bearer, id).await })
            })
            .await
    }
    pub async fn observe_change(
        &mut self,
        id: uuid::Uuid,
        partition: &str,
        timeout: Duration,
    ) -> std::result::Result<VerifiedControlChange, ClientError> {
        self.inner
            .request(timeout, true, |client, bearer| {
                let partition = partition.to_owned();
                Box::pin(async move { client.observe_change(bearer, id, &partition).await })
            })
            .await
    }
    pub async fn read_status(
        &mut self,
        request: &ReadLifecycleStatus,
        timeout: Duration,
    ) -> std::result::Result<LifecycleStatus, ClientError> {
        self.inner
            .request(timeout, true, |client, bearer| {
                let request = request.clone();
                Box::pin(async move { client.read_status(bearer, &request).await })
            })
            .await
    }
}

fn command_id(request: &LifecycleControlCommand) -> uuid::Uuid {
    match request {
        LifecycleControlCommand::Install { command_id, .. } => *command_id,
        LifecycleControlCommand::CommitIntent(request) => request.command_id,
        LifecycleControlCommand::BeginPolicyChange(request) => request.command_id,
        LifecycleControlCommand::CompletePolicyChange(request) => request.command_id,
    }
}

fn same<T: serde::Serialize>(left: &T, right: &T) -> std::result::Result<bool, ClientError> {
    Ok(staged_digest(left).map_err(anyhow::Error::from)?
        == staged_digest(right).map_err(anyhow::Error::from)?)
}

fn resolved(
    request: &LifecycleControlCommand,
    status: &LifecycleStatus,
) -> std::result::Result<Option<WriteReceipt>, ClientError> {
    let mismatch =
        || ClientError::InvalidResponse("lifecycle receipt differs from original command");
    if status.request.command_id != command_id(request) {
        return Err(mismatch());
    }
    let Some(command) = &status.command else {
        return Ok(None);
    };
    let revision = match (request, command) {
        (
            LifecycleControlCommand::Install {
                command_id,
                installation,
            },
            LifecycleCommandStatus::Installation {
                command_id: retained,
                installation: value,
                revision,
            },
        ) if command_id == retained
            && installation.root.control_incarnation == status.request.expected_incarnation
            && same(installation, value)? =>
        {
            *revision
        }
        (LifecycleControlCommand::CommitIntent(request), LifecycleCommandStatus::Intent(value))
            if request.as_ref() == &value.request
                && value.control_incarnation == status.request.expected_incarnation =>
        {
            value.revision
        }
        (
            LifecycleControlCommand::BeginPolicyChange(request),
            LifecycleCommandStatus::PolicyChange(value),
        ) if same(request, &value.request)?
            && value.control_incarnation == status.request.expected_incarnation =>
        {
            value.accepted_revision
        }
        (
            LifecycleControlCommand::CompletePolicyChange(request),
            LifecycleCommandStatus::PolicyChange(value),
        ) if request.command_id == value.request.command_id
            && request.change_sha256 == value.request_sha256
            && value.control_incarnation == status.request.expected_incarnation =>
        {
            let Some(revision) = value.completed_revision else {
                return Ok(None);
            };
            if value
                .completion_stops
                .as_ref()
                .is_none_or(|stops| stops != &request.stops)
            {
                return Err(mismatch());
            }
            revision
        }
        _ => return Err(mismatch()),
    };
    if revision == 0 || revision > status.observed_revision {
        return Err(mismatch());
    }
    Ok(Some(WriteReceipt {
        revision,
        versions: BTreeMap::new(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn installation() -> LifecycleInstallation {
        let partition = ControlAuthorityPartition {
            authority_id: uuid::Uuid::new_v4(),
            manifest_sha256: "ab".repeat(32),
            partition: 0,
            signing_public_key: "cd".repeat(32),
            maximum_lifetime_ms: 1000,
            drain_ms: 1000,
        };
        LifecycleInstallation {
            root: ControlSigningRoot {
                control_incarnation: uuid::Uuid::new_v4(),
                public_key: "ef".repeat(32),
            },
            generation: 1,
            partitions: BTreeMap::from([(partition.key(), partition)]),
            max_intents: 64,
            max_changes: 64,
            max_state_bytes: 1 << 20,
        }
    }
    #[test]
    fn installation_receipt_requires_original_identity_input_and_revision() {
        let installation = installation();
        installation.validate().unwrap();
        let command_id = uuid::Uuid::new_v4();
        let request = LifecycleControlCommand::Install {
            command_id,
            installation: installation.clone(),
        };
        let mut status = LifecycleStatus {
            request: ReadLifecycleStatus {
                command_id,
                expected_incarnation: installation.root.control_incarnation,
            },
            policy_epoch: 1,
            observed_revision: 9,
            observed_term: 1,
            retired: false,
            command: Some(LifecycleCommandStatus::Installation {
                command_id,
                installation: installation.clone(),
                revision: 3,
            }),
        };
        assert_eq!(resolved(&request, &status).unwrap().unwrap().revision, 3);
        let mut substituted = installation;
        substituted.generation += 1;
        assert!(
            resolved(
                &LifecycleControlCommand::Install {
                    command_id,
                    installation: substituted
                },
                &status
            )
            .is_err()
        );
        status.observed_revision = 2;
        assert!(resolved(&request, &status).is_err());
        status.command = None;
        assert!(resolved(&request, &status).unwrap().is_none());
        status.request.command_id = uuid::Uuid::new_v4();
        assert!(resolved(&request, &status).is_err());
    }
    #[test]
    fn policy_change_resolution_preserves_original_revision_and_completion_inputs() {
        let installation = installation();
        let request = BeginControlPolicyChange {
            command_id: uuid::Uuid::new_v4(),
            expected_policy_epoch: 1,
            installation_sha256: staged_digest(&installation).unwrap().0,
            candidate: ControlPolicyCandidate {
                policy: Policy {
                    grants: vec![Grant {
                        principal: "owner".into(),
                        collection: None,
                        actions: [Action::Admin].into(),
                    }],
                    strict_read_audit: false,
                },
                retire_control: false,
            },
        };
        request.validate().unwrap();
        let digest = staged_digest(&request).unwrap().0;
        let mut value = ControlPolicyChange {
            request: request.clone(),
            request_sha256: digest.clone(),
            control_incarnation: installation.root.control_incarnation,
            installation,
            original_principal: "owner".into(),
            accepted_at_ms: 100,
            accepted_revision: 2,
            completed_revision: None,
            completion_stops: None,
        };
        let mut status = LifecycleStatus {
            request: ReadLifecycleStatus {
                command_id: request.command_id,
                expected_incarnation: value.control_incarnation,
            },
            policy_epoch: 1,
            observed_revision: 3,
            observed_term: 1,
            retired: false,
            command: Some(LifecycleCommandStatus::PolicyChange(Box::new(
                value.clone(),
            ))),
        };
        let begin = LifecycleControlCommand::BeginPolicyChange(request.clone());
        assert_eq!(resolved(&begin, &status).unwrap().unwrap().revision, 2);
        let mut changed = request;
        changed.expected_policy_epoch += 1;
        assert!(
            resolved(
                &LifecycleControlCommand::BeginPolicyChange(changed),
                &status
            )
            .is_err()
        );
        let complete = LifecycleControlCommand::CompletePolicyChange(CompleteControlPolicyChange {
            command_id: command_id(&begin),
            change_sha256: digest,
            stops: BTreeMap::new(),
        });
        assert!(resolved(&complete, &status).unwrap().is_none());
        // A claimed completed command without its actual retained input cannot
        // be turned into a successful receipt by the client.
        value.completed_revision = Some(3);
        status.command = Some(LifecycleCommandStatus::PolicyChange(Box::new(value)));
        assert!(resolved(&complete, &status).is_err());
        assert_eq!(resolved(&begin, &status).unwrap().unwrap().revision, 2);
    }
}
