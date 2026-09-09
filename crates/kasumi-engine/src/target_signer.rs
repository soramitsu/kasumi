//! Installed target signing keys accept only proofs created by the actual
//! materialization/consensus path. Wire facts cannot invoke this signer.
use crate::{TargetOperation, VerifiedTargetMaterialization};
use kasumi_serving::NodeIdentity;
use kasumi_types::*;
use ring::signature::{Ed25519KeyPair, KeyPair};

pub struct TargetSigner {
    node: NodeIdentity,
    key: Ed25519KeyPair,
}
impl TargetSigner {
    pub async fn sign_completion_terminal_status(
        &self,
        proof: &crate::VerifiedTargetReceiver,
        operation: &TargetOperation,
    ) -> Result<SignedTargetCompletionTerminalStatus> {
        proof.release(operation).await?;
        let observation = proof.terminal_status()?;
        self.check(&observation.fact.input.attempt.origin, operation)
            .map_err(|_| {
                Error::new(
                    ErrorCode::Forbidden,
                    "installed terminal status signer differs",
                )
            })?;
        if observation.observer_node_id != self.node.node_id {
            return Err(Error::new(
                ErrorCode::Forbidden,
                "terminal status observer is another leader",
            ));
        }
        let bytes = serde_json::to_vec(&(
            "kasumi.target-completion-terminal-status-observation.v1",
            &observation,
        ))
        .map_err(|_| Error::new(ErrorCode::Unavailable, "terminal status encoding failed"))?;
        let signature = hex::encode(self.key.sign(&bytes).as_ref());
        proof.release(operation).await?;
        self.check(&observation.fact.input.attempt.origin, operation)
            .map_err(|_| {
                Error::new(
                    ErrorCode::Unavailable,
                    "terminal status signer changed during release",
                )
            })?;
        Ok(SignedTargetCompletionTerminalStatus {
            observation,
            signature,
        })
    }
    pub async fn sign_completion_attempt_status(
        &self,
        proof: &crate::VerifiedTargetReceiver,
        operation: &TargetOperation,
    ) -> Result<SignedTargetCompletionAttemptStatus> {
        proof.release(operation).await?;
        let observation = proof.attempt_status()?;
        self.check(&observation.attempt.origin, operation)
            .map_err(|_| {
                Error::new(
                    ErrorCode::Forbidden,
                    "installed preparation status signer differs",
                )
            })?;
        if observation.observer_node_id != self.node.node_id {
            return Err(Error::new(
                ErrorCode::Forbidden,
                "preparation status observer is another leader",
            ));
        }
        let signature = hex::encode(
            self.key
                .sign(
                    &serde_json::to_vec(&(
                        "kasumi.target-completion-attempt-status-observation.v1",
                        &observation,
                    ))
                    .map_err(|_| {
                        Error::new(ErrorCode::Unavailable, "preparation status encoding failed")
                    })?,
                )
                .as_ref(),
        );
        proof.release(operation).await?;
        self.check(&observation.attempt.origin, operation)
            .map_err(|_| {
                Error::new(
                    ErrorCode::Unavailable,
                    "preparation status signer changed during release",
                )
            })?;
        Ok(SignedTargetCompletionAttemptStatus {
            observation,
            signature,
        })
    }
    pub async fn sign_completion_preparation(
        &self,
        proof: &crate::VerifiedTargetReceiver,
        operation: &TargetOperation,
    ) -> Result<SignedTargetCompletionAttempt> {
        proof.release(operation).await?;
        let observation = proof.preparation()?;
        self.check(&observation.attempt.origin, operation)
            .map_err(|_| {
                Error::new(ErrorCode::Forbidden, "installed preparation signer differs")
            })?;
        if observation.observer_node_id != self.node.node_id {
            return Err(Error::new(
                ErrorCode::Forbidden,
                "preparation observer is another native leader",
            ));
        }
        let signature = hex::encode(
            self.key
                .sign(
                    &serde_json::to_vec(&(
                        "kasumi.prepared-target-completion-observation.v1",
                        &observation,
                    ))
                    .map_err(|_| {
                        Error::new(
                            ErrorCode::UnknownOutcome,
                            "preparation observation encoding failed",
                        )
                    })?,
                )
                .as_ref(),
        );
        proof.release(operation).await?;
        self.check(&observation.attempt.origin, operation)
            .map_err(|_| {
                Error::new(
                    ErrorCode::UnknownOutcome,
                    "preparation signer changed during release",
                )
            })?;
        Ok(SignedTargetCompletionAttempt {
            observation,
            signature,
        })
    }
    pub async fn sign_completion_resolution(
        &self,
        proof: &crate::VerifiedTargetReceiver,
        operation: &TargetOperation,
    ) -> Result<SignedTargetCompletionResolution> {
        proof.release(operation).await?;
        let observation = proof.resolution()?;
        self.check(&observation.fact.input.attempt.origin, operation)
            .map_err(|_| Error::new(ErrorCode::Forbidden, "installed terminal signer differs"))?;
        if observation.observer_node_id != self.node.node_id {
            return Err(Error::new(
                ErrorCode::Forbidden,
                "terminal observer is another native leader",
            ));
        }
        let signature = hex::encode(
            self.key
                .sign(
                    &serde_json::to_vec(&(
                        "kasumi.resolved-target-completion-observation.v1",
                        &observation,
                    ))
                    .map_err(|_| {
                        Error::new(
                            ErrorCode::UnknownOutcome,
                            "terminal observation encoding failed",
                        )
                    })?,
                )
                .as_ref(),
        );
        proof.release(operation).await?;
        self.check(&observation.fact.input.attempt.origin, operation)
            .map_err(|_| {
                Error::new(
                    ErrorCode::UnknownOutcome,
                    "terminal signer changed during release",
                )
            })?;
        Ok(SignedTargetCompletionResolution {
            observation,
            signature,
        })
    }
    pub async fn sign_resolution_budget(
        &self,
        proof: &crate::VerifiedTargetReceiver,
        operation: &TargetOperation,
    ) -> Result<SignedTargetResolutionBudget> {
        proof.release(operation).await?;
        let observation = proof.budget()?;
        self.check(&observation.fact.origin, operation)
            .map_err(|_| Error::new(ErrorCode::Forbidden, "installed budget signer differs"))?;
        if observation.observer_node_id != self.node.node_id {
            return Err(Error::new(
                ErrorCode::Forbidden,
                "budget observer is another native leader",
            ));
        }
        let signature = hex::encode(
            self.key
                .sign(
                    &serde_json::to_vec(&(
                        "kasumi.target-resolution-budget-observation.v1",
                        &observation,
                    ))
                    .map_err(|_| {
                        Error::new(
                            ErrorCode::UnknownOutcome,
                            "budget observation encoding failed",
                        )
                    })?,
                )
                .as_ref(),
        );
        proof.release(operation).await?;
        self.check(&observation.fact.origin, operation)
            .map_err(|_| {
                Error::new(
                    ErrorCode::UnknownOutcome,
                    "budget signer changed during release",
                )
            })?;
        Ok(SignedTargetResolutionBudget {
            observation,
            signature,
        })
    }
    pub fn from_pkcs8(node: NodeIdentity, bytes: &[u8]) -> anyhow::Result<Self> {
        node.validate()?;
        let key = Ed25519KeyPair::from_pkcs8(bytes)
            .map_err(|_| anyhow::anyhow!("invalid installed target signer"))?;
        Ok(Self { node, key })
    }
    pub fn public_key(&self) -> String {
        hex::encode(self.key.public_key().as_ref())
    }
    pub fn node(&self) -> &NodeIdentity {
        &self.node
    }
    fn check(&self, origin: &TargetOrigin, operation: &TargetOperation) -> anyhow::Result<()> {
        operation.check()?;
        let lease = operation.invocation().gate().current()?;
        anyhow::ensure!(
            lease.signed().claims.request.target_node == self.node,
            "target signer differs from actual phase node credential"
        );
        let installed = origin
            .materialization
            .request
            .target_nodes
            .get(&self.node.node_id)
            .ok_or_else(|| anyhow::anyhow!("target signer is not installed"))?;
        anyhow::ensure!(
            installed.verifier == self.node.verifier
                && installed.principal == self.node.principal
                && installed.certificate_sha256 == self.node.certificate_sha256
                && installed.attestation_public_key == hex::encode(self.key.public_key().as_ref()),
            "target signing key differs from exact committed installation"
        );
        Ok(())
    }
    pub async fn sign_materialized(
        &self,
        proof: &VerifiedTargetMaterialization,
        operation: &TargetOperation,
    ) -> anyhow::Result<SignedTargetMaterialization> {
        proof.release(operation).await?;
        self.check(&proof.fact().origin, operation)?;
        anyhow::ensure!(
            proof.fact().node_id == self.node.node_id,
            "materialization belongs to another target replica"
        );
        let signed = SignedTargetMaterialization {
            fact: proof.fact().clone(),
            signature: hex::encode(
                self.key
                    .sign(&serde_json::to_vec(&(
                        "kasumi.materialized-target.v1",
                        proof.fact(),
                    ))?)
                    .as_ref(),
            ),
        };
        proof.release(operation).await?;
        self.check(&signed.fact.origin, operation)?;
        Ok(signed)
    }
}

impl TargetSigner {
    pub async fn sign_completed(
        &self,
        proof: &crate::VerifiedTargetCompletion,
        operation: &TargetOperation,
    ) -> Result<SignedTargetCompletion> {
        proof.release(operation).await?;
        self.check(&proof.observation().fact.origin, operation)
            .map_err(|_| Error::new(ErrorCode::Forbidden, "installed target signer differs"))?;
        if proof.observation().observer_node_id != self.node.node_id {
            return Err(Error::new(
                ErrorCode::Forbidden,
                "completion observation belongs to another native leader",
            ));
        }
        let signature = hex::encode(
            self.key
                .sign(
                    &serde_json::to_vec(&(
                        "kasumi.completed-target-observation.v1",
                        proof.observation(),
                    ))
                    .map_err(|_| {
                        Error::new(
                            ErrorCode::UnknownOutcome,
                            "target observation encoding failed",
                        )
                    })?,
                )
                .as_ref(),
        );
        proof.release(operation).await?;
        Ok(SignedTargetCompletion {
            observation: proof.observation().clone(),
            signature,
        })
    }
}

impl TargetSigner {
    pub async fn sign_inspection(
        &self,
        proof: &crate::VerifiedTargetInspection,
        operation: &TargetOperation,
    ) -> Result<SignedTargetInspection> {
        proof.release(operation).await?;
        self.check(&proof.observation().completion.origin, operation)
            .map_err(|_| Error::new(ErrorCode::Forbidden, "installed target signer differs"))?;
        if proof.observation().observer_node_id != self.node.node_id {
            return Err(Error::new(
                ErrorCode::Forbidden,
                "inspection belongs to another native leader",
            ));
        }
        let signature = hex::encode(
            self.key
                .sign(
                    &serde_json::to_vec(&(
                        "kasumi.inspected-target-observation.v1",
                        proof.observation(),
                    ))
                    .map_err(|_| {
                        Error::new(ErrorCode::Unavailable, "target inspection encoding failed")
                    })?,
                )
                .as_ref(),
        );
        proof.release(operation).await?;
        Ok(SignedTargetInspection {
            observation: proof.observation().clone(),
            signature,
        })
    }
}

impl TargetSigner {
    pub async fn sign_activated(
        &self,
        proof: &crate::VerifiedTargetActivation,
        operation: &TargetOperation,
    ) -> Result<SignedTargetActivation> {
        proof.release(operation).await?;
        self.check(&proof.observation().completion.origin, operation)
            .map_err(|_| Error::new(ErrorCode::Forbidden, "installed activation signer differs"))?;
        if proof.observation().observer_node_id != self.node.node_id {
            return Err(Error::new(
                ErrorCode::Forbidden,
                "activation signer differs from actual leader",
            ));
        }
        let signed = SignedTargetActivation {
            observation: proof.observation().clone(),
            signature: hex::encode(
                self.key
                    .sign(
                        &serde_json::to_vec(&(
                            "kasumi.activated-target-observation.v1",
                            proof.observation(),
                        ))
                        .map_err(|_| {
                            Error::new(ErrorCode::UnknownOutcome, "activation encoding failed")
                        })?,
                    )
                    .as_ref(),
            ),
        };
        proof.release(operation).await?;
        Ok(signed)
    }
}
