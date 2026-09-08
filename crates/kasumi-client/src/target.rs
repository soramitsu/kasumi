//! Typed native target acknowledgements. Immutable observations never grant
//! mutation authority or replace an issuer lease or current Control observation.
use crate::{ClientError, KasumiClientConfig, authorized, encode, proto};
use anyhow::ensure;
use kasumi_serving::*;
use kasumi_types::*;
use tonic::transport::Channel;
#[derive(Clone)]
pub struct KasumiTargetClient {
    inner: proto::kasumi_target_recovery_client::KasumiTargetRecoveryClient<Channel>,
    control: ControlTrust,
    authority: AuthorityTrust,
    node_id: u64,
}
/// Construction requires the pinned native response and its exact signed phase
/// and node attestations. A serialized acknowledgement is not a live proof.
/// ```compile_fail
/// let _:kasumi_client::TargetAcknowledgement=serde_json::from_str("{}").unwrap();
/// ```
pub struct TargetAcknowledgement {
    response: TargetRuntimeResponse,
}
impl TargetAcknowledgement {
    pub fn response(&self) -> &TargetRuntimeResponse {
        &self.response
    }
}
impl KasumiTargetClient {
    pub async fn connect(
        config: &KasumiClientConfig,
        control: ControlTrust,
        authority: AuthorityTrust,
        node_id: u64,
    ) -> std::result::Result<Self, ClientError> {
        if node_id == 0 {
            return Err(ClientError::Authorization);
        }
        let channel = kasumi_transport::grpc_channel(
            &config.endpoint,
            &config.identity,
            &config.trusted_ca_pem,
            config.server_certificate_pins.clone(),
        )
        .await?;
        Ok(Self {
            inner: proto::kasumi_target_recovery_client::KasumiTargetRecoveryClient::new(channel)
                .max_encoding_message_size(512 << 10)
                .max_decoding_message_size(1 << 20),
            control,
            authority,
            node_id,
        })
    }
    pub async fn execute(
        &mut self,
        bearer: &str,
        phase: &VerifiedControlIntent,
        request: &TargetRuntimeRequest,
    ) -> std::result::Result<TargetAcknowledgement, ClientError> {
        request.validate()?;
        let phase = self.control.verify_intent(phase.signed())?;
        let intent = &phase.observation().intent;
        if intent.request.command_id != request.command_id
            || intent.request.tenant != request.tenant
            || !intent.request.target_nodes.contains_key(&self.node_id)
            || phase.observation().authority_partition
                != self
                    .authority
                    .manifest()
                    .control_partition(self.authority.manifest().partition(&request.tenant)?)?
        {
            return Err(ClientError::Authorization);
        }
        validate_request_phase(intent, &request.step)?;
        let response = self
            .inner
            .execute(authorized(
                bearer,
                proto::TargetRuntimeRequest {
                    request_json: encode(request)?,
                },
            )?)
            .await?
            .into_inner();
        let response: TargetRuntimeResponse = serde_json::from_slice(&response.response_json)?;
        self.verify_response(intent, request, &response)?;
        Ok(TargetAcknowledgement { response })
    }
    fn verify_response(
        &self,
        intent: &LifecycleIntent,
        request: &TargetRuntimeRequest,
        response: &TargetRuntimeResponse,
    ) -> anyhow::Result<()> {
        ensure!(
            response.command_id == request.command_id && response.node_id == self.node_id,
            "target response identity differs"
        );
        match (&request.step, &response.outcome) {
            (TargetRuntimeStep::Materialize(input), TargetRuntimeOutcome::Materialized(signed)) => {
                let origin = TargetOrigin {
                    authority_manifest_sha256: self.authority.digest().into(),
                    materialization: intent.clone(),
                    input: input.clone(),
                };
                verify_target_materialization(&origin, self.node_id, signed)?;
            }
            (TargetRuntimeStep::Start(input), TargetRuntimeOutcome::Started { origin_sha256 }) => {
                let origin = origin(input.quorum())?;
                origin.accepts_phase(intent, intent.request.phase)?;
                ensure!(*origin_sha256 == origin.digest()?, "started origin differs");
            }
            (
                TargetRuntimeStep::Initialize(input),
                TargetRuntimeOutcome::Initialized { origin_sha256 },
            ) => {
                let origin = origin(input)?;
                origin.accepts_phase(intent, LifecyclePhase::Initialize)?;
                ensure!(
                    *origin_sha256 == origin.digest()?,
                    "initialized origin differs"
                );
            }
            (TargetRuntimeStep::Complete(input), TargetRuntimeOutcome::Completed(signed)) => {
                let origin = origin(input)?;
                ensure!(
                    signed.observation.fact.completion_intent == *intent
                        && signed.observation.observer_node_id == self.node_id,
                    "completion phase differs"
                );
                verify_target_completion(&origin, signed)?;
            }
            (
                TargetRuntimeStep::Activate { quorum, .. },
                TargetRuntimeOutcome::Activated(signed),
            ) => {
                let origin = origin(quorum)?;
                origin.accepts_phase(intent, LifecyclePhase::Activate)?;
                ensure!(
                    signed
                        .observation
                        .activation
                        .intent
                        .request
                        .phase_input_sha256
                        == intent.request.phase_input_sha256
                        && signed.observation.observer_node_id == self.node_id,
                    "activation input differs"
                );
                verify_target_activation(&origin, signed)?;
            }
            (
                TargetRuntimeStep::ConfirmActivation(expected),
                TargetRuntimeOutcome::Activated(signed),
            ) => {
                let origin = &expected.observation.completion.origin;
                origin.accepts_phase(intent, LifecyclePhase::Activate)?;
                verify_target_activation(origin, expected)?;
                verify_target_activation(origin, signed)?;
                ensure!(
                    signed.observation.activation == expected.observation.activation
                        && signed.observation.completion == expected.observation.completion
                        && signed.observation.observer_node_id == self.node_id,
                    "local target confirmation differs from exact committed fact"
                );
            }
            (
                TargetRuntimeStep::ConfirmInspection(expected),
                TargetRuntimeOutcome::Inspected(signed),
            ) => {
                verify_target_inspection(&expected.observation.input, expected)?;
                verify_target_inspection(&expected.observation.input, signed)?;
                ensure!(
                    signed.observation.inspection_intent == *intent
                        && expected.observation.inspection_intent == *intent
                        && signed.observation.completion == expected.observation.completion
                        && signed.observation.activation == expected.observation.activation
                        && signed.observation.observer_node_id == self.node_id,
                    "local inspection differs from exact original metadata"
                );
            }
            (TargetRuntimeStep::Inspect(input), TargetRuntimeOutcome::Inspected(signed)) => {
                ensure!(
                    signed.observation.inspection_intent == *intent
                        && signed.observation.observer_node_id == self.node_id,
                    "inspection phase differs"
                );
                verify_target_inspection(input, signed)?;
            }
            (TargetRuntimeStep::Stop(reference), TargetRuntimeOutcome::Stopped(signed)) => {
                ensure!(
                    signed.fact.stopped.observation.reference == *reference,
                    "cleanup stop differs"
                );
                verify_local_target_cleanup(&self.authority, intent, self.node_id, signed)?;
            }
            _ => anyhow::bail!("target returned another operation kind"),
        }
        Ok(())
    }
}
fn origin(input: &TargetQuorumInput) -> anyhow::Result<TargetOrigin> {
    let origin = input
        .materialized
        .values()
        .next()
        .ok_or_else(|| anyhow::anyhow!("target materializations absent"))?
        .fact
        .origin
        .clone();
    ensure!(
        origin.digest()? == input.origin_sha256,
        "target origin differs"
    );
    verify_target_materializations(&origin, &input.materialized)?;
    Ok(origin)
}
fn validate_request_phase(
    intent: &LifecycleIntent,
    step: &TargetRuntimeStep,
) -> anyhow::Result<()> {
    let (phase, hash) = match step {
        TargetRuntimeStep::Materialize(i) => {
            i.validate(intent)?;
            (LifecyclePhase::Materialize, Some(i.digest()?))
        }
        TargetRuntimeStep::Start(TargetReplicaInput::Quorum(i)) => {
            ensure!(
                matches!(
                    intent.request.phase,
                    LifecyclePhase::Initialize | LifecyclePhase::Complete
                ),
                "invalid target startup phase"
            );
            (intent.request.phase, Some(i.digest()?))
        }
        TargetRuntimeStep::Start(TargetReplicaInput::Inspection(i)) => {
            (LifecyclePhase::InspectTarget, Some(i.digest()?))
        }
        TargetRuntimeStep::ConfirmActivation(signed) => {
            verify_target_activation(&signed.observation.completion.origin, signed)?;
            signed
                .observation
                .completion
                .origin
                .accepts_phase(intent, LifecyclePhase::Activate)?;
            (
                LifecyclePhase::Activate,
                Some(
                    signed
                        .observation
                        .activation
                        .intent
                        .request
                        .phase_input_sha256
                        .clone(),
                ),
            )
        }
        TargetRuntimeStep::ConfirmInspection(signed) => {
            verify_target_inspection(&signed.observation.input, signed)?;
            ensure!(
                signed.observation.inspection_intent == *intent,
                "inspection phase differs"
            );
            (
                LifecyclePhase::InspectTarget,
                Some(signed.observation.input.digest()?),
            )
        }
        TargetRuntimeStep::Inspect(i) => (LifecyclePhase::InspectTarget, Some(i.digest()?)),
        TargetRuntimeStep::Initialize(i) => (LifecyclePhase::Initialize, Some(i.digest()?)),
        TargetRuntimeStep::Complete(i) => (LifecyclePhase::Complete, Some(i.digest()?)),
        TargetRuntimeStep::Activate { quorum, .. } => {
            origin(quorum)?.accepts_phase(intent, LifecyclePhase::Activate)?;
            (LifecyclePhase::Activate, None)
        }
        TargetRuntimeStep::Stop(reference) => (
            LifecyclePhase::StopLocal,
            Some(digest(&("kasumi.stop-local-target-input.v1", reference))?),
        ),
    };
    ensure!(
        intent.request.phase == phase
            && hash.is_none_or(|hash| hash == intent.request.phase_input_sha256),
        "target request phase input differs"
    );
    Ok(())
}
