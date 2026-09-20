//! A current publication observation can only originate in this actual pinned
//! native request. A serialized coverage record cannot reconstruct its clock.
use crate::{ClientError, KasumiAdminClient, KasumiAuthorityClient, KasumiClientConfig};
use kasumi_clock::{ElapsedDeadline, EpochClock};
use kasumi_serving::*;
use std::time::Duration;

pub struct CurrentSignerPublication {
    dispatch_sha256: String,
    response: SignerPublicationResponse,
    deadline: ElapsedDeadline,
}
impl CurrentSignerPublication {
    /// Uses exactly the enrolled origin and leaf pins and one caller-provided
    /// credential snapshot. No endpoint retry, discovery or environment source.
    pub async fn observe(
        config: &KasumiClientConfig,
        bearer: &str,
        trust: AuthorityTrust,
        dispatch: &SignerCoverageDispatch,
    ) -> Result<Self, ClientError> {
        let dispatch_sha256 = dispatch.digest()?;
        let expected = &dispatch.registration.enrollment;
        if url::Url::parse(&config.endpoint)
            .map_err(anyhow::Error::from)?
            .to_string()
            != expected.endpoint
            || config
                .server_certificate_pins
                .iter()
                .map(hex::encode)
                .collect::<std::collections::BTreeSet<_>>()
                != expected.certificate_pins
        {
            return Err(ClientError::InvalidResponse(
                "publication connection differs from frozen physical enrollment",
            ));
        }
        let manifest = trust.manifest().clone();
        let anchor = EpochClock::system()?.observe()?;
        let lifetime_ms = manifest.max_lease_ms.min(5000);
        let deadline = anchor.until(
            anchor
                .utc_ms()
                .checked_add(lifetime_ms)
                .ok_or_else(|| anyhow::anyhow!("publication observation deadline overflow"))?,
        )?;
        let operation = async {
            match &dispatch.command.publication {
                SignerPublicationRequest::Issuer { .. } => {
                    let mut client = KasumiAuthorityClient::connect(config, trust).await?;
                    Ok::<_, ClientError>(SignerPublicationResponse::Issuer(Box::new(
                        client
                            .signer_maintenance(
                                bearer,
                                &dispatch.command.publication.issuer_request()?,
                            )
                            .await?,
                    )))
                }
                SignerPublicationRequest::Control { request } => {
                    let mut client = KasumiAdminClient::connect(config).await?;
                    Ok(SignerPublicationResponse::Control(Box::new(
                        client
                            .control_signer_maintenance(bearer, request, &manifest)
                            .await?,
                    )))
                }
            }
        };
        let response = tokio::time::timeout(Duration::from_millis(lifetime_ms), operation)
            .await
            .map_err(|_| {
                tonic::Status::deadline_exceeded("original publication observation expired")
            })??;
        response.validate_for(&dispatch.command.publication, &manifest)?;
        let observation = Self {
            dispatch_sha256,
            response,
            deadline,
        };
        observation.check(dispatch)?;
        Ok(observation)
    }
    pub fn check(&self, dispatch: &SignerCoverageDispatch) -> anyhow::Result<()> {
        self.deadline.check()?;
        anyhow::ensure!(
            self.dispatch_sha256 == dispatch.digest()?,
            "current publication cannot acknowledge another dispatch"
        );
        Ok(())
    }
    /// Historical data only. Callers must retain and check this opaque owner
    /// through consensus admission and response release.
    pub fn response(&self) -> &SignerPublicationResponse {
        &self.response
    }
}
