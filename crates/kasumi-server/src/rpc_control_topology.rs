//! Current routing observations over the installed authenticated Control listener.
use super::*;
use kasumi_types::{ControlTopologyCaller, ReadControlTopology, ReleaseControlTopology};
use sha2::{Digest, Sha256};

impl NativeLifecycleControl {
    /// Called only after native authentication. Headers cannot supply the TLS pin
    /// or principal; the exact verified bearer is represented only by its digest.
    fn topology_caller<T>(
        &self,
        request: &Request<T>,
        context: &RequestContext,
    ) -> Result<ControlTopologyCaller, Status> {
        let pin = request
            .extensions()
            .get::<crate::tls::AuthenticatedTlsPeer>()
            .and_then(|peer| peer.certificate_pin())
            .ok_or_else(|| Status::unauthenticated("actual mTLS caller required"))?;
        let mut headers = request.metadata().get_all("authorization").iter();
        let bearer = headers
            .next()
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .filter(|value| !value.is_empty())
            .ok_or_else(|| Status::unauthenticated("exact native bearer required"))?;
        if headers.next().is_some() {
            return Err(Status::unauthenticated("duplicate authorization"));
        }
        Ok(ControlTopologyCaller {
            principal: context.principal.clone(),
            certificate_sha256: hex::encode(pin),
            credential_sha256: hex::encode(Sha256::digest(bearer.as_bytes())),
        })
    }

    pub(super) async fn observe_topology_response(
        &self,
        request: Request<ControlJsonRequest>,
    ) -> Result<Response<ControlJsonResponse>, Status> {
        let context = self.context(&request).await?;
        let caller = self.topology_caller(&request, &context)?;
        let input: ReadControlTopology =
            decode_json(&request.into_inner().request_json).map_err(status)?;
        let proof = self
            .auth
            .audit_result(
                &context,
                self.database
                    .observe_control_topology(context.clone(), input, caller)
                    .await,
            )
            .await
            .map_err(status)?;
        let signed = self
            .auth
            .audit_result(&context, self.signer.sign_topology(&proof).await)
            .await
            .map_err(status)?;
        let response = ControlJsonResponse {
            response_json: encode_json(&signed).map_err(status)?,
        };
        self.auth
            .audit_result(&context, proof.release().await)
            .await
            .map_err(status)?;
        proof.release().await.map_err(status)?;
        Ok(Response::new(response))
    }

    pub(super) async fn release_topology_response(
        &self,
        request: Request<ControlJsonRequest>,
    ) -> Result<Response<ControlJsonResponse>, Status> {
        let context = self.context(&request).await?;
        let caller = self.topology_caller(&request, &context)?;
        let input: ReleaseControlTopology =
            decode_json(&request.into_inner().request_json).map_err(status)?;
        let trust = kasumi_serving::ControlTrust::install(self.signer.root().clone())
            .map_err(|_| Status::internal("installed Control trust unavailable"))?;
        let proof = self
            .auth
            .audit_result(
                &context,
                self.database
                    .release_control_topology(context.clone(), &input, caller, &trust)
                    .await,
            )
            .await
            .map_err(status)?;
        let signed = self
            .auth
            .audit_result(
                &context,
                self.signer.sign_topology_release(&proof, &input).await,
            )
            .await
            .map_err(status)?;
        let response = ControlJsonResponse {
            response_json: encode_json(&signed).map_err(status)?,
        };
        self.auth
            .audit_result(&context, proof.release().await)
            .await
            .map_err(status)?;
        proof.release().await.map_err(status)?;
        Ok(Response::new(response))
    }
}
