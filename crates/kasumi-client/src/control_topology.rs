//! A native invocation owns its request identity and original elapsed deadline.
//! Routing metadata never grants a tenant operation or an issuer lease.
use super::*;
use kasumi_clock::{ClockObservation, ElapsedDeadline, EpochClock};
use sha2::{Digest, Sha256};
use std::result::Result;
use std::time::Duration;

#[cfg(test)]
#[path = "control_topology_tests.rs"]
mod tests;

/// A verified reply from an actual pinned connection. It has no deserializer or
/// public constructor. Copies preserve the original suspend-aware deadline.
#[derive(Clone)]
pub struct CurrentControlTopology {
    signed: SignedControlTopology,
    deadline: ElapsedDeadline,
}
impl CurrentControlTopology {
    pub fn check(&self) -> anyhow::Result<()> {
        self.deadline.check()
    }
    pub fn observation(&self) -> anyhow::Result<&ControlTopologyObservation> {
        self.check()?;
        Ok(&self.signed.observation)
    }
    fn admit(
        trust: &ControlTrust,
        request: &ReadControlTopology,
        caller: &ControlTopologyCaller,
        anchor: ClockObservation,
        signed: SignedControlTopology,
    ) -> Result<Self, ClientError> {
        trust.verify_topology(&signed)?;
        let observation = &signed.observation;
        if observation.request != *request || observation.caller != *caller {
            return Err(ClientError::InvalidResponse(
                "Control topology request or caller differs",
            ));
        }
        // Queue, network, decode and verification time consume the original
        // request lifetime. A future server timestamp cannot extend it.
        let local_limit = anchor
            .utc_ms()
            .checked_add(request.maximum_lifetime_ms)
            .ok_or(ClientError::InvalidResponse(
                "Control topology deadline overflow",
            ))?;
        let deadline = anchor.until(local_limit.min(observation.not_after_ms))?;
        let value = Self { signed, deadline };
        value.check()?;
        Ok(value)
    }
}

/// A subsequent current quorum release of exactly one retained original read.
/// It shares that read's deadline and is not an execution authorization.
#[derive(Clone)]
pub struct CurrentControlTopologyRelease {
    original: CurrentControlTopology,
    signed: SignedControlTopologyRelease,
}
impl CurrentControlTopologyRelease {
    pub fn check(&self) -> anyhow::Result<()> {
        self.original.check()
    }
    pub fn observation(&self) -> anyhow::Result<&ControlTopologyObservation> {
        self.original.observation()
    }
    pub fn release(&self) -> anyhow::Result<&ControlTopologyRelease> {
        self.check()?;
        Ok(&self.signed.release)
    }
}

impl KasumiLifecycleClient {
    /// Requests a new observation. The transport fixes the actual certificate;
    /// the caller supplies the expected principal, never a response timestamp.
    pub async fn observe_topology(
        &mut self,
        bearer: &str,
        principal: &str,
        maximum_lifetime_ms: u64,
    ) -> Result<CurrentControlTopology, ClientError> {
        let request = ReadControlTopology {
            request_id: uuid::Uuid::new_v4(),
            control_incarnation: self.trust.root().control_incarnation,
            maximum_lifetime_ms,
        };
        request.validate()?;
        let caller = self.topology_caller(bearer, principal)?;
        let wire = self.authorized(
            bearer,
            proto::ControlJsonRequest {
                request_json: encode(&request)?,
            },
        )?;
        let anchor = EpochClock::system()?.observe()?;
        let response = tokio::time::timeout(
            Duration::from_millis(maximum_lifetime_ms),
            self.inner.observe_topology(wire),
        )
        .await
        .map_err(|_| tonic::Status::deadline_exceeded("Control topology request expired"))??
        .into_inner();
        if response.response_json.len() > MAX_CONTROL_TOPOLOGY_BYTES {
            return Err(ClientError::InvalidResponse(
                "Control topology response too large",
            ));
        }
        let signed = serde_json::from_slice(&response.response_json)?;
        CurrentControlTopology::admit(&self.trust, &request, &caller, anchor, signed)
    }

    /// Release never renews the original request or credential. A different
    /// client certificate, signer root or bearer cannot release a retained read.
    pub async fn release_topology(
        &mut self,
        bearer: &str,
        original: &CurrentControlTopology,
    ) -> Result<CurrentControlTopologyRelease, ClientError> {
        original.check()?;
        let observed = &original.signed.observation;
        if observed.root != *self.trust.root()
            || observed.caller != self.topology_caller(bearer, &observed.caller.principal)?
        {
            return Err(ClientError::InvalidResponse(
                "Control topology release caller differs",
            ));
        }
        let request = ReleaseControlTopology {
            request_id: uuid::Uuid::new_v4(),
            original: original.signed.clone(),
        };
        let wire = self.authorized(
            bearer,
            proto::ControlJsonRequest {
                request_json: encode(&request)?,
            },
        )?;
        let response = tokio::time::timeout(
            original.deadline.remaining()?,
            self.inner.release_topology(wire),
        )
        .await
        .map_err(|_| tonic::Status::deadline_exceeded("Control topology release expired"))??
        .into_inner();
        original.check()?;
        if response.response_json.len() > 4096 {
            return Err(ClientError::InvalidResponse(
                "Control topology release too large",
            ));
        }
        let signed = serde_json::from_slice(&response.response_json)?;
        self.trust
            .verify_topology_release(&original.signed, request.request_id, &signed)?;
        original.check()?;
        Ok(CurrentControlTopologyRelease {
            original: original.clone(),
            signed,
        })
    }

    fn topology_caller(
        &self,
        bearer: &str,
        principal: &str,
    ) -> Result<ControlTopologyCaller, ClientError> {
        // Share the native header admission before hashing untrusted input.
        self.authorized(bearer, ())?;
        let caller = ControlTopologyCaller {
            principal: principal.to_owned(),
            certificate_sha256: self.certificate_sha256.clone(),
            credential_sha256: hex::encode(Sha256::digest(bearer.as_bytes())),
        };
        caller.validate()?;
        Ok(caller)
    }
}
