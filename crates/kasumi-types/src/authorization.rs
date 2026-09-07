//! Required first-release invocation validity. Deserialization yields replicated
//! observations, never a new live service or bearer invocation.
use crate::{CredentialResource, Error, ErrorCode, Result};
use kasumi_clock::{ClockObservation, ElapsedDeadline};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum AuthorizationMetadata {
    ServiceIdentity {},
    Credential {
        expires_at_ms: u64,
        resource: CredentialResource,
    },
}
#[derive(Clone)]
enum LiveAuthorization {
    ServiceIdentity,
    Credential(ElapsedDeadline),
}

/// Trusted embedding applications explicitly choose service identity or supply
/// verified credential claims. Native adapters must derive credential validity
/// from verified authentication; remote payloads never select service identity.
/// Clones preserve the original live deadline. Serialized records retain only
/// deterministic metadata and cannot be admitted as a fresh local request.
#[derive(Clone)]
pub struct RequestAuthorization {
    metadata: AuthorizationMetadata,
    live: Option<Arc<LiveAuthorization>>,
}
impl std::fmt::Debug for RequestAuthorization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.metadata.fmt(f)
    }
}
impl PartialEq for RequestAuthorization {
    fn eq(&self, other: &Self) -> bool {
        self.metadata == other.metadata
    }
}
impl Eq for RequestAuthorization {}
impl Serialize for RequestAuthorization {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        self.metadata.serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for RequestAuthorization {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        Ok(Self {
            metadata: AuthorizationMetadata::deserialize(deserializer)?,
            live: None,
        })
    }
}
impl RequestAuthorization {
    /// For an explicitly trusted installed or embedding identity, never native
    /// request metadata/body and never a deserialized replicated context.
    pub fn service_identity() -> Self {
        Self {
            metadata: AuthorizationMetadata::ServiceIdentity {},
            live: Some(Arc::new(LiveAuthorization::ServiceIdentity)),
        }
    }
    /// Called only after cryptographic credential verification, using the
    /// original paired trusted time observation captured by that boundary.
    pub fn from_verified_credential(
        expires_at_ms: u64,
        observation: &ClockObservation,
        resource: CredentialResource,
    ) -> Result<Self> {
        resource.validate()?;
        let deadline = observation.until(expires_at_ms).map_err(|_| expired())?;
        Ok(Self {
            metadata: AuthorizationMetadata::Credential {
                expires_at_ms,
                resource,
            },
            live: Some(Arc::new(LiveAuthorization::Credential(deadline))),
        })
    }
    /// Source admission, serialized leader execution and plaintext handoff call
    /// this against the original local proof, not its serialized metadata.
    pub fn check_live(&self) -> Result<()> {
        match self.live.as_deref() {
            Some(LiveAuthorization::ServiceIdentity) => Ok(()),
            Some(LiveAuthorization::Credential(deadline)) => {
                deadline.check().map_err(|_| expired())
            }
            None => Err(Error::new(
                ErrorCode::Unauthorized,
                "replicated authorization metadata is not a live invocation",
            )),
        }
    }
    /// Deterministic replica check against the trusted timestamp captured by the
    /// serialized leader. It deliberately does not sample a replica wall clock.
    pub fn check_admitted_at(&self, trusted_timestamp_ms: u64) -> Result<()> {
        match &self.metadata {
            AuthorizationMetadata::ServiceIdentity {} => Ok(()),
            AuthorizationMetadata::Credential { expires_at_ms, .. }
                if trusted_timestamp_ms < *expires_at_ms =>
            {
                Ok(())
            }
            AuthorizationMetadata::Credential { .. } => Err(expired()),
        }
    }
    /// Exact locally verified invocation identity. Equal serialized claims or a
    /// second verification of the same token cannot recreate a captured fence.
    pub fn same_live_invocation(&self, other: &Self) -> bool {
        match (&self.live, &other.live) {
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }
    pub fn expires_at_ms(&self) -> Option<u64> {
        match &self.metadata {
            AuthorizationMetadata::ServiceIdentity {} => None,
            AuthorizationMetadata::Credential { expires_at_ms, .. } => Some(*expires_at_ms),
        }
    }
    pub fn resource(&self) -> Option<&CredentialResource> {
        match &self.metadata {
            AuthorizationMetadata::ServiceIdentity {} => None,
            AuthorizationMetadata::Credential { resource, .. } => Some(resource),
        }
    }
    /// Deterministic scope checks apply equally to live leader invocations and
    /// replicated credential metadata. They never turn metadata into a live call.
    pub fn require_database(&self, incarnation: &str) -> Result<()> {
        self.resource()
            .map_or(Ok(()), |r| r.require_database(incarnation))
    }
    pub fn require_control(&self, incarnation: &str) -> Result<()> {
        self.resource()
            .map_or(Ok(()), |r| r.require_control(incarnation))
    }
    pub fn require_custody(&self, incarnation: &str) -> Result<()> {
        self.resource()
            .map_or(Ok(()), |r| r.require_custody(incarnation))
    }
    pub fn require_authority(&self, authority_id: uuid::Uuid, partition: u16) -> Result<()> {
        self.resource()
            .map_or(Ok(()), |r| r.require_authority(authority_id, partition))
    }
}
fn expired() -> Error {
    Error::new(ErrorCode::Unauthorized, "authenticated credential expired")
}

#[cfg(test)]
mod tests {
    use super::*;
    use kasumi_clock::{EpochClock, LeaseClock, WallClock};
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::Duration,
    };
    fn resource() -> CredentialResource {
        CredentialResource::Database {
            incarnation: uuid::Uuid::from_u128(1),
        }
    }
    struct Wall;
    impl WallClock for Wall {
        fn now_ms(&self) -> anyhow::Result<u64> {
            Ok(1000)
        }
    }
    struct Clock(AtomicU64);
    impl LeaseClock for Clock {
        fn now(&self) -> Duration {
            Duration::from_millis(self.0.load(Ordering::SeqCst))
        }
    }
    #[test]
    fn credential_clone_cannot_renew_expiry_and_serialization_cannot_mint_live_authority() {
        let clock = Arc::new(Clock(AtomicU64::new(20)));
        let epoch = EpochClock::new(clock.clone(), Arc::new(Wall)).unwrap();
        let original = RequestAuthorization::from_verified_credential(
            2000,
            &epoch.observe().unwrap(),
            resource(),
        )
        .unwrap();
        clock.0.store(1000, Ordering::SeqCst);
        let delayed_clone = original.clone();
        delayed_clone.check_live().unwrap();
        let decoded: RequestAuthorization =
            serde_json::from_slice(&serde_json::to_vec(&original).unwrap()).unwrap();
        assert!(decoded.check_live().is_err());
        decoded.check_admitted_at(1999).unwrap();
        assert!(decoded.check_admitted_at(2000).is_err());
        clock.0.store(1020, Ordering::SeqCst);
        assert!(original.check_live().is_err());
        assert!(delayed_clone.check_live().is_err());
        let service: RequestAuthorization =
            serde_json::from_str(r#"{"kind":"service_identity"}"#).unwrap();
        assert!(service.check_live().is_err());
        service.check_admitted_at(u64::MAX).unwrap();
        RequestAuthorization::service_identity()
            .check_live()
            .unwrap();
    }
    #[test]
    fn invalid_credentials_and_a_regressing_elapsed_clock_fail_closed() {
        let clock = Arc::new(Clock(AtomicU64::new(20)));
        let epoch = EpochClock::new(clock.clone(), Arc::new(Wall)).unwrap();
        let observation = epoch.observe().unwrap();
        assert!(
            RequestAuthorization::from_verified_credential(1000, &observation, resource()).is_err()
        );
        assert!(
            RequestAuthorization::from_verified_credential(999, &observation, resource()).is_err()
        );
        let credential =
            RequestAuthorization::from_verified_credential(2000, &observation, resource()).unwrap();
        clock.0.store(19, Ordering::SeqCst);
        assert!(credential.check_live().is_err());
        assert!(serde_json::from_str::<RequestAuthorization>(r#"{"kind":"credential"}"#).is_err());
        assert!(
            serde_json::from_str::<RequestAuthorization>(
                r#"{"kind":"service_identity","live":true}"#
            )
            .is_err()
        );
    }
}
