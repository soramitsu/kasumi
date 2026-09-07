use kasumi_types::{RestoreLineageCommitment, RestoreLineageObservation};

/// Historical provenance, observed through current authenticated data access.
/// This is not a lease, credential, membership or permission grant. Consumers
/// must independently authorize every current financial/People operation.
///
/// ```compile_fail
/// let _: kasumi_engine::VerifiedRestoreLineage = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct VerifiedRestoreLineage {
    observation: RestoreLineageObservation,
}
impl VerifiedRestoreLineage {
    pub(crate) fn from_verified_read(observation: RestoreLineageObservation) -> Self {
        Self { observation }
    }
    pub fn observation(&self) -> &RestoreLineageObservation {
        &self.observation
    }
    pub fn tenant(&self) -> &str {
        &self.observation.tenant
    }
    pub fn incarnation(&self) -> &str {
        &self.observation.incarnation
    }
    pub fn collection(&self) -> &str {
        &self.observation.collection
    }
    pub fn links(&self) -> &[RestoreLineageCommitment] {
        &self.observation.links
    }
    pub fn revision(&self) -> u64 {
        self.observation.revision
    }
    pub fn policy_epoch(&self) -> u64 {
        self.observation.policy_epoch
    }
}
