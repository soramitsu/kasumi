//! Data-purpose admission of a complete future mutation's immutable shape.
use crate::{MutationBatch, ReadAssertion};
use serde::{Deserialize, Serialize};

/// Full future batch. Document versions are still late bound by its owning
/// application; Snapshot assertions must already name the current native epochs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmitMutationCapacity {
    pub expected_incarnation: String,
    pub batch: MutationBatch,
}

/// Exact batch shape admitted under one linearizable current policy/schema.
/// This neither executes writes nor reserves future tenant storage. Dispatch
/// must retain the Snapshot assertion and all original business read assertions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MutationCapacityAdmission {
    pub tenant: String,
    pub incarnation: String,
    pub revision: u64,
    pub policy_epoch: u64,
    pub schema_epoch: u64,
    pub batch_digest: String,
}

impl MutationCapacityAdmission {
    /// Native epoch assertion that must fence the actual later mutation.
    pub fn snapshot_assertion(&self) -> ReadAssertion {
        ReadAssertion::Snapshot {
            incarnation: self.incarnation.clone(),
            policy_epoch: self.policy_epoch,
            schema_epoch: self.schema_epoch,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn complete_batch_and_epoch_admission_have_closed_exact_json() {
        let admission = MutationCapacityAdmission {
            tenant: "fi".into(),
            incarnation: "native-current".into(),
            revision: 7,
            policy_epoch: 3,
            schema_epoch: 2,
            batch_digest: "a".repeat(64),
        };
        let batch = MutationBatch::with_key("effect-plus-phase")
            .read_set([admission.snapshot_assertion()])
            .insert("auth", "phase", json!({"phase":"applied"}));
        let request = AdmitMutationCapacity {
            expected_incarnation: admission.incarnation.clone(),
            batch,
        };
        let encoded = serde_json::to_vec(&request).unwrap();
        let decoded: AdmitMutationCapacity = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.expected_incarnation, request.expected_incarnation);
        assert_eq!(decoded.batch, request.batch);
        assert_eq!(
            serde_json::from_slice::<MutationCapacityAdmission>(
                &serde_json::to_vec(&admission).unwrap()
            )
            .unwrap(),
            admission
        );
        let mut unknown = serde_json::to_value(&request).unwrap();
        unknown["admin"] = json!(true);
        assert!(serde_json::from_value::<AdmitMutationCapacity>(unknown).is_err());
    }
}
