use kasumi_engine::{SECURITY_TENANT, SecurityAudit};
use kasumi_store::{NodeStore, TenantStore, test_utils::LocalKeyProvider};
use std::sync::Arc;

/// The node's service security ledger uses its own encrypted tenant namespace
/// and wrapping key, independently of customer tenant revocation.
pub async fn security_audit(node: Arc<NodeStore>) -> Arc<SecurityAudit> {
    security_audit_with_admission(
        node,
        kasumi_engine::admission::NodeAdmission::new(Default::default()).unwrap(),
    )
    .await
}

#[allow(dead_code)]
pub async fn security_audit_with_admission(
    node: Arc<NodeStore>,
    admission: Arc<kasumi_engine::admission::NodeAdmission>,
) -> Arc<SecurityAudit> {
    let store = TenantStore::open_fixture(
        node,
        SECURITY_TENANT.into(),
        Arc::new(LocalKeyProvider::new([0xA7; 32])),
    )
    .await
    .unwrap();
    SecurityAudit::open(
        store,
        kasumi_types::AuditRetentionBudget::default(),
        admission,
    )
    .unwrap()
}

#[allow(dead_code)]
pub fn local_restore_request(
    context: kasumi_types::RequestContext,
    checkpoint: &kasumi_types::FullBackupCheckpoint,
    target: uuid::Uuid,
) -> kasumi_engine::LocalRestoreRequest {
    kasumi_engine::LocalRestoreRequest {
        checkpoint: checkpoint.clone(),
        target_incarnation: target,
        source_context: context.clone(),
        target_context: context,
        source_purpose: kasumi_store::StoragePurpose::LocalFixture,
    }
}

/// Structurally valid input for tests whose source never completes an I/O.
#[allow(dead_code)]
pub fn unavailable_checkpoint(tenant: &str, id: uuid::Uuid) -> kasumi_types::FullBackupCheckpoint {
    kasumi_types::FullBackupCheckpoint {
        tenant: tenant.into(),
        source_incarnation: uuid::Uuid::new_v4().to_string(),
        revision: 1,
        resident_sha256: "00".repeat(32),
        backup_id: id,
        manifest_ciphertext_sha256: "00".repeat(32),
        key_lineage_digest: "00".repeat(32),
    }
}
