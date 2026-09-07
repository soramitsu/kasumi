use kasumi_engine::{SECURITY_TENANT, SecurityAudit};
use kasumi_store::{NodeStore, TenantStore, test_utils::LocalKeyProvider};
use std::sync::Arc;

/// The node's service security ledger uses its own encrypted tenant namespace
/// and wrapping key, independently of customer tenant revocation.
pub async fn security_audit(node: Arc<NodeStore>) -> Arc<SecurityAudit> {
    let store = TenantStore::open_fixture(
        node,
        SECURITY_TENANT.into(),
        Arc::new(LocalKeyProvider::new([0xA7; 32])),
    )
    .await
    .unwrap();
    SecurityAudit::open(store, 100_000).unwrap()
}
