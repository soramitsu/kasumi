//! Explicit deterministic bootstrap for tests that drive maintenance transitions
//! themselves. This module is absent from production builds.
use super::*;

fn check(stores: &TenantStorageSet) -> anyhow::Result<()> {
    anyhow::ensure!(
        matches!(
            stores.application().storage_access().purpose(),
            kasumi_store::StoragePurpose::LocalFixture | kasumi_store::StoragePurpose::NodeControl
        ),
        "fixture bootstrap cannot open production application storage"
    );
    Ok(())
}

pub async fn open_fixture(
    stores: Arc<TenantStorageSet>,
    policy: Policy,
    limits: Limits,
    audit: Arc<SecurityAudit>,
) -> anyhow::Result<Arc<Database>> {
    check(&stores)?;
    open_local_inner(
        stores,
        policy,
        limits,
        audit,
        None,
        LocalRuntime::FixtureDefault,
    )
    .await
}

pub async fn open_fixture_with_incarnation(
    stores: Arc<TenantStorageSet>,
    policy: Policy,
    limits: Limits,
    audit: Arc<SecurityAudit>,
    incarnation: uuid::Uuid,
) -> anyhow::Result<Arc<Database>> {
    check(&stores)?;
    anyhow::ensure!(!incarnation.is_nil(), "nil fixture incarnation");
    open_local_inner(
        stores,
        policy,
        limits,
        audit,
        Some(incarnation),
        LocalRuntime::FixtureDefault,
    )
    .await
}

pub async fn open_fixture_replicated(
    node_id: u64,
    stores: Arc<TenantStorageSet>,
    bootstrap: &ReplicatedBootstrap,
    transport: Arc<dyn RaftTransport>,
    config: Config,
    audit: Arc<SecurityAudit>,
) -> anyhow::Result<Arc<Database>> {
    check(&stores)?;
    let (database, _) = open_replicated_inner(
        node_id,
        stores,
        transport,
        config,
        audit,
        ReplicaRuntime::FixtureEnrollment(bootstrap),
    )
    .await?;
    Ok(database)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::NodeAdmission;
    use kasumi_store::{NodeStore, TenantStore, test_utils::LocalKeyProvider};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn production_bootstrap_installs_shared_pool_for_application_and_control() {
        let directory = tempfile::tempdir().unwrap();
        let node = NodeStore::create_new(
            directory.path().join("node.redb"),
            kasumi_store::test_utils::NODE_STORE_ID,
            kasumi_store::ScratchDisk::fixture(),
        )
        .unwrap();
        let admission = NodeAdmission::new(Default::default()).unwrap();
        let audit_store = TenantStore::open_fixture(
            node.clone(),
            crate::SECURITY_TENANT.into(),
            Arc::new(LocalKeyProvider::new([41; 32])),
        )
        .await
        .unwrap();
        let audit =
            SecurityAudit::initialize(audit_store.clone(), Default::default(), admission.clone())
                .unwrap();
        assert!(
            SecurityAudit::open(
                audit_store,
                Default::default(),
                NodeAdmission::new(Default::default()).unwrap()
            )
            .is_err()
        );
        let mut databases = Vec::new();
        for name in ["tenant", "__kasumi_control", "manual"] {
            let store = TenantStore::open_fixture(
                node.clone(),
                name.into(),
                Arc::new(LocalKeyProvider::new([42; 32])),
            )
            .await
            .unwrap();
            let stores = kasumi_store::test_utils::with_custody(
                store,
                Arc::new(LocalKeyProvider::new([43; 32])),
            )
            .await
            .unwrap();
            let policy = Policy {
                grants: vec![Grant {
                    principal: "owner".into(),
                    collection: None,
                    actions: BTreeSet::from([Action::Admin]),
                }],
                strict_read_audit: false,
            };
            let database = if name == "manual" {
                open_fixture(stores, policy, Limits::default(), audit.clone())
                    .await
                    .unwrap()
            } else {
                super::super::open_local(stores, policy, Limits::default(), audit.clone())
                    .await
                    .unwrap()
            };
            assert_eq!(
                database.audit_maintenance_status().is_some(),
                name != "manual"
            );
            database.install_admission(admission.clone()).unwrap();
            database.install_admission(admission.clone()).unwrap();
            assert!(
                database
                    .install_admission(NodeAdmission::new(Default::default()).unwrap())
                    .is_err()
            );
            databases.push(database);
        }
        assert_eq!(
            admission.snapshot().reserved_bytes,
            3 * AuditRetentionBudget::MAINTENANCE_BYTES
        );
        for database in databases {
            database.shutdown().await.unwrap();
        }
        audit.shutdown().await;
        assert_eq!(admission.snapshot().reserved_bytes, 0);
    }
}
