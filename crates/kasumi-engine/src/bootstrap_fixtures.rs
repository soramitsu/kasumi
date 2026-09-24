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
        DatabaseConstruction::new(stores, audit)?,
        policy,
        limits,
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
        DatabaseConstruction::new(stores, audit)?,
        policy,
        limits,
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
    use kasumi_store::{TenantStore, test_utils::LocalKeyProvider};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn production_bootstrap_installs_shared_pool_for_application_and_control() {
        let directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let (persistent_config, scratch_config) =
            crate::test_utils::fixture_disk_configs(directory.path()).unwrap();
        let metadata =
            crate::test_utils::isolated_disk_metadata_bytes(&persistent_config, &scratch_config)
                .unwrap();
        let storage = crate::test_utils::FixtureStorage::open(
            &persistent_config,
            &scratch_config,
            Default::default(),
        )
        .unwrap();
        assert_eq!(
            crate::test_utils::reserved_payload_bytes(&storage.admission),
            metadata
        );
        let node = storage
            .create_new(
                directory.path().join("persistent/node.kv"),
                kasumi_store::test_utils::NODE_STORE_ID,
            )
            .unwrap();
        let admission = storage.admission.clone();
        let audit_store = TenantStore::initialize_catalog_fixture(
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
        let before_databases = admission.snapshot().reserved_bytes;
        let mut databases = Vec::new();
        for name in ["tenant", "__kasumi_control", "manual"] {
            let store = TenantStore::initialize_catalog_fixture(
                node.clone(),
                name.into(),
                Arc::new(LocalKeyProvider::new([42; 32])),
            )
            .await
            .unwrap();
            let stores = kasumi_store::test_utils::initialize_custody_fixture(
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
            assert!(Arc::ptr_eq(database.admission(), &admission));
            databases.push(database);
        }
        // Opening these tenants also installs native KV index entries. The
        // fixed audit and snapshot owners are additional to that live charge.
        assert!(
            admission.snapshot().reserved_bytes
                >= before_databases
                    + 2 * AuditRetentionBudget::MAINTENANCE_BYTES
                    + 3 * kasumi_raft::SnapshotBufferOwner::required_bytes(
                        kasumi_raft::SNAPSHOT_BUFFER_SLOTS,
                    )
                    .unwrap()
        );
        for database in databases {
            database.shutdown().await.unwrap();
        }
        audit.shutdown().await.unwrap();
        drop(audit);
        drop(node);
        let drained = admission.snapshot();
        // Shared installed disk metadata remains charged after all three
        // databases and their shared audit/maintenance workers have drained.
        assert_eq!(
            drained.reserved_bytes,
            drained.bookkeeping_bytes.checked_add(metadata).unwrap()
        );
    }
}
