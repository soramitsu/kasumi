use super::*;
use kasumi_store::{NodeStore, ScratchDisk, StorageAccess, test_utils::LocalKeyProvider};

async fn fixture() -> Result<(tempfile::TempDir, Arc<NodeStore>, Arc<TenantStore>, Input)> {
    let directory = tempfile::tempdir()?;
    let mut configuration = crate::runtime::example_config();
    configuration.database_path = directory.path().join("node.redb");
    let node = NodeStore::create_new(
        &configuration.database_path,
        configuration.database_id,
        ScratchDisk::fixture(),
    )?;
    let store = TenantStore::initialize_catalog(
        node.clone(),
        kasumi_engine::SECURITY_TENANT.into(),
        Arc::new(LocalKeyProvider::new([73; 32])),
        StorageAccess::security_audit(),
    )
    .await?;
    Ok((
        directory,
        node,
        store,
        Input::Data {
            configuration: Box::new(configuration),
        },
    ))
}

fn record_genesis(enrollment: &Enrollment, store: &TenantStore, input: &Input) -> Result<()> {
    if let Input::Data { configuration } = input {
        for tenant in &configuration.tenants {
            enrollment.record_genesis_tenant(
                store,
                &tenant.tenant,
                tenant
                    .incarnation
                    .as_deref()
                    .map(Uuid::parse_str)
                    .transpose()?
                    .unwrap_or_else(Uuid::new_v4),
                "11".repeat(32),
            )?;
        }
    }
    Ok(())
}

fn records(store: &TenantStore) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut rows = Vec::new();
    store.visit(NS, MAX_INPUT, |key, value| {
        rows.push((key.to_vec(), value.to_vec()));
        Ok(())
    })?;
    Ok(rows)
}

#[tokio::test]
async fn enrollment_requires_exact_completed_input_and_never_adopts_partial_history() -> Result<()>
{
    let (_directory, node, store, input) = fixture().await?;
    let (_, id) = input.identity();
    assert!(require_complete(&store, id, Kind::Data).is_err());
    let enrollment = Enrollment::begin(&store, &input)?;
    let original = records(&store)?;
    assert!(require_complete(&store, id, Kind::Data).is_err());
    assert!(Enrollment::begin(&store, &input).is_err());
    assert_eq!(records(&store)?, original);
    record_genesis(&enrollment, &store, &input)?;
    enrollment.complete(&store)?;
    require_complete(&store, id, Kind::Data)?;
    let completed = records(&store)?;
    assert!(require_complete(&store, Uuid::new_v4(), Kind::Data).is_err());
    assert!(require_complete(&store, id, Kind::Authority).is_err());
    assert!(Enrollment::begin(&store, &input).is_err());
    assert_eq!(records(&store)?, completed);
    store.shutdown().await;
    drop(store);
    let reopened = TenantStore::open_existing(
        node,
        kasumi_engine::SECURITY_TENANT.into(),
        Arc::new(LocalKeyProvider::new([73; 32])),
        StorageAccess::security_audit(),
    )
    .await?;
    require_complete(&reopened, id, Kind::Data)?;
    assert_eq!(records(&reopened)?, completed);
    reopened.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn missing_or_substituted_enrollment_records_fail_without_logical_mutation() -> Result<()> {
    for corruption in [0, 1, 2] {
        let (_directory, _node, store, input) = fixture().await?;
        let (_, id) = input.identity();
        let enrollment = Enrollment::begin(&store, &input)?;
        record_genesis(&enrollment, &store, &input)?;
        enrollment.complete(&store)?;
        let change = match corruption {
            0 => WriteOp::delete(NS, b"head"),
            1 => WriteOp::put(NS, b"head", b"{}".to_vec()),
            _ => WriteOp::put(NS, b"input", b"{}".to_vec()),
        };
        store.write_batch(&[change])?;
        let before = records(&store)?;
        assert!(require_complete(&store, id, Kind::Data).is_err());
        assert!(Enrollment::begin(&store, &input).is_err());
        assert_eq!(records(&store)?, before);
        store.shutdown().await;
    }
    Ok(())
}

#[tokio::test]
async fn completed_genesis_requires_all_tenant_records_and_rejects_the_old_head_format()
-> Result<()> {
    let (_directory, _node, store, input) = fixture().await?;
    let (_, id) = input.identity();
    let enrollment = Enrollment::begin(&store, &input)?;
    assert!(enrollment.complete(&store).is_err());
    // The failed completion wrote nothing and did not erase its original input.
    let enrollment = Enrollment {
        head: serde_json::from_slice(&store.get(NS, b"head")?.unwrap())?,
    };
    record_genesis(&enrollment, &store, &input)?;
    enrollment.complete(&store)?;
    let Input::Data { configuration } = &input else {
        unreachable!()
    };
    let key = format!("tenant/{}", configuration.tenants[0].tenant);
    let record = store.get(NS, key.as_bytes())?.unwrap();
    store.write_batch(&[WriteOp::delete(NS, key.as_bytes())])?;
    let before = records(&store)?;
    assert!(require_complete(&store, id, Kind::Data).is_err());
    assert_eq!(records(&store)?, before);
    store.write_batch(&[WriteOp::put(NS, key.as_bytes(), record)])?;
    let mut head: Head = serde_json::from_slice(&store.get(NS, b"head")?.unwrap())?;
    head.format = 1;
    store.write_batch(&[WriteOp::put(NS, b"head", serde_json::to_vec(&head)?)])?;
    let before = records(&store)?;
    assert!(require_complete(&store, id, Kind::Data).is_err());
    assert_eq!(records(&store)?, before);
    store.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn explicit_tenant_dispatch_and_prepared_outcome_never_restore_creation_permission()
-> Result<()> {
    let (_directory, _node, store, input) = fixture().await?;
    let enrollment = Enrollment::begin(&store, &input)?;
    record_genesis(&enrollment, &store, &input)?;
    enrollment.complete(&store)?;
    let Input::Data { configuration } = &input else {
        unreachable!()
    };
    let proposal = Proposal {
        format: 1,
        tenant: "new-tenant".into(),
        route: kasumi_engine::control::TenantRoute {
            incarnation: Uuid::new_v4().to_string(),
            mode: kasumi_engine::control::DeploymentMode::Local,
            voters: std::collections::BTreeSet::from([1]),
        },
        nodes: std::collections::BTreeMap::from([(
            1,
            kasumi_engine::control::ControlNode {
                endpoint: "https://localhost:9000".into(),
                failure_domain: "local".into(),
                certificate_pins: std::collections::BTreeSet::from(["22".repeat(32)]),
            },
        )]),
        initial_policy: configuration.tenants[0].initial_policy.clone(),
        initial_limits: configuration.tenants[0].initial_limits.clone(),
        application_keys: serde_json::json!({"identity":"application"}),
        custody_keys: serde_json::json!({"identity":"custody"}),
        authority_id: None,
    };
    assert!(tenant_record(&store, &proposal.tenant)?.is_none());
    let original = dispatch_tenant(&store, proposal.clone(), "exact-original-request".into())?;
    let before = records(&store)?;
    assert!(dispatch_tenant(&store, proposal.clone(), "retry".into()).is_err());
    assert_eq!(records(&store)?, before);
    let mut different = proposal.clone();
    different.initial_limits.max_documents -= 1;
    assert!(original.require_proposal(&different).is_err());
    let mut prepared = original.clone();
    prepared.stage = Stage::Prepared;
    prepared.bootstrap_sha256 = Some("33".repeat(32));
    update_tenant(&store, &original, &prepared)?;
    let before = records(&store)?;
    assert!(update_tenant(&store, &prepared, &original).is_err());
    assert!(dispatch_tenant(&store, proposal.clone(), "retry".into()).is_err());
    assert_eq!(records(&store)?, before);
    assert_eq!(
        tenant_record(&store, &proposal.tenant)?.unwrap().stage,
        Stage::Prepared
    );
    store.shutdown().await;
    Ok(())
}
