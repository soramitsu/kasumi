use super::*;
use kasumi_store::{NodeStore, StorageAccess, test_utils::LocalKeyProvider};

async fn fixture() -> Result<(tempfile::TempDir, Arc<NodeStore>, Arc<TenantStore>, Input)> {
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let mut configuration =
        crate::runtime::example_config(kasumi_store::DirectoryPolicy::fixture()).unwrap();
    configuration.admission = Default::default();
    configuration.persistent_disk =
        crate::persistent_disk::fixture_config(&directory.path().join("data"));
    configuration.database_path = directory.path().join("data/node.kv");
    configuration.scratch_disk.directory = directory.path().join("scratch");
    configuration
        .signer_verifier
        .as_mut()
        .unwrap()
        .database_path = directory.path().join("data/trust.kv");
    let storage = crate::runtime_storage_fixtures::configure(&mut configuration)?;
    let _admission = storage.facade(storage.policy())?;
    let node = NodeStore::create_new(
        &configuration.database_path,
        configuration.database_id,
        storage.open_persistent(&configuration.persistent_disk)?,
        storage.open_scratch(&configuration.scratch_disk)?,
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
        if configuration.mode == crate::runtime::DeploymentMode::Replicated {
            enrollment.record_genesis_tenant(
                store,
                crate::runtime::CONTROL_TENANT,
                Uuid::parse_str(configuration.control.incarnation.as_deref().unwrap())?,
                "22".repeat(32),
            )?;
        }
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
    store.shutdown().await.unwrap();
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
    reopened.shutdown().await.unwrap();
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
        store.shutdown().await.unwrap();
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
    store.shutdown().await.unwrap();
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
    let encoded = serde_json::to_vec(&original)?;
    let from_bytes: tenants::TenantRecord = serde_json::from_slice(&encoded)?;
    let from_value: tenants::TenantRecord =
        serde_json::from_value(serde_json::to_value(&original)?)?;
    for decoded in [from_bytes, from_value] {
        assert_eq!(serde_json::to_vec(&decoded)?, encoded);
        decoded.require_proposal(&proposal)?;
    }
    let encoded_text = std::str::from_utf8(&encoded)?;
    let valid_nodes = serde_json::to_string(&proposal.nodes)?;
    let node = serde_json::to_string(&proposal.nodes[&1])?;
    for invalid in [
        format!("{{\"01\":{node}}}"),
        format!("{{\"+1\":{node}}}"),
        format!("{{\"-1\":{node}}}"),
        format!("{{\"18446744073709551616\":{node}}}"),
        format!("{{\"1\":{node},\"1\":{node}}}"),
    ] {
        let replaced = encoded_text.replace(
            &format!("\"nodes\":{valid_nodes}"),
            &format!("\"nodes\":{invalid}"),
        );
        assert_ne!(replaced, encoded_text);
        assert!(serde_json::from_str::<tenants::TenantRecord>(&replaced).is_err());
    }
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
    store.shutdown().await.unwrap();
    Ok(())
}

/// Equivalent spellings the current writer never produces. Serde alone admits
/// each of them as the original value.
fn respelled(current: &[u8]) -> Result<[Vec<u8>; 2]> {
    let spaced = std::str::from_utf8(current)?
        .replacen(':', ": ", 1)
        .into_bytes();
    let reordered = serde_json::to_vec(&serde_json::from_slice::<serde_json::Value>(current)?)?;
    ensure!(
        reordered != current,
        "fixture record already has sorted keys"
    );
    Ok([spaced, reordered])
}

async fn reopen(node: &Arc<NodeStore>) -> Result<Arc<TenantStore>> {
    TenantStore::open_existing(
        node.clone(),
        kasumi_engine::SECURITY_TENANT.into(),
        Arc::new(LocalKeyProvider::new([73; 32])),
        StorageAccess::security_audit(),
    )
    .await
}

#[tokio::test]
async fn noncanonical_enrollment_records_fail_closed_across_restart_without_rewrite() -> Result<()>
{
    let (_directory, node, mut store, input) = fixture().await?;
    let (_, id) = input.identity();
    let Input::Data { configuration } = &input else {
        unreachable!()
    };
    let tenant = configuration.tenants[0].tenant.clone();
    let tenant_key = format!("tenant/{tenant}");
    let enrollment = Enrollment::begin(&store, &input)?;
    record_genesis(&enrollment, &store, &input)?;
    let head = store.get(NS, b"head")?.unwrap();
    let current_input = store.get(NS, b"input")?.unwrap();
    let genesis = store.get(NS, tenant_key.as_bytes())?.unwrap();

    // Completion never adopts a respelled head as its own original outcome.
    let begun = records(&store)?;
    for alternate in respelled(&head)? {
        let admitted: Head = serde_json::from_slice(&alternate)?;
        assert!(admitted == enrollment.head);
        store.write_batch(&[WriteOp::put(NS, b"head", alternate)])?;
        let before = records(&store)?;
        let error = Enrollment {
            head: enrollment.head.clone(),
        }
        .complete(&store)
        .unwrap_err();
        assert_eq!(format!("{error:#}"), "noncanonical node enrollment head");
        assert_eq!(records(&store)?, before);
        store.write_batch(&[WriteOp::put(NS, b"head", head.clone())])?;
    }
    assert_eq!(records(&store)?, begun);
    enrollment.complete(&store)?;
    let head = store.get(NS, b"head")?.unwrap();
    let completed = records(&store)?;

    let mut cases = Vec::new();
    for alternate in respelled(&head)? {
        cases.push((
            vec![WriteOp::put(NS, b"head", alternate)],
            "noncanonical node enrollment head",
        ));
    }
    for alternate in respelled(&genesis)? {
        cases.push((
            vec![WriteOp::put(NS, tenant_key.as_bytes(), alternate)],
            "noncanonical tenant enrollment record",
        ));
    }
    // The input is digest-bound. Rebind a current-writer head to each alternate
    // input so that only the exact-byte admission can refuse it. An omitted
    // default may be refused as noncanonical or as an invalid input.
    let omitted = std::str::from_utf8(&current_input)?
        .replacen(",\"startup_principal\":null", "", 1)
        .into_bytes();
    assert_ne!(omitted, current_input);
    let [spaced, reordered] = respelled(&current_input)?;
    for (alternate, refused) in [
        (spaced, "noncanonical node enrollment input"),
        (reordered, "noncanonical node enrollment input"),
        (omitted, "node enrollment input"),
    ] {
        let mut rebound = decode_head(&head)?;
        rebound.input_sha256 = hex::encode(Sha256::digest(&alternate));
        cases.push((
            vec![
                WriteOp::put(NS, b"input", alternate),
                WriteOp::put(NS, b"head", serde_json::to_vec(&rebound)?),
            ],
            refused,
        ));
    }
    for (change, refused) in cases {
        store.write_batch(&change)?;
        store.shutdown().await.unwrap();
        drop(store);
        store = reopen(&node).await?;
        let before = records(&store)?;
        let error = require_complete(&store, id, Kind::Data).unwrap_err();
        assert!(format!("{error:#}").contains(refused), "{error:#}");
        assert!(Enrollment::begin(&store, &input).is_err());
        if refused.contains("tenant") {
            assert!(tenant_record(&store, &tenant).is_err());
        }
        assert_eq!(records(&store)?, before);
        // Current-writer bytes restart the completed enrollment unchanged.
        store.write_batch(&[
            WriteOp::put(NS, b"head", head.clone()),
            WriteOp::put(NS, b"input", current_input.clone()),
            WriteOp::put(NS, tenant_key.as_bytes(), genesis.clone()),
        ])?;
        store.shutdown().await.unwrap();
        drop(store);
        store = reopen(&node).await?;
        require_complete(&store, id, Kind::Data)?;
        assert_eq!(records(&store)?, completed);
    }
    store.shutdown().await.unwrap();
    Ok(())
}
