use super::*;
use kasumi_store::{NodeStore, StorageAccess, test_utils::LocalKeyProvider};

async fn fixture() -> Result<(tempfile::TempDir, NodeStore, Arc<TenantStore>, Input)> {
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let mut configuration = crate::runtime::example_config(
        kasumi_store::DirectoryPolicy::fixture(),
        kasumi_store::FileAllocationPolicy::fixture(),
    )
    .unwrap();
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
    let node = {
        let native_path = &configuration.database_path;
        let native_id = configuration.database_id;
        let native_disk = storage.open_persistent(&configuration.persistent_disk)?;
        let native_scratch_disk = storage.open_scratch(&configuration.scratch_disk)?;
        NodeStore::create_new(
            native_path,
            native_id,
            native_disk.clone(),
            native_scratch_disk,
            native_disk.native_storage_config(),
        )
    }
    .expect("node enrollment fixture must create its installed native node");
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
    store.write_batch(&[WriteOp::put(NS, key.as_bytes(), record.as_bytes())])?;
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

async fn reopen(node: &NodeStore) -> Result<Arc<TenantStore>> {
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
        store.write_batch(&[WriteOp::put(NS, b"head", head.as_bytes())])?;
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
    // input. Completed history remains bound to its original genesis digest,
    // independently of today's operational configuration schema.
    let omitted = std::str::from_utf8(&current_input)?
        .replacen(",\"startup_principal\":null", "", 1)
        .into_bytes();
    assert_ne!(omitted, current_input);
    let [spaced, reordered] = respelled(&current_input)?;
    for (alternate, refused) in [
        (spaced, "genesis tenant or Control enrollment differs"),
        (reordered, "genesis tenant or Control enrollment differs"),
        (omitted, "genesis tenant or Control enrollment differs"),
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
        if refused == "noncanonical tenant enrollment record" {
            assert!(tenant_record(&store, &tenant).is_err());
        }
        assert_eq!(records(&store)?, before);
        // Current-writer bytes restart the completed enrollment unchanged.
        store.write_batch(&[
            WriteOp::put(NS, b"head", head.as_bytes()),
            WriteOp::put(NS, b"input", current_input.as_bytes()),
            WriteOp::put(NS, tenant_key.as_bytes(), genesis.as_bytes()),
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

// Fixture construction only: establish one historical input and its original
// digest references before exercising the read-only completed-enrollment path.
fn establish_historical_input(store: &TenantStore, input: Vec<u8>) -> Result<()> {
    let mut head = decode_head(&store.get(NS, b"head")?.unwrap())?;
    ensure!(head.complete, "historical fixture must already be complete");
    let digest = hex::encode(Sha256::digest(&input));
    let mut changes = vec![WriteOp::put(NS, b"input", input)];
    store.visit(NS, MAX_INPUT, |key, bytes| {
        if key.starts_with(b"tenant/") {
            let mut record: tenants::TenantRecord = serde_json::from_slice(bytes)?;
            if let Origin::Genesis { input_sha256 } = &mut record.origin {
                ensure!(*input_sha256 == head.input_sha256, "fixture origin mismatch");
                *input_sha256 = digest.clone();
                changes.push(WriteOp::put(NS, key, serde_json::to_vec(&record)?));
            }
        }
        Ok(())
    })?;
    head.input_sha256 = digest;
    changes.push(WriteOp::put(NS, b"head", serde_json::to_vec(&head)?));
    store.write_batch(&changes)
}

#[tokio::test]
async fn completed_enrollment_reopens_original_input_without_current_scratch_policy() -> Result<()> {
    let (_directory, node, store, input) = fixture().await?;
    let (_, id) = input.identity();
    let enrollment = Enrollment::begin(&store, &input)?;
    record_genesis(&enrollment, &store, &input)?;
    enrollment.complete(&store)?;
    let current = store.get(NS, b"input")?.unwrap();
    let current_text = std::str::from_utf8(&current)?;
    let scratch_start = current_text.find("\"scratch_disk\":").unwrap();
    let value: serde_json::Value = serde_json::from_slice(&current)?;
    let field = format!("\"file_allocation_policy\":{},",
        value["configuration"]["scratch_disk"]["file_allocation_policy"]);
    let mut historical = current_text[..scratch_start].to_owned();
    historical.push_str(&current_text[scratch_start..].replacen(&field, "", 1));
    assert_eq!(historical.len() + field.len(), current.len());
    // Historical admission never supplies a default for a live configuration.
    assert!(Input::decode(historical.as_bytes()).is_err());
    let historical_value: serde_json::Value = serde_json::from_str(&historical)?;
    assert!(serde_json::from_value::<crate::runtime::RuntimeConfig>(
        historical_value["configuration"].clone()).is_err());
    establish_historical_input(&store, historical.into_bytes())?;
    let original = records(&store)?;
    require_complete(&store, id, Kind::Data)?;
    assert_eq!(records(&store)?, original);
    store.shutdown().await.unwrap();
    drop(store);
    let reopened = reopen(&node).await?;
    require_complete(&reopened, id, Kind::Data)?;
    assert_eq!(records(&reopened)?, original);
    reopened.shutdown().await.unwrap();
    Ok(())
}

#[test]
fn retained_enrollment_requires_unambiguous_complete_immutable_identities() -> Result<()> {
    let database_id = Uuid::new_v4();
    let incarnation = Uuid::new_v4();
    let original = serde_json::json!({
        "kind": "data", "configuration": {
            "database_id": database_id, "mode": "standalone",
            "control": {"incarnation": incarnation},
            "tenants": [{"tenant": "retail", "incarnation": incarnation}],
            "removed_operational_policy": {"arbitrary": [null, true, 1.25, 18446744073709551615_u64]},
        }
    });
    let encoded = serde_json::to_vec(&original)?;
    assert_eq!(retained::RetainedInput::decode(&encoded)?.identity(), (Kind::Data, database_id));
    for field in ["database_id", "mode", "control", "tenants"] {
        let mut malformed = original.clone();
        malformed["configuration"].as_object_mut().unwrap().remove(field);
        assert!(retained::RetainedInput::decode(&serde_json::to_vec(&malformed)?).is_err(), "{field}");
    }
    for value in [serde_json::Value::Null, serde_json::json!(Uuid::nil()), serde_json::json!("invalid")] {
        let mut malformed = original.clone();
        malformed["configuration"]["tenants"][0]["incarnation"] = value.clone();
        assert!(retained::RetainedInput::decode(&serde_json::to_vec(&malformed)?).is_err());
        malformed = original.clone();
        malformed["configuration"]["control"]["incarnation"] = value;
        assert!(retained::RetainedInput::decode(&serde_json::to_vec(&malformed)?).is_err());
    }
    let mut malformed = original.clone();
    malformed["configuration"]["tenants"][0].as_object_mut().unwrap().remove("incarnation");
    assert!(retained::RetainedInput::decode(&serde_json::to_vec(&malformed)?).is_err());
    let mut duplicate = original.clone();
    duplicate["configuration"]["tenants"].as_array_mut().unwrap()
        .push(original["configuration"]["tenants"][0].clone());
    assert!(retained::RetainedInput::decode(&serde_json::to_vec(&duplicate)?).is_err());
    let text = std::str::from_utf8(&encoded)?;
    for duplicate in [
        text.replacen("\"kind\":\"data\"", "\"kind\":\"data\",\"kind\":\"data\"", 1),
        text.replacen("\"removed_operational_policy\":", "\"removed_operational_policy\":{},\"removed_operational_policy\":", 1),
        text.replacen("\"arbitrary\":", "\"arbitrary\":0,\"arbitrary\":", 1),
    ] {
        assert_ne!(duplicate, text);
        assert!(retained::RetainedInput::decode(duplicate.as_bytes()).is_err());
    }
    let authority = serde_json::json!({"kind": "authority", "configuration": {"database_id": database_id}});
    assert_eq!(retained::RetainedInput::decode(&serde_json::to_vec(&authority)?)?.identity(), (Kind::Authority, database_id));
    Ok(())
}

#[tokio::test]
async fn retained_enrollment_rejects_tampering_and_substituted_identity_without_rewriting() -> Result<()> {
    let (_directory, _node, store, input) = fixture().await?;
    let (_, id) = input.identity();
    let enrollment = Enrollment::begin(&store, &input)?;
    record_genesis(&enrollment, &store, &input)?;
    enrollment.complete(&store)?;
    let original = records(&store)?;
    let bytes = store.get(NS, b"input")?.unwrap();
    let original_input: serde_json::Value = serde_json::from_slice(&bytes)?;
    for change in [0, 1, 2] {
        let mut substituted = original_input.clone();
        if change == 0 {
            substituted["configuration"]["scratch_disk"]["max_bytes"] = 1.into();
            store.write_batch(&[WriteOp::put(NS, b"input", serde_json::to_vec(&substituted)?)])?;
        } else {
            if change == 1 {
                substituted["configuration"]["tenants"][0]["incarnation"] = Uuid::new_v4().to_string().into();
            } else {
                substituted["configuration"]["database_id"] = Uuid::new_v4().to_string().into();
            }
            establish_historical_input(&store, serde_json::to_vec(&substituted)?)?;
        }
        let before = records(&store)?;
        assert!(require_complete(&store, id, Kind::Data).is_err());
        assert_eq!(records(&store)?, before);
        let restore: Vec<_> = original.iter().map(|(key, value)| WriteOp::put(NS, key.as_slice(), value.as_slice())).collect();
        store.write_batch(&restore)?;
        require_complete(&store, id, Kind::Data)?;
    }
    assert_eq!(records(&store)?, original);
    store.shutdown().await.unwrap();
    Ok(())
}
