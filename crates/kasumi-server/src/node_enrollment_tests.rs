use super::*;
use kasumi_store::{ScratchDisk, StorageAccess, test_utils::LocalKeyProvider};

async fn fixture() -> Result<(tempfile::TempDir, Arc<NodeStore>, Arc<TenantStore>, Input)> {
    let directory = tempfile::tempdir()?;
    let mut configuration = crate::runtime::example_config();
    configuration.database_path = directory.path().join("node.redb");
    let node = NodeStore::create_new(
        &configuration.database_path,
        configuration.database_id,
        ScratchDisk::fixture(),
    )?;
    let store = TenantStore::open(
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
        Enrollment::begin(&store, &input)?.complete(&store)?;
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
