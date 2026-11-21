use super::*;
use std::time::Duration;

fn replacement(db: &TenantEngine, names: &[String]) -> SchemaChangeSet {
    let old = db.generation().unwrap();
    let changes = names
        .iter()
        .map(|name| {
            let mut definition = definition(name);
            definition.schema = json!({"type":"object","description":""});
            for i in 0..64 {
                let fields = (8 * i..8 * i + 8)
                    .map(|n| IndexField {
                        path: format!("/f{n:03}"),
                        kind: ScalarType::String,
                    })
                    .collect();
                definition.indexes.push(IndexDefinition {
                    name: format!("index_{i:02}"),
                    fields,
                    unique: i == 63,
                    text: None,
                });
            }
            SchemaChange::Replace {
                definition,
                expected_data_epoch: old.state.collections[name].data_epoch,
            }
        })
        .collect();
    let mut request = request(db, "maximum-replacement", changes);
    let extra = MAX_SCHEMA_CHANGESET_BYTES - staged_digest(&request).unwrap().1;
    let count = request.changes.len();
    for (i, change) in request.changes.iter_mut().enumerate() {
        let SchemaChange::Replace { definition, .. } = change else {
            unreachable!()
        };
        definition.schema["description"] =
            json!("p".repeat(extra / count + usize::from(i < extra % count)));
    }
    assert_eq!(
        staged_digest(&request).unwrap().1,
        MAX_SCHEMA_CHANGESET_BYTES
    );
    request
}

async fn activate(db: &Database, request: &SchemaChangeSet) -> WriteReceipt {
    match db.activate_schema(context("owner"), request.clone()).await {
        Ok(receipt) => return receipt,
        Err(error) => assert_eq!(error.code, ErrorCode::UnknownOutcome, "{error}"),
    }
    let lookup = ReadSchemaActivation {
        reference: request.reference().unwrap(),
        read_set: vec![],
    };
    tokio::time::timeout(Duration::from_secs(900), async {
        loop {
            match db
                .schema_activation_status(&context("owner"), &lookup)
                .await
            {
                Ok(stored) => return stored.outcome.clone().unwrap(),
                Err(error) if error.code == ErrorCode::NotFound => {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                Err(error) => panic!("schema activation status failed: {error}"),
            }
        }
    })
    .await
    .expect("accepted activation did not resolve")
}

async fn check_bodies(db: &Database, names: &[String]) {
    for chunk in names.chunks(8) {
        let documents = chunk
            .iter()
            .flat_map(|name| {
                (0..2).map(|i| DocumentKey {
                    collection: name.clone(),
                    id: format!("invoice_{i}"),
                })
            })
            .collect();
        let read = db
            .read_snapshot(
                &context("owner"),
                ReadSnapshotRequest {
                    documents,
                    queries: vec![],
                    time_bounds: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(read.documents.len(), 2 * chunk.len());
        for selected in &read.documents {
            let body = &selected.document.as_ref().unwrap().body;
            assert_eq!(body["f380"], "value-2");
            let i = selected.key.id.strip_prefix("invoice_").unwrap();
            assert_eq!(body["f511"], format!("order-{i}"));
        }
    }
}

#[tokio::test]
async fn default_budget_replaces_the_maximum_bundle_and_reopens_it() {
    let root = kasumi_store::test_utils::private_tempdir().unwrap();
    let path = root.path().join("node.kv");
    let physical = common::PhysicalFixture::new(&path, Default::default());
    let (db, audit, node) = open(&physical, &path, true).await;
    let names: Vec<_> = (0..MAX_SCHEMA_CHANGESET_COLLECTIONS)
        .map(|n| format!("ledger_{n:03}"))
        .collect();
    let refs: Vec<_> = names.iter().map(String::as_str).collect();
    let create = creates(db.engine(), "maximum-setup", &refs);
    activate(&db, &create).await;
    let base: serde_json::Map<_, _> = (0..512)
        .map(|n| (format!("f{n:03}"), json!(format!("value-{}", n % 7))))
        .collect();
    for (serial, chunk) in names.chunks(8).enumerate() {
        let mut operations = Vec::new();
        for name in chunk {
            for i in 0..2 {
                let mut body = base.clone();
                body.insert("f511".into(), json!(format!("order-{i}")));
                operations.push(Mutation::Put {
                    collection: name.clone(),
                    id: format!("invoice_{i}"),
                    body: body.into(),
                    expected: Precondition::Absent,
                });
            }
        }
        db.mutate(
            context("owner"),
            MutationBatch {
                idempotency_key: format!("seed-{serial}"),
                read_set: vec![],
                operations,
            },
        )
        .await
        .unwrap();
    }
    let preceding = db.engine().generation().unwrap();
    let request = replacement(db.engine(), &names);
    let receipt = activate(&db, &request).await;
    for name in &names {
        assert!(
            preceding.state.collections[name]
                .definition
                .indexes
                .is_empty()
        );
    }
    drop(preceding);
    check_bodies(&db, &names).await;
    db.shutdown().await.unwrap();
    audit.shutdown().await.unwrap();
    node.shutdown().await.unwrap();
    drop((db, audit, node));
    let (db, audit, node) = open(&physical, &path, false).await;
    assert_eq!(activate(&db, &request).await, receipt);
    let current = db.engine().generation().unwrap();
    for name in &names {
        assert_eq!(current.state.collections[name].definition.indexes.len(), 64);
    }
    drop(current);
    check_bodies(&db, &names).await;
    db.shutdown().await.unwrap();
    audit.shutdown().await.unwrap();
    node.shutdown().await.unwrap();
}
