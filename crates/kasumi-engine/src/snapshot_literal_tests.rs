//! Literal objects must survive canonical verification and indexed rereads.
use super::*;
use serde_json::json;

#[test]
fn literal_marker_documents_schema_and_staged_records_survive_canonical_snapshots() {
    let body = json!({
        "raw": {"$serde_json::private::RawValue":"not JSON"},
        "number": {"$serde_json::private::Number":"7"},
        "exact": "90071992547409931234567890.123456789".parse::<serde_json::Number>().unwrap()
    });
    let document = Arc::new(Document {
        id: "first".into(),
        version: 1,
        body: body.clone(),
    });
    let definition = CollectionDefinition {
        name: "docs".into(),
        write_mode: CollectionWriteMode::Mutable,
        retention_class: CollectionRetentionClass::Operational,
        schema: json!({"type":"object","properties":{
            "$serde_json::private::Number":{"type":"string"},
            "$serde_json::private::RawValue":{"type":"string"}
        }}),
        indexes: vec![],
        strict_read_audit: false,
    };
    let mut state = tests::state();
    state.revision = 1;
    state.document_count = 1;
    state.logical_bytes = serde_json::to_vec(&body).unwrap().len() as u64;
    state.collections.insert(
        "docs".into(),
        CollectionState {
            definition: definition.clone(),
            data_epoch: 1,
            documents: [(document.id.clone(), document.clone())]
                .into_iter()
                .collect(),
            archived_documents: Default::default(),
            archived_document_bytes: 0,
        },
    );
    let disk = kasumi_store::ScratchDisk::fixture();
    let terminals = crate::staged_terminal::View::empty(&state.tenant, &state.incarnation).unwrap();
    let target_resolutions =
        crate::target_resolution::View::empty(&state.tenant, &state.incarnation).unwrap();
    let image = kasumi_store::SnapshotImage::capture(&disk, 64 << 20, |writer| {
        write(&state, &terminals, &target_resolutions, writer)
    })
    .unwrap();
    let restored = read(image.disk(), &mut image.reader()).unwrap();
    assert_eq!(restored.state.collections["docs"].definition, definition);
    assert_eq!(
        restored.state.collections["docs"].documents["first"],
        document
    );
    let index = crate::snapshot_index::StagedSnapshot::new(image, 16 << 20, || Ok(())).unwrap();
    let Some(Record::Document(_, observed)) = index.get(3, "docs", "first").unwrap() else {
        panic!("document record missing")
    };
    assert_eq!(observed, document);
    let stage = Record::StageChunk(
        "transaction".into(),
        0,
        Arc::new(StagedChunk {
            read_set: vec![],
            operations: vec![Mutation::Put {
                collection: "docs".into(),
                id: "first".into(),
                body,
                expected: Precondition::Absent,
            }],
        }),
    );
    let bytes = serde_json::to_vec(&stage).unwrap();
    let decoded = decode_record(&bytes).unwrap();
    assert_eq!(serde_json::to_vec(&decoded).unwrap(), bytes);
}
