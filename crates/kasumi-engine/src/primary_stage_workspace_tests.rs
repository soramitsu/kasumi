use super::*;
use crate::{
    admission::{AdmissionConfig, NodeAdmission},
    document_pool::allocation_tests::measure_topology_input,
};

#[test]
fn primary_dto_workspace_matches_archived_direct_and_live_canonical_writers() -> Result<()> {
    let node = NodeAdmission::with_fixed_memory(
        AdmissionConfig {
            high_water_bytes: Some(128 << 20),
            max_inflight_bytes: Some(64 << 20),
            ..Default::default()
        },
        256 << 20,
        0,
    )?;
    let input = node.reserve_document_source(1 << 20)?;
    let mut nested = serde_json::Map::new();
    for i in (0..257).rev() {
        nested.insert(format!("k{i:04}"), serde_json::json!([i, 1.25]));
    }
    let mut outer = serde_json::Map::new();
    outer.insert("z".into(), serde_json::Value::Object(nested));
    outer.insert("a".into(), serde_json::Value::Null);
    let archived = ArchivedDocument {
        version: 0,
        archive_id: "physical-fixture".into(),
        chunk_index: 0,
        document_sha256: "00".repeat(32),
        document_bytes: 32,
        indexed_fields: std::collections::BTreeMap::from([(
            "nested".into(),
            serde_json::Value::Object(outer),
        )]),
    };
    // Archive Value fields use their direct borrowed writer, which allocates no sorter.
    let dto = CanonicalDto::Archived(&archived);
    let quote = dto.workspace()?;
    assert_eq!(quote, 0);
    let before = node.snapshot().reserved_bytes;
    let grant = node.reserve_document_source(4096 + quote)?;
    let (result, live, peak, allocations) = measure_topology_input(|| {
        let mut count = CountHash::new();
        dto.write(&mut count).map(|()| count.bytes)
    });
    assert!(result? > 257);
    assert_eq!(live, 0);
    assert_eq!((allocations, peak), (0, 0));
    assert!(
        peak as u64 <= quote,
        "actual serializer heap {peak} exceeds admitted quote {quote}"
    );
    drop(grant);
    assert_eq!(node.snapshot().reserved_bytes, before);
    // Document.body is the distinct canonical wrapper. Only an actually
    // unsorted Map backend uses its borrowed-entry sort vector. The pinned
    // default BTreeMap backend remains sorted despite reverse insertion.
    let document = Document {
        id: "a".into(),
        version: 0,
        body: archived.indexed_fields.get("nested").unwrap().clone(),
    };
    let live_dto = CanonicalDto::Live(&document);
    let live_quote = live_dto.workspace()?;
    let unsorted = !document.body.as_object().unwrap().keys().is_sorted()
        || !document.body["z"].as_object().unwrap().keys().is_sorted();
    assert_eq!(live_quote > 0, unsorted);
    let live_grant = node.reserve_document_source(4096 + live_quote)?;
    let (result, live, peak, allocations) = measure_topology_input(|| {
        let mut count = CountHash::new();
        live_dto.write(&mut count).map(|()| count.bytes)
    });
    assert!(result? > 257);
    assert_eq!(live, 0);
    if unsorted {
        assert!(allocations > 0 && peak > 0);
    } else {
        assert_eq!((allocations, peak), (0, 0));
    }
    assert!(
        peak as u64 <= live_quote,
        "canonical heap {peak} exceeds quote {live_quote}"
    );
    drop(live_grant);
    assert_eq!(node.snapshot().reserved_bytes, before);
    drop((document, archived, input));
    Ok(())
}

#[test]
fn primary_quote_refusal_keeps_pointer_bearing_original_before_full_walk() -> Result<()> {
    let mut values = serde_json::Map::new();
    for i in 0..1000 {
        values.insert(format!("k{i:04}"), serde_json::json!([i]));
    }
    let document = Document {
        id: "a".into(),
        version: 1,
        body: serde_json::Value::Object(values),
    };
    #[derive(Debug)]
    struct Refusal(Box<u64>);
    impl std::fmt::Display for Refusal {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("original quote refusal")
        }
    }
    impl std::error::Error for Refusal {}
    let marker = Box::new(3289);
    let address = std::ptr::from_ref(marker.as_ref());
    let mut original = Some(anyhow::Error::new(Refusal(marker)));
    let mut visited = 0;
    let result = CanonicalDto::Live(&document).workspace_checked(&mut || {
        visited += 1;
        if visited == 9 {
            Err(original.take().unwrap())
        } else {
            Ok(())
        }
    });
    let error = result.unwrap_err();
    assert_eq!(visited, 9);
    assert_eq!(
        std::ptr::from_ref(error.downcast_ref::<Refusal>().unwrap().0.as_ref()),
        address
    );
    Ok(())
}
