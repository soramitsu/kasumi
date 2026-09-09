use super::*;

fn raw(records: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut bytes = MAGIC.to_vec();
    for (kind, record) in records {
        bytes.extend_from_slice(&(record.len() as u64).to_be_bytes());
        bytes.push(*kind);
        bytes.extend_from_slice(record);
    }
    let total = bytes.len() as u64;
    let digest = Sha256::digest(&bytes);
    bytes.extend_from_slice(&0u64.to_be_bytes());
    bytes.extend_from_slice(&(records.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&total.to_be_bytes());
    bytes.extend_from_slice(&digest);
    bytes
}

fn header() -> Vec<u8> {
    serde_json::to_vec(&Record::Header(Box::new(super::tests::state()))).unwrap()
}

#[test]
fn permanent_kind_cannot_forward_a_resident_payload_to_semantic_consumers() {
    let document = serde_json::to_vec(&Record::Document(
        "rows".into(),
        Arc::new(Document {
            id: "one".into(),
            version: 1,
            body: serde_json::json!({"large": "x".repeat(1024)}),
        }),
    ))
    .unwrap();
    for kind in [21, 22] {
        let bytes = raw(&[(0, header()), (kind, document.clone())]);
        // Framing hints determine a bounded initial allocation only. This is
        // deliberately a fresh valid digest over the malicious typed hint.
        let layout = inspect(&mut bytes.as_slice()).unwrap();
        assert_eq!(layout.kinds[usize::from(kind)].records, 1);
        assert!(layout.materialization_workspace().unwrap() >= 64 << 20);
        let mut forwarded = 0;
        let error = visit(&mut bytes.as_slice(), |_, _| {
            forwarded += 1;
            Ok(())
        })
        .unwrap_err();
        assert!(error.to_string().contains("frame kind differs"));
        assert_eq!(forwarded, 1, "only the valid header may be forwarded");
    }
}

#[test]
fn typed_inspection_rejects_bounds_kind_order_and_terminal_substitutions() {
    for (kind, size) in [
        (0, MAX_RECORD as u64 + 1),
        (21, record_limit(21).unwrap() + 1),
        (22, record_limit(22).unwrap() + 1),
        (255, 1),
    ] {
        let mut bytes = raw(&[(0, header())]);
        bytes.truncate(bytes.len() - 56);
        if kind == 0 {
            bytes.truncate(8);
        }
        bytes.extend_from_slice(&size.to_be_bytes());
        bytes.push(kind);
        // There are no payload bytes: both paths must reject the kind/length
        // before attempting a proportional read or DTO allocation.
        let frame_error = inspect(&mut bytes.as_slice()).unwrap_err().to_string();
        let decode_error = visit(&mut bytes.as_slice(), |_, _| Ok(()))
            .unwrap_err()
            .to_string();
        assert!(frame_error.contains("limit") || frame_error.contains("kind"));
        assert!(decode_error.contains("limit") || decode_error.contains("kind"));
    }
    for records in [
        vec![(0, header()), (0, header())],
        vec![(0, header()), (22, b"{}".to_vec()), (21, b"{}".to_vec())],
    ] {
        assert!(inspect(&mut raw(&records).as_slice()).is_err());
    }
    let original = raw(&[(0, header())]);
    let layout = inspect(&mut original.as_slice()).unwrap();
    assert_eq!(
        layout,
        visit(&mut original.as_slice(), |_, _| Ok(())).unwrap()
    );
    assert_eq!(layout.resident_bytes().unwrap(), original.len() as u64);
    for offset in [
        original.len() - 48,
        original.len() - 40,
        original.len() - 32,
    ] {
        let mut changed = original.clone();
        changed[offset] ^= 1;
        assert!(inspect(&mut changed.as_slice()).is_err());
        assert!(visit(&mut changed.as_slice(), |_, _| Ok(())).is_err());
    }
    let mut old = original;
    old[..8].copy_from_slice(b"KASUMIT4");
    assert!(inspect(&mut old.as_slice()).is_err());
    assert!(visit(&mut old.as_slice(), |_, _| Ok(())).is_err());
}

#[test]
fn permanent_aggregate_does_not_become_ram_and_all_layout_arithmetic_is_checked() {
    let mut layout = StreamSummary::empty();
    layout.add(0, 4096).unwrap();
    layout.add(21, 64 << 10).unwrap();
    layout.record_work(21, 1 << 20).unwrap();
    let first = layout.materialization_workspace().unwrap();
    for _ in 0..32768 {
        layout.add(21, 64 << 10).unwrap();
    }
    // Arithmetic only: this is not an actual multi-GiB payload capacity gate.
    assert!(layout.bytes > 2 << 30);
    assert_eq!(layout.materialization_workspace().unwrap(), first);
    layout.add(22, 128 << 10).unwrap();
    layout.record_work(22, 2 << 20).unwrap();
    assert!(layout.materialization_workspace().unwrap() > first);
    let mut overflow = layout;
    overflow.kinds[21].records = u64::MAX;
    assert!(overflow.add(21, 1).is_err());
    overflow = layout;
    overflow.kinds[21].framed_bytes = u64::MAX;
    assert!(overflow.add(21, 1).is_err());
    overflow = layout;
    overflow.bytes = u64::MAX;
    assert!(overflow.add(21, 1).is_err());
    overflow = layout;
    overflow.kinds[0].framed_bytes = u64::MAX;
    assert!(overflow.resident_bytes().is_err());
    assert!(overflow.materialization_workspace().is_err());
    overflow = layout;
    overflow.kinds[21].maximum_decode_work = u64::MAX;
    assert!(overflow.index_workspace().is_err());
    assert!(overflow.materialization_workspace().is_err());
}

#[test]
fn inspection_reads_large_typed_payload_in_fixed_chunks_before_any_dto() {
    struct Bounded<'a>(&'a [u8]);
    impl Read for Bounded<'_> {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            assert!(output.len() <= 64 << 10);
            self.0.read(output)
        }
    }
    let payload = serde_json::to_vec(&Record::Document(
        "rows".into(),
        Arc::new(Document {
            id: "one".into(),
            version: 1,
            body: serde_json::json!({"payload": "x".repeat(256 << 10)}),
        }),
    ))
    .unwrap();
    let image = raw(&[(0, header()), (3, payload)]);
    let layout = inspect(&mut Bounded(&image)).unwrap();
    let verified = visit(&mut image.as_slice(), |_, _| Ok(())).unwrap();
    assert_eq!(layout, verified);
    assert!(layout.kinds[3].maximum_decode_work > layout.kinds[3].maximum_payload_bytes);
}
