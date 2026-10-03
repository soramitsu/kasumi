use super::*;
use crate::core::BackendCloseOutcome;
use crate::group::{FaultTiming, GroupOp, InMemoryGroup};
use crate::root::{ROOT_SLOT_BYTES, RootRoll, RootSlot};
use crate::segment::test_support::*;
use std::ffi::OsStr;
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};

fn prepare(log: &mut Log, operation: MaintenanceOp<'_>) -> Result<PreparedBatch, CoreError> {
    prepare_many(log, &[operation])
}

fn prepare_many(
    log: &mut Log,
    operations: &[MaintenanceOp<'_>],
) -> Result<PreparedBatch, CoreError> {
    let mut roll = RootRoll::new(&log.group, &mut log.root);
    log.writer
        .prepare_maintenance(&log.group, operations, &mut roll)
}

fn finish(log: &mut Log, prepared: PreparedBatch) -> Result<CommittedBatch, CoreError> {
    let directory = fixture_directory_root(prepared.batch_seq());
    let mut roll = RootRoll::new(&log.group, &mut log.root);
    log.writer
        .finish_batch(&log.group, prepared, directory, &mut roll)
}

fn operation(source: ValueLocation) -> MaintenanceOp<'static> {
    MaintenanceOp::Relocate {
        table: "accounts",
        key: b"alice",
        logical_batch_seq: 1,
        source,
    }
}

#[test]
fn directory_only_batches_bind_an_exact_root_without_a_logical_write() {
    let mut log = Log::new(SEGMENT_BYTES);
    let prepared = prepare(&mut log, MaintenanceOp::DirectoryOnly).unwrap();
    assert_eq!(prepared.values(), &[None]);
    assert!(reopen(&log.group.crash()).unwrap().batches.is_empty());
    let committed = finish(&mut log, prepared).unwrap();
    assert_eq!(committed.batch_seq, 1);
    let reopened = reopen(&log.group.crash()).unwrap();
    assert_eq!(reopened.batches.len(), 1);
    assert_eq!(
        reopened.batches[0].records,
        vec![ReplayedRecord::DirectoryOnly]
    );
    assert_eq!(reopened.batches[0].directory_root, committed.directory_root);
}

#[test]
fn relocation_preserves_original_logical_version_and_source_bytes() {
    let mut log = Log::new(SEGMENT_BYTES);
    let original = log
        .commit(&[put("accounts", "alice", b"value".to_vec())])
        .unwrap();
    let source = original.values[0].unwrap();
    log.commit(&[put("accounts", "bob", b"other".to_vec())])
        .unwrap();
    let before = log
        .group
        .durable_image(GroupFile::segment(source.segment_id))
        .unwrap();
    let prepared = prepare(&mut log, operation(source)).unwrap();
    let relocated = prepared.values()[0].unwrap();
    assert_ne!(relocated, source);
    assert_eq!(read_value(&log.group, &relocated).unwrap(), b"value");
    assert_eq!(read_value(&log.group, &source).unwrap(), b"value");
    let committed = finish(&mut log, prepared).unwrap();
    let image = log
        .group
        .durable_image(GroupFile::segment(source.segment_id))
        .unwrap();
    assert_eq!(&image[..before.len()], before);
    let reopened = reopen(&log.group.crash()).unwrap();
    assert_eq!(reopened.batches[2].batch_seq, committed.batch_seq);
    assert_eq!(
        reopened.batches[2].records,
        vec![ReplayedRecord::Relocate {
            table: "accounts".into(),
            key: b"alice".to_vec(),
            logical_batch_seq: 1,
            value: relocated,
        }]
    );
}

struct WindowBound<'a> {
    group: &'a InMemoryGroup,
    largest_read: AtomicUsize,
    largest_write: AtomicUsize,
    mutate_on_second_read: Option<ValueLocation>,
    source_reads: AtomicUsize,
}

impl SegmentGroupBackend for WindowBound<'_> {
    fn reserve_transaction(
        &self,
        plan: &crate::TransactionSpacePlan,
    ) -> std::result::Result<(), crate::TransactionReserveError> {
        self.group.reserve_transaction(plan)
    }
    fn finish_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
        self.group.finish_transaction(group_id, batch_seq)
    }
    fn cancel_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
        self.group.cancel_transaction(group_id, batch_seq)
    }

    fn read_root(&self, slot: RootSlot, out: &mut [u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        self.group.read_root(slot, out)
    }
    fn write_root(&self, slot: RootSlot, bytes: &[u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        self.group.write_root(slot, bytes)
    }
    fn sync_root(&self) -> io::Result<()> {
        self.group.sync_root()
    }
    fn visit_entries(&self, visitor: &mut dyn FnMut(&OsStr) -> io::Result<()>) -> io::Result<()> {
        self.group.visit_entries(visitor)
    }
    fn exists(&self, file: GroupFile) -> io::Result<bool> {
        self.group.exists(file)
    }
    fn create(&self, file: GroupFile) -> io::Result<()> {
        self.group.create(file)
    }
    fn len(&self, file: GroupFile) -> io::Result<u64> {
        self.group.len(file)
    }
    fn read(&self, file: GroupFile, at: u64, out: &mut [u8]) -> io::Result<()> {
        assert!(
            out.len() <= IO_WINDOW,
            "read allocated a value-sized buffer"
        );
        self.largest_read.fetch_max(out.len(), Ordering::Relaxed);
        if let Some(source) = self.mutate_on_second_read
            && file == GroupFile::segment(source.segment_id)
            && at == source.offset
            && self.source_reads.fetch_add(1, Ordering::Relaxed) == 1
        {
            self.group
                .with_durable(file, |bytes| bytes[source.offset as usize] ^= 1);
        }
        self.group.read(file, at, out)
    }
    fn write(&self, file: GroupFile, at: u64, bytes: &[u8]) -> io::Result<()> {
        assert!(
            bytes.len() <= IO_WINDOW,
            "write passed a value-sized buffer"
        );
        self.largest_write.fetch_max(bytes.len(), Ordering::Relaxed);
        self.group.write(file, at, bytes)
    }
    fn set_len(&self, file: GroupFile, length: u64) -> io::Result<()> {
        self.group.set_len(file, length)
    }
    fn sync(&self, file: GroupFile) -> io::Result<()> {
        self.group.sync(file)
    }
    fn unlink(&self, file: GroupFile) -> io::Result<()> {
        self.group.unlink(file)
    }
    fn sync_names(&self) -> io::Result<()> {
        self.group.sync_names()
    }
    fn close(&self) -> BackendCloseOutcome {
        self.group.close()
    }
}

#[test]
fn relocation_and_abort_stream_long_values_through_fixed_windows() {
    for length in [0, IO_WINDOW * 3 + 19] {
        let mut log = Log::new(SEGMENT_BYTES);
        let bytes = vec![71; length];
        let original = log
            .commit(&[put("accounts", "alice", bytes.clone())])
            .unwrap();
        let source = original.values[0].unwrap();
        let bound = WindowBound {
            group: &log.group,
            largest_read: AtomicUsize::new(0),
            largest_write: AtomicUsize::new(0),
            mutate_on_second_read: None,
            source_reads: AtomicUsize::new(0),
        };
        let mut roll = RootRoll::new(&bound, &mut log.root);
        let prepared = log
            .writer
            .prepare_maintenance(&bound, &[operation(source)], &mut roll)
            .unwrap();
        assert!(maintenance_workspace_bytes() < 3 << 20);
        let attempted = prepared.batch_seq();
        log.writer
            .abort_prepared(&bound, prepared, &log.root.log_bounds())
            .unwrap();
        assert!(!log.writer.is_fenced());
        assert_eq!(log.writer.last_batch_seq(), 1);
        assert_eq!(read_value(&log.group, &source).unwrap(), bytes);
        if length != 0 {
            assert_eq!(bound.largest_read.load(Ordering::Relaxed), IO_WINDOW);
            assert_eq!(bound.largest_write.load(Ordering::Relaxed), IO_WINDOW);
        }
        let prepared = prepare(&mut log, MaintenanceOp::DirectoryOnly).unwrap();
        assert!(prepared.batch_seq() > attempted);
        finish(&mut log, prepared).unwrap();
        assert_eq!(reopen(&log.group.crash()).unwrap().batches.len(), 2);
    }
}

#[test]
fn source_change_during_copy_cannot_produce_a_prepared_commit() {
    let mut log = Log::new(SEGMENT_BYTES);
    let original = log
        .commit(&[put("accounts", "alice", vec![13; IO_WINDOW + 1])])
        .unwrap();
    let source = original.values[0].unwrap();
    let bound = WindowBound {
        group: &log.group,
        largest_read: AtomicUsize::new(0),
        largest_write: AtomicUsize::new(0),
        mutate_on_second_read: Some(source),
        source_reads: AtomicUsize::new(0),
    };
    let mut roll = RootRoll::new(&bound, &mut log.root);
    assert_eq!(
        corrupt_reason(
            log.writer
                .prepare_maintenance(&bound, &[operation(source)], &mut roll)
        ),
        "relocation source checksum differs"
    );
    assert!(log.writer.is_fenced());
    assert!(log.writer.prepared.is_none());
    assert_eq!(log.writer.last_batch_seq(), original.batch_seq);
    assert_eq!(
        log.group
            .durable_image(GroupFile::segment(source.segment_id))
            .unwrap()[source.offset as usize],
        12
    );
}

#[test]
fn corrupt_source_fences_without_appending_or_erasing_evidence() {
    let mut log = Log::new(SEGMENT_BYTES);
    let original = log
        .commit(&[put("accounts", "alice", vec![3; IO_WINDOW + 1])])
        .unwrap();
    let source = original.values[0].unwrap();
    let file = GroupFile::segment(source.segment_id);
    log.group
        .with_durable(file, |bytes| bytes[source.offset as usize + IO_WINDOW] ^= 1);
    let evidence = log.group.durable_image(file).unwrap();
    assert_eq!(
        corrupt_reason(prepare(&mut log, operation(source))),
        "relocation source checksum differs"
    );
    assert!(log.writer.is_fenced());
    assert_eq!(log.group.durable_image(file).unwrap(), evidence);
}

#[test]
fn force_roll_keeps_capacity_and_cannot_interrupt_a_prepared_batch() {
    let mut log = Log::new(1024);
    log.commit(&[put("t", "key", b"value".to_vec())]).unwrap();
    let previous = log.writer.position().unwrap();
    let mut roll = RootRoll::new(&log.group, &mut log.root);
    log.writer.force_roll(&log.group, &mut roll).unwrap();
    assert_eq!(log.writer.capacity, 1024);
    assert_eq!(
        log.writer.position().unwrap().segment_id,
        previous.segment_id + 1
    );
    assert_eq!(log.writer.position().unwrap().offset, SEGMENT_HEADER_BYTES);
    let prepared = prepare(&mut log, MaintenanceOp::DirectoryOnly).unwrap();
    let before = log.writer.position();
    let mut roll = RootRoll::new(&log.group, &mut log.root);
    assert!(matches!(
        log.writer.force_roll(&log.group, &mut roll),
        Err(CoreError::OwnerFailed)
    ));
    assert_eq!(log.writer.position(), before);
    finish(&mut log, prepared).unwrap();
    assert_eq!(reopen(&log.group.crash()).unwrap().batches.len(), 2);
}

#[test]
fn maintenance_prepare_and_commit_faults_reopen_at_a_complete_boundary() {
    for directory_only in [false, true] {
        for op in [GroupOp::Write, GroupOp::Sync] {
            for timing in [FaultTiming::BeforeEffect, FaultTiming::AfterEffect] {
                for phase in 0..3 {
                    let mut log = Log::new(SEGMENT_BYTES);
                    let original = log
                        .commit(&[put("accounts", "alice", b"value".to_vec())])
                        .unwrap();
                    let source = original.values[0].unwrap();
                    let operation = if directory_only {
                        MaintenanceOp::DirectoryOnly
                    } else {
                        operation(source)
                    };
                    if phase == 0 {
                        log.group.fail(op, 1, timing);
                        assert!(prepare(&mut log, operation).is_err());
                    } else {
                        let prepared = prepare(&mut log, operation).unwrap();
                        log.group.fail(op, phase, timing);
                        assert!(finish(&mut log, prepared).is_err());
                    }
                    assert!(log.writer.is_fenced());
                    let crashed = log.group.crash();
                    let reopened = reopen(&crashed).unwrap();
                    assert!(reopened.batches.len() == 1 || reopened.batches.len() == 2);
                    if reopened.batches.len() == 2 {
                        assert!(matches!(
                            reopened.batches[1].records.as_slice(),
                            [ReplayedRecord::DirectoryOnly]
                                | [ReplayedRecord::Relocate {
                                    logical_batch_seq: 1,
                                    ..
                                }]
                        ));
                    }
                    assert_eq!(read_value(&crashed, &source).unwrap(), b"value");
                }
            }
        }
    }
}

#[test]
fn force_roll_effect_failures_fence_and_reopen_preserves_prior_commit() {
    for op in [
        GroupOp::Create,
        GroupOp::Write,
        GroupOp::Sync,
        GroupOp::RootWrite,
        GroupOp::RootSync,
    ] {
        for timing in [FaultTiming::BeforeEffect, FaultTiming::AfterEffect] {
            let mut log = Log::new(SEGMENT_BYTES);
            log.commit(&[put("t", "key", b"value".to_vec())]).unwrap();
            log.group.fail(op, 1, timing);
            let mut roll = RootRoll::new(&log.group, &mut log.root);
            assert!(log.writer.force_roll(&log.group, &mut roll).is_err());
            assert!(log.writer.is_fenced());
            assert_eq!(reopen(&log.group.crash()).unwrap().batches.len(), 1);
        }
    }
}

fn reseal(bytes: &mut [u8], segment_id: u64, at: usize) {
    let body_len = le_u32(&bytes[at + 24..at + 28]) as usize;
    let crc = crc32c(&bytes[at + RECORD_HEADER_BYTES..at + RECORD_HEADER_BYTES + body_len]);
    bytes[at + 28..at + 32].copy_from_slice(&crc.to_le_bytes());
    let position = LogPosition {
        segment_id,
        offset: at as u64,
    };
    let crc = header_checksum(&GROUP, position, &bytes[at..at + 32]);
    bytes[at + 32..at + 36].copy_from_slice(&crc.to_le_bytes());
}

#[test]
fn checksum_valid_maintenance_metadata_must_be_canonical() {
    for sequence in [0, 2, u64::MAX] {
        let mut log = Log::new(SEGMENT_BYTES);
        let original = log
            .commit(&[put("accounts", "alice", b"value".to_vec())])
            .unwrap();
        let source = original.values[0].unwrap();
        let at = log.writer.position().unwrap();
        let prepared = prepare(&mut log, operation(source)).unwrap();
        finish(&mut log, prepared).unwrap();
        log.group
            .with_durable(GroupFile::segment(at.segment_id), |bytes| {
                let field = at.offset as usize + RECORD_HEADER_BYTES + PUT_PREFIX_BYTES;
                bytes[field..field + 8].copy_from_slice(&sequence.to_le_bytes());
                reseal(bytes, at.segment_id, at.offset as usize);
            });
        assert_eq!(
            corrupt_reason(reopen(&log.group.crash())),
            "relocation logical version is invalid"
        );
    }
    let mut log = Log::new(SEGMENT_BYTES);
    let prepared = prepare(&mut log, MaintenanceOp::DirectoryOnly).unwrap();
    finish(&mut log, prepared).unwrap();
    log.group.with_durable(GroupFile::segment(1), |bytes| {
        bytes[SEGMENT_HEADER_BYTES as usize + RECORD_HEADER_BYTES] = 1;
        reseal(bytes, 1, SEGMENT_HEADER_BYTES as usize);
    });
    assert_eq!(
        corrupt_reason(reopen(&log.group.crash())),
        "directory maintenance record is noncanonical"
    );
}

#[test]
fn prior_segment_format_is_rejected_without_conversion() {
    assert_eq!(
        corrupt_reason(reject_legacy(b"KASUMI-KVSEG0002")),
        "unsupported KASUMI-KVSEG0002 segmented image"
    );
    assert_eq!(
        corrupt_reason(reject_legacy(b"KASUMI-KVSEG0003")),
        "unsupported KASUMI-KVSEG0003 segmented image"
    );
}

#[test]
fn root_only_replay_checks_every_operation_without_retaining_key_records() {
    let mut log = Log::new(SEGMENT_BYTES);
    let operations: Vec<_> = (0..128)
        .map(|index| {
            put(
                "accounts",
                &format!("row{index:04}"),
                vec![index as u8; IO_WINDOW + 3],
            )
        })
        .collect();
    let committed = log.commit(&operations).unwrap();
    let source = committed.values[17].unwrap();
    let prepared = prepare(
        &mut log,
        MaintenanceOp::Relocate {
            table: "accounts",
            key: b"row0017",
            logical_batch_seq: 1,
            source,
        },
    )
    .unwrap();
    finish(&mut log, prepared).unwrap();
    let prepared = prepare(&mut log, MaintenanceOp::DirectoryOnly).unwrap();
    finish(&mut log, prepared).unwrap();
    let full = reopen(&log.group.crash()).unwrap();
    let mut roots = Vec::new();
    let end = replay_roots(
        &log.group,
        GROUP,
        &ReplayStart::GENESIS,
        &log.root.log_bounds(),
        |root| {
            roots.push(root);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(end.batch_seq, full.end.batch_seq);
    assert_eq!(end.chain, full.end.chain);
    assert_eq!(roots.len(), full.batches.len());
    for (root, batch) in roots.iter().zip(&full.batches) {
        assert_eq!(root.directory_root, batch.directory_root);
        assert_eq!(root.end, batch.end);
        assert_eq!(root.chain, batch.chain);
    }
    assert!(root_replay_workspace_bytes() < 3 << 20);
    let file = GroupFile::segment(1);
    let len = log.group.len(file).unwrap();
    let mut reader = FileReader::new(&log.group, file, len, SEGMENT_HEADER_BYTES);
    let mut replay = Replay {
        directory_end: None,
        directory_root: None,
        backend: &log.group,
        group_id: GROUP,
        batch_seq: 0,
        chain: [0; 32],
        max_seen: 0,
        pending: None,
        segment_attempt: None,
        max_operations: MAX_BATCH_OPERATIONS,
        retain_records: false,
        prepared: None,
    };
    let mut largest_count = 0;
    while reader.remaining() != 0 {
        replay
            .record(&mut reader, 1, &mut |batch| {
                assert!(batch.records.is_empty());
                Ok(())
            })
            .unwrap();
        if let Some(pending) = &replay.pending {
            assert_eq!(pending.records.capacity(), 0);
            largest_count = largest_count.max(pending.op_count);
        }
    }
    assert_eq!(largest_count, 128);
}

#[test]
fn root_only_replay_rejects_bad_value_bytes_and_operation_counts() {
    for corrupt_count in [false, true] {
        let mut log = Log::new(SEGMENT_BYTES);
        let committed = log
            .commit(&[put("accounts", "alice", b"value".to_vec())])
            .unwrap();
        let source = committed.values[0].unwrap();
        log.group
            .with_durable(GroupFile::segment(source.segment_id), |bytes| {
                if corrupt_count {
                    let at = committed.end.offset as usize - COMMIT_RECORD_BYTES;
                    bytes[at + RECORD_HEADER_BYTES..at + RECORD_HEADER_BYTES + 4]
                        .copy_from_slice(&2u32.to_le_bytes());
                    reseal(bytes, source.segment_id, at);
                } else {
                    bytes[source.offset as usize] ^= 1;
                }
            });
        let full = corrupt_reason(reopen(&log.group.crash()));
        let roots = corrupt_reason(replay_roots(
            &log.group.crash(),
            GROUP,
            &ReplayStart::GENESIS,
            &log.root.log_bounds(),
            |_| Ok(()),
        ));
        assert_eq!(full, roots);
    }
}

fn sources<'a>(keys: &'a [Vec<u8>], locations: &[Option<ValueLocation>]) -> Vec<MaintenanceOp<'a>> {
    keys.iter()
        .zip(locations)
        .map(|(key, source)| MaintenanceOp::Relocate {
            table: "accounts",
            key,
            logical_batch_seq: 1,
            source: source.unwrap(),
        })
        .collect()
}

#[test]
fn a_leaf_batch_crosses_segments_but_publishes_one_root_and_preserves_every_version() {
    let mut log = Log::new(1024);
    let keys: Vec<_> = (0..12u8).map(|key| vec![key]).collect();
    let original_ops: Vec<_> = keys
        .iter()
        .map(|key| Operation::put("accounts", key.clone(), vec![key[0]; 260]))
        .collect();
    let original = log.commit(&original_ops).unwrap();
    let operations = sources(&keys, &original.values);
    let cutoff = log.writer.position().unwrap().segment_id;
    let prepared = prepare_many(&mut log, &operations).unwrap();
    assert_eq!(prepared.values().len(), keys.len());
    assert_eq!(prepared.values.capacity(), keys.len());
    assert_eq!(prepared.identity.operation_count, keys.len() as u32);
    assert!(prepared.values().last().unwrap().unwrap().segment_id > cutoff);
    let destinations: Vec<_> = prepared
        .values()
        .iter()
        .map(|value| value.unwrap())
        .collect();
    assert_eq!(reopen(&log.group.crash()).unwrap().batches.len(), 1);
    let committed = finish(&mut log, prepared).unwrap();
    let reopened = reopen(&log.group.crash()).unwrap();
    assert_eq!(reopened.batches.len(), 2);
    assert_eq!(reopened.batches[1].records.len(), keys.len());
    assert_eq!(reopened.batches[1].directory_root, committed.directory_root);
    for (index, record) in reopened.batches[1].records.iter().enumerate() {
        assert_eq!(
            record,
            &ReplayedRecord::Relocate {
                table: "accounts".into(),
                key: keys[index].clone(),
                logical_batch_seq: 1,
                value: destinations[index],
            }
        );
        assert_eq!(
            read_value(&log.group, &destinations[index]).unwrap(),
            vec![index as u8; 260]
        );
        assert_eq!(
            read_value(&log.group, &original.values[index].unwrap()).unwrap(),
            vec![index as u8; 260]
        );
    }
}

#[test]
fn a_cross_segment_batch_aborts_with_its_exact_count_and_can_retry() {
    let mut log = Log::new(1024);
    let keys: Vec<_> = (0..8u8).map(|key| vec![key]).collect();
    let original_ops: Vec<_> = keys
        .iter()
        .map(|key| Operation::put("accounts", key.clone(), vec![key[0]; 300]))
        .collect();
    let original = log.commit(&original_ops).unwrap();
    let operations = sources(&keys, &original.values);
    let prepared = prepare_many(&mut log, &operations).unwrap();
    let abandoned = prepared.batch_seq();
    log.writer
        .abort_prepared(&log.group, prepared, &log.root.log_bounds())
        .unwrap();
    assert!(!log.writer.is_fenced());
    let prepared = prepare_many(&mut log, &operations).unwrap();
    assert!(prepared.batch_seq() > abandoned);
    finish(&mut log, prepared).unwrap();
    let reopened = reopen(&log.group.crash()).unwrap();
    assert_eq!(reopened.batches.len(), 2);
    assert_eq!(reopened.batches[1].records.len(), operations.len());
    assert!(reopened.batches[1].batch_seq > abandoned);
}

#[test]
fn complete_metadata_preflight_rejects_late_invalid_inputs_without_effects() {
    let mut log = Log::new(SEGMENT_BYTES);
    let committed = log
        .commit(&[put("accounts", "alice", vec![23; 64])])
        .unwrap();
    let source = committed.values[0].unwrap();
    let invalid_table = "t".repeat(MAX_TABLE_BYTES + 1);
    let invalid_key = vec![1; MAX_KEY_BYTES + 1];
    let invalids = [
        MaintenanceOp::DirectoryOnly,
        MaintenanceOp::Relocate {
            table: &invalid_table,
            key: b"alice",
            logical_batch_seq: 1,
            source,
        },
        MaintenanceOp::Relocate {
            table: "accounts",
            key: &invalid_key,
            logical_batch_seq: 1,
            source,
        },
        MaintenanceOp::Relocate {
            table: "accounts",
            key: b"alice",
            logical_batch_seq: 2,
            source,
        },
        MaintenanceOp::Relocate {
            table: "accounts",
            key: b"alice",
            logical_batch_seq: 0,
            source,
        },
        MaintenanceOp::Relocate {
            table: "accounts",
            key: b"alice",
            logical_batch_seq: 1,
            source: ValueLocation {
                offset: 0,
                ..source
            },
        },
        MaintenanceOp::Relocate {
            table: "accounts",
            key: b"alice",
            logical_batch_seq: 1,
            source: ValueLocation {
                segment_id: u64::MAX,
                ..source
            },
        },
        MaintenanceOp::Relocate {
            table: "accounts",
            key: b"alice",
            logical_batch_seq: 1,
            source: ValueLocation {
                len: MAX_VALUE_BYTES as u32 + 1,
                ..source
            },
        },
    ];
    let file = GroupFile::segment(source.segment_id);
    let before = log.group.durable_image(file).unwrap();
    let position = log.writer.position();
    let root = log.root.clone();
    for invalid in invalids {
        assert!(matches!(
            prepare_many(&mut log, &[operation(source), invalid]),
            Err(CoreError::InvalidInput(_))
        ));
        assert!(!log.writer.is_fenced());
        assert!(log.writer.prepared.is_none());
        assert_eq!(log.writer.position(), position);
        assert_eq!(log.root, root);
        assert_eq!(log.group.len(file).unwrap(), before.len() as u64);
        assert_eq!(log.group.durable_image(file).unwrap(), before);
    }
    assert!(matches!(
        prepare_many(&mut log, &[]),
        Err(CoreError::InvalidInput(_))
    ));
    assert!(matches!(
        prepare_many(&mut log, &[MaintenanceOp::DirectoryOnly; 2]),
        Err(CoreError::InvalidInput(_))
    ));
    let prepared = prepare(&mut log, operation(source)).unwrap();
    finish(&mut log, prepared).unwrap();
}

#[test]
fn maintenance_count_and_encoded_bytes_have_exact_preflight_bounds() {
    let mut log = Log::new(SEGMENT_BYTES);
    let original = log.commit(&[put("accounts", "alice", Vec::new())]).unwrap();
    let source = original.values[0].unwrap();
    let allowed = vec![operation(source); MAX_MAINTENANCE_OPERATIONS];
    let prepared = prepare_many(&mut log, &allowed).unwrap();
    assert_eq!(prepared.values().len(), MAX_MAINTENANCE_OPERATIONS);
    finish(&mut log, prepared).unwrap();
    assert_eq!(
        reopen(&log.group.crash()).unwrap().batches[1].records.len(),
        MAX_MAINTENANCE_OPERATIONS
    );
    let too_many = vec![operation(source); MAX_MAINTENANCE_OPERATIONS + 1];
    assert!(matches!(
        prepare_many(&mut log, &too_many),
        Err(CoreError::InvalidInput(
            "empty or oversized maintenance batch"
        ))
    ));
    assert!(!log.writer.is_fenced());

    let overhead = maintenance_operation_bytes(operation(source)).unwrap();
    let first = ValueLocation {
        len: MAX_VALUE_BYTES as u32,
        ..source
    };
    let remaining = MAX_BATCH_BYTES - 2 * MAX_VALUE_BYTES - 3 * overhead;
    let last = ValueLocation {
        len: remaining as u32,
        ..source
    };
    let exact = [operation(first), operation(first), operation(last)];
    assert_eq!(
        exact
            .iter()
            .map(|&op| maintenance_operation_bytes(op).unwrap())
            .sum::<usize>(),
        MAX_BATCH_BYTES
    );
    validate_maintenance(&exact, 1, SEGMENT_BYTES).unwrap();
    let too_large = [
        operation(first),
        operation(first),
        operation(ValueLocation {
            len: last.len + 1,
            ..last
        }),
    ];
    assert!(matches!(
        prepare_many(&mut log, &too_large),
        Err(CoreError::InvalidInput(
            "maintenance batch exceeds encoded byte bound"
        ))
    ));
    assert!(
        !log.writer.is_fenced(),
        "metadata rejection should precede source extent reads"
    );
}

#[test]
fn a_bad_later_source_is_detected_before_any_batch_append() {
    let mut log = Log::new(SEGMENT_BYTES);
    let committed = log
        .commit(&[
            put("accounts", "alice", vec![29; 64]),
            put("accounts", "bob", vec![31; 64]),
        ])
        .unwrap();
    let first = committed.values[0].unwrap();
    let second = committed.values[1].unwrap();
    let file = GroupFile::segment(second.segment_id);
    log.group
        .with_durable(file, |bytes| bytes[second.offset as usize] ^= 1);
    let evidence = log.group.durable_image(file).unwrap();
    let root = log.root.clone();
    let position = log.writer.position();
    assert_eq!(
        corrupt_reason(prepare_many(
            &mut log,
            &[
                operation(first),
                MaintenanceOp::Relocate {
                    table: "accounts",
                    key: b"bob",
                    logical_batch_seq: 1,
                    source: second,
                }
            ]
        )),
        "relocation source checksum differs"
    );
    assert!(log.writer.is_fenced());
    assert_eq!(log.writer.position(), position);
    assert_eq!(log.root, root);
    assert_eq!(log.group.len(file).unwrap(), evidence.len() as u64);
    assert_eq!(log.group.durable_image(file).unwrap(), evidence);
}

#[test]
fn batched_copy_and_publication_faults_recover_only_complete_batches() {
    for op in [
        GroupOp::Create,
        GroupOp::Write,
        GroupOp::Sync,
        GroupOp::RootWrite,
        GroupOp::RootSync,
    ] {
        for timing in [FaultTiming::BeforeEffect, FaultTiming::AfterEffect] {
            for nth in 1..=64 {
                let mut log = Log::new(1024);
                let keys: Vec<_> = (0..4u8).map(|key| vec![key]).collect();
                let original_ops: Vec<_> = keys
                    .iter()
                    .map(|key| Operation::put("accounts", key.clone(), vec![key[0]; 300]))
                    .collect();
                let original = log.commit(&original_ops).unwrap();
                let operations = sources(&keys, &original.values);
                log.group.fail(op, nth, timing);
                let result = prepare_many(&mut log, &operations)
                    .and_then(|prepared| finish(&mut log, prepared));
                let failed = result.is_err();
                assert_eq!(log.writer.is_fenced(), failed);
                let crashed = log.group.crash();
                let reopened = reopen(&crashed)
                    .unwrap_or_else(|error| panic!("{op:?}/{timing:?}/{nth}: {error}"));
                assert!(reopened.batches.len() == 1 || reopened.batches.len() == 2);
                if reopened.batches.len() == 2 {
                    assert_eq!(reopened.batches[1].records.len(), keys.len());
                    assert!(reopened.batches[1].records.iter().all(|record| matches!(
                        record,
                        ReplayedRecord::Relocate {
                            logical_batch_seq: 1,
                            ..
                        }
                    )));
                }
                for (index, source) in original.values.iter().enumerate() {
                    assert_eq!(
                        read_value(&crashed, &source.unwrap()).unwrap(),
                        vec![index as u8; 300]
                    );
                }
                if !failed {
                    break;
                }
                assert!(
                    nth < 64,
                    "maintenance effects exceeded the fault fixture bound"
                );
            }
        }
    }
}

#[test]
fn replay_rejects_maintenance_user_mixes_and_repeated_directory_markers() {
    for markers in [[true, false], [false, true], [true, true]] {
        let mut log = Log::new(SEGMENT_BYTES);
        log.commit(&[
            Operation::create_table("abcdefgh"),
            Operation::create_table("ijklmnop"),
        ])
        .unwrap();
        log.group.with_durable(GroupFile::segment(1), |bytes| {
            let mut at = SEGMENT_HEADER_BYTES as usize;
            for marker in markers {
                let body_len = le_u32(&bytes[at + 24..at + 28]) as usize;
                assert_eq!(body_len, MAINTENANCE_BODY_BYTES);
                if marker {
                    bytes[at + 4] = RecordKind::Maintenance.tag();
                    bytes[at + RECORD_HEADER_BYTES..at + RECORD_HEADER_BYTES + body_len].fill(0);
                    reseal(bytes, 1, at);
                }
                at += RECORD_HEADER_BYTES + body_len;
            }
        });
        assert_eq!(
            corrupt_reason(reopen(&log.group.crash())),
            "maintenance batch mixes operations"
        );
        assert_eq!(
            corrupt_reason(replay_roots(
                &log.group.crash(),
                GROUP,
                &ReplayStart::GENESIS,
                &log.root.log_bounds(),
                |_| Ok(())
            )),
            "maintenance batch mixes operations"
        );
    }
}

fn append_relocations(log: &Log, count: usize) {
    let mut at = log.writer.position().unwrap();
    let source = ValueLocation {
        segment_id: 1,
        offset: 128,
        len: 0,
        crc: 0,
    };
    let mut inline = [0u8; MAX_INLINE_BODY];
    let (kind, len, _) = encode_maintenance(operation(source), &mut inline);
    for _ in 0..count {
        let header = record_header(
            &GROUP,
            at,
            &RecordHead {
                kind,
                batch_seq: 2,
                base_seq: 1,
                body_len: len as u32,
                body_crc: crc32c(&inline[..len]),
            },
        );
        let file = GroupFile::segment(at.segment_id);
        log.group.write(file, at.offset, &header).unwrap();
        log.group
            .write(file, at.offset + RECORD_HEADER_BYTES as u64, &inline[..len])
            .unwrap();
        at.offset += (RECORD_HEADER_BYTES + len) as u64;
    }
    log.group.sync(GroupFile::segment(at.segment_id)).unwrap();
}

#[test]
fn root_only_replay_enforces_maintenance_and_exact_abort_count_caps() {
    let mut log = Log::new(SEGMENT_BYTES);
    log.commit(&[Operation::create_table("accounts")]).unwrap();
    append_relocations(&log, MAX_MAINTENANCE_OPERATIONS + 1);
    assert_eq!(
        corrupt_reason(replay_roots(
            &log.group,
            GROUP,
            &ReplayStart::GENESIS,
            &log.root.log_bounds(),
            |_| Ok(())
        )),
        "maintenance batch exceeds operation bound"
    );
    assert_eq!(
        corrupt_reason(replay_limited(
            &log.group,
            GROUP,
            &ReplayStart::GENESIS,
            &log.root.log_bounds(),
            2,
            false,
            |_| Ok(())
        )),
        "batch exceeds replay operation bound"
    );
}

#[test]
fn ordinary_large_and_cross_segment_batches_abort_with_fixed_read_windows() {
    for (capacity, value_len, count) in [(SEGMENT_BYTES, 6 << 20, 1), (1 << 20, 600 << 10, 3)] {
        let mut log = Log::new(capacity);
        let original = log.commit(&[Operation::create_table("accounts")]).unwrap();
        let operations: Vec<_> = (0..count)
            .map(|index| put("accounts", &format!("key{index}"), vec![17; value_len]))
            .collect();
        assert!(prepared_batch_workspace_bytes(&operations).unwrap() < 3 << 20);
        let prepared = log
            .writer
            .prepare_batch(
                &log.group,
                &operations,
                &mut RootRoll::new(&log.group, &mut log.root),
            )
            .unwrap();
        assert_eq!(prepared.identity.operation_count, count as u32);
        assert_eq!(prepared.values.capacity(), count);
        let abandoned = prepared.batch_seq();
        let bound = WindowBound {
            group: &log.group,
            largest_read: AtomicUsize::new(0),
            largest_write: AtomicUsize::new(0),
            mutate_on_second_read: None,
            source_reads: AtomicUsize::new(0),
        };
        log.writer
            .abort_prepared(&bound, prepared, &log.root.log_bounds())
            .unwrap();
        assert_eq!(bound.largest_read.load(Ordering::Relaxed), IO_WINDOW);
        assert!(!log.writer.is_fenced());
        assert_eq!(log.writer.last_batch_seq(), original.batch_seq);
        let committed = log
            .commit(&[put("accounts", "survives", b"yes".to_vec())])
            .unwrap();
        assert!(committed.batch_seq > abandoned);
        let reopened = reopen(&log.group.crash()).unwrap();
        assert_eq!(reopened.batches.len(), 2);
        assert_eq!(reopened.batches[1].records.len(), 1);
    }
}

#[test]
fn ordinary_abort_rejects_noncanonical_or_extra_records_without_erasing_evidence() {
    for extra_record in [false, true] {
        let mut log = Log::new(SEGMENT_BYTES);
        log.commit(&[Operation::create_table("t")]).unwrap();
        let prepared = log
            .writer
            .prepare_batch(
                &log.group,
                &[put("t", "key", vec![41; 300])],
                &mut RootRoll::new(&log.group, &mut log.root),
            )
            .unwrap();
        let start = prepared.identity.start.position;
        let file = GroupFile::segment(start.segment_id);
        if extra_record {
            let total = prepared.identity.end.offset - start.offset;
            let value_len = total as usize / 2 - (RECORD_HEADER_BYTES + PUT_PREFIX_BYTES + 2);
            let mut at = start;
            for key in ["a", "b"] {
                let operation = put("t", key, vec![43; value_len]);
                let record = encode_op(&operation);
                let header = record_header(
                    &GROUP,
                    at,
                    &RecordHead {
                        kind: record.kind,
                        batch_seq: prepared.batch_seq(),
                        base_seq: log.writer.last_batch_seq(),
                        body_len: record.body_len(),
                        body_crc: record.body_crc,
                    },
                );
                log.group.write(file, at.offset, &header).unwrap();
                log.group
                    .write(file, at.offset + RECORD_HEADER_BYTES as u64, &record.inline)
                    .unwrap();
                log.group
                    .write(
                        file,
                        at.offset + RECORD_HEADER_BYTES as u64 + record.inline.len() as u64,
                        record.value,
                    )
                    .unwrap();
                at.offset += record.len();
            }
            assert_eq!(at, prepared.identity.end);
            log.group.sync(file).unwrap();
        } else {
            log.group.with_durable(file, |bytes| {
                bytes[start.offset as usize + RECORD_HEADER_BYTES + 12] = 1;
                reseal(bytes, start.segment_id, start.offset as usize);
            });
        }
        let evidence = log.group.durable_image(file).unwrap();
        let reason = corrupt_reason(log.writer.abort_prepared(
            &log.group,
            prepared,
            &log.root.log_bounds(),
        ));
        assert_eq!(
            reason,
            if extra_record {
                "batch exceeds replay operation bound"
            } else {
                "segment operation record is invalid"
            }
        );
        assert!(log.writer.is_fenced());
        assert_eq!(log.group.len(file).unwrap(), evidence.len() as u64);
        assert_eq!(log.group.durable_image(file).unwrap(), evidence);
    }
}

#[test]
fn abort_binds_synced_normal_and_maintenance_bytes_to_the_prepared_digest() {
    for maintenance in [false, true] {
        for change in 0..3 {
            let mut log = Log::new(SEGMENT_BYTES);
            let original = log
                .commit(&[put("accounts", "alice", vec![53; 300])])
                .unwrap();
            let prepared = if maintenance {
                prepare(&mut log, operation(original.values[0].unwrap())).unwrap()
            } else {
                log.writer
                    .prepare_batch(
                        &log.group,
                        &[put("accounts", "alice", vec![53; 300])],
                        &mut RootRoll::new(&log.group, &mut log.root),
                    )
                    .unwrap()
            };
            let value = prepared.values()[0].unwrap();
            let start = prepared.identity.start.position;
            let file = GroupFile::segment(start.segment_id);
            log.group.with_durable(file, |bytes| {
                if change == 1 {
                    // Same count, length and value bytes; a different key.
                    bytes[value.offset as usize - 1] ^= 1;
                } else {
                    bytes[value.offset as usize] ^= 1;
                    if change == 2 {
                        // Same count and length, with all value/body/header
                        // CRCs resealed. Only the prepared SHA proves change.
                        let crc = crc32c(&bytes[value.offset as usize..value.end() as usize]);
                        let crc_at = start.offset as usize + RECORD_HEADER_BYTES + 8;
                        bytes[crc_at..crc_at + 4].copy_from_slice(&crc.to_le_bytes());
                    }
                }
                if change != 0 {
                    reseal(bytes, start.segment_id, start.offset as usize);
                }
            });
            let evidence = log.group.durable_image(file).unwrap();
            assert_eq!(
                corrupt_reason(log.writer.abort_prepared(
                    &log.group,
                    prepared,
                    &log.root.log_bounds()
                )),
                if change == 0 {
                    "synchronized prepared prefix is damaged"
                } else {
                    "prepared operation digest differs"
                }
            );
            assert!(log.writer.is_fenced());
            assert_eq!(log.group.len(file).unwrap(), evidence.len() as u64);
            assert_eq!(log.group.durable_image(file).unwrap(), evidence);
        }
    }
}

#[test]
fn abort_rejects_fewer_records_wrong_batch_or_a_publication_at_the_exact_end() {
    for change in 0..4 {
        let mut log = Log::new(SEGMENT_BYTES);
        log.commit(&[Operation::create_table("t")]).unwrap();
        let prepared = log
            .writer
            .prepare_batch(
                &log.group,
                &[put("t", "a", vec![59; 100]), put("t", "b", vec![61; 100])],
                &mut RootRoll::new(&log.group, &mut log.root),
            )
            .unwrap();
        let start = prepared.identity.start.position;
        let file = GroupFile::segment(start.segment_id);
        if change == 0 {
            let total = prepared.identity.end.offset - start.offset;
            let operation = put(
                "t",
                "a",
                vec![67; total as usize - (RECORD_HEADER_BYTES + PUT_PREFIX_BYTES + 2)],
            );
            let record = encode_op(&operation);
            let header = record_header(
                &GROUP,
                start,
                &RecordHead {
                    kind: record.kind,
                    batch_seq: prepared.batch_seq(),
                    base_seq: log.writer.last_batch_seq(),
                    body_len: record.body_len(),
                    body_crc: record.body_crc,
                },
            );
            log.group.write(file, start.offset, &header).unwrap();
            log.group
                .write(
                    file,
                    start.offset + RECORD_HEADER_BYTES as u64,
                    &record.inline,
                )
                .unwrap();
            log.group
                .write(
                    file,
                    start.offset + RECORD_HEADER_BYTES as u64 + record.inline.len() as u64,
                    record.value,
                )
                .unwrap();
            assert_eq!(start.offset + record.len(), prepared.identity.end.offset);
            log.group.sync(file).unwrap();
        } else {
            log.group.with_durable(file, |bytes| {
                let at = start.offset as usize;
                if change == 1 {
                    bytes[at + 8..at + 16]
                        .copy_from_slice(&(prepared.batch_seq() + 1).to_le_bytes());
                } else {
                    let (kind, len) = if change == 2 {
                        (RecordKind::Directory, DIRECTORY_ROOT_BYTES)
                    } else {
                        (RecordKind::Commit, COMMIT_BODY_BYTES)
                    };
                    bytes[at + 4] = kind.tag();
                    bytes[at + 24..at + 28].copy_from_slice(&(len as u32).to_le_bytes());
                }
                reseal(bytes, start.segment_id, at);
            });
        }
        let evidence = log.group.durable_image(file).unwrap();
        let reason = corrupt_reason(log.writer.abort_prepared(
            &log.group,
            prepared,
            &log.root.log_bounds(),
        ));
        assert_eq!(
            reason,
            match change {
                0 => "prepared operation prefix differs",
                1 => "prepared operation batch differs",
                _ => "prepared prefix contains a publication record",
            }
        );
        assert!(log.writer.is_fenced());
        assert_eq!(log.group.len(file).unwrap(), evidence.len() as u64);
        assert_eq!(log.group.durable_image(file).unwrap(), evidence);
    }
}
