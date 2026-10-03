use crate::core::BackendCloseOutcome;
use crate::root::{ROOT_SLOT_BYTES, RootSlot};
use std::ffi::OsStr;
use std::io;
use std::sync::Mutex;

const GROUP: [u8; 16] = [71; 16];
const SEGMENT: u64 = 7;
const RECORD_AT: usize = SEGMENT_HEADER_BYTES as usize;

struct ReadOnly {
    bytes: Vec<u8>,
    payload_at: u64,
    reads: Mutex<Vec<(u64, usize)>>,
    fail_read: bool,
    length: Option<u64>,
}

impl SegmentGroupBackend for ReadOnly {
    // Required explicit corridor; unsupported fixtures/scratch backends fail closed.
    fn reserve_transaction(
        &self,
        _plan: &crate::TransactionSpacePlan,
    ) -> std::result::Result<(), crate::TransactionReserveError> {
        Err(crate::TransactionReserveError::Failed(
            std::io::ErrorKind::Unsupported.into(),
        ))
    }
    fn finish_transaction(&self, _group_id: [u8; 16], _batch_seq: u64) -> std::io::Result<()> {
        Err(std::io::ErrorKind::Unsupported.into())
    }
    fn cancel_transaction(&self, _group_id: [u8; 16], _batch_seq: u64) -> std::io::Result<()> {
        Err(std::io::ErrorKind::Unsupported.into())
    }

    fn len(&self, file: GroupFile) -> io::Result<u64> {
        assert_eq!(file, GroupFile::segment(SEGMENT));
        Ok(self.length.unwrap_or(self.bytes.len() as u64))
    }
    fn read(&self, file: GroupFile, at: u64, out: &mut [u8]) -> io::Result<()> {
        assert_eq!(file, GroupFile::segment(SEGMENT));
        assert!(at >= SEGMENT_HEADER_BYTES);
        assert!(out.len() <= CACHED_VALUE_LOCATOR_BYTES);
        assert!(
            at + out.len() as u64 <= self.payload_at,
            "disk payload was read"
        );
        self.reads.lock().unwrap().push((at, out.len()));
        if self.fail_read {
            return Err(io::Error::other("locator read failed"));
        }
        out.copy_from_slice(&self.bytes[at as usize..at as usize + out.len()]);
        Ok(())
    }
    fn read_root(&self, _: RootSlot, _: &mut [u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        unreachable!()
    }
    fn write_root(&self, _: RootSlot, _: &[u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        unreachable!()
    }
    fn sync_root(&self) -> io::Result<()> {
        unreachable!()
    }
    fn visit_entries(&self, _: &mut dyn FnMut(&OsStr) -> io::Result<()>) -> io::Result<()> {
        unreachable!()
    }
    fn exists(&self, _: GroupFile) -> io::Result<bool> {
        unreachable!()
    }
    fn create(&self, _: GroupFile) -> io::Result<()> {
        unreachable!()
    }
    fn write(&self, _: GroupFile, _: u64, _: &[u8]) -> io::Result<()> {
        unreachable!()
    }
    fn set_len(&self, _: GroupFile, _: u64) -> io::Result<()> {
        unreachable!()
    }
    fn sync(&self, _: GroupFile) -> io::Result<()> {
        unreachable!()
    }
    fn unlink(&self, _: GroupFile) -> io::Result<()> {
        unreachable!()
    }
    fn sync_names(&self) -> io::Result<()> {
        unreachable!()
    }
    fn close(&self) -> BackendCloseOutcome {
        unreachable!()
    }
}

struct Fixture {
    backend: ReadOnly,
    location: ValueLocation,
    table_len: u16,
    key_len: u16,
    cached: Vec<u8>,
}

impl Fixture {
    fn new(kind: RecordKind, table: &[u8], key: &[u8], payload: Vec<u8>) -> Self {
        let prefix = if kind == RecordKind::Put {
            PUT_PREFIX_BYTES
        } else {
            RELOCATE_PREFIX_BYTES
        };
        let mut inline = vec![0; prefix];
        inline[..2].copy_from_slice(&(table.len() as u16).to_le_bytes());
        inline[2..4].copy_from_slice(&(key.len() as u16).to_le_bytes());
        inline[4..8].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        inline[8..12].copy_from_slice(&crc32c(&payload).to_le_bytes());
        if kind == RecordKind::Relocate {
            inline[PUT_PREFIX_BYTES..RELOCATE_PREFIX_BYTES].copy_from_slice(&3u64.to_le_bytes());
        }
        inline.extend_from_slice(table);
        inline.extend_from_slice(key);
        let mut body_crc = Crc32c::new();
        body_crc.update(&inline);
        body_crc.update(&payload);
        let header = record_header(
            &GROUP,
            LogPosition {
                segment_id: SEGMENT,
                offset: RECORD_AT as u64,
            },
            &RecordHead {
                kind,
                batch_seq: 7,
                base_seq: 6,
                body_len: (inline.len() + payload.len()) as u32,
                body_crc: body_crc.finish(),
            },
        );
        let mut bytes = segment_header(&GROUP, SEGMENT).to_vec();
        bytes.extend_from_slice(&header);
        bytes.extend_from_slice(&inline);
        let payload_at = bytes.len() as u64;
        bytes.extend_from_slice(&payload);
        Self {
            backend: ReadOnly {
                bytes,
                payload_at,
                reads: Mutex::new(Vec::new()),
                fail_read: false,
                length: None,
            },
            location: ValueLocation {
                segment_id: SEGMENT,
                offset: payload_at,
                len: payload.len() as u32,
                crc: crc32c(&payload),
            },
            table_len: table.len() as u16,
            key_len: key.len() as u16,
            cached: payload,
        }
    }

    fn inspect<'a>(
        &self,
        scratch: &'a mut [u8; CACHED_VALUE_LOCATOR_BYTES],
    ) -> Result<CachedValueIdentity<'a>, CoreError> {
        inspect_cached_value_identity(
            &self.backend,
            &GROUP,
            self.location,
            self.table_len,
            self.key_len,
            &self.cached,
            scratch,
        )
    }

    fn seal(&mut self) {
        let bytes = &mut self.backend.bytes;
        let body_crc = crc32c(&bytes[RECORD_AT + RECORD_HEADER_BYTES..]);
        bytes[RECORD_AT + 28..RECORD_AT + 32].copy_from_slice(&body_crc.to_le_bytes());
        let header_crc = header_checksum(
            &GROUP,
            LogPosition {
                segment_id: SEGMENT,
                offset: RECORD_AT as u64,
            },
            &bytes[RECORD_AT..RECORD_AT + 32],
        );
        bytes[RECORD_AT + 32..RECORD_AT + 36].copy_from_slice(&header_crc.to_le_bytes());
    }
}

#[test]
fn cached_locator_accepts_put_at_segment_start_with_empty_key_and_value() {
    let fixture = Fixture::new(RecordKind::Put, b"a", b"", Vec::new());
    let mut scratch = [0; CACHED_VALUE_LOCATOR_BYTES];
    let identity = fixture.inspect(&mut scratch).unwrap();
    assert_eq!(identity.table, "a");
    assert!(identity.key.is_empty());
    assert_eq!(identity.logical_batch_seq, 7);
    assert_eq!(
        *fixture.backend.reads.lock().unwrap(),
        [(
            SEGMENT_HEADER_BYTES,
            RECORD_HEADER_BYTES + PUT_PREFIX_BYTES + 1
        )]
    );
}

#[test]
fn cached_locator_recovers_maximum_suffix_and_large_relocated_value_with_one_bounded_read() {
    let table = "é".repeat(MAX_TABLE_BYTES / 2);
    let key = vec![255; MAX_KEY_BYTES];
    let fixture = Fixture::new(
        RecordKind::Relocate,
        table.as_bytes(),
        &key,
        vec![41; 1 << 20],
    );
    let mut scratch = [0; CACHED_VALUE_LOCATOR_BYTES];
    let identity = fixture.inspect(&mut scratch).unwrap();
    assert_eq!(identity.table, table);
    assert_eq!(identity.key, key);
    assert_eq!(identity.logical_batch_seq, 3);
    assert_eq!(
        *fixture.backend.reads.lock().unwrap(),
        [(SEGMENT_HEADER_BYTES, CACHED_VALUE_LOCATOR_BYTES)]
    );
}

#[test]
fn cached_locator_put_with_long_suffix_checks_both_fixed_positions_without_scanning_key_magic() {
    let mut key = vec![0; MAX_KEY_BYTES];
    for part in key.chunks_exact_mut(RECORD_MAGIC.len()) {
        part.copy_from_slice(&RECORD_MAGIC);
    }
    let mut fixture = Fixture::new(RecordKind::Put, b"accounts", &key, vec![9; 7]);
    // Make both fixed candidate positions lie after the segment header. The
    // earlier Relocate position is padding, not a reason to scan the key.
    fixture.backend.bytes.splice(RECORD_AT..RECORD_AT, [0; 8]);
    fixture.location.offset += 8;
    fixture.backend.payload_at += 8;
    let moved_at = RECORD_AT + 8;
    let header_crc = header_checksum(
        &GROUP,
        LogPosition {
            segment_id: SEGMENT,
            offset: moved_at as u64,
        },
        &fixture.backend.bytes[moved_at..moved_at + 32],
    );
    fixture.backend.bytes[moved_at + 32..moved_at + 36].copy_from_slice(&header_crc.to_le_bytes());
    let mut scratch = [0; CACHED_VALUE_LOCATOR_BYTES];
    assert_eq!(fixture.inspect(&mut scratch).unwrap().key, key);
    assert_eq!(fixture.backend.reads.lock().unwrap().len(), 1);
}

#[test]
fn cached_locator_ignores_checksum_valid_fake_header_in_previous_payload() {
    // These arbitrary payload bytes make the overlapping Relocate candidate's
    // CRC equal the next Put's body length (34), which occupies the fake CRC
    // field. Its kind tag is invalid. Both actual Put records remain valid.
    let previous = Fixture::new(
        RecordKind::Put,
        b"accounts",
        b"previous",
        vec![75, 86, 83, 82, 11, 14, 231, 205],
    );
    let mut fixture = Fixture::new(RecordKind::Put, b"accounts", b"key", vec![9; 7]);
    let shift = previous.backend.bytes.len() - RECORD_AT;
    let mut bytes = previous.backend.bytes;
    bytes.extend_from_slice(&fixture.backend.bytes[RECORD_AT..]);
    fixture.backend.bytes = bytes;
    fixture.location.offset += shift as u64;
    fixture.backend.payload_at += shift as u64;
    let actual_at = RECORD_AT + shift;
    assert_eq!(actual_at, 140);
    let checksum = header_checksum(
        &GROUP,
        LogPosition {
            segment_id: SEGMENT,
            offset: actual_at as u64,
        },
        &fixture.backend.bytes[actual_at..actual_at + 32],
    );
    fixture.backend.bytes[actual_at + 32..actual_at + 36].copy_from_slice(&checksum.to_le_bytes());

    for (at, end) in [
        (RECORD_AT, actual_at),
        (actual_at, fixture.backend.bytes.len()),
    ] {
        let header = (&fixture.backend.bytes[at..at + RECORD_HEADER_BYTES])
            .try_into()
            .unwrap();
        let head = decode_record_header(
            header,
            &GROUP,
            LogPosition {
                segment_id: SEGMENT,
                offset: at as u64,
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(head.kind, RecordKind::Put);
        assert_eq!(head.body_len as usize, end - at - RECORD_HEADER_BYTES);
        assert_eq!(
            head.body_crc,
            crc32c(&fixture.backend.bytes[at + RECORD_HEADER_BYTES..end])
        );
    }
    let fake_at = actual_at - 8;
    let fake_header = (&fixture.backend.bytes[fake_at..fake_at + RECORD_HEADER_BYTES])
        .try_into()
        .unwrap();
    assert!(matches!(
        decode_record_header(
            fake_header,
            &GROUP,
            LogPosition {
                segment_id: SEGMENT,
                offset: fake_at as u64,
            },
        ),
        Err(CoreError::Corrupt("segment record has an unknown kind"))
    ));
    let mut scratch = [0; CACHED_VALUE_LOCATOR_BYTES];
    let identity = fixture.inspect(&mut scratch).unwrap();
    assert_eq!(identity.table, "accounts");
    assert_eq!(identity.key, b"key");
    assert_eq!(identity.logical_batch_seq, 7);
    assert_eq!(fixture.backend.reads.lock().unwrap().len(), 1);
}

#[test]
fn cached_locator_rejects_bad_cached_payload_and_invalid_lengths_before_io() {
    for change in 0..6 {
        let mut fixture = Fixture::new(RecordKind::Put, b"table", b"key", vec![9; 7]);
        match change {
            0 => {
                fixture.cached.pop().unwrap();
            }
            1 => fixture.cached[0] ^= 1,
            2 => fixture.table_len = 0,
            3 => fixture.table_len = MAX_TABLE_BYTES as u16 + 1,
            4 => fixture.key_len = MAX_KEY_BYTES as u16 + 1,
            _ => fixture.location.offset = 0,
        }
        let mut scratch = [0; CACHED_VALUE_LOCATOR_BYTES];
        let error = fixture.inspect(&mut scratch).unwrap_err();
        if (2..=4).contains(&change) {
            assert!(matches!(error, CoreError::InvalidInput(_)));
        } else {
            assert!(matches!(error, CoreError::Corrupt(_)));
        }
        assert!(fixture.backend.reads.lock().unwrap().is_empty());
    }
}

#[test]
fn cached_locator_checks_group_record_position_and_stored_checksums() {
    for change in 0..5 {
        let mut fixture = Fixture::new(RecordKind::Relocate, b"accounts", b"key", vec![9; 7]);
        let mut group = GROUP;
        match change {
            0 => group[0] ^= 1,
            1 => fixture.backend.bytes[RECORD_AT] ^= 1,
            2 => fixture.backend.bytes[RECORD_AT + 32] ^= 1,
            3 => {
                fixture.backend.bytes[RECORD_AT + RECORD_HEADER_BYTES + RELOCATE_PREFIX_BYTES] ^= 1
            }
            _ => {
                let header_crc = header_checksum(
                    &GROUP,
                    LogPosition {
                        segment_id: SEGMENT,
                        offset: RECORD_AT as u64 + 1,
                    },
                    &fixture.backend.bytes[RECORD_AT..RECORD_AT + 32],
                );
                fixture.backend.bytes[RECORD_AT + 32..RECORD_AT + 36]
                    .copy_from_slice(&header_crc.to_le_bytes());
            }
        }
        let mut scratch = [0; CACHED_VALUE_LOCATOR_BYTES];
        assert!(
            matches!(
                inspect_cached_value_identity(
                    &fixture.backend,
                    &group,
                    fixture.location,
                    fixture.table_len,
                    fixture.key_len,
                    &fixture.cached,
                    &mut scratch
                ),
                Err(CoreError::Corrupt(_))
            ),
            "case {change}"
        );
    }
}

#[test]
fn cached_locator_rejects_checksum_valid_noncanonical_envelopes() {
    for change in 0..13 {
        let mut fixture = Fixture::new(RecordKind::Relocate, b"accounts", b"key", vec![9; 7]);
        let prefix = RECORD_AT + RECORD_HEADER_BYTES;
        match change {
            0 => fixture.backend.bytes[prefix] ^= 1,
            1 => fixture.backend.bytes[prefix + 2] ^= 1,
            2 => fixture.backend.bytes[prefix + 4] ^= 1,
            3 => fixture.backend.bytes[prefix + 8] ^= 1,
            4 => fixture.backend.bytes[prefix + 12] = 1,
            5 => fixture.backend.bytes[prefix + 16..prefix + 24].fill(0),
            6 => {
                fixture.backend.bytes[prefix + 16..prefix + 24].copy_from_slice(&7u64.to_le_bytes())
            }
            7 => fixture.backend.bytes[prefix + RELOCATE_PREFIX_BYTES] = 255,
            8 => fixture.backend.bytes[RECORD_AT + 24] ^= 1,
            9 => fixture.backend.bytes[RECORD_AT + 4] = RecordKind::Put.tag(),
            10 => fixture.backend.bytes[RECORD_AT + 5] = 1,
            11 => fixture.backend.bytes[RECORD_AT + 8..RECORD_AT + 16].fill(0),
            _ => fixture.backend.bytes[RECORD_AT + 4] = 255,
        }
        fixture.seal();
        let mut scratch = [0; CACHED_VALUE_LOCATOR_BYTES];
        assert!(
            matches!(fixture.inspect(&mut scratch), Err(CoreError::Corrupt(_))),
            "case {change}"
        );
    }
}

#[test]
fn cached_locator_rejects_truncated_or_oversized_segment_and_preserves_io_failure() {
    for length in [SEGMENT_HEADER_BYTES, SEGMENT_BYTES + 1] {
        let mut fixture = Fixture::new(RecordKind::Put, b"table", b"key", vec![9; 7]);
        fixture.backend.length = Some(length);
        let mut scratch = [0; CACHED_VALUE_LOCATOR_BYTES];
        assert!(matches!(
            fixture.inspect(&mut scratch),
            Err(CoreError::Corrupt(_))
        ));
        assert!(fixture.backend.reads.lock().unwrap().is_empty());
    }
    let mut fixture = Fixture::new(RecordKind::Put, b"table", b"key", vec![9; 7]);
    fixture.backend.fail_read = true;
    let mut scratch = [0; CACHED_VALUE_LOCATOR_BYTES];
    assert!(
        fixture
            .inspect(&mut scratch)
            .unwrap_err()
            .to_string()
            .contains("locator read failed")
    );
}
