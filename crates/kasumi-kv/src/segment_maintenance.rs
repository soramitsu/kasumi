//! Bounded maintenance batches with a fixed streaming workspace.
//!
//! Relocation keeps the row's logical version while creating a fresh physical
//! value address. A directory-only record binds page evacuation to the same
//! prepare/directory/commit protocol. Neither operation exposes a logical
//! user write, and neither collects the keys or value bytes in memory.

use super::*;

/// More than the maximum number of minimum-size records in a 16 KiB leaf.
/// The operation array/key backing belongs to the admitted leaf planner;
/// this codec reserves only fixed workspace and returned locations.
pub(crate) const MAX_MAINTENANCE_OPERATIONS: usize = 512;

#[derive(Clone, Copy, Debug)]
pub(crate) enum MaintenanceOp<'a> {
    DirectoryOnly,
    Relocate {
        table: &'a str,
        key: &'a [u8],
        logical_batch_seq: u64,
        source: ValueLocation,
    },
}

/// Reserve this before preparation and hold it through finish or abort.
/// Includes the streaming buffer, inline record, bounded destination array,
/// torn-tail search and conservative allocation/lease overhead. The writer's
/// persistent IO_WINDOW staging allocation is owned separately by DiskState.
/// This reservation is independent of the relocated value's length.
pub(crate) fn maintenance_workspace_bytes() -> u64 {
    (2 * SEARCH_WINDOW
        + 4 * IO_WINDOW
        + 4 * MAX_INLINE_BODY
        + 4 * std::mem::size_of::<ReplayedRecord>()
        + MAX_MAINTENANCE_OPERATIONS * (std::mem::size_of::<Option<ValueLocation>>() + 4)
        + 4096) as u64
}

/// Encoded operation bytes for the leaf planner's batch limit, including the
/// record header and inline metadata, but not the final directory/commit.
/// Structural rejection here requires no I/O or allocation.
pub(crate) fn maintenance_operation_bytes(
    operation: MaintenanceOp<'_>,
) -> Result<usize, CoreError> {
    match operation {
        MaintenanceOp::DirectoryOnly => Ok(RECORD_HEADER_BYTES + MAINTENANCE_BODY_BYTES),
        MaintenanceOp::Relocate {
            table,
            key,
            logical_batch_seq,
            source,
        } => {
            if table.is_empty()
                || table.len() > MAX_TABLE_BYTES
                || key.len() > MAX_KEY_BYTES
                || logical_batch_seq == 0
                || source.segment_id == u64::MAX
                || source.validate().is_err()
            {
                return Err(CoreError::InvalidInput("relocation metadata is invalid"));
            }
            Ok(RECORD_HEADER_BYTES
                + RELOCATE_PREFIX_BYTES
                + table.len()
                + key.len()
                + source.len as usize)
        }
    }
}

fn validate_maintenance(
    operations: &[MaintenanceOp<'_>],
    last_batch_seq: u64,
    capacity: u64,
) -> Result<(), CoreError> {
    if operations.is_empty() || operations.len() > MAX_MAINTENANCE_OPERATIONS {
        return Err(CoreError::InvalidInput(
            "empty or oversized maintenance batch",
        ));
    }
    let mut encoded = 0usize;
    for &operation in operations {
        match operation {
            MaintenanceOp::DirectoryOnly if operations.len() != 1 => {
                return Err(CoreError::InvalidInput(
                    "directory maintenance marker must stand alone",
                ));
            }
            MaintenanceOp::Relocate {
                logical_batch_seq, ..
            } if logical_batch_seq > last_batch_seq => {
                return Err(CoreError::InvalidInput("relocation metadata is invalid"));
            }
            _ => {}
        }
        let bytes = maintenance_operation_bytes(operation)?;
        if bytes as u64 > capacity - SEGMENT_HEADER_BYTES {
            return Err(CoreError::InvalidInput("record exceeds segment capacity"));
        }
        encoded = encoded
            .checked_add(bytes)
            .filter(|&bytes| bytes <= MAX_BATCH_BYTES)
            .ok_or(CoreError::InvalidInput(
                "maintenance batch exceeds encoded byte bound",
            ))?;
    }
    Ok(())
}

impl SegmentWriter {
    /// Prepare a leaf's bounded physical maintenance batch. Every source is
    /// verified in a read-only pass before any destination writes. A second
    /// pass streams each source while checking its CRC again. The operation
    /// prefix is synchronized once, except when a segment rollover requires
    /// sealing the previous file. Up to MAX_BATCH_BYTES may be copied, but
    /// memory and each backend read/write are bounded by IO_WINDOW.
    pub(crate) fn prepare_maintenance(
        &mut self,
        backend: &dyn SegmentGroupBackend,
        operations: &[MaintenanceOp<'_>],
        roll: &mut dyn SegmentRoll,
    ) -> Result<PreparedBatch, CoreError> {
        if self.fenced || self.prepared.is_some() {
            return Err(CoreError::OwnerFailed);
        }
        if self.next_batch_seq == u64::MAX {
            return Err(CoreError::InvalidInput("batch sequence overflow"));
        }
        validate_maintenance(operations, self.last_batch_seq, self.capacity)?;
        if self.stage.capacity() < IO_WINDOW {
            self.stage
                .try_reserve_exact(IO_WINDOW - self.stage.len())
                .map_err(|_| CoreError::CapacityDenied)?;
        }
        if self.stage.capacity() > IO_WINDOW {
            self.stage = Vec::new();
            return Err(CoreError::CapacityDenied);
        }
        let mut values = Vec::new();
        values
            .try_reserve_exact(operations.len())
            .map_err(|_| CoreError::CapacityDenied)?;
        let mut window = Vec::new();
        window
            .try_reserve_exact(IO_WINDOW)
            .map_err(|_| CoreError::CapacityDenied)?;
        if window.capacity() != IO_WINDOW || values.capacity() != operations.len() {
            return Err(CoreError::CapacityDenied);
        }
        window.resize(IO_WINDOW, 0);
        let start = ReplayStart {
            position: self.position().unwrap_or(LogPosition::GENESIS),
            batch_seq: self.last_batch_seq,
            chain: self.chain,
        };
        let result = self.write_maintenance(backend, operations, roll, values, &mut window, start);
        match &result {
            Ok(prepared) => self.prepared = Some(prepared.identity),
            Err(_) => self.fenced = true,
        }
        result
    }

    fn write_maintenance(
        &mut self,
        backend: &dyn SegmentGroupBackend,
        operations: &[MaintenanceOp<'_>],
        roll: &mut dyn SegmentRoll,
        mut values: Vec<Option<ValueLocation>>,
        window: &mut [u8],
        start: ReplayStart,
    ) -> Result<PreparedBatch, CoreError> {
        let mut inline = [0; MAX_INLINE_BODY];
        let mut body_checksums = [0u32; MAX_MAINTENANCE_OPERATIONS];
        // Preflight every source header, extent and checksum before the first
        // append/roll. A bad later source cannot leave an earlier private copy.
        for (index, &operation) in operations.iter().enumerate() {
            let (_, inline_len, source) = encode_maintenance(operation, &mut inline);
            let mut body_crc = Crc32c::new();
            body_crc.update(&inline[..inline_len]);
            if let Some(source) = source {
                if read_segment_header(backend, &self.group_id, source.segment_id)?
                    != HeaderState::Valid
                {
                    return Err(CoreError::Corrupt("relocation source header is damaged"));
                }
                let len = backend.len(GroupFile::segment(source.segment_id))?;
                if len > SEGMENT_BYTES || source.offset + u64::from(source.len) > len {
                    return Err(CoreError::Corrupt("relocation source exceeds its segment"));
                }
                read_source(backend, source, window, |chunk| {
                    body_crc.update(chunk);
                    Ok(())
                })?;
            }
            body_checksums[index] = body_crc.finish();
        }
        let batch_seq = self.next_batch_seq;
        let mut ops = Sha256::new();
        for (index, &operation) in operations.iter().enumerate() {
            let (kind, inline_len, source) = encode_maintenance(operation, &mut inline);
            let inline = &inline[..inline_len];
            let body_len = inline_len + source.map_or(0, |value| value.len as usize);
            self.ensure_room(backend, (RECORD_HEADER_BYTES + body_len) as u64, roll)?;
            let at = self.position().expect("maintenance has an active segment");
            let header = record_header(
                &self.group_id,
                at,
                &RecordHead {
                    kind,
                    batch_seq,
                    base_seq: self.last_batch_seq,
                    body_len: body_len as u32,
                    body_crc: body_checksums[index],
                },
            );
            ops.update(header);
            ops.update(inline);
            self.stage(backend, &header)?;
            self.stage(backend, inline)?;
            let value_at = self.end;
            if let Some(source) = source {
                read_source(backend, source, window, |chunk| {
                    ops.update(chunk);
                    self.stage(backend, chunk)
                })?;
            }
            values.push(source.map(|source| ValueLocation {
                segment_id: at.segment_id,
                offset: value_at,
                len: source.len,
                crc: source.crc,
            }));
        }
        self.flush(backend)?;
        let end = self.position().expect("maintenance has an active segment");
        backend.sync(GroupFile::segment(end.segment_id))?;
        Ok(PreparedBatch {
            identity: PreparedIdentity {
                group_id: self.group_id,
                batch_seq,
                start,
                end,
                ops_sha256: ops.finalize().into(),
                operation_count: operations.len() as u32,
            },
            values,
        })
    }
}

fn encode_maintenance(
    operation: MaintenanceOp<'_>,
    inline: &mut [u8; MAX_INLINE_BODY],
) -> (RecordKind, usize, Option<ValueLocation>) {
    inline[..RELOCATE_PREFIX_BYTES].fill(0);
    match operation {
        MaintenanceOp::DirectoryOnly => (RecordKind::Maintenance, MAINTENANCE_BODY_BYTES, None),
        MaintenanceOp::Relocate {
            table,
            key,
            logical_batch_seq,
            source,
        } => {
            inline[..2].copy_from_slice(&(table.len() as u16).to_le_bytes());
            inline[2..4].copy_from_slice(&(key.len() as u16).to_le_bytes());
            inline[4..8].copy_from_slice(&source.len.to_le_bytes());
            inline[8..12].copy_from_slice(&source.crc.to_le_bytes());
            inline[PUT_PREFIX_BYTES..RELOCATE_PREFIX_BYTES]
                .copy_from_slice(&logical_batch_seq.to_le_bytes());
            let key_at = RELOCATE_PREFIX_BYTES + table.len();
            inline[RELOCATE_PREFIX_BYTES..key_at].copy_from_slice(table.as_bytes());
            inline[key_at..key_at + key.len()].copy_from_slice(key);
            (RecordKind::Relocate, key_at + key.len(), Some(source))
        }
    }
}

fn read_source(
    backend: &dyn SegmentGroupBackend,
    source: ValueLocation,
    window: &mut [u8],
    mut consume: impl FnMut(&[u8]) -> Result<(), CoreError>,
) -> Result<(), CoreError> {
    let mut read = 0;
    let mut crc = Crc32c::new();
    while read < source.len as usize {
        let len = (source.len as usize - read).min(window.len());
        let chunk = &mut window[..len];
        backend.read(
            GroupFile::segment(source.segment_id),
            source.offset + read as u64,
            chunk,
        )?;
        crc.update(chunk);
        consume(chunk)?;
        read += len;
    }
    if crc.finish() != source.crc {
        return Err(CoreError::Corrupt("relocation source checksum differs"));
    }
    Ok(())
}

#[cfg(test)]
#[path = "segment_maintenance_tests.rs"]
mod tests;
