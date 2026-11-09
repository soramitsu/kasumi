//! A generation-bound append log. Each checksum-protected frame is one atomic
//! batch. Its separately checked header bounds allocation and identifies a torn
//! final frame without interpreting a corrupted length as a crash tail.

#[path = "live_wal_serial.rs"]
mod serial;
use crate::{MAX_KEY, MAX_VALUE, invalid};
use lz4_flex::block;
use serial::SerialWriter;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};

const MAGIC: &[u8; 8] = b"KSLVWAL1";
const WAL_HEADER: usize = 80;
const FRAME_MAGIC: &[u8; 4] = b"KWB1";
const FIELDS: usize = 24;
const DIGEST: usize = 16;
const HEADER: usize = FIELDS + DIGEST;
const PACKED: u32 = 1 << 31;
pub const MAX_WAL_BATCH_BYTES: usize = 64 << 20;
pub const MAX_WAL_BATCH_OPS: usize = 65_536;

/// One ordered mutation. Empty binary keys and values are supported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalOp<'a> {
    Put(&'a [u8], &'a [u8]),
    Delete(&'a [u8]),
}

/// Flush file data through the device's volatile write cache before acknowledgment.
pub(crate) fn sync_durable(file: &File) -> io::Result<()> {
    #[cfg(target_vendor = "apple")]
    {
        use std::os::fd::AsRawFd;
        loop {
            // F_FULLFSYNC has no argument and does not retain the borrowed fd.
            if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_FULLFSYNC) } == 0 {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
    #[cfg(not(target_vendor = "apple"))]
    file.sync_all()
}

fn reserve<T>(buffer: &mut Vec<T>, additional: usize) -> io::Result<()> {
    buffer
        .try_reserve_exact(additional)
        .map_err(|_| io::ErrorKind::OutOfMemory.into())
}

fn varint_len(value: usize) -> usize {
    ((usize::BITS - value.leading_zeros()) as usize)
        .max(1)
        .div_ceil(7)
}

fn put_varint(out: &mut Vec<u8>, mut value: usize) {
    while value >= 128 {
        out.push(value as u8 | 128);
        value >>= 7;
    }
    out.push(value as u8);
}

fn get_varint(input: &mut &[u8]) -> io::Result<usize> {
    let mut value = 0u32;
    for index in 0..5 {
        let (&byte, rest) = input
            .split_first()
            .ok_or_else(|| invalid("truncated WAL length"))?;
        *input = rest;
        if index == 4 && byte > 15 {
            break;
        }
        value |= u32::from(byte & 127) << (7 * index);
        if byte < 128 {
            if index != 0 && byte == 0 {
                break;
            }
            return Ok(value as usize);
        }
    }
    Err(invalid("invalid WAL length"))
}

/// Validate every operation before touching the file and return the exact raw
/// payload length, including all operation and length fields.
pub(crate) fn validate_wal_batch(ops: &[WalOp<'_>]) -> io::Result<usize> {
    let limit = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "WAL batch exceeds storage limits",
        )
    };
    if ops.len() > MAX_WAL_BATCH_OPS {
        return Err(limit());
    }
    let mut size = 0usize;
    for op in ops {
        let (key, value) = match *op {
            WalOp::Put(key, value) => (key, Some(value)),
            WalOp::Delete(key) => (key, None),
        };
        if key.len() > MAX_KEY || value.is_some_and(|value| value.len() > MAX_VALUE) {
            return Err(limit());
        }
        size += varint_len(key.len() * 2 + usize::from(value.is_none())) + key.len();
        if let Some(value) = value {
            size += varint_len(value.len()) + value.len();
        }
        if size > MAX_WAL_BATCH_BYTES {
            return Err(limit());
        }
    }
    Ok(size)
}

fn encode_ops(out: &mut Vec<u8>, ops: &[WalOp<'_>]) {
    for op in ops {
        match *op {
            WalOp::Put(key, value) => {
                put_varint(out, key.len() * 2);
                put_varint(out, value.len());
                out.extend_from_slice(key);
                out.extend_from_slice(value);
            }
            WalOp::Delete(key) => {
                put_varint(out, key.len() * 2 + 1);
                out.extend_from_slice(key);
            }
        }
    }
}

fn decode_ops(mut raw: &[u8], count: usize) -> io::Result<Vec<WalOp<'_>>> {
    let mut ops = Vec::new();
    reserve(&mut ops, count)?;
    for _ in 0..count {
        let code = get_varint(&mut raw)?;
        let key_size = code >> 1;
        if key_size > MAX_KEY {
            return Err(invalid("WAL key exceeds storage limit"));
        }
        if code & 1 != 0 {
            ops.push(WalOp::Delete(crate::take(&mut raw, key_size)?));
        } else {
            let value_size = get_varint(&mut raw)?;
            if value_size > MAX_VALUE {
                return Err(invalid("WAL value exceeds storage limit"));
            }
            let key = crate::take(&mut raw, key_size)?;
            let value = crate::take(&mut raw, value_size)?;
            ops.push(WalOp::Put(key, value));
        }
    }
    if !raw.is_empty() {
        return Err(invalid("unexpected bytes after WAL operations"));
    }
    Ok(ops)
}

pub(crate) fn wal_header(base: u64, root: [u8; 32]) -> [u8; WAL_HEADER] {
    let mut bytes = [0; WAL_HEADER];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..16].copy_from_slice(&base.to_le_bytes());
    bytes[16..48].copy_from_slice(&root);
    let digest = Sha256::digest(&bytes[..48]);
    bytes[48..].copy_from_slice(&digest);
    bytes
}

fn generation_digest(header: &[u8; WAL_HEADER]) -> [u8; DIGEST] {
    header[WAL_HEADER - DIGEST..].try_into().unwrap()
}

struct Frame {
    count: usize,
    raw: usize,
    stored: usize,
    compressed: bool,
}

fn frame_header(
    previous: &[u8; DIGEST],
    sequence: u64,
    count: usize,
    raw: usize,
    stored: usize,
    compressed: bool,
) -> [u8; HEADER] {
    let mut header = [0; HEADER];
    header[..4].copy_from_slice(FRAME_MAGIC);
    header[4..12].copy_from_slice(&sequence.to_le_bytes());
    header[12..16].copy_from_slice(&(count as u32).to_le_bytes());
    header[16..20].copy_from_slice(&(raw as u32).to_le_bytes());
    let encoded = stored as u32 | if compressed { PACKED } else { 0 };
    header[20..24].copy_from_slice(&encoded.to_le_bytes());
    let digest = frame_digest(previous, &header[..FIELDS]);
    header[FIELDS..].copy_from_slice(&digest[..DIGEST]);
    header
}

fn parse_header(bytes: &[u8; HEADER], previous: &[u8; DIGEST], sequence: u64) -> io::Result<Frame> {
    let fields = &bytes[..FIELDS];
    if &fields[..4] != FRAME_MAGIC
        || fields[4..12] != sequence.to_le_bytes()
        || frame_digest(previous, fields) != bytes[FIELDS..]
    {
        return Err(invalid("WAL frame header checksum or sequence mismatch"));
    }
    let count = u32::from_le_bytes(fields[12..16].try_into().unwrap()) as usize;
    let raw = u32::from_le_bytes(fields[16..20].try_into().unwrap()) as usize;
    let encoded = u32::from_le_bytes(fields[20..24].try_into().unwrap());
    let stored = (encoded & !PACKED) as usize;
    let compressed = encoded & PACKED != 0;
    if raw > MAX_WAL_BATCH_BYTES
        || count > MAX_WAL_BATCH_OPS
        || count > raw
        || (count == 0 && raw != 0)
        || (compressed && (stored == 0 || stored >= raw))
        || (!compressed && stored != raw)
    {
        return Err(invalid("invalid WAL frame bounds"));
    }
    Ok(Frame {
        count,
        raw,
        stored,
        compressed,
    })
}

fn frame_digest(prefix: &[u8], stored: &[u8]) -> [u8; DIGEST] {
    let mut hasher = Sha256::new();
    hasher.update(prefix);
    hasher.update(stored);
    hasher.finalize()[..DIGEST].try_into().unwrap()
}

fn read_frames(
    file: &File,
    base: u64,
    root: [u8; 32],
    mut visit: impl FnMut(u64, &[WalOp<'_>]) -> io::Result<()>,
) -> io::Result<(u64, u64, u64, [u8; DIGEST])> {
    let length = file.metadata()?.len();
    let mut reader = BufReader::new(file);
    reader.seek(SeekFrom::Start(0))?;
    let mut start = [0; WAL_HEADER];
    reader.read_exact(&mut start)?;
    if start != wal_header(base, root) {
        return Err(invalid("WAL generation or header checksum mismatch"));
    }
    let mut end = WAL_HEADER as u64;
    let mut sequence = base;
    let mut previous = generation_digest(&start);
    let mut stored = Vec::new();
    let mut decoded = Vec::new();
    while end < length {
        let next = sequence
            .checked_add(1)
            .ok_or_else(|| invalid("WAL sequence overflow"))?;
        let remaining = length - end;
        let head_bytes = remaining.min(HEADER as u64) as usize;
        let mut header = [0; HEADER];
        reader.read_exact(&mut header[..head_bytes])?;
        if head_bytes < HEADER {
            // A valid short write begins with the expected frame marker and sequence.
            let marker = FRAME_MAGIC.len().min(head_bytes);
            let seq_bytes = head_bytes.saturating_sub(marker).min(8);
            if header[..marker] != FRAME_MAGIC[..marker]
                || header[marker..marker + seq_bytes] != next.to_le_bytes()[..seq_bytes]
            {
                return Err(invalid("unexpected bytes at WAL tail"));
            }
            break;
        }
        let frame = parse_header(&header, &previous, next)?;
        let frame_bytes = (HEADER + frame.stored + DIGEST) as u64;
        if remaining < frame_bytes {
            break;
        }
        stored.clear();
        reserve(&mut stored, frame.stored)?;
        stored.resize(frame.stored, 0);
        reader.read_exact(&mut stored)?;
        let mut digest = [0; DIGEST];
        reader.read_exact(&mut digest)?;
        if frame_digest(&header, &stored) != digest {
            return Err(invalid("WAL payload checksum mismatch"));
        }
        let raw = if frame.compressed {
            decoded.clear();
            reserve(&mut decoded, frame.raw)?;
            decoded.resize(frame.raw, 0);
            let size = block::decompress_into(&stored, &mut decoded)
                .map_err(|_| invalid("invalid WAL compressed payload"))?;
            if size != frame.raw {
                return Err(invalid("WAL decompressed size mismatch"));
            }
            decoded.as_slice()
        } else {
            stored.as_slice()
        };
        let ops = decode_ops(raw, frame.count)?;
        visit(next, &ops)?;
        previous = digest;
        sequence = next;
        end += frame_bytes;
    }
    Ok((sequence, end, length, previous))
}

/// Reuse both encodings between commits. The compressed scratch remains
/// initialized up to its largest request. Only the returned frame is emitted.
struct FrameEncoder {
    raw: Vec<u8>,
    packed: Vec<u8>,
    table: block::CompressTable,
}

impl FrameEncoder {
    fn new() -> Self {
        Self {
            raw: Vec::new(),
            packed: Vec::new(),
            table: block::CompressTable::small(),
        }
    }

    fn encode(
        &mut self,
        ops: &[WalOp<'_>],
        size: usize,
        next: u64,
        previous: &[u8; DIGEST],
    ) -> io::Result<(&[u8], [u8; DIGEST])> {
        self.raw.clear();
        reserve(&mut self.raw, HEADER + size + DIGEST)?;
        self.raw.resize(HEADER, 0);
        encode_ops(&mut self.raw, ops);
        self.raw.resize(HEADER + size + DIGEST, 0);
        let mut frame = self.raw.as_mut_slice();
        if size >= 128 {
            let capacity = block::get_maximum_output_size(size);
            let needed = HEADER + capacity + DIGEST;
            if needed > self.packed.len() {
                let additional = needed - self.packed.len();
                reserve(&mut self.packed, additional)?;
                self.packed.resize(needed, 0);
            }
            let bytes = block::compress_into_with_table(
                &frame[HEADER..HEADER + size],
                &mut self.packed[HEADER..HEADER + capacity],
                &mut self.table,
            )
            .map_err(|_| invalid("could not compress WAL batch"))?;
            if bytes < size {
                frame = &mut self.packed[..HEADER + bytes + DIGEST];
            }
        }
        let trailer = frame.len() - DIGEST;
        let stored = trailer - HEADER;
        let header = frame_header(previous, next, ops.len(), size, stored, stored < size);
        frame[..HEADER].copy_from_slice(&header);
        let digest = frame_digest(&header, &frame[HEADER..trailer]);
        frame[trailer..].copy_from_slice(&digest);
        Ok((frame, digest))
    }
}

/// The file is held under the engine's exclusive lock for the complete lifetime
/// of this writer. A write or device synchronization failure seals it until reopen.
pub(crate) struct Wal {
    file: File,
    end: u64,
    sequence: u64,
    previous: [u8; DIGEST],
    fenced: bool,
    syncs: u64,
    encoder: FrameEncoder,
    serial: SerialWriter,
}

impl Wal {
    fn new(file: File, end: u64, sequence: u64, syncs: u64, previous: [u8; DIGEST]) -> Self {
        Self {
            file,
            end,
            sequence,
            previous,
            fenced: false,
            syncs,
            encoder: FrameEncoder::new(),
            serial: SerialWriter::default(),
        }
    }

    pub(crate) fn initialize(mut file: File, base: u64, root: [u8; 32]) -> io::Result<Self> {
        if file.metadata()?.len() != 0 {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "WAL file already contains data",
            ));
        }
        file.seek(SeekFrom::Start(0))?;
        let header = wal_header(base, root);
        file.write_all(&header)?;
        sync_durable(&file)?;
        Ok(Self::new(
            file,
            WAL_HEADER as u64,
            base,
            1,
            generation_digest(&header),
        ))
    }

    pub(crate) fn open(
        mut file: File,
        base: u64,
        root: [u8; 32],
        visit: impl FnMut(u64, &[WalOp<'_>]) -> io::Result<()>,
    ) -> io::Result<Self> {
        let (sequence, end, length, previous) = read_frames(&file, base, root, visit)?;
        if end != length {
            file.set_len(end)?;
        }
        // A full frame may have survived only in the operating system's cache
        // after process death between write and sync. Stabilize the recovered
        // prefix, including any tail truncation, before returning a writer.
        let needs_sync = length != WAL_HEADER as u64;
        if needs_sync {
            sync_durable(&file)?;
        }
        file.seek(SeekFrom::Start(end))?;
        Ok(Self::new(
            file,
            end,
            sequence,
            u64::from(needs_sync),
            previous,
        ))
    }

    pub(crate) fn read_sealed(
        file: &File,
        base: u64,
        root: [u8; 32],
        visit: impl FnMut(u64, &[WalOp<'_>]) -> io::Result<()>,
    ) -> io::Result<u64> {
        let (sequence, end, length, _) = read_frames(file, base, root, visit)?;
        if end != length {
            return Err(invalid("incomplete WAL in read-only database"));
        }
        Ok(sequence)
    }

    pub(crate) fn len(&self) -> u64 {
        self.end
    }
    pub(crate) fn sequence(&self) -> u64 {
        self.sequence
    }
    pub(crate) fn syncs(&self) -> u64 {
        self.syncs
    }
    pub(crate) fn is_fenced(&self) -> bool {
        self.fenced
    }

    pub(crate) fn append(&mut self, ops: &[WalOp<'_>]) -> io::Result<u64> {
        self.append_with(ops, SerialWriter::write)
    }

    fn append_with(
        &mut self,
        ops: &[WalOp<'_>],
        write: impl FnOnce(&mut SerialWriter, &mut File, u64, &[u8]) -> io::Result<u64>,
    ) -> io::Result<u64> {
        if self.fenced {
            return Err(io::Error::other("WAL writer requires recovery"));
        }
        let size = validate_wal_batch(ops)?;
        let next = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| io::Error::other("WAL sequence exhausted"))?;
        let (frame, digest) = self.encoder.encode(ops, size, next, &self.previous)?;
        let end = self
            .end
            .checked_add(frame.len() as u64)
            .ok_or_else(|| io::Error::other("WAL file size exhausted"))?;
        // Mark uncertain before the first effect and keep the writer fenced on error.
        self.fenced = true;
        let syncs = write(&mut self.serial, &mut self.file, self.end, frame)?;
        self.syncs = self.syncs.saturating_add(syncs);
        self.previous = digest;
        self.sequence = next;
        self.end = end;
        self.fenced = false;
        Ok(next)
    }
}

#[path = "live_wal_group.rs"]
mod group;

#[cfg(test)]
#[path = "live_wal_tests.rs"]
mod tests;
