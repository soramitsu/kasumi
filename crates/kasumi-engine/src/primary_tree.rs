//! Private logical page codec above encrypted application records.
//!
//! No I/O, publication, allocation, source selection or cache ownership lives
//! here. Callers supply admitted fixed page storage and retain it through loans.
//! A validated page proves its local framing and parent contract, not that its
//! child/overflow objects exist or match their descriptors. Those require real
//! selected-view reads and explicit retained failure/close ownership.
use sha2::{Digest, Sha256};

pub(crate) const PAGE_BYTES: usize = 16 << 10;
pub(crate) const HEADER_BYTES: usize = 104;
pub(crate) const DESCRIPTOR_BYTES: usize = 88;
const MAGIC: [u8; 16] = *b"KASUMI-DOCBT0001";
const FORMAT: u16 = 1;
const MAX_ID_BYTES: usize = 256;
// The bounded editor will rebuild through the staged path before exceeding
// this format depth; it must not turn workspace exhaustion into a user limit.
const MAX_LEVEL: u8 = 63;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CodecError {
    Length,
    Format,
    Identity,
    Digest,
    Level,
    Version,
    Name,
    Order,
    Range,
    Totals,
    Overflow,
    Capacity,
    Kind,
    Padding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ObjectId {
    pub(crate) attempt: [u8; 16],
    pub(crate) ordinal: u64,
}
impl ObjectId {
    fn check(self) -> Result<(), CodecError> {
        if self.attempt == [0; 16] {
            Err(CodecError::Identity)
        } else {
            Ok(())
        }
    }
    fn read(bytes: &[u8]) -> Self {
        Self {
            attempt: bytes[..16].try_into().expect("checked fixed descriptor"),
            ordinal: u64_at(bytes, 16),
        }
    }
    fn write(self, bytes: &mut [u8]) {
        bytes[..16].copy_from_slice(&self.attempt);
        bytes[16..24].copy_from_slice(&self.ordinal.to_le_bytes());
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PageRef {
    pub(crate) id: ObjectId,
    pub(crate) sha256: [u8; 32],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OverflowRef {
    pub(crate) id: ObjectId,
    /// Exact serialized Document or ArchivedDocument DTO bytes, excluding
    /// storage/chunk framing. This is not the live-body quota measurement.
    pub(crate) encoded_bytes: u64,
    pub(crate) sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Totals {
    pub(crate) live_count: u64,
    pub(crate) archived_count: u64,
    /// Sum of encoded_len(Document.body); archives contribute zero.
    pub(crate) live_body_bytes: u64,
    /// Sum of history::metadata_entry(id, ArchivedDocument); live rows zero.
    pub(crate) archived_metadata_bytes: u64,
}
impl Totals {
    fn check(self) -> Result<(), CodecError> {
        let count = self
            .live_count
            .checked_add(self.archived_count)
            .ok_or(CodecError::Overflow)?;
        if count == 0
            || (self.live_count == 0) != (self.live_body_bytes == 0)
            || (self.archived_count == 0) != (self.archived_metadata_bytes == 0)
            || self.live_body_bytes < self.live_count
            || self.archived_metadata_bytes < self.archived_count
        {
            return Err(CodecError::Totals);
        }
        Ok(())
    }
    fn add(self, other: Self) -> Result<Self, CodecError> {
        Ok(Self {
            live_count: self
                .live_count
                .checked_add(other.live_count)
                .ok_or(CodecError::Overflow)?,
            archived_count: self
                .archived_count
                .checked_add(other.archived_count)
                .ok_or(CodecError::Overflow)?,
            live_body_bytes: self
                .live_body_bytes
                .checked_add(other.live_body_bytes)
                .ok_or(CodecError::Overflow)?,
            archived_metadata_bytes: self
                .archived_metadata_bytes
                .checked_add(other.archived_metadata_bytes)
                .ok_or(CodecError::Overflow)?,
        })
    }
    fn read(bytes: &[u8]) -> Self {
        Self {
            live_count: u64_at(bytes, 0),
            archived_count: u64_at(bytes, 8),
            live_body_bytes: u64_at(bytes, 16),
            archived_metadata_bytes: u64_at(bytes, 24),
        }
    }
    fn write(self, bytes: &mut [u8]) {
        for (at, value) in [
            self.live_count,
            self.archived_count,
            self.live_body_bytes,
            self.archived_metadata_bytes,
        ]
        .into_iter()
        .enumerate()
        {
            bytes[at * 8..at * 8 + 8].copy_from_slice(&value.to_le_bytes());
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecordKind {
    Live,
    Archived,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Leaf {
    pub(crate) version: u64,
    pub(crate) kind: RecordKind,
    pub(crate) object: OverflowRef,
    /// Live body bytes OR archived map-entry bytes, according to kind.
    pub(crate) semantic_bytes: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Child {
    pub(crate) reference: PageRef,
    pub(crate) totals: Totals,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Value {
    Leaf(Leaf),
    Child(Child),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Entry<'a> {
    pub(crate) id: &'a str,
    pub(crate) value: Value,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PageSpec {
    pub(crate) tree_id: [u8; 16],
    pub(crate) id: ObjectId,
    pub(crate) generation: u64,
    pub(crate) level: u8,
}
impl PageSpec {
    fn check(self) -> Result<(), CodecError> {
        self.id.check()?;
        if self.tree_id == [0; 16] {
            return Err(CodecError::Identity);
        }
        if self.level > MAX_LEVEL {
            return Err(CodecError::Level);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct KeyRange<'a> {
    /// A child's actual first key must equal its parent's separator.
    pub(crate) lower: Option<&'a str>,
    /// Exclusive next-sibling minimum, inherited for a last child.
    pub(crate) upper: Option<&'a str>,
}
impl KeyRange<'_> {
    fn check(self) -> Result<(), CodecError> {
        if let Some(lower) = self.lower {
            check_id(lower)?;
        }
        if let Some(upper) = self.upper {
            check_id(upper)?;
        }
        if matches!((self.lower, self.upper), (Some(lower), Some(upper)) if lower >= upper) {
            return Err(CodecError::Range);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExpectedPage<'a> {
    pub(crate) tree_id: [u8; 16],
    pub(crate) reference: PageRef,
    pub(crate) generation_ceiling: u64,
    pub(crate) level: u8,
    pub(crate) totals: Totals,
    pub(crate) range: KeyRange<'a>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EncodedPage {
    pub(crate) reference: PageRef,
    pub(crate) totals: Totals,
}

/// Exact current archived map-entry accounting, without constructing JSON.
/// Name validation excludes controls; serde_json escapes only quotes and
/// backslashes among the remaining valid UTF-8 name bytes.
pub(crate) fn archived_metadata_bytes(id: &str, object_bytes: u64) -> Result<u64, CodecError> {
    check_id(id)?;
    let escaped = id
        .bytes()
        .filter(|byte| matches!(byte, b'"' | b'\\'))
        .count() as u64;
    (id.len() as u64)
        .checked_add(escaped)
        .and_then(|n| n.checked_add(3)) // JSON string quotes plus map colon.
        .and_then(|n| n.checked_add(object_bytes))
        .ok_or(CodecError::Overflow)
}
fn check_id(id: &str) -> Result<(), CodecError> {
    // Same accepted names as kasumi_types::validate_name, without constructing
    // its allocating wire Error on refusal.
    if id.is_empty() || id.len() > MAX_ID_BYTES || id.chars().any(char::is_control) {
        Err(CodecError::Name)
    } else {
        Ok(())
    }
}
fn entry_totals(entry: Entry<'_>, spec: PageSpec) -> Result<Totals, CodecError> {
    match entry.value {
        Value::Leaf(leaf) => {
            if spec.level != 0 {
                return Err(CodecError::Kind);
            }
            leaf.object.id.check()?;
            // Version zero is not rejected here: existing restored Document
            // validation only constrains the upper bound. Source validation
            // must also preserve index_source::record's nonzero requirement
            // and bind versions to the selected revision/collection data epoch.
            if leaf.version > spec.generation {
                return Err(CodecError::Version);
            }
            if leaf.object.encoded_bytes == 0 || leaf.semantic_bytes == 0 {
                return Err(CodecError::Totals);
            }
            match leaf.kind {
                RecordKind::Live => {
                    if leaf.semantic_bytes > leaf.object.encoded_bytes {
                        return Err(CodecError::Totals);
                    }
                    Ok(Totals {
                        live_count: 1,
                        live_body_bytes: leaf.semantic_bytes,
                        ..Totals::default()
                    })
                }
                RecordKind::Archived => {
                    if leaf.semantic_bytes
                        != archived_metadata_bytes(entry.id, leaf.object.encoded_bytes)?
                    {
                        return Err(CodecError::Totals);
                    }
                    Ok(Totals {
                        archived_count: 1,
                        archived_metadata_bytes: leaf.semantic_bytes,
                        ..Totals::default()
                    })
                }
            }
        }
        Value::Child(child) => {
            if spec.level == 0 {
                return Err(CodecError::Kind);
            }
            child.reference.id.check()?;
            if child.reference.id == spec.id {
                return Err(CodecError::Identity);
            }
            child.totals.check()?;
            Ok(child.totals)
        }
    }
}

/// Two passes: all input/refusal checks precede the first output mutation.
/// Empty logical roots are represented by no page, never an empty page record.
pub(crate) fn encode(
    out: &mut [u8; PAGE_BYTES],
    spec: PageSpec,
    entries: &[Entry<'_>],
) -> Result<EncodedPage, CodecError> {
    spec.check()?;
    if entries.is_empty() || entries.len() > u16::MAX as usize {
        return Err(CodecError::Capacity);
    }
    let mut used = HEADER_BYTES;
    let mut previous = None;
    let mut totals = Totals::default();
    for entry in entries {
        check_id(entry.id)?;
        if previous.is_some_and(|id| id >= entry.id) {
            return Err(CodecError::Order);
        }
        previous = Some(entry.id);
        used = used
            .checked_add(2 + entry.id.len() + DESCRIPTOR_BYTES)
            .ok_or(CodecError::Overflow)?;
        if used > PAGE_BYTES {
            return Err(CodecError::Capacity);
        }
        totals = totals.add(entry_totals(*entry, spec)?)?;
    }
    totals.check()?;
    out.fill(0);
    out[..16].copy_from_slice(&MAGIC);
    out[16..18].copy_from_slice(&FORMAT.to_le_bytes());
    out[18] = u8::from(spec.level != 0);
    out[19] = spec.level;
    out[20..36].copy_from_slice(&spec.tree_id);
    out[36..44].copy_from_slice(&spec.generation.to_le_bytes());
    spec.id.write(&mut out[44..68]);
    out[68..70].copy_from_slice(&(entries.len() as u16).to_le_bytes());
    out[70..72].copy_from_slice(&(used as u16).to_le_bytes());
    totals.write(&mut out[72..104]);
    let mut at = HEADER_BYTES;
    for entry in entries {
        out[at..at + 2].copy_from_slice(&(entry.id.len() as u16).to_le_bytes());
        at += 2;
        out[at..at + entry.id.len()].copy_from_slice(entry.id.as_bytes());
        at += entry.id.len();
        write_value(entry.value, &mut out[at..at + DESCRIPTOR_BYTES]);
        at += DESCRIPTOR_BYTES;
    }
    Ok(EncodedPage {
        reference: PageRef {
            id: spec.id,
            sha256: Sha256::digest(out.as_slice()).into(),
        },
        totals,
    })
}
fn write_value(value: Value, out: &mut [u8]) {
    match value {
        Value::Leaf(leaf) => {
            out[..8].copy_from_slice(&leaf.version.to_le_bytes());
            out[8] = u8::from(leaf.kind == RecordKind::Archived);
            leaf.object.id.write(&mut out[16..40]);
            out[40..48].copy_from_slice(&leaf.object.encoded_bytes.to_le_bytes());
            out[48..80].copy_from_slice(&leaf.object.sha256);
            out[80..88].copy_from_slice(&leaf.semantic_bytes.to_le_bytes());
        }
        Value::Child(child) => {
            child.reference.id.write(&mut out[..24]);
            out[24..56].copy_from_slice(&child.reference.sha256);
            child.totals.write(&mut out[56..88]);
        }
    }
}

#[derive(Debug)]
pub(crate) struct Page<'a> {
    bytes: &'a [u8],
    spec: PageSpec,
    totals: Totals,
    count: usize,
    used: usize,
    range: KeyRange<'a>,
}
/// Borrow immutable bytes only after framing, digest and the parent contract
/// have all been checked. A malicious length must never reach an unchecked slice.
pub(crate) fn validate<'a>(
    bytes: &'a [u8],
    expected: ExpectedPage<'a>,
) -> Result<Page<'a>, CodecError> {
    if bytes.len() != PAGE_BYTES {
        return Err(CodecError::Length);
    }
    expected.reference.id.check()?;
    expected.range.check()?;
    expected.totals.check()?;
    if bytes[..16] != MAGIC || u16_at(bytes, 16) != FORMAT {
        return Err(CodecError::Format);
    }
    let spec = PageSpec {
        tree_id: bytes[20..36].try_into().expect("fixed header"),
        id: ObjectId::read(&bytes[44..68]),
        generation: u64_at(bytes, 36),
        level: bytes[19],
    };
    spec.check()?;
    if bytes[18] != u8::from(spec.level != 0) {
        return Err(CodecError::Kind);
    }
    if spec.tree_id != expected.tree_id || spec.id != expected.reference.id {
        return Err(CodecError::Identity);
    }
    if spec.generation > expected.generation_ceiling {
        return Err(CodecError::Version);
    }
    if spec.level != expected.level {
        return Err(CodecError::Level);
    }
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    if digest != expected.reference.sha256 {
        return Err(CodecError::Digest);
    }
    let count = u16_at(bytes, 68) as usize;
    let used = u16_at(bytes, 70) as usize;
    if count == 0 || !(HEADER_BYTES..=PAGE_BYTES).contains(&used) {
        return Err(CodecError::Length);
    }
    if bytes[used..].iter().any(|byte| *byte != 0) {
        return Err(CodecError::Padding);
    }
    let declared = Totals::read(&bytes[72..104]);
    let mut total = Totals::default();
    let mut at = HEADER_BYTES;
    let mut first = None;
    let mut previous = None;
    for _ in 0..count {
        let (entry, next) = read_entry(bytes, at, used, spec.level)?;
        if previous.is_some_and(|id| id >= entry.id) {
            return Err(CodecError::Order);
        }
        if first.is_none() {
            first = Some(entry.id);
        }
        previous = Some(entry.id);
        total = total.add(entry_totals(entry, spec)?)?;
        at = next;
    }
    if at != used {
        return Err(CodecError::Length);
    }
    total.check()?;
    if total != declared || total != expected.totals {
        return Err(CodecError::Totals);
    }
    if expected
        .range
        .lower
        .is_some_and(|lower| first != Some(lower))
        || expected
            .range
            .upper
            .is_some_and(|upper| previous.is_some_and(|last| last >= upper))
    {
        return Err(CodecError::Range);
    }
    Ok(Page {
        bytes,
        spec,
        totals: total,
        count,
        used,
        range: expected.range,
    })
}
fn read_entry(
    bytes: &[u8],
    at: usize,
    used: usize,
    level: u8,
) -> Result<(Entry<'_>, usize), CodecError> {
    let key_start = at.checked_add(2).ok_or(CodecError::Overflow)?;
    if key_start > used {
        return Err(CodecError::Length);
    }
    let len = u16_at(bytes, at) as usize;
    let end = key_start.checked_add(len).ok_or(CodecError::Overflow)?;
    let next = end
        .checked_add(DESCRIPTOR_BYTES)
        .ok_or(CodecError::Overflow)?;
    if next > used {
        return Err(CodecError::Length);
    }
    let id = std::str::from_utf8(&bytes[key_start..end]).map_err(|_| CodecError::Name)?;
    check_id(id)?;
    let value = &bytes[end..next];
    let value = if level == 0 {
        if value[9..16].iter().any(|byte| *byte != 0) {
            return Err(CodecError::Padding);
        }
        let kind = match value[8] {
            0 => RecordKind::Live,
            1 => RecordKind::Archived,
            _ => return Err(CodecError::Kind),
        };
        Value::Leaf(Leaf {
            version: u64_at(value, 0),
            kind,
            object: OverflowRef {
                id: ObjectId::read(&value[16..40]),
                encoded_bytes: u64_at(value, 40),
                sha256: value[48..80].try_into().expect("fixed descriptor"),
            },
            semantic_bytes: u64_at(value, 80),
        })
    } else {
        Value::Child(Child {
            reference: PageRef {
                id: ObjectId::read(&value[..24]),
                sha256: value[24..56].try_into().expect("fixed descriptor"),
            },
            totals: Totals::read(&value[56..88]),
        })
    };
    Ok((Entry { id, value }, next))
}
fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().expect("checked fixed field"))
}
fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("checked fixed field"))
}

pub(crate) struct Entries<'a> {
    bytes: &'a [u8],
    at: usize,
    used: usize,
    level: u8,
    remaining: usize,
}
impl<'a> Iterator for Entries<'a> {
    type Item = Entry<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let (entry, at) = read_entry(self.bytes, self.at, self.used, self.level)
            .expect("validated immutable page");
        self.at = at;
        self.remaining -= 1;
        Some(entry)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}
impl ExactSizeIterator for Entries<'_> {}
impl<'a> Page<'a> {
    pub(crate) fn spec(&self) -> PageSpec {
        self.spec
    }
    pub(crate) fn totals(&self) -> Totals {
        self.totals
    }
    pub(crate) fn entries(&self) -> Entries<'a> {
        Entries {
            bytes: self.bytes,
            at: HEADER_BYTES,
            used: self.used,
            level: self.spec.level,
            remaining: self.count,
        }
    }
    pub(crate) fn lookup(&self, id: &str) -> Result<Option<Leaf>, CodecError> {
        self.successor(id, false).map(|entry| {
            entry
                .filter(|entry| entry.id == id)
                .map(|entry| match entry.value {
                    Value::Leaf(leaf) => leaf,
                    Value::Child(_) => unreachable!("leaf lookup"),
                })
        })
    }
    pub(crate) fn successor(
        &self,
        id: &str,
        exclusive: bool,
    ) -> Result<Option<Entry<'a>>, CodecError> {
        check_id(id)?;
        if self.spec.level != 0 {
            return Err(CodecError::Kind);
        }
        Ok(self
            .entries()
            .find(|entry| entry.id > id || (!exclusive && entry.id == id)))
    }
    /// Route below-minimum IDs to the first child, also supporting future edits.
    /// Loading that child still requires validate with the returned exact bounds.
    pub(crate) fn route(&self, id: &str) -> Result<ExpectedPage<'a>, CodecError> {
        check_id(id)?;
        if self.spec.level == 0 {
            return Err(CodecError::Kind);
        }
        let mut entries = self.entries();
        let mut selected = entries.next().expect("nonempty validated page");
        let mut upper = self.range.upper;
        for next in entries {
            if next.id > id {
                upper = Some(next.id);
                break;
            }
            selected = next;
        }
        let Value::Child(child) = selected.value else {
            unreachable!("branch page");
        };
        Ok(ExpectedPage {
            tree_id: self.spec.tree_id,
            reference: child.reference,
            generation_ceiling: self.spec.generation,
            level: self.spec.level - 1,
            totals: child.totals,
            range: KeyRange {
                lower: Some(selected.id),
                upper,
            },
        })
    }
}

#[cfg(test)]
#[path = "primary_tree_tests.rs"]
pub(crate) mod tests;

#[path = "primary_records.rs"]
pub(crate) mod records;

#[path = "primary_stage.rs"]
pub(crate) mod stage;

#[path = "primary_read.rs"]
pub(crate) mod read;
