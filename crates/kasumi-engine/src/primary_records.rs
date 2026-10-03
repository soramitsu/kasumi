//! Fixed primary selection and cleanup records. No I/O or ownership transfer.
//!
//! Physical decoding checks only local invariants. Publication must additionally
//! validate the exact producer, paired source, references, linked journals and
//! checked aggregate counters. These records do not establish serving authority.
use super::{
    CodecError, MAX_LEVEL, ObjectId, OverflowRef, PAGE_BYTES, PageRef, Totals, u16_at, u64_at,
};
use sha2::{Digest, Sha256};

pub(crate) const CATALOG_ENTRY_BYTES: usize = 160;
pub(crate) const MANIFEST_BYTES: usize = 260;
pub(crate) const SELECTOR_BYTES: usize = 220;
pub(crate) const GC_BYTES: usize = 64;
pub(crate) const EPOCH_BYTES: usize = 120;
pub(crate) const ATTEMPT_BYTES: usize = 160;
pub(crate) const INVENTORY_BYTES: usize = 160;
pub(crate) const RETIRE_BYTES: usize = 48;
pub(crate) const CHUNK_PAYLOAD_BYTES: u64 = 65_536;

type Uuid = [u8; 16];
type Hash = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CatalogId(pub(crate) ObjectId);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ManifestRef {
    pub(crate) id: ObjectId,
    pub(crate) sha256: Hash,
}
/// Exact point mapping under (CatalogId, collection-name hash), versioned by
/// the supplied native snapshot. It confers no publication/readiness authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CatalogEntry {
    pub(crate) catalog: CatalogId,
    pub(crate) scope: Hash,
    pub(crate) name_hash: Hash,
    pub(crate) manifest: ManifestRef,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Root {
    pub(crate) reference: PageRef,
    pub(crate) level: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Manifest {
    pub(crate) scope: Hash,
    pub(crate) name_hash: Hash,
    pub(crate) tree_id: Uuid,
    pub(crate) definition: OverflowRef,
    pub(crate) data_epoch: u64,
    pub(crate) revision: u64,
    pub(crate) root: Option<Root>,
    pub(crate) totals: Totals,
}

macro_rules! tags {
    ($name:ident { $($variant:ident = $value:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[repr(u8)]
        pub(crate) enum $name { $($variant = $value),+ }
        impl $name {
            fn read(value: u8) -> Result<Self, CodecError> {
                match value { $($value => Ok(Self::$variant),)+ _ => Err(CodecError::Kind) }
            }
        }
    };
}
tags!(Boundary { Bootstrap = 0, Entry = 1, Snapshot = 2 });
tags!(AttemptPhase { Building = 0, Prepared = 1, Committed = 2, Aborting = 3, Cleaning = 4 });
tags!(ResourceKind { Page = 0, Live = 1, Archived = 2, Definition = 3, CollectionManifest = 4, Catalog = 5 });
tags!(InventoryPhase { Allocating = 0, Complete = 1, Deleting = 2 });

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Selector {
    pub(crate) boundary: Boundary,
    pub(crate) scope: Hash,
    pub(crate) bootstrap_sha256: Hash,
    pub(crate) projection_epoch: Uuid,
    pub(crate) revision: u64,
    pub(crate) revision_base: u64,
    pub(crate) catalog: CatalogId,
    pub(crate) collection_count: u64,
    pub(crate) totals: Totals,
    pub(crate) activation_attempt: Uuid,
    pub(crate) boundary_digest: Hash,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GcState {
    pub(crate) current: Option<Uuid>,
    pub(crate) building: Option<Uuid>,
    pub(crate) retired: Option<Uuid>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Epoch {
    pub(crate) scope: Hash,
    pub(crate) id: Uuid,
    pub(crate) head: Option<Uuid>,
    pub(crate) tail: Option<Uuid>,
    pub(crate) pending: Option<Uuid>,
    pub(crate) live_resources: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Attempt {
    pub(crate) phase: AttemptPhase,
    pub(crate) scope: Hash,
    pub(crate) epoch: Uuid,
    pub(crate) id: Uuid,
    pub(crate) previous: Option<Uuid>,
    pub(crate) next: Option<Uuid>,
    pub(crate) next_object: u64,
    pub(crate) live_resources: u64,
    pub(crate) retire_count: u64,
    pub(crate) abort_object_cursor: u64,
    pub(crate) retire_cursor: u64,
    /// Flat inventory ordinals, then retire ordinals. Outcome eligibility is
    /// additionally checked by cleanup against the durable committed marker.
    pub(crate) journal_erase_cursor: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Inventory {
    pub(crate) kind: ResourceKind,
    pub(crate) phase: InventoryPhase,
    pub(crate) scope: Hash,
    pub(crate) id: ObjectId,
    pub(crate) tree_id: Uuid,
    pub(crate) encoded_bytes: u64,
    pub(crate) sha256: Hash,
    pub(crate) total_units: u64,
    pub(crate) completed_units: u64,
    pub(crate) cleanup_unit_cursor: u64,
    pub(crate) catalog_dense_count: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Retire {
    pub(crate) target: ObjectId,
}

// Every encoder checks before writing: refusal leaves caller storage unchanged.
macro_rules! fixed_record {
    ($name:ident, $size:ident, $magic:literal) => {
        impl $name {
            pub(crate) fn encode(self, out: &mut [u8]) -> Result<(), CodecError> {
                if out.len() != $size {
                    return Err(CodecError::Length);
                }
                self.check()?;
                out.fill(0);
                out[..8].copy_from_slice($magic);
                out[8..10].copy_from_slice(&1_u16.to_le_bytes());
                self.write(out);
                Ok(())
            }
            pub(crate) fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
                if bytes.len() != $size {
                    return Err(CodecError::Length);
                }
                if &bytes[..8] != $magic || u16_at(bytes, 8) != 1 {
                    return Err(CodecError::Format);
                }
                let value = Self::read(bytes)?;
                value.check()?;
                Ok(value)
            }
        }
    };
}
fixed_record!(CatalogEntry, CATALOG_ENTRY_BYTES, b"KSPCAT01");
fixed_record!(Manifest, MANIFEST_BYTES, b"KSPCOL01");
fixed_record!(Selector, SELECTOR_BYTES, b"KSPSEL01");
fixed_record!(GcState, GC_BYTES, b"KSPGC001");
fixed_record!(Epoch, EPOCH_BYTES, b"KSPEPC01");
fixed_record!(Attempt, ATTEMPT_BYTES, b"KSPATT01");
fixed_record!(Inventory, INVENTORY_BYTES, b"KSPINV01");
fixed_record!(Retire, RETIRE_BYTES, b"KSPRET01");

fn uuid(id: Uuid) -> Result<(), CodecError> {
    if id == [0; 16] {
        Err(CodecError::Identity)
    } else {
        Ok(())
    }
}
fn optional(id: Option<Uuid>) -> Result<(), CodecError> {
    id.map_or(Ok(()), uuid)
}
fn zero(bytes: &[u8]) -> Result<(), CodecError> {
    if bytes.iter().any(|byte| *byte != 0) {
        Err(CodecError::Padding)
    } else {
        Ok(())
    }
}
fn array<const N: usize>(bytes: &[u8], at: usize) -> [u8; N] {
    bytes[at..at + N].try_into().expect("checked fixed record")
}
fn put_u64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn read_optional(bytes: &[u8], at: usize, present: bool) -> Result<Option<Uuid>, CodecError> {
    let id = array(bytes, at);
    if present {
        uuid(id)?;
        Ok(Some(id))
    } else {
        zero(&id)?;
        Ok(None)
    }
}
fn write_optional(bytes: &mut [u8], at: usize, id: Option<Uuid>) {
    if let Some(id) = id {
        bytes[at..at + 16].copy_from_slice(&id);
    }
}
fn journal_header(bytes: &[u8], mask: u8) -> Result<(), CodecError> {
    if bytes[11] & !mask != 0 {
        return Err(CodecError::Padding);
    }
    zero(&bytes[12..16])
}
fn aggregate(totals: Totals) -> Result<(), CodecError> {
    if totals == Totals::default() {
        Ok(())
    } else {
        totals.check()
    }
}
fn read_page_ref(bytes: &[u8]) -> PageRef {
    PageRef {
        id: ObjectId::read(&bytes[..24]),
        sha256: array(bytes, 24),
    }
}
fn write_page_ref(bytes: &mut [u8], reference: PageRef) {
    reference.id.write(&mut bytes[..24]);
    bytes[24..56].copy_from_slice(&reference.sha256);
}

impl CatalogEntry {
    fn check(self) -> Result<(), CodecError> {
        self.catalog.0.check()?;
        self.manifest.id.check()
    }
    fn read(bytes: &[u8]) -> Result<Self, CodecError> {
        zero(&bytes[10..16])?;
        Ok(Self {
            catalog: CatalogId(ObjectId::read(&bytes[16..40])),
            scope: array(bytes, 40),
            name_hash: array(bytes, 72),
            manifest: ManifestRef {
                id: ObjectId::read(&bytes[104..128]),
                sha256: array(bytes, 128),
            },
        })
    }
    fn write(self, bytes: &mut [u8]) {
        self.catalog.0.write(&mut bytes[16..40]);
        bytes[40..72].copy_from_slice(&self.scope);
        bytes[72..104].copy_from_slice(&self.name_hash);
        self.manifest.id.write(&mut bytes[104..128]);
        bytes[128..160].copy_from_slice(&self.manifest.sha256);
    }
    pub(crate) fn key(catalog: CatalogId, name_hash: Hash) -> [u8; 56] {
        let mut key = [0; 56];
        catalog.0.write(&mut key[..24]);
        key[24..].copy_from_slice(&name_hash);
        key
    }
}

impl Manifest {
    fn check(self) -> Result<(), CodecError> {
        uuid(self.tree_id)?;
        self.definition.id.check()?;
        if self.definition.encoded_bytes == 0 {
            return Err(CodecError::Length);
        }
        if self.data_epoch > self.revision {
            return Err(CodecError::Version);
        }
        if let Some(root) = self.root {
            root.reference.id.check()?;
            if root.level > MAX_LEVEL {
                return Err(CodecError::Level);
            }
            self.totals.check()?;
        } else if self.totals != Totals::default() {
            return Err(CodecError::Totals);
        }
        Ok(())
    }
    fn read(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes[10] & !1 != 0 {
            return Err(CodecError::Padding);
        }
        let root = if bytes[10] == 1 {
            Some(Root {
                reference: read_page_ref(&bytes[172..228]),
                level: bytes[11],
            })
        } else {
            zero(&bytes[11..12])?;
            zero(&bytes[172..228])?;
            None
        };
        Ok(Self {
            scope: array(bytes, 12),
            name_hash: array(bytes, 44),
            tree_id: array(bytes, 76),
            definition: OverflowRef {
                id: ObjectId::read(&bytes[92..116]),
                encoded_bytes: u64_at(bytes, 116),
                sha256: array(bytes, 124),
            },
            data_epoch: u64_at(bytes, 156),
            revision: u64_at(bytes, 164),
            root,
            totals: Totals::read(&bytes[228..260]),
        })
    }
    fn write(self, out: &mut [u8]) {
        out[12..44].copy_from_slice(&self.scope);
        out[44..76].copy_from_slice(&self.name_hash);
        out[76..92].copy_from_slice(&self.tree_id);
        self.definition.id.write(&mut out[92..116]);
        put_u64(out, 116, self.definition.encoded_bytes);
        out[124..156].copy_from_slice(&self.definition.sha256);
        put_u64(out, 156, self.data_epoch);
        put_u64(out, 164, self.revision);
        if let Some(root) = self.root {
            out[10] = 1;
            out[11] = root.level;
            write_page_ref(&mut out[172..228], root.reference);
        }
        self.totals.write(&mut out[228..260]);
    }
    pub(crate) fn validate_context(
        self,
        scope: Hash,
        name_hash: Hash,
        revision: u64,
    ) -> Result<(), CodecError> {
        if self.scope != scope || self.name_hash != name_hash {
            return Err(CodecError::Identity);
        }
        if self.revision > revision {
            return Err(CodecError::Version);
        }
        Ok(())
    }
    /// The caller selects the exact ObjectId key and checks it before invoking
    /// this. A matching hash does not prove the referenced definition/root.
    pub(crate) fn decode_referenced(
        bytes: &[u8],
        reference: ManifestRef,
    ) -> Result<Self, CodecError> {
        reference.id.check()?;
        let value = Self::decode(bytes)?;
        if <Hash>::from(Sha256::digest(bytes)) != reference.sha256 {
            return Err(CodecError::Digest);
        }
        Ok(value)
    }
}
impl Selector {
    fn check(self) -> Result<(), CodecError> {
        uuid(self.projection_epoch)?;
        uuid(self.activation_attempt)?;
        self.catalog.0.check()?;
        if self.revision_base > self.revision {
            return Err(CodecError::Version);
        }
        aggregate(self.totals)?;
        if self.collection_count == 0 && self.totals != Totals::default() {
            return Err(CodecError::Totals);
        }
        // Bootstrap is exactly the authenticated initial application revision.
        if self.boundary == Boundary::Bootstrap {
            if self.revision != self.revision_base {
                return Err(CodecError::Version);
            }
            if self.boundary_digest != self.bootstrap_sha256 {
                return Err(CodecError::Digest);
            }
        }
        Ok(())
    }
    fn read(bytes: &[u8]) -> Result<Self, CodecError> {
        zero(&bytes[10..11])?;
        Ok(Self {
            boundary: Boundary::read(bytes[11])?,
            scope: array(bytes, 12),
            bootstrap_sha256: array(bytes, 44),
            projection_epoch: array(bytes, 76),
            revision: u64_at(bytes, 92),
            revision_base: u64_at(bytes, 100),
            catalog: CatalogId(ObjectId::read(&bytes[108..132])),
            collection_count: u64_at(bytes, 132),
            totals: Totals::read(&bytes[140..172]),
            activation_attempt: array(bytes, 172),
            boundary_digest: array(bytes, 188),
        })
    }
    fn write(self, out: &mut [u8]) {
        out[11] = self.boundary as u8;
        out[12..44].copy_from_slice(&self.scope);
        out[44..76].copy_from_slice(&self.bootstrap_sha256);
        out[76..92].copy_from_slice(&self.projection_epoch);
        put_u64(out, 92, self.revision);
        put_u64(out, 100, self.revision_base);
        self.catalog.0.write(&mut out[108..132]);
        put_u64(out, 132, self.collection_count);
        self.totals.write(&mut out[140..172]);
        out[172..188].copy_from_slice(&self.activation_attempt);
        out[188..220].copy_from_slice(&self.boundary_digest);
    }
}
impl GcState {
    fn check(self) -> Result<(), CodecError> {
        optional(self.current)?;
        optional(self.building)?;
        optional(self.retired)?;
        if self.building.is_some() && self.retired.is_some() {
            return Err(CodecError::Range);
        }
        if self.retired.is_some() && self.current.is_none() {
            return Err(CodecError::Identity);
        }
        if self.current.is_some() && (self.current == self.building || self.current == self.retired)
        {
            return Err(CodecError::Identity);
        }
        Ok(())
    }
    fn read(bytes: &[u8]) -> Result<Self, CodecError> {
        zero(&bytes[10..11])?;
        journal_header(bytes, 7)?;
        Ok(Self {
            current: read_optional(bytes, 16, bytes[11] & 1 != 0)?,
            building: read_optional(bytes, 32, bytes[11] & 2 != 0)?,
            retired: read_optional(bytes, 48, bytes[11] & 4 != 0)?,
        })
    }
    fn write(self, out: &mut [u8]) {
        out[11] = u8::from(self.current.is_some())
            | (u8::from(self.building.is_some()) << 1)
            | (u8::from(self.retired.is_some()) << 2);
        write_optional(out, 16, self.current);
        write_optional(out, 32, self.building);
        write_optional(out, 48, self.retired);
    }
}
impl Epoch {
    fn check(self) -> Result<(), CodecError> {
        uuid(self.id)?;
        optional(self.head)?;
        optional(self.tail)?;
        optional(self.pending)?;
        if self.head.is_some() != self.tail.is_some() {
            return Err(CodecError::Identity);
        }
        if self.head.is_none() && (self.pending.is_some() || self.live_resources != 0) {
            return Err(CodecError::Range);
        }
        Ok(())
    }
    fn read(bytes: &[u8]) -> Result<Self, CodecError> {
        zero(&bytes[10..11])?;
        journal_header(bytes, 7)?;
        Ok(Self {
            scope: array(bytes, 16),
            id: array(bytes, 48),
            head: read_optional(bytes, 64, bytes[11] & 1 != 0)?,
            tail: read_optional(bytes, 80, bytes[11] & 2 != 0)?,
            pending: read_optional(bytes, 96, bytes[11] & 4 != 0)?,
            live_resources: u64_at(bytes, 112),
        })
    }
    fn write(self, out: &mut [u8]) {
        out[11] = u8::from(self.head.is_some())
            | (u8::from(self.tail.is_some()) << 1)
            | (u8::from(self.pending.is_some()) << 2);
        out[16..48].copy_from_slice(&self.scope);
        out[48..64].copy_from_slice(&self.id);
        write_optional(out, 64, self.head);
        write_optional(out, 80, self.tail);
        write_optional(out, 96, self.pending);
        put_u64(out, 112, self.live_resources);
    }
}
impl Attempt {
    fn check(self) -> Result<(), CodecError> {
        uuid(self.epoch)?;
        uuid(self.id)?;
        optional(self.previous)?;
        optional(self.next)?;
        if self.previous == Some(self.id)
            || self.next == Some(self.id)
            || (self.previous.is_some() && self.previous == self.next)
        {
            return Err(CodecError::Identity);
        }
        let erase_end = self
            .next_object
            .checked_add(self.retire_count)
            .ok_or(CodecError::Overflow)?;
        if self.live_resources > self.next_object
            || self.abort_object_cursor > self.next_object
            || self.retire_cursor > self.retire_count
            || self.journal_erase_cursor > erase_end
        {
            return Err(CodecError::Range);
        }
        // Outcome resolution and phase-transition eligibility are cross-record
        // checks; this codec only forbids erasing known live resources.
        if self.journal_erase_cursor != 0 && self.live_resources != 0 {
            return Err(CodecError::Range);
        }
        Ok(())
    }
    fn read(bytes: &[u8]) -> Result<Self, CodecError> {
        journal_header(bytes, 3)?;
        Ok(Self {
            phase: AttemptPhase::read(bytes[10])?,
            scope: array(bytes, 16),
            epoch: array(bytes, 48),
            id: array(bytes, 64),
            previous: read_optional(bytes, 80, bytes[11] & 1 != 0)?,
            next: read_optional(bytes, 96, bytes[11] & 2 != 0)?,
            next_object: u64_at(bytes, 112),
            live_resources: u64_at(bytes, 120),
            retire_count: u64_at(bytes, 128),
            abort_object_cursor: u64_at(bytes, 136),
            retire_cursor: u64_at(bytes, 144),
            journal_erase_cursor: u64_at(bytes, 152),
        })
    }
    fn write(self, out: &mut [u8]) {
        out[10] = self.phase as u8;
        out[11] = u8::from(self.previous.is_some()) | (u8::from(self.next.is_some()) << 1);
        out[16..48].copy_from_slice(&self.scope);
        out[48..64].copy_from_slice(&self.epoch);
        out[64..80].copy_from_slice(&self.id);
        write_optional(out, 80, self.previous);
        write_optional(out, 96, self.next);
        for (at, value) in [
            self.next_object,
            self.live_resources,
            self.retire_count,
            self.abort_object_cursor,
            self.retire_cursor,
            self.journal_erase_cursor,
        ]
        .into_iter()
        .enumerate()
        {
            put_u64(out, 112 + 8 * at, value);
        }
    }
}
/// Division-first ceiling avoids imposing a false limit near u64::MAX.
pub(crate) fn chunk_count(encoded_bytes: u64) -> Result<u64, CodecError> {
    if encoded_bytes == 0 {
        return Err(CodecError::Length);
    }
    Ok(encoded_bytes / CHUNK_PAYLOAD_BYTES
        + u64::from(!encoded_bytes.is_multiple_of(CHUNK_PAYLOAD_BYTES)))
}
impl Inventory {
    fn check(self) -> Result<(), CodecError> {
        self.id.check()?;
        if self.completed_units > self.total_units
            || self.cleanup_unit_cursor > self.completed_units
        {
            return Err(CodecError::Range);
        }
        if self.phase == InventoryPhase::Complete && self.completed_units != self.total_units {
            return Err(CodecError::Range);
        }
        if self.phase != InventoryPhase::Deleting && self.cleanup_unit_cursor != 0 {
            return Err(CodecError::Range);
        }
        if self.kind == ResourceKind::Catalog {
            if self.tree_id != [0; 16] || self.encoded_bytes != 0 || self.sha256 != [0; 32] {
                return Err(CodecError::Padding);
            }
            if self.catalog_dense_count != self.total_units {
                return Err(CodecError::Range);
            }
        } else {
            uuid(self.tree_id)?;
            if self.catalog_dense_count != 0 {
                return Err(CodecError::Padding);
            }
            let units = match self.kind {
                ResourceKind::Page => {
                    if self.encoded_bytes != PAGE_BYTES as u64 {
                        return Err(CodecError::Length);
                    }
                    1
                }
                ResourceKind::CollectionManifest => {
                    if self.encoded_bytes != MANIFEST_BYTES as u64 {
                        return Err(CodecError::Length);
                    }
                    1
                }
                ResourceKind::Live | ResourceKind::Archived | ResourceKind::Definition => {
                    chunk_count(self.encoded_bytes)?
                }
                ResourceKind::Catalog => unreachable!("separate catalog branch"),
            };
            if self.total_units != units {
                return Err(CodecError::Range);
            }
        }
        Ok(())
    }
    fn read(bytes: &[u8]) -> Result<Self, CodecError> {
        zero(&bytes[12..16])?;
        Ok(Self {
            kind: ResourceKind::read(bytes[10])?,
            phase: InventoryPhase::read(bytes[11])?,
            scope: array(bytes, 16),
            id: ObjectId::read(&bytes[48..72]),
            tree_id: array(bytes, 72),
            encoded_bytes: u64_at(bytes, 88),
            sha256: array(bytes, 96),
            total_units: u64_at(bytes, 128),
            completed_units: u64_at(bytes, 136),
            cleanup_unit_cursor: u64_at(bytes, 144),
            catalog_dense_count: u64_at(bytes, 152),
        })
    }
    fn write(self, out: &mut [u8]) {
        out[10] = self.kind as u8;
        out[11] = self.phase as u8;
        out[16..48].copy_from_slice(&self.scope);
        self.id.write(&mut out[48..72]);
        out[72..88].copy_from_slice(&self.tree_id);
        put_u64(out, 88, self.encoded_bytes);
        out[96..128].copy_from_slice(&self.sha256);
        for (at, value) in [
            self.total_units,
            self.completed_units,
            self.cleanup_unit_cursor,
            self.catalog_dense_count,
        ]
        .into_iter()
        .enumerate()
        {
            put_u64(out, 128 + 8 * at, value);
        }
    }
}
impl Retire {
    fn check(self) -> Result<(), CodecError> {
        self.target.check()
    }
    fn read(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes[10] != 0 {
            return Err(CodecError::Kind);
        }
        zero(&bytes[11..16])?;
        zero(&bytes[40..48])?;
        Ok(Self {
            target: ObjectId::read(&bytes[16..40]),
        })
    }
    fn write(self, out: &mut [u8]) {
        self.target.write(&mut out[16..40]);
    }
}

/// Length-prefix hashing preserves boundaries without temporary concatenation.
/// Names and tenant/incarnation identities still require existing validation.
pub(crate) fn scope_hash(
    tenant: &str,
    incarnation: &str,
    bootstrap: Hash,
) -> Result<Hash, CodecError> {
    let tenant_len = u32::try_from(tenant.len()).map_err(|_| CodecError::Length)?;
    let incarnation_len = u32::try_from(incarnation.len()).map_err(|_| CodecError::Length)?;
    let mut hash = Sha256::new();
    hash.update(b"kasumi.primary.scope.v1\0");
    hash.update(tenant_len.to_le_bytes());
    hash.update(tenant.as_bytes());
    hash.update(incarnation_len.to_le_bytes());
    hash.update(incarnation.as_bytes());
    hash.update(bootstrap);
    Ok(hash.finalize().into())
}
pub(crate) fn name_hash(name: &str) -> Result<Hash, CodecError> {
    let len = u32::try_from(name.len()).map_err(|_| CodecError::Length)?;
    let mut hash = Sha256::new();
    hash.update(b"kasumi.primary.collection.v1\0");
    hash.update(len.to_le_bytes());
    hash.update(name.as_bytes());
    Ok(hash.finalize().into())
}

#[path = "primary_boundary.rs"]
pub(crate) mod boundary;

#[path = "primary_catalog_records.rs"]
mod catalog;
pub(crate) use catalog::{CATALOG_MEMBER_BYTES, CatalogMember};
