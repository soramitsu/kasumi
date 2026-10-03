//! Replayable lending inputs for private index preparation. These contracts
//! carry no client cancellation: an ordered mutation cannot be canceled by its
//! original caller. Sources retain/admit their own row or pair workspace.
use crate::{QueryIndexes, ReadResult, Record, SourceIdentity};
use kasumi_types::{CollectionDefinition, Error, ErrorCode, Result, validate_name};
use sha2::{Digest, Sha256};
use std::{cell::RefCell, io};

pub trait CollectionRecords {
    type Failure: std::error::Error + Send + Sync + 'static;
    fn identity(&self) -> SourceIdentity<'_>;
    fn definition(&self) -> &CollectionDefinition;
    /// Strictly increasing unique logical IDs, replayable at the exact bound
    /// view. A verified hydrated body replaces its archive reference once.
    fn visit_records(
        &self,
        lend: impl for<'a> FnMut(&'a str, Record<'a>) -> Result<()>,
    ) -> ReadResult<(), Self::Failure>;
}

#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct DocumentDelta<'a> {
    pub id: &'a str,
    pub old: Option<Record<'a>>,
    pub new: Option<Record<'a>>,
}
pub trait DocumentChanges {
    type Failure: std::error::Error + Send + Sync + 'static;
    fn old_identity(&self) -> SourceIdentity<'_>;
    fn new_identity(&self) -> SourceIdentity<'_>;
    fn old_definition(&self) -> &CollectionDefinition;
    fn new_definition(&self) -> &CollectionDefinition;
    fn indexes(&self) -> &QueryIndexes;
    /// The mutation producer supplies every changed ID exactly once, in order.
    /// Repeated operations resolve to one old/final-new pair. Every replay must
    /// lend the same complete sequence while retaining these exact owners.
    fn visit_changes(
        &self,
        lend: impl for<'a> FnMut(DocumentDelta<'a>) -> Result<()>,
    ) -> ReadResult<(), Self::Failure>;
}

pub enum IndexUpdate<'a, R, D> {
    Rebuild(R),
    Delta(D),
    Remove(&'a str),
    Unchanged(&'a str),
}

fn corrupt(message: &'static str) -> Error {
    Error::new(ErrorCode::Corruption, message)
}

/// A fixed stack continuation validates ordering without retaining all IDs.
struct Order {
    last: [u8; 256],
    len: usize,
}
impl Order {
    fn new() -> Self {
        Self {
            last: [0; 256],
            len: 0,
        }
    }
    fn row(&mut self, id: &str, record: Option<Record<'_>>) -> Result<()> {
        validate_name(id)?;
        if self.len != 0 && self.last[..self.len] >= *id.as_bytes() {
            return Err(corrupt("index input IDs are not strictly ordered"));
        }
        if let Some(record) = record {
            check_record(id, record)?;
        }
        self.last[..id.len()].copy_from_slice(id.as_bytes());
        self.len = id.len();
        Ok(())
    }
}
fn check_record(id: &str, record: Record<'_>) -> Result<()> {
    // Version zero is valid in restored sources. Revision/epoch bounds belong
    // to the exact source; this generic adapter checks identity and replay.
    if matches!(record, Record::Live(document) if document.id != id) {
        return Err(corrupt("index input record identity differs"));
    }
    Ok(())
}
fn record_header(record: Option<Record<'_>>) -> Option<(u8, u64)> {
    record.map(|record| {
        (
            match record {
                Record::Live(_) => 0,
                Record::Archived(_) => 1,
            },
            record.version(),
        )
    })
}
// Identity/version replay proofs are bounded metadata. Immutable payload bytes
// remain the source's responsibility; preparation does not rehash whole bodies.
struct Proof(Sha256);
impl io::Write for Proof {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Proof {
    fn new() -> Self {
        Self(Sha256::new())
    }
    fn row(&mut self, row: &impl serde::Serialize) -> Result<()> {
        serde_json::to_writer(&mut *self, row)
            .map_err(|_| corrupt("index input proof encoding failed"))?;
        self.0.update(*b"\n");
        Ok(())
    }
    fn finish(self, previous: &RefCell<Option<[u8; 32]>>) -> Result<()> {
        let digest: [u8; 32] = self.0.finalize().into();
        let mut previous = previous.borrow_mut();
        if previous.as_ref().is_some_and(|old| *old != digest) {
            return Err(corrupt("index input changed between preparation passes"));
        }
        *previous = Some(digest);
        Ok(())
    }
}

pub(crate) struct CheckedRecords<'a, R: CollectionRecords + ?Sized> {
    source: &'a R,
    identity: SourceIdentity<'a>,
    definition: &'a CollectionDefinition,
    proof: RefCell<Option<[u8; 32]>>,
}
impl<'a, R: CollectionRecords + ?Sized> CheckedRecords<'a, R> {
    pub(crate) fn new(source: &'a R) -> Result<Self> {
        let identity = source.identity();
        let definition = source.definition();
        if identity.collection() != definition.name {
            return Err(corrupt("index collection source identity differs"));
        }
        Ok(Self {
            source,
            identity,
            definition,
            proof: RefCell::new(None),
        })
    }
    fn check(&self) -> Result<()> {
        if self.source.identity() != self.identity
            || !same_definition(self.source.definition(), self.definition)
        {
            return Err(corrupt("index collection view changed"));
        }
        Ok(())
    }
}
impl<R: CollectionRecords + ?Sized> CollectionRecords for CheckedRecords<'_, R> {
    type Failure = R::Failure;
    fn identity(&self) -> SourceIdentity<'_> {
        self.identity
    }
    fn definition(&self) -> &CollectionDefinition {
        self.definition
    }
    fn visit_records(
        &self,
        mut lend: impl for<'a> FnMut(&'a str, Record<'a>) -> Result<()>,
    ) -> ReadResult<(), Self::Failure> {
        self.check()?;
        let mut order = Order::new();
        let mut proof = Proof::new();
        self.source.visit_records(|id, record| {
            self.check()?;
            order.row(id, Some(record))?;
            proof.row(&(id, record_header(Some(record))))?;
            lend(id, record)
        })?;
        self.check()?;
        proof.finish(&self.proof)?;
        Ok(())
    }
}

pub(crate) struct CheckedChanges<'a, D: DocumentChanges + ?Sized> {
    source: &'a D,
    old: SourceIdentity<'a>,
    new: SourceIdentity<'a>,
    indexes: &'a QueryIndexes,
    old_definition: &'a CollectionDefinition,
    new_definition: &'a CollectionDefinition,
    proof: RefCell<Option<[u8; 32]>>,
}
impl<'a, D: DocumentChanges + ?Sized> CheckedChanges<'a, D> {
    pub(crate) fn new(source: &'a D) -> Result<Self> {
        let old = source.old_identity();
        let new = source.new_identity();
        let old_definition = source.old_definition();
        let new_definition = source.new_definition();
        let indexes = source.indexes();
        if old.tenant() != new.tenant()
            || old.incarnation() != new.incarnation()
            || old.collection() != new.collection()
            || old.collection() != old_definition.name
            || new.collection() != new_definition.name
            || !same_definition(old_definition, new_definition)
        {
            return Err(corrupt(
                "index delta scope or definition differs; rebuild required",
            ));
        }
        Ok(Self {
            source,
            old,
            new,
            indexes,
            old_definition,
            new_definition,
            proof: RefCell::new(None),
        })
    }
    fn check(&self) -> Result<()> {
        if !std::ptr::eq(self.indexes, self.source.indexes())
            || self.old != self.source.old_identity()
            || self.new != self.source.new_identity()
            || !same_definition(self.old_definition, self.source.old_definition())
            || !same_definition(self.new_definition, self.source.new_definition())
        {
            return Err(corrupt("index delta view changed"));
        }
        Ok(())
    }
}
impl<D: DocumentChanges + ?Sized> DocumentChanges for CheckedChanges<'_, D> {
    type Failure = D::Failure;
    fn old_identity(&self) -> SourceIdentity<'_> {
        self.old
    }
    fn new_identity(&self) -> SourceIdentity<'_> {
        self.new
    }
    fn old_definition(&self) -> &CollectionDefinition {
        self.old_definition
    }
    fn new_definition(&self) -> &CollectionDefinition {
        self.new_definition
    }
    fn indexes(&self) -> &QueryIndexes {
        self.indexes
    }
    fn visit_changes(
        &self,
        mut lend: impl for<'a> FnMut(DocumentDelta<'a>) -> Result<()>,
    ) -> ReadResult<(), Self::Failure> {
        self.check()?;
        let mut order = Order::new();
        let mut proof = Proof::new();
        self.source.visit_changes(|delta| {
            self.check()?;
            order.row(delta.id, delta.old)?;
            if let Some(new) = delta.new {
                check_record(delta.id, new)?;
            }
            proof.row(&(delta.id, record_header(delta.old), record_header(delta.new)))?;
            lend(delta)
        })?;
        self.check()?;
        proof.finish(&self.proof)?;
        Ok(())
    }
}

pub(crate) fn definition_sha256(definition: &CollectionDefinition) -> Result<[u8; 32]> {
    let mut proof = Proof::new();
    proof.row(definition)?;
    Ok(proof.0.finalize().into())
}

fn same_definition(left: &CollectionDefinition, right: &CollectionDefinition) -> bool {
    std::ptr::eq(left, right) || left == right
}
