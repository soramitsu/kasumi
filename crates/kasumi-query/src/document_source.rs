//! Collection-scoped, version-consistent lending reads.
//!
//! Sources retain their exact selected view. A loan cannot escape its callback;
//! disk implementations own decoded workspace and admission through that loan.
use crate::QueryCancellation;
use kasumi_types::{ArchivedDocument, CollectionDefinition, Document, Error, ErrorCode};
use std::{any::Any, convert::Infallible, fmt};

#[derive(Clone, Copy)]
pub struct SourceIdentity<'a> {
    owner: &'a dyn Any,
    tenant: &'a str,
    incarnation: &'a str,
    collection: &'a str,
}
impl<'a> SourceIdentity<'a> {
    /// Borrow the actual retained owner, never a numeric revision or address
    /// supplied independently of that owner. Zero-sized markers are not owners.
    pub fn new<T: 'static>(
        owner: &'a T,
        tenant: &'a str,
        incarnation: &'a str,
        collection: &'a str,
    ) -> Self {
        assert!(
            std::mem::size_of::<T>() != 0,
            "source owner must have a distinct allocation"
        );
        Self {
            owner,
            tenant,
            incarnation,
            collection,
        }
    }
    pub fn tenant(self) -> &'a str {
        self.tenant
    }
    pub fn incarnation(self) -> &'a str {
        self.incarnation
    }
    pub fn collection(self) -> &'a str {
        self.collection
    }
}
impl PartialEq for SourceIdentity<'_> {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(
            self.owner as *const dyn Any as *const (),
            other.owner as *const dyn Any as *const (),
        ) && self.owner.type_id() == other.owner.type_id()
            && self.tenant == other.tenant
            && self.incarnation == other.incarnation
            && self.collection == other.collection
    }
}
impl Eq for SourceIdentity<'_> {}
impl fmt::Debug for SourceIdentity<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SourceIdentity")
            .field("tenant", &self.tenant)
            .field("incarnation", &self.incarnation)
            .field("collection", &self.collection)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordKind {
    Live,
    Archived,
}
#[derive(Debug, Clone, Copy)]
pub struct Header<'a> {
    pub id: &'a str,
    pub version: u64,
    pub kind: RecordKind,
}
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub enum Record<'a> {
    Live(&'a Document),
    Archived(&'a ArchivedDocument),
}
impl Record<'_> {
    pub fn version(self) -> u64 {
        match self {
            Self::Live(record) => record.version,
            Self::Archived(record) => record.version,
        }
    }
}

/// The original source error stays owned; it is never converted into a wire
/// message. Production workers with fallible sources must retain this custody
/// independently of a canceled waiter and acknowledge explicit view cleanup.
#[derive(Debug)]
pub enum ReadFailure<E> {
    Query(Error),
    Source(E),
}
pub type ReadResult<T, E> = std::result::Result<T, ReadFailure<E>>;
impl<E> From<Error> for ReadFailure<E> {
    fn from(error: Error) -> Self {
        Self::Query(error)
    }
}
impl<E: fmt::Display> fmt::Display for ReadFailure<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Query(error) => fmt::Display::fmt(error, f),
            Self::Source(error) => fmt::Display::fmt(error, f),
        }
    }
}
impl<E: std::error::Error + 'static> std::error::Error for ReadFailure<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match self {
            Self::Query(error) => error,
            Self::Source(error) => error,
        })
    }
}
impl ReadFailure<Infallible> {
    /// Available only when the adapter cannot own a storage/close failure.
    pub fn into_query_error(self) -> Error {
        match self {
            Self::Query(error) => error,
            Self::Source(never) => match never {},
        }
    }
}

pub trait DocumentSource: crate::CollectionRecords {
    /// Indexes captured with this exact source, including verified hydration.
    fn indexes(&self) -> &crate::QueryIndexes;
    /// Visit the authenticated primary headers in increasing ID order.
    /// A source without a selected header directory returns false before lending.
    fn visit_primary_ids(
        &self,
        _cancellation: &QueryCancellation,
        _lend: impl FnMut(&str) -> kasumi_types::Result<()>,
    ) -> ReadResult<bool, Self::Failure> {
        Ok(false)
    }
    /// Visit one field's ordered postings if this exact
    /// generation has published them. An unsupported layout returns false
    /// before lending any IDs. An installed but unreadable index returns an error.
    fn visit_field_posting(
        &self,
        _field: usize,
        _predicate: crate::FieldPredicate<'_>,
        _cancellation: &QueryCancellation,
        _lend: impl FnMut(&str) -> kasumi_types::Result<()>,
    ) -> ReadResult<bool, Self::Failure> {
        Ok(false)
    }
    fn has_ordered_unique_source(&self) -> bool {
        false
    }
    /// A selected checkpoint with every compound tuple in complete order.
    fn ranked_compound_count(
        &self,
        _index: usize,
        _cancellation: &QueryCancellation,
    ) -> ReadResult<Option<u64>, Self::Failure> {
        Ok(None)
    }
    /// Read up to `ORDERED_TUPLE_WINDOW` consecutive owners from `[start, end)`.
    /// Begin at `start` when ascending and `end - 1` when descending. A
    /// nonempty interval in a selected ranked index must return an owner.
    fn ranked_compound_window(
        &self,
        _index: usize,
        _start: u64,
        _end: u64,
        _descending: bool,
        _cancellation: &QueryCancellation,
    ) -> ReadResult<Option<Vec<crate::RankedOwner>>, Self::Failure> {
        Ok(None)
    }
    /// Return at most one window of representable compound tuples in native order.
    /// The planner merges longer keys from the same generation into that order.
    /// None means the directory is absent at this generation before any row
    /// was returned. Installed page failures keep their original owner.
    fn ordered_unique_window(
        &self,
        _index: usize,
        _lower: std::ops::Bound<&[u8]>,
        _upper: std::ops::Bound<&[u8]>,
        _descending: bool,
        _cancellation: &QueryCancellation,
    ) -> ReadResult<Option<crate::OrderedTupleWindow>, Self::Failure> {
        Ok(None)
    }
    /// Lend this exact generation's persisted text shards for the source's
    /// collection. `Ok(None)` when no directory is current at this generation;
    /// a directory that is selected but unreadable returns an error.
    fn with_text_shards<T>(
        &self,
        _search: impl FnOnce(&dyn crate::TextShardSet) -> kasumi_types::Result<T>,
    ) -> ReadResult<Option<T>, Self::Failure> {
        Ok(None)
    }
    /// Check cancellation before/after read work and immediately before lending.
    /// An expected version requires presence and an exact version match.
    fn with_record<T>(
        &self,
        id: &str,
        expected_version: Option<u64>,
        cancellation: &QueryCancellation,
        lend: impl for<'a> FnOnce(Option<Record<'a>>) -> kasumi_types::Result<T>,
    ) -> ReadResult<T, Self::Failure>;
    /// Lend the first logical ID strictly after the bound, in stable ID order.
    /// Live and archived rows form one deduplicated logical sequence.
    fn header_after<T>(
        &self,
        exclusive_id: Option<&str>,
        cancellation: &QueryCancellation,
        lend: impl for<'a> FnOnce(Option<Header<'a>>) -> kasumi_types::Result<T>,
    ) -> ReadResult<T, Self::Failure>;
}

/// Bind the entire query, including separate sorting/output loans, to one
/// capture. Per-loan identity checks alone miss a switch between loans.
pub(crate) struct BoundSource<'a, S: DocumentSource + ?Sized> {
    source: &'a S,
    identity: SourceIdentity<'a>,
}
impl<'a, S: DocumentSource + ?Sized> BoundSource<'a, S> {
    pub(crate) fn new(source: &'a S) -> Self {
        Self {
            source,
            identity: source.identity(),
        }
    }
    fn check(&self) -> kasumi_types::Result<()> {
        if self.identity != self.source.identity() {
            return Err(Error::new(
                ErrorCode::Corruption,
                "query source view changed",
            ));
        }
        Ok(())
    }
}
impl<S: DocumentSource + ?Sized> crate::CollectionRecords for BoundSource<'_, S> {
    type Failure = S::Failure;
    fn identity(&self) -> SourceIdentity<'_> {
        self.source.identity()
    }
    fn definition(&self) -> &CollectionDefinition {
        self.source.definition()
    }
    fn visit_records(
        &self,
        mut lend: impl for<'a> FnMut(&'a str, Record<'a>) -> kasumi_types::Result<()>,
    ) -> ReadResult<(), Self::Failure> {
        self.check()?;
        self.source.visit_records(|id, record| {
            self.check()?;
            lend(id, record)
        })?;
        self.check()?;
        Ok(())
    }
}
impl<S: DocumentSource + ?Sized> DocumentSource for BoundSource<'_, S> {
    fn indexes(&self) -> &crate::QueryIndexes {
        self.source.indexes()
    }
    fn visit_primary_ids(
        &self,
        cancellation: &QueryCancellation,
        mut lend: impl FnMut(&str) -> kasumi_types::Result<()>,
    ) -> ReadResult<bool, Self::Failure> {
        self.check()?;
        let available = self.source.visit_primary_ids(cancellation, |id| {
            self.check()?;
            lend(id)
        })?;
        self.check()?;
        Ok(available)
    }
    fn has_ordered_unique_source(&self) -> bool {
        self.source.has_ordered_unique_source()
    }
    fn ranked_compound_count(
        &self,
        index: usize,
        cancel: &QueryCancellation,
    ) -> ReadResult<Option<u64>, Self::Failure> {
        self.check()?;
        let count = self.source.ranked_compound_count(index, cancel)?;
        self.check()?;
        Ok(count)
    }
    fn ranked_compound_window(
        &self,
        index: usize,
        start: u64,
        end: u64,
        descending: bool,
        cancel: &QueryCancellation,
    ) -> ReadResult<Option<Vec<crate::RankedOwner>>, Self::Failure> {
        self.check()?;
        let rows = self
            .source
            .ranked_compound_window(index, start, end, descending, cancel)?;
        self.check()?;
        if let Some(rows) = &rows {
            let length = end
                .checked_sub(start)
                .map(|n| n.min(crate::ORDERED_TUPLE_WINDOW as u64));
            if length != Some(rows.len() as u64)
                || rows.iter().enumerate().any(|(offset, row)| {
                    let expected = if descending {
                        end - 1 - offset as u64
                    } else {
                        start + offset as u64
                    };
                    row.rank != expected || kasumi_types::validate_name(&row.id).is_err()
                })
            {
                return Err(
                    Error::new(ErrorCode::Corruption, "invalid ranked compound window").into(),
                );
            }
        }
        Ok(rows)
    }
    fn ordered_unique_window(
        &self,
        index: usize,
        lower: std::ops::Bound<&[u8]>,
        upper: std::ops::Bound<&[u8]>,
        descending: bool,
        cancellation: &QueryCancellation,
    ) -> ReadResult<Option<crate::OrderedTupleWindow>, Self::Failure> {
        self.check()?;
        let result =
            self.source
                .ordered_unique_window(index, lower, upper, descending, cancellation)?;
        self.check()?;
        if let Some(rows) = &result {
            crate::ordered_tuple::check_window(rows, lower, upper, descending)?;
        }
        Ok(result)
    }
    fn visit_field_posting(
        &self,
        field: usize,
        predicate: crate::FieldPredicate<'_>,
        cancellation: &QueryCancellation,
        mut lend: impl FnMut(&str) -> kasumi_types::Result<()>,
    ) -> ReadResult<bool, Self::Failure> {
        self.check()?;
        let available = self
            .source
            .visit_field_posting(field, predicate, cancellation, |id| {
                self.check()?;
                lend(id)
            })?;
        self.check()?;
        Ok(available)
    }
    fn with_text_shards<T>(
        &self,
        search: impl FnOnce(&dyn crate::TextShardSet) -> kasumi_types::Result<T>,
    ) -> ReadResult<Option<T>, Self::Failure> {
        self.check()?;
        let result = self.source.with_text_shards(|shards| {
            self.check()?;
            search(shards)
        })?;
        self.check()?;
        Ok(result)
    }
    fn with_record<T>(
        &self,
        id: &str,
        version: Option<u64>,
        cancellation: &QueryCancellation,
        lend: impl for<'a> FnOnce(Option<Record<'a>>) -> kasumi_types::Result<T>,
    ) -> ReadResult<T, Self::Failure> {
        self.check()?;
        let result = self
            .source
            .with_record(id, version, cancellation, |record| {
                self.check()?;
                lend(record)
            })?;
        self.check()?;
        Ok(result)
    }
    fn header_after<T>(
        &self,
        after: Option<&str>,
        cancellation: &QueryCancellation,
        lend: impl for<'a> FnOnce(Option<Header<'a>>) -> kasumi_types::Result<T>,
    ) -> ReadResult<T, Self::Failure> {
        self.check()?;
        let result = self.source.header_after(after, cancellation, |header| {
            self.check()?;
            lend(header)
        })?;
        self.check()?;
        Ok(result)
    }
}

pub(crate) fn check_source<S: DocumentSource + ?Sized>(
    source: &S,
    indexes: &crate::QueryIndexes,
    collection: &str,
) -> kasumi_types::Result<()> {
    if !std::ptr::eq(indexes, source.indexes())
        || source.identity().collection() != collection
        || source.definition().name != collection
    {
        return Err(Error::new(
            ErrorCode::Corruption,
            "query source collection differs",
        ));
    }
    Ok(())
}

pub(crate) fn with_live<S: DocumentSource + ?Sized, T>(
    source: &S,
    id: &str,
    version: Option<u64>,
    cancellation: &QueryCancellation,
    lend: impl for<'a> FnOnce(&'a Document) -> kasumi_types::Result<T>,
) -> ReadResult<T, S::Failure> {
    cancellation.check()?;
    let identity = source.identity();
    let result = source.with_record(id, version, cancellation, |record| {
        cancellation.check()?;
        if source.identity() != identity {
            return Err(Error::new(
                ErrorCode::Corruption,
                "query source view changed",
            ));
        }
        if version.is_some_and(|version| record.is_none_or(|record| record.version() != version)) {
            return Err(Error::new(
                ErrorCode::Corruption,
                "source document version differs",
            ));
        }
        let document = match record {
            Some(Record::Live(document)) => document,
            Some(Record::Archived(_)) => {
                return Err(Error::new(
                    ErrorCode::Unavailable,
                    "selected archived content requires bounded hydration",
                ));
            }
            None => {
                return Err(Error::new(
                    ErrorCode::Corruption,
                    "index/document generation mismatch",
                ));
            }
        };
        if document.id != id {
            return Err(Error::new(
                ErrorCode::Corruption,
                "source document identity/version differs",
            ));
        }
        lend(document)
    })?;
    cancellation.check()?;
    if source.identity() != identity {
        return Err(Error::new(ErrorCode::Corruption, "query source view changed").into());
    }
    Ok(result)
}
