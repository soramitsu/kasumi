//! Lending index inputs from an exact ordered-application state pair.
//!
//! The adapters retain at most the current old/new decoded pair, never a second
//! collection map. Only the applying command supplies changed IDs;
//! an unexplained changed root is an invariant error, never a rebuild fallback.

use kasumi_query::{
    CollectionRecords, DocumentChanges, DocumentDelta, IndexUpdate, QueryIndexes, ReadFailure,
    ReadResult, Record, SourceIdentity,
};
use kasumi_types::{
    ArchivedDocument, CollectionDefinition, CollectionState, DocumentLoan, DocumentResolver,
    DocumentSlot, Error, ErrorCode, Result, TenantState,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

/// Keep local storage/admission failure separate from deterministic validation.
#[derive(Debug)]
pub(crate) struct DocumentSourceFailure(pub(crate) anyhow::Error);
impl fmt::Display for DocumentSourceFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, formatter)
    }
}
impl std::error::Error for DocumentSourceFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}
pub(crate) type SourceResult<T> = ReadResult<T, DocumentSourceFailure>;

/// Leave the lending adapter without wrapping the original operation or
/// native failure. Callers rely on its exact type and owning allocation.
pub(crate) fn into_anyhow(error: ReadFailure<DocumentSourceFailure>) -> anyhow::Error {
    match error {
        ReadFailure::Query(error) => error.into(),
        ReadFailure::Source(error) => error.0,
    }
}

pub(crate) enum RecordLoan<'a> {
    Live(DocumentLoan<'a>),
    Archived(&'a ArchivedDocument),
}
impl RecordLoan<'_> {
    pub(crate) fn as_record(&self) -> Record<'_> {
        match self {
            Self::Live(document) => Record::Live(document.as_ref()),
            Self::Archived(document) => Record::Archived(document),
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct StateCollection<'a> {
    state: &'a TenantState,
    name: &'a str,
    collection: &'a CollectionState,
    resolver: Option<&'a dyn DocumentResolver>,
}

impl<'a> StateCollection<'a> {
    /// `collection` may be a private schema candidate not yet installed in
    /// `state`; the identity therefore uses that actual collection owner.
    pub(crate) fn new(
        state: &'a TenantState,
        name: &'a str,
        collection: &'a CollectionState,
    ) -> Self {
        Self::with_resolver(state, name, collection, None)
    }

    pub(crate) fn with_resolver(
        state: &'a TenantState,
        name: &'a str,
        collection: &'a CollectionState,
        resolver: Option<&'a dyn DocumentResolver>,
    ) -> Self {
        Self {
            state,
            name,
            collection,
            resolver,
        }
    }
}

fn corruption(message: &'static str) -> Error {
    Error::new(ErrorCode::Corruption, message)
}

/// Validate metadata without fetching a body; point absence and ordered headers
/// must not decode a document merely to discover its identity or version.
pub(crate) fn header<'a>(
    collection: &'a CollectionState,
    id: &'a str,
    revision: u64,
) -> Result<Option<kasumi_query::Header<'a>>> {
    let live = collection.documents.get(id);
    let archived = collection.archived_documents.get(id);
    // Zero is a valid restored version, as in the snapshot and primary codecs.
    // The selected source still cannot lend a version newer than its revision.
    let valid_version = |version| version <= revision;
    if live.is_some_and(|document| document.id() != id || !valid_version(document.version()))
        || archived.is_some_and(|reference| !valid_version(reference.version))
    {
        return Err(corruption("source document identity/version differs"));
    }
    if let Some((document, reference)) = live.zip(archived)
        && document.version() != reference.version
    {
        return Err(corruption("hydrated source version differs from archive"));
    }
    Ok(live
        .map(|document| kasumi_query::Header {
            id,
            version: document.version(),
            kind: kasumi_query::RecordKind::Live,
        })
        .or_else(|| {
            archived.map(|reference| kasumi_query::Header {
                id,
                version: reference.version,
                kind: kasumi_query::RecordKind::Archived,
            })
        }))
}

pub(crate) fn record<'a>(
    collection: &'a CollectionState,
    id: &str,
    revision: u64,
    resolver: Option<&dyn DocumentResolver>,
) -> SourceResult<Option<RecordLoan<'a>>> {
    if header(collection, id, revision)?.is_none() {
        return Ok(None);
    }
    if let Some(document) = collection.documents.get(id) {
        let loan = match document.as_ref() {
            DocumentSlot::Pending(document) => DocumentLoan::Pending(document),
            DocumentSlot::Stored(document) => {
                let resolver = resolver.ok_or_else(|| {
                    ReadFailure::Source(DocumentSourceFailure(anyhow::anyhow!(
                        "stored document has no selected resolver"
                    )))
                })?;
                DocumentLoan::Stored(
                    document
                        .load(resolver)
                        .map_err(|error| ReadFailure::Source(DocumentSourceFailure(error)))?,
                )
            }
        };
        return Ok(Some(RecordLoan::Live(loan)));
    }
    Ok(collection
        .archived_documents
        .get(id)
        .map(|reference| RecordLoan::Archived(reference.as_ref())))
}

/// Iterate the logical union directly, validating both sides of a hydrated
/// duplicate before lending it once. Scratch is two ordered-map iterators.
pub(crate) fn visit(
    collection: &CollectionState,
    revision: u64,
    resolver: Option<&dyn DocumentResolver>,
    mut lend: impl for<'a> FnMut(&'a str, Record<'a>) -> Result<()>,
) -> SourceResult<()> {
    let mut live = collection.documents.keys().peekable();
    let mut archived = collection.archived_documents.keys().peekable();
    loop {
        let id = match (live.peek(), archived.peek()) {
            (Some(a), Some(b)) => match a.cmp(b) {
                std::cmp::Ordering::Less => live.next(),
                std::cmp::Ordering::Greater => archived.next(),
                std::cmp::Ordering::Equal => {
                    archived.next();
                    live.next()
                }
            },
            (Some(_), None) => live.next(),
            (None, Some(_)) => archived.next(),
            (None, None) => break,
        }
        .expect("selected nonempty source iterator");
        let value = record(collection, id, revision, resolver)?
            .ok_or_else(|| corruption("source iterator lost its record"))?;
        lend(id, value.as_record())?;
    }
    Ok(())
}

impl CollectionRecords for StateCollection<'_> {
    type Failure = DocumentSourceFailure;
    fn identity(&self) -> SourceIdentity<'_> {
        SourceIdentity::new(
            self.collection,
            &self.state.tenant,
            &self.state.incarnation,
            self.name,
        )
    }
    fn definition(&self) -> &CollectionDefinition {
        &self.collection.definition
    }
    fn visit_records(
        &self,
        lend: impl for<'a> FnMut(&'a str, Record<'a>) -> Result<()>,
    ) -> ReadResult<(), Self::Failure> {
        visit(self.collection, self.state.revision, self.resolver, lend)
    }
}

pub(crate) struct StateChanges<'a> {
    old: StateCollection<'a>,
    new: StateCollection<'a>,
    indexes: &'a QueryIndexes,
    ids: &'a BTreeSet<String>,
}
impl DocumentChanges for StateChanges<'_> {
    type Failure = DocumentSourceFailure;
    fn old_identity(&self) -> SourceIdentity<'_> {
        self.old.identity()
    }
    fn new_identity(&self) -> SourceIdentity<'_> {
        self.new.identity()
    }
    fn old_definition(&self) -> &CollectionDefinition {
        self.old.definition()
    }
    fn new_definition(&self) -> &CollectionDefinition {
        self.new.definition()
    }
    fn indexes(&self) -> &QueryIndexes {
        self.indexes
    }
    fn visit_changes(
        &self,
        mut lend: impl for<'a> FnMut(DocumentDelta<'a>) -> Result<()>,
    ) -> ReadResult<(), Self::Failure> {
        for id in self.ids {
            let old = record(
                self.old.collection,
                id,
                self.old.state.revision,
                self.old.resolver,
            )?;
            let new = record(
                self.new.collection,
                id,
                self.new.state.revision,
                self.new.resolver,
            )?;
            lend(DocumentDelta {
                id,
                old: old.as_ref().map(RecordLoan::as_record),
                new: new.as_ref().map(RecordLoan::as_record),
            })?;
        }
        Ok(())
    }
}

pub(crate) fn collections(state: &TenantState) -> impl Iterator<Item = StateCollection<'_>> {
    state
        .collections
        .iter()
        .map(|(name, collection)| StateCollection::new(state, name, collection))
}

pub(crate) fn build(state: &TenantState) -> SourceResult<QueryIndexes> {
    build_with_resolver(state, None)
}

pub(crate) fn build_with_resolver(
    state: &TenantState,
    resolver: Option<&dyn DocumentResolver>,
) -> SourceResult<QueryIndexes> {
    QueryIndexes::build(state.collections.iter().map(|(name, collection)| {
        StateCollection::with_resolver(state, name, collection, resolver)
    }))
}

fn check_scope(old: &TenantState, new: &TenantState) -> Result<()> {
    if old.tenant != new.tenant || old.incarnation != new.incarnation {
        return Err(corruption("index input tenant/incarnation changed"));
    }
    Ok(())
}

fn changes_for<'a>(
    indexes: &'a QueryIndexes,
    old: &'a TenantState,
    new: &'a TenantState,
    name: &'a str,
    ids: &'a BTreeSet<String>,
    old_resolver: Option<&'a dyn DocumentResolver>,
    new_resolver: Option<&'a dyn DocumentResolver>,
) -> Result<StateChanges<'a>> {
    let previous = old
        .collections
        .get(name)
        .ok_or_else(|| corruption("previous changed collection missing"))?;
    let next = new
        .collections
        .get(name)
        .ok_or_else(|| corruption("next changed collection missing"))?;
    if previous.definition != next.definition {
        return Err(corruption("document delta changed collection definition"));
    }
    Ok(StateChanges {
        old: StateCollection::with_resolver(old, name, previous, old_resolver),
        new: StateCollection::with_resolver(new, name, next, new_resolver),
        indexes,
        ids,
    })
}

pub(crate) fn validate_changes(
    indexes: &QueryIndexes,
    old: &TenantState,
    new: &TenantState,
    changed: &BTreeMap<String, BTreeSet<String>>,
) -> SourceResult<()> {
    validate_changes_with_resolvers(indexes, old, new, changed, None, None)
}

pub(crate) fn validate_changes_with_resolvers(
    indexes: &QueryIndexes,
    old: &TenantState,
    new: &TenantState,
    changed: &BTreeMap<String, BTreeSet<String>>,
    old_resolver: Option<&dyn DocumentResolver>,
    new_resolver: Option<&dyn DocumentResolver>,
) -> SourceResult<()> {
    check_scope(old, new)?;
    // Validate all descriptors before querying. The second pass only borrows
    // these immutable maps, so no fallible metadata lookup remains in Iterator.
    for (name, ids) in changed {
        changes_for(indexes, old, new, name, ids, old_resolver, new_resolver)?;
    }
    indexes.validate_unique_changes(changed.iter().map(|(name, ids)| {
        changes_for(indexes, old, new, name, ids, old_resolver, new_resolver)
            .expect("validated immutable delta scope")
    }))
}

fn action<'a>(
    indexes: &'a QueryIndexes,
    old: &'a TenantState,
    new: &'a TenantState,
    changed: &'a BTreeMap<String, BTreeSet<String>>,
    name: &'a str,
    collection: &'a CollectionState,
    old_resolver: Option<&'a dyn DocumentResolver>,
    new_resolver: Option<&'a dyn DocumentResolver>,
) -> Result<IndexUpdate<'a, StateCollection<'a>, StateChanges<'a>>> {
    let Some(previous) = old.collections.get(name) else {
        return Ok(IndexUpdate::Rebuild(StateCollection::with_resolver(
            new,
            name,
            collection,
            new_resolver,
        )));
    };
    if previous.definition != collection.definition {
        return Ok(IndexUpdate::Rebuild(StateCollection::with_resolver(
            new,
            name,
            collection,
            new_resolver,
        )));
    }
    if previous.documents.ptr_eq(&collection.documents)
        && previous
            .archived_documents
            .ptr_eq(&collection.archived_documents)
    {
        return Ok(IndexUpdate::Unchanged(name));
    }
    let ids = changed
        .get(name)
        .filter(|ids| !ids.is_empty())
        .ok_or_else(|| corruption("changed document roots have no exact index delta"))?;
    Ok(IndexUpdate::Delta(changes_for(
        indexes,
        old,
        new,
        name,
        ids,
        old_resolver,
        new_resolver,
    )?))
}

pub(crate) fn update(
    indexes: &QueryIndexes,
    old: &TenantState,
    new: &TenantState,
    changed: &BTreeMap<String, BTreeSet<String>>,
) -> SourceResult<QueryIndexes> {
    update_with_resolvers(indexes, old, new, changed, None, None)
}

pub(crate) fn update_with_resolvers(
    indexes: &QueryIndexes,
    old: &TenantState,
    new: &TenantState,
    changed: &BTreeMap<String, BTreeSet<String>>,
    old_resolver: Option<&dyn DocumentResolver>,
    new_resolver: Option<&dyn DocumentResolver>,
) -> SourceResult<QueryIndexes> {
    check_scope(old, new)?;
    // Complete metadata planning before any shared text writer can advance.
    for (name, collection) in &new.collections {
        action(
            indexes,
            old,
            new,
            changed,
            name,
            collection,
            old_resolver,
            new_resolver,
        )?;
    }
    if changed
        .keys()
        .any(|name| !new.collections.contains_key(name))
    {
        return Err(corruption("index delta targets removed collection").into());
    }
    let actions = new
        .collections
        .iter()
        .map(|(name, collection)| {
            action(
                indexes,
                old,
                new,
                changed,
                name,
                collection,
                old_resolver,
                new_resolver,
            )
            .expect("validated immutable index action")
        })
        .chain(
            old.collections
                .keys()
                .filter(|name| !new.collections.contains_key(*name))
                .map(|name| IndexUpdate::Remove(name)),
        );
    indexes.update(actions)
}

#[cfg(test)]
#[path = "index_source_tests.rs"]
mod tests;
