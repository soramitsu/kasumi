//! Borrowed index inputs from an exact ordered-application state pair.
//!
//! The adapters lend records without cloning document bodies or materializing
//! a second collection map. Only the applying command supplies changed IDs;
//! an unexplained changed root is an invariant error, never a rebuild fallback.

use kasumi_query::{
    CollectionRecords, DocumentChanges, DocumentDelta, IndexUpdate, QueryIndexes, ReadFailure,
    ReadResult, Record, SourceIdentity,
};
use kasumi_types::{CollectionDefinition, CollectionState, Error, ErrorCode, Result, TenantState};
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::Infallible,
};

#[derive(Clone, Copy)]
pub(crate) struct StateCollection<'a> {
    state: &'a TenantState,
    name: &'a str,
    collection: &'a CollectionState,
}

impl<'a> StateCollection<'a> {
    /// `collection` may be a private schema candidate not yet installed in
    /// `state`; the identity therefore uses that actual collection owner.
    pub(crate) fn new(
        state: &'a TenantState,
        name: &'a str,
        collection: &'a CollectionState,
    ) -> Self {
        Self {
            state,
            name,
            collection,
        }
    }
}

fn corruption(message: &'static str) -> Error {
    Error::new(ErrorCode::Corruption, message)
}

pub(crate) fn record<'a>(
    collection: &'a CollectionState,
    id: &str,
    revision: u64,
) -> Result<Option<Record<'a>>> {
    let live = collection.documents.get(id);
    let archived = collection.archived_documents.get(id);
    // Zero is a valid restored version, as in the snapshot and primary codecs.
    // The selected source still cannot lend a version newer than its revision.
    let valid_version = |version| version <= revision;
    if live.is_some_and(|document| document.id != id || !valid_version(document.version))
        || archived.is_some_and(|reference| !valid_version(reference.version))
    {
        return Err(corruption("source document identity/version differs"));
    }
    if let Some((document, reference)) = live.zip(archived)
        && document.version != reference.version
    {
        return Err(corruption("hydrated source version differs from archive"));
    }
    Ok(live
        .map(|document| Record::Live(document))
        .or_else(|| archived.map(|reference| Record::Archived(reference))))
}

/// Iterate the logical union directly, validating both sides of a hydrated
/// duplicate before lending it once. Scratch is two ordered-map iterators.
pub(crate) fn visit(
    collection: &CollectionState,
    revision: u64,
    mut lend: impl for<'a> FnMut(&'a str, Record<'a>) -> Result<()>,
) -> Result<()> {
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
        let value = record(collection, id, revision)?
            .ok_or_else(|| corruption("source iterator lost its record"))?;
        lend(id, value)?;
    }
    Ok(())
}

impl CollectionRecords for StateCollection<'_> {
    type Failure = Infallible;
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
        visit(self.collection, self.state.revision, lend).map_err(Into::into)
    }
}

pub(crate) struct StateChanges<'a> {
    old: StateCollection<'a>,
    new: StateCollection<'a>,
    indexes: &'a QueryIndexes,
    ids: &'a BTreeSet<String>,
}
impl DocumentChanges for StateChanges<'_> {
    type Failure = Infallible;
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
            let old = record(self.old.collection, id, self.old.state.revision)?;
            let new = record(self.new.collection, id, self.new.state.revision)?;
            lend(DocumentDelta { id, old, new })?;
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

pub(crate) fn build(state: &TenantState) -> Result<QueryIndexes> {
    QueryIndexes::build(collections(state)).map_err(ReadFailure::into_query_error)
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
        old: StateCollection::new(old, name, previous),
        new: StateCollection::new(new, name, next),
        indexes,
        ids,
    })
}

pub(crate) fn validate_changes(
    indexes: &QueryIndexes,
    old: &TenantState,
    new: &TenantState,
    changed: &BTreeMap<String, BTreeSet<String>>,
) -> Result<()> {
    check_scope(old, new)?;
    // Validate all descriptors before querying. The second pass only borrows
    // these immutable maps, so no fallible metadata lookup remains in Iterator.
    for (name, ids) in changed {
        changes_for(indexes, old, new, name, ids)?;
    }
    indexes
        .validate_unique_changes(changed.iter().map(|(name, ids)| {
            changes_for(indexes, old, new, name, ids).expect("validated immutable delta scope")
        }))
        .map_err(ReadFailure::into_query_error)
}

fn action<'a>(
    indexes: &'a QueryIndexes,
    old: &'a TenantState,
    new: &'a TenantState,
    changed: &'a BTreeMap<String, BTreeSet<String>>,
    name: &'a str,
    collection: &'a CollectionState,
) -> Result<IndexUpdate<'a, StateCollection<'a>, StateChanges<'a>>> {
    let Some(previous) = old.collections.get(name) else {
        return Ok(IndexUpdate::Rebuild(StateCollection::new(
            new, name, collection,
        )));
    };
    if previous.definition != collection.definition {
        return Ok(IndexUpdate::Rebuild(StateCollection::new(
            new, name, collection,
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
        indexes, old, new, name, ids,
    )?))
}

pub(crate) fn update(
    indexes: &QueryIndexes,
    old: &TenantState,
    new: &TenantState,
    changed: &BTreeMap<String, BTreeSet<String>>,
) -> Result<QueryIndexes> {
    check_scope(old, new)?;
    // Complete metadata planning before any shared text writer can advance.
    for (name, collection) in &new.collections {
        action(indexes, old, new, changed, name, collection)?;
    }
    if changed
        .keys()
        .any(|name| !new.collections.contains_key(name))
    {
        return Err(corruption("index delta targets removed collection"));
    }
    let actions = new
        .collections
        .iter()
        .map(|(name, collection)| {
            action(indexes, old, new, changed, name, collection)
                .expect("validated immutable index action")
        })
        .chain(
            old.collections
                .keys()
                .filter(|name| !new.collections.contains_key(*name))
                .map(|name| IndexUpdate::Remove(name)),
        );
    indexes
        .update(actions)
        .map_err(ReadFailure::into_query_error)
}

#[cfg(test)]
#[path = "index_source_tests.rs"]
mod tests;
