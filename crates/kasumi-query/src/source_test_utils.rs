//! Only fixtures adapt resident collection maps. Canonical APIs require a
//! selected source, so production callers cannot fall back to map reads.
use crate::*;
use std::convert::Infallible;

pub(crate) struct FixtureWorkspace;
impl QueryWorkspace for FixtureWorkspace {
    fn ensure_peak(&mut self, bytes: u64) -> Result<()> {
        if bytes > 1 << 30 {
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                "query fixture workspace limit",
            ));
        }
        Ok(())
    }
}
pub(crate) fn query_memory() -> QueryMemory<FixtureWorkspace> {
    QueryMemory::new(FixtureWorkspace, 0).unwrap()
}

pub(crate) struct ResidentSource<'a> {
    pub collection: &'a CollectionState,
    pub indexes: &'a QueryIndexes,
}
impl CollectionRecords for ResidentSource<'_> {
    type Failure = Infallible;
    fn identity(&self) -> SourceIdentity<'_> {
        SourceIdentity::new(
            self.collection,
            "fixture",
            "incarnation",
            &self.collection.definition.name,
        )
    }
    fn definition(&self) -> &CollectionDefinition {
        &self.collection.definition
    }
    fn visit_records(
        &self,
        lend: impl for<'a> FnMut(&'a str, Record<'a>) -> Result<()>,
    ) -> ReadResult<(), Self::Failure> {
        visit_collection(self.collection, lend).map_err(Into::into)
    }
}
impl DocumentSource for ResidentSource<'_> {
    fn indexes(&self) -> &QueryIndexes {
        self.indexes
    }
    fn with_record<T>(
        &self,
        id: &str,
        expected_version: Option<u64>,
        cancellation: &QueryCancellation,
        lend: impl for<'a> FnOnce(Option<Record<'a>>) -> Result<T>,
    ) -> ReadResult<T, Self::Failure> {
        cancellation.check()?;
        let record = self
            .collection
            .documents
            .get(id)
            .map(|document| Record::Live(document))
            .or_else(|| {
                self.collection
                    .archived_documents
                    .get(id)
                    .map(|reference| Record::Archived(reference))
            });
        if expected_version
            .is_some_and(|version| record.is_none_or(|record| record.version() != version))
        {
            return Err(Error::new(ErrorCode::Corruption, "fixture version differs").into());
        }
        cancellation.check()?;
        let result = lend(record)?;
        cancellation.check()?;
        Ok(result)
    }
    fn header_after<T>(
        &self,
        after: Option<&str>,
        cancellation: &QueryCancellation,
        lend: impl for<'a> FnOnce(Option<Header<'a>>) -> Result<T>,
    ) -> ReadResult<T, Self::Failure> {
        use std::ops::Bound::{Excluded, Unbounded};
        cancellation.check()?;
        let bound = after.map_or(Unbounded, Excluded);
        let live = self
            .collection
            .documents
            .range::<_, str>((bound, Unbounded))
            .next()
            .map(|(id, document)| Header {
                id,
                version: document.version,
                kind: RecordKind::Live,
            });
        let archived = self
            .collection
            .archived_documents
            .range::<_, str>((bound, Unbounded))
            .next()
            .map(|(id, document)| Header {
                id,
                version: document.version,
                kind: RecordKind::Archived,
            });
        let header = match (live, archived) {
            (Some(live), Some(archived)) => Some(if live.id <= archived.id {
                live
            } else {
                archived
            }),
            (live, archived) => live.or(archived),
        };
        cancellation.check()?;
        let result = lend(header)?;
        cancellation.check()?;
        Ok(result)
    }
}

pub(crate) struct FixtureRecords<'a> {
    pub collection: &'a CollectionState,
}
impl CollectionRecords for FixtureRecords<'_> {
    type Failure = Infallible;
    fn identity(&self) -> SourceIdentity<'_> {
        SourceIdentity::new(
            self.collection,
            "fixture",
            "incarnation",
            &self.collection.definition.name,
        )
    }
    fn definition(&self) -> &CollectionDefinition {
        &self.collection.definition
    }
    fn visit_records(
        &self,
        lend: impl for<'a> FnMut(&'a str, Record<'a>) -> Result<()>,
    ) -> ReadResult<(), Self::Failure> {
        visit_collection(self.collection, lend).map_err(Into::into)
    }
}
fn visit_collection(
    collection: &CollectionState,
    mut lend: impl for<'a> FnMut(&'a str, Record<'a>) -> Result<()>,
) -> Result<()> {
    let mut live = collection.documents.iter().peekable();
    let mut archived = collection.archived_documents.iter().peekable();
    loop {
        let next_live = match (live.peek(), archived.peek()) {
            (Some((id, document)), Some((archived_id, reference))) if id == archived_id => {
                if document.version != reference.version {
                    return Err(Error::new(
                        ErrorCode::Corruption,
                        "fixture hydration version differs",
                    ));
                }
                archived.next();
                true
            }
            (Some((id, _)), Some((archived_id, _))) => id < archived_id,
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => break,
        };
        if next_live {
            let (id, record) = live.next().unwrap();
            lend(id, Record::Live(record))?;
        } else {
            let (id, record) = archived.next().unwrap();
            lend(id, Record::Archived(record))?;
        }
    }
    Ok(())
}
fn record<'a>(collection: &'a CollectionState, id: &str) -> Option<Record<'a>> {
    collection
        .documents
        .get(id)
        .map(|document| Record::Live(document))
        .or_else(|| {
            collection
                .archived_documents
                .get(id)
                .map(|reference| Record::Archived(reference))
        })
}
pub(crate) struct FixtureChanges<'a> {
    pub previous: &'a CollectionState,
    pub next: &'a CollectionState,
    pub changed: &'a BTreeSet<String>,
    pub indexes: &'a QueryIndexes,
}
impl DocumentChanges for FixtureChanges<'_> {
    type Failure = Infallible;
    fn old_identity(&self) -> SourceIdentity<'_> {
        SourceIdentity::new(
            self.previous,
            "fixture",
            "incarnation",
            &self.previous.definition.name,
        )
    }
    fn new_identity(&self) -> SourceIdentity<'_> {
        SourceIdentity::new(
            self.next,
            "fixture",
            "incarnation",
            &self.next.definition.name,
        )
    }
    fn old_definition(&self) -> &CollectionDefinition {
        &self.previous.definition
    }
    fn new_definition(&self) -> &CollectionDefinition {
        &self.next.definition
    }
    fn indexes(&self) -> &QueryIndexes {
        self.indexes
    }
    fn visit_changes(
        &self,
        mut lend: impl for<'a> FnMut(DocumentDelta<'a>) -> Result<()>,
    ) -> ReadResult<(), Self::Failure> {
        for id in self.changed {
            lend(DocumentDelta {
                id,
                old: record(self.previous, id),
                new: record(self.next, id),
            })?;
        }
        Ok(())
    }
}
pub(crate) fn validate_collection_fixture(
    definition: &CollectionDefinition,
    documents: &imbl::OrdMap<String, Arc<Document>>,
) -> Result<()> {
    let collection = CollectionState {
        definition: definition.clone(),
        data_epoch: 0,
        documents: documents.clone(),
        archived_documents: Default::default(),
        archived_document_bytes: 0,
    };
    validate_collection(&FixtureRecords {
        collection: &collection,
    })
    .map_err(ReadFailure::into_query_error)
}

pub(crate) trait FixtureQueries {
    fn build_fixture(collections: &BTreeMap<String, CollectionState>) -> Result<Self>
    where
        Self: Sized;
    fn update_fixture(
        &self,
        previous: &BTreeMap<String, CollectionState>,
        next: &BTreeMap<String, CollectionState>,
        changed: &BTreeMap<String, BTreeSet<String>>,
    ) -> Result<Self>
    where
        Self: Sized;
    fn validate_unique_changes_fixture(
        &self,
        previous: &BTreeMap<String, CollectionState>,
        next: &BTreeMap<String, CollectionState>,
        changed: &BTreeMap<String, BTreeSet<String>>,
    ) -> Result<()>;

    fn execute_fixture(
        &self,
        collections: &BTreeMap<String, CollectionState>,
        request: &QueryRequest,
        limits: &Limits,
    ) -> Result<QueryResponse>;
    fn execute_with_cancellation_fixture(
        &self,
        collections: &BTreeMap<String, CollectionState>,
        request: &QueryRequest,
        limits: &Limits,
        cancellation: &QueryCancellation,
    ) -> Result<QueryResponse>;
    fn ordered_seek_with_cancellation_fixture(
        &self,
        collections: &BTreeMap<String, CollectionState>,
        request: &OrderedSeekRequest,
        limits: &Limits,
        cancellation: &QueryCancellation,
    ) -> Result<OrderedSeekPage>;
}
impl FixtureQueries for QueryIndexes {
    fn build_fixture(collections: &BTreeMap<String, CollectionState>) -> Result<Self> {
        Self::build(
            collections
                .values()
                .map(|collection| FixtureRecords { collection }),
        )
        .map_err(ReadFailure::into_query_error)
    }
    fn update_fixture(
        &self,
        previous: &BTreeMap<String, CollectionState>,
        next: &BTreeMap<String, CollectionState>,
        changed: &BTreeMap<String, BTreeSet<String>>,
    ) -> Result<Self> {
        let mut actions: Vec<IndexUpdate<'_, FixtureRecords<'_>, FixtureChanges<'_>>> = Vec::new();
        for (name, collection) in next {
            match previous.get(name) {
                None => actions.push(IndexUpdate::Rebuild(FixtureRecords { collection })),
                Some(old) if old.definition != collection.definition => {
                    actions.push(IndexUpdate::Rebuild(FixtureRecords { collection }))
                }
                Some(old)
                    if old.documents.ptr_eq(&collection.documents)
                        && old
                            .archived_documents
                            .ptr_eq(&collection.archived_documents) =>
                {
                    actions.push(IndexUpdate::Unchanged(name))
                }
                Some(old) => {
                    let ids = changed
                        .get(name)
                        .filter(|ids| !ids.is_empty())
                        .ok_or_else(|| {
                            invalid("changed fixture collection needs explicit delta")
                        })?;
                    actions.push(IndexUpdate::Delta(FixtureChanges {
                        previous: old,
                        next: collection,
                        changed: ids,
                        indexes: self,
                    }));
                }
            }
        }
        for name in previous.keys().filter(|name| !next.contains_key(*name)) {
            actions.push(IndexUpdate::Remove(name));
        }
        self.update(actions).map_err(ReadFailure::into_query_error)
    }
    fn validate_unique_changes_fixture(
        &self,
        previous: &BTreeMap<String, CollectionState>,
        next: &BTreeMap<String, CollectionState>,
        changed: &BTreeMap<String, BTreeSet<String>>,
    ) -> Result<()> {
        let sources = changed.iter().map(|(name, ids)| FixtureChanges {
            previous: &previous[name],
            next: &next[name],
            changed: ids,
            indexes: self,
        });
        self.validate_unique_changes(sources)
            .map_err(ReadFailure::into_query_error)
    }

    fn execute_fixture(
        &self,
        collections: &BTreeMap<String, CollectionState>,
        request: &QueryRequest,
        limits: &Limits,
    ) -> Result<QueryResponse> {
        self.execute_with_cancellation_fixture(
            collections,
            request,
            limits,
            &QueryCancellation::default(),
        )
    }
    fn execute_with_cancellation_fixture(
        &self,
        collections: &BTreeMap<String, CollectionState>,
        request: &QueryRequest,
        limits: &Limits,
        cancellation: &QueryCancellation,
    ) -> Result<QueryResponse> {
        let collection = collections
            .get(&request.collection)
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "fixture collection absent"))?;
        self.execute_with_cancellation(
            &ResidentSource {
                collection,
                indexes: self,
            },
            request,
            limits,
            cancellation,
            &mut query_memory(),
        )
        .map_err(ReadFailure::into_query_error)
    }
    fn ordered_seek_with_cancellation_fixture(
        &self,
        collections: &BTreeMap<String, CollectionState>,
        request: &OrderedSeekRequest,
        limits: &Limits,
        cancellation: &QueryCancellation,
    ) -> Result<OrderedSeekPage> {
        let collection = collections
            .get(&request.collection)
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "fixture collection absent"))?;
        self.ordered_seek_with_cancellation(
            &ResidentSource {
                collection,
                indexes: self,
            },
            request,
            limits,
            cancellation,
        )
        .map_err(ReadFailure::into_query_error)
    }
}
