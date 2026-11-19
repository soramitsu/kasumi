//! Lending access to one captured immutable generation and collection.
//!
//! Stored bodies are decoded only inside an admitted loan from this generation's
//! exact resolver. Hydrated read views retain their reservations and index owner.
//! Authorization and current key access remain the enclosing service's duty.

use crate::Generation;
use crate::document_store::SharedRead;
use crate::index_source::{DocumentSourceFailure, RecordLoan, SourceResult};
use kasumi_query::{
    CollectionRecords, DocumentSource, Header, QueryCancellation, QueryIndexes, ReadResult, Record,
    SourceIdentity,
};
use kasumi_types::{
    CollectionDefinition, CollectionState, DocumentResolver, Error, ErrorCode, Result,
    validate_name,
};
use std::{sync::Arc, time::Instant};

/// One selected collection of an immutable generation, including any verified
/// hydration overlay. Cloning the source retains that exact owner and view.
#[derive(Clone)]
pub(crate) struct GenerationDocumentSource<'r> {
    generation: Arc<Generation>,
    collection: String,
    // A bounded read's shared loans; otherwise each load opens its own view.
    reads: Option<&'r DocumentReads>,
}

impl Generation {
    pub(crate) fn document_source(
        self: &Arc<Self>,
        collection: &str,
    ) -> Result<GenerationDocumentSource<'static>> {
        source(self, collection, None)
    }
}

fn source<'r>(
    generation: &Arc<Generation>,
    collection: &str,
    reads: Option<&'r DocumentReads>,
) -> Result<GenerationDocumentSource<'r>> {
    validate_name(collection)?;
    let selected = generation
        .state
        .collections
        .get(collection)
        .ok_or_else(|| Error::new(ErrorCode::NotFound, "collection not found"))?;
    if selected.definition.name != collection {
        return Err(corruption("source collection definition differs"));
    }
    Ok(GenerationDocumentSource {
        generation: generation.clone(),
        collection: collection.to_owned(),
        reads,
    })
}

/// One bounded read of a generation: a query page, a snapshot read or a lease
/// scan page. Its stored documents load through one selected source view,
/// opened by the first load, rather than through a view opened and retired
/// for every document. Each load keeps its own admitted decode workspace,
/// cancellation checks and key access recheck. The read's blocking worker owns
/// this and finishes it before returning, so the view is never held across a
/// strict read audit, a release check or a retained cursor.
pub(crate) struct DocumentReads {
    generation: Arc<Generation>,
    shared: Option<Box<dyn SharedRead>>,
    // The read's native deadline: no load starts after it, even if the
    // caller's cancellation has not reached this worker yet.
    deadline: Instant,
}
impl DocumentReads {
    pub(crate) fn new(generation: &Arc<Generation>, deadline: Instant) -> anyhow::Result<Self> {
        Ok(Self {
            generation: generation.clone(),
            shared: generation.shared_document_read()?,
            deadline,
        })
    }

    pub(crate) fn source(&self, collection: &str) -> Result<GenerationDocumentSource<'_>> {
        source(&self.generation, collection, Some(self))
    }

    /// Retire the shared view. A failed view or ended key access fails the
    /// read, as a single load's own close does.
    pub(crate) fn finish(self) -> anyhow::Result<()> {
        self.shared.map_or(Ok(()), SharedRead::finish)
    }

    pub(crate) fn deadline_error() -> Error {
        Error::new(
            ErrorCode::ResourceExhausted,
            "document read deadline exceeded",
        )
    }

    fn check_deadline(&self) -> Result<()> {
        if Instant::now() >= self.deadline {
            return Err(Self::deadline_error());
        }
        Ok(())
    }
}

fn corruption(message: &'static str) -> Error {
    Error::new(ErrorCode::Corruption, message)
}

impl GenerationDocumentSource<'_> {
    fn collection(&self) -> &CollectionState {
        // The source retains this immutable allocation. No later engine
        // publication or hydration view can remove its validated collection.
        &self.generation.state.collections[&self.collection]
    }

    fn resolver(&self) -> Option<&dyn DocumentResolver> {
        match self.reads.and_then(|reads| reads.shared.as_deref()) {
            Some(shared) => Some(shared as &dyn DocumentResolver),
            None => self.generation.document_resolver(),
        }
    }

    fn check_deadline(&self) -> Result<()> {
        self.reads.map_or(Ok(()), DocumentReads::check_deadline)
    }

    fn record(&self, id: &str) -> SourceResult<Option<RecordLoan<'_>>> {
        self.check_deadline()?;
        crate::index_source::record(
            self.collection(),
            id,
            self.generation.state.revision,
            self.resolver(),
        )
    }
}

impl CollectionRecords for GenerationDocumentSource<'_> {
    type Failure = DocumentSourceFailure;

    fn identity(&self) -> SourceIdentity<'_> {
        SourceIdentity::new(
            self.generation.as_ref(),
            &self.generation.state.tenant,
            &self.generation.state.incarnation,
            &self.collection,
        )
    }

    fn definition(&self) -> &CollectionDefinition {
        &self.collection().definition
    }

    fn visit_records(
        &self,
        mut lend: impl for<'a> FnMut(&'a str, Record<'a>) -> Result<()>,
    ) -> ReadResult<(), Self::Failure> {
        // Checked before each load: the visit loads a record, then lends it.
        self.check_deadline()?;
        crate::index_source::visit(
            self.collection(),
            self.generation.state.revision,
            self.resolver(),
            |id, record| {
                lend(id, record)?;
                self.check_deadline()
            },
        )
    }
}

impl DocumentSource for GenerationDocumentSource<'_> {
    fn indexes(&self) -> &QueryIndexes {
        self.generation.indexes.as_ref()
    }

    fn visit_field_posting(
        &self,
        field: usize,
        predicate: kasumi_query::FieldPredicate<'_>,
        cancellation: &QueryCancellation,
        mut lend: impl FnMut(&str) -> Result<()>,
    ) -> ReadResult<bool, Self::Failure> {
        self.check_deadline()?;
        cancellation.check()?;
        let state = &self.generation.state;
        let Some(selection) = self
            .generation
            .application_selection
            .get()
            .filter(|selection| selection.has_exact_snapshot(state.revision_base, state.revision))
        else {
            return Ok(false);
        };
        let mut failure = None;
        let selected = selection
            .with_snapshot_records(state, |tree, _, layout| {
                let check = || {
                    cancellation.check()?;
                    self.check_deadline()
                };
                let visit = |id: &str| {
                    failure = check().and_then(|()| lend(id)).err();
                    Ok(failure.is_none())
                };
                match predicate {
                    kasumi_query::FieldPredicate::Exists(present)
                        if layout >= kasumi_store::application_manifest::FIELD_POSTINGS_LAYOUT =>
                    {
                        crate::application_records::visit_field_presence(
                            tree,
                            &self.collection,
                            field,
                            present,
                            visit,
                        )?;
                    }
                    kasumi_query::FieldPredicate::Equals { .. }
                    | kasumi_query::FieldPredicate::In { .. }
                    | kasumi_query::FieldPredicate::Range { .. }
                        if layout >= kasumi_store::application_manifest::FIELD_VALUES_LAYOUT =>
                    {
                        crate::application_records::visit_value_ids(
                            tree,
                            &self.collection,
                            field,
                            predicate,
                            || Ok(check()?),
                            visit,
                        )?;
                    }
                    _ => return Ok(false),
                }
                Ok(true)
            })
            .map_err(|error| kasumi_query::ReadFailure::Source(DocumentSourceFailure(error)))?;
        if let Some(error) = failure {
            return Err(error.into());
        }
        self.check_deadline()?;
        cancellation.check()?;
        Ok(selected.unwrap_or(false))
    }

    fn with_record<T>(
        &self,
        id: &str,
        expected_version: Option<u64>,
        cancellation: &QueryCancellation,
        lend: impl for<'a> FnOnce(Option<Record<'a>>) -> Result<T>,
    ) -> ReadResult<T, Self::Failure> {
        cancellation.check()?;
        let record = self.record(id);
        cancellation.check()?;
        let record = record?;
        if expected_version.is_some_and(|version| {
            record
                .as_ref()
                .is_none_or(|record| record.as_record().version() != version)
        }) {
            return Err(corruption("source document expected version differs").into());
        }
        cancellation.check()?;
        let result = lend(record.as_ref().map(RecordLoan::as_record))?;
        cancellation.check()?;
        Ok(result)
    }

    fn header_after<T>(
        &self,
        exclusive_id: Option<&str>,
        cancellation: &QueryCancellation,
        lend: impl for<'a> FnOnce(Option<Header<'a>>) -> Result<T>,
    ) -> ReadResult<T, Self::Failure> {
        cancellation.check()?;
        self.check_deadline()?;
        let state = &self.generation.state;
        if let Some(selection) = self
            .generation
            .application_selection
            .get()
            .filter(|selection| selection.has_exact_snapshot(state.revision_base, state.revision))
        {
            let selected = selection
                .with_snapshot_records(state, |tree, memory, layout| {
                    if layout < kasumi_store::application_manifest::DOCUMENT_HEADERS_LAYOUT {
                        return Ok(None);
                    }
                    let workspace = memory.clone().reserve_document_decode(2048)?;
                    let mut row = None;
                    crate::application_records::visit_snapshot_headers(
                        tree,
                        &self.collection,
                        exclusive_id,
                        state.revision,
                        |id, version, kind| {
                            row = Some((id.to_owned(), version, kind));
                            Ok(false)
                        },
                    )?;
                    Ok(Some((row, workspace)))
                })
                .map_err(|error| kasumi_query::ReadFailure::Source(DocumentSourceFailure(error)))?;
            if let Some((row, _workspace)) = selected.flatten() {
                let header = row
                    .as_ref()
                    .map(|(id, version, kind)| -> Result<_> {
                        let mut kind = *kind;
                        // A request can hydrate an archived body into its own read
                        // view without changing the persisted ID order or version.
                        if kind == kasumi_query::RecordKind::Archived
                            && let Some(live) = self.collection().documents.get(id)
                        {
                            if live.id() != id || live.version() != *version {
                                return Err(corruption(
                                    "hydrated header differs from selected version",
                                ));
                            }
                            kind = kasumi_query::RecordKind::Live;
                        }
                        Ok(Header {
                            id: id.as_str(),
                            version: *version,
                            kind,
                        })
                    })
                    .transpose()?;
                self.check_deadline()?;
                cancellation.check()?;
                let result = lend(header)?;
                cancellation.check()?;
                return Ok(result);
            }
        }
        let collection = self.collection();
        let id = crate::index_source::resident_ids_after(collection, exclusive_id).next();
        let header = id
            .map(|id| -> Result<_> {
                crate::index_source::header(collection, id, self.generation.state.revision)?
                    .ok_or_else(|| corruption("source header lost its record"))
            })
            .transpose();
        cancellation.check()?;
        let header = header?;
        cancellation.check()?;
        let result = lend(header)?;
        cancellation.check()?;
        Ok(result)
    }
}

#[cfg(test)]
#[path = "document_source_tests.rs"]
mod tests;
