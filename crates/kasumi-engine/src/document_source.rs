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
use std::{ops::Bound, sync::Arc, time::Instant};

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

    fn check_deadline(&self) -> Result<()> {
        if Instant::now() >= self.deadline {
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                "document read deadline exceeded",
            ));
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
        let bound = exclusive_id.map_or(Bound::Unbounded, Bound::Excluded);
        let collection = self.collection();
        let live = collection
            .documents
            .range::<_, str>((bound, Bound::Unbounded))
            .next()
            .map(|(id, _)| id.as_str());
        let archived = collection
            .archived_documents
            .range::<_, str>((bound, Bound::Unbounded))
            .next()
            .map(|(id, _)| id.as_str());
        let id = match (live, archived) {
            (Some(live), Some(archived)) => Some(live.min(archived)),
            (live, archived) => live.or(archived),
        };
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
