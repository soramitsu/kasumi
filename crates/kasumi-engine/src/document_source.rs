//! Lending access to one captured immutable generation and collection.
//!
//! This adapter performs no I/O. Hydrated read views keep their reservations
//! and exact index owner alive through the captured Generation. Authorization
//! and current key access remain the enclosing service's responsibility.

use crate::Generation;
use kasumi_query::{
    CollectionRecords, DocumentSource, Header, QueryCancellation, QueryIndexes, ReadResult, Record,
    RecordKind, SourceIdentity,
};
use kasumi_types::{
    CollectionDefinition, CollectionState, Error, ErrorCode, Result, validate_name,
};
use std::{convert::Infallible, ops::Bound, sync::Arc};

/// One selected collection of an immutable generation, including any verified
/// hydration overlay. Cloning the source retains that exact owner and view.
#[derive(Clone)]
pub(crate) struct GenerationDocumentSource {
    generation: Arc<Generation>,
    collection: String,
}

impl Generation {
    pub(crate) fn document_source(
        self: &Arc<Self>,
        collection: &str,
    ) -> Result<GenerationDocumentSource> {
        validate_name(collection)?;
        let selected = self
            .state
            .collections
            .get(collection)
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "collection not found"))?;
        if selected.definition.name != collection {
            return Err(corruption("source collection definition differs"));
        }
        Ok(GenerationDocumentSource {
            generation: self.clone(),
            collection: collection.to_owned(),
        })
    }
}

fn corruption(message: &'static str) -> Error {
    Error::new(ErrorCode::Corruption, message)
}

impl GenerationDocumentSource {
    fn collection(&self) -> &CollectionState {
        // The source retains this immutable allocation. No later engine
        // publication or hydration view can remove its validated collection.
        &self.generation.state.collections[&self.collection]
    }

    fn record(&self, id: &str) -> Result<Option<Record<'_>>> {
        crate::index_source::record(self.collection(), id, self.generation.state.revision)
    }
}

impl CollectionRecords for GenerationDocumentSource {
    type Failure = Infallible;

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
        lend: impl for<'a> FnMut(&'a str, Record<'a>) -> Result<()>,
    ) -> ReadResult<(), Self::Failure> {
        crate::index_source::visit(self.collection(), self.generation.state.revision, lend)
            .map_err(Into::into)
    }
}

impl DocumentSource for GenerationDocumentSource {
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
        if expected_version
            .is_some_and(|version| record.is_none_or(|record| record.version() != version))
        {
            return Err(corruption("source document expected version differs").into());
        }
        cancellation.check()?;
        let result = lend(record)?;
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
                let record = self
                    .record(id)?
                    .ok_or_else(|| corruption("source header lost its record"))?;
                Ok(Header {
                    id,
                    version: record.version(),
                    kind: match record {
                        Record::Live(_) => RecordKind::Live,
                        Record::Archived(_) => RecordKind::Archived,
                    },
                })
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
