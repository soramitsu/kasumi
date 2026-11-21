//! Lending access to one captured immutable generation and collection.
//!
//! Stored bodies are decoded only inside an admitted loan from this generation's
//! exact resolver. Hydrated read views retain their reservations and index owner.
//! Authorization and current key access remain the enclosing service's duty.

use crate::Generation;
use crate::application_records::PrimaryPoint;
use crate::document_store::SharedRead;
use crate::index_source::DocumentSourceFailure;
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

#[cfg(any(test, feature = "test-utils"))]
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
        Ok(Self::from_shared(
            generation,
            deadline,
            generation.shared_document_read()?,
        ))
    }

    pub(crate) fn from_shared(
        generation: &Arc<Generation>,
        deadline: Instant,
        shared: Option<Box<dyn SharedRead>>,
    ) -> Self {
        Self {
            generation: generation.clone(),
            shared,
            deadline,
        }
    }

    pub(crate) fn into_shared(self) -> Option<Box<dyn SharedRead>> {
        self.shared
    }

    pub(crate) fn shared(&self) -> Option<&dyn SharedRead> {
        self.shared.as_deref()
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

    pub(crate) fn check_deadline(&self) -> Result<()> {
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
    fn with_ranked_compounds<T>(
        &self,
        cancel: &QueryCancellation,
        read: impl FnOnce(&kasumi_store::ordered_pages::TreeReader<'_>) -> anyhow::Result<T>,
    ) -> ReadResult<Option<T>, DocumentSourceFailure> {
        self.check_deadline()?;
        cancel.check()?;
        let Some(selected) = self.generation.application_selection.get() else {
            return Ok(None);
        };
        let result = selected
            .with_checkpoint_tuples_since(
                self.directory_reader(),
                &self.generation.state,
                std::iter::once(self.collection.as_str()),
                kasumi_store::application_manifest::RANKED_COMPOUND_LAYOUT,
                read,
            )
            .map_err(|e| kasumi_query::ReadFailure::Source(DocumentSourceFailure(e)))?;
        self.check_deadline()?;
        cancel.check()?;
        Ok(result)
    }

    fn collection(&self) -> &CollectionState {
        // The source retains this immutable allocation. No later engine
        // publication or hydration view can remove its validated collection.
        &self.generation.state.collections[&self.collection]
    }

    fn directory_reader(&self) -> Option<&crate::document_store::SelectedRead> {
        self.reads
            .and_then(DocumentReads::shared)
            .map(SharedRead::selected)
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

    /// The selected directory owns both point records. Only an archived row
    /// may be replaced by the verified hydration overlay of this read.
    fn with_primary_point<T>(
        &self,
        id: &str,
        cancellation: &QueryCancellation,
        lend: impl FnOnce(PrimaryPoint, u64) -> ReadResult<T, DocumentSourceFailure>,
    ) -> ReadResult<T, DocumentSourceFailure> {
        self.check_deadline()?;
        let state = &self.generation.state;
        if let Some(selection) = self.generation.application_selection.get() {
            let selected = selection
                .with_serving_primary(self.directory_reader(), state, |tree, memory, _| {
                    let mut leases = Vec::new();
                    let mut retained = 0u64;
                    let point = crate::application_records::snapshot_point(
                        tree,
                        &self.collection,
                        id,
                        state.revision,
                        |bytes| {
                            let work = crate::snapshot_codec::inspect_external_json_work(
                                bytes,
                                &mut || {
                                    cancellation.check()?;
                                    self.check_deadline()?;
                                    Ok(())
                                },
                            )?;
                            let required =
                                work.checked_add(2 * bytes.len() as u64 + 512).ok_or_else(
                                    || anyhow::anyhow!("primary record workspace overflow"),
                                )?;
                            retained = retained.checked_add(required).ok_or_else(|| {
                                anyhow::anyhow!("primary record workspace overflow")
                            })?;
                            leases.push(crate::document_restore::ReadAdmissionFailure::reserve(
                                memory, required,
                            )?);
                            Ok(())
                        },
                    )?;
                    Ok((point, leases, retained))
                })
                .map_err(|error| kasumi_query::ReadFailure::Source(DocumentSourceFailure(error)))?;
            if let Some((mut point, _leases, retained)) = selected {
                if let PrimaryPoint::Archived(reference) = &point
                    && let Some(hydrated) = self.collection().documents.get(id)
                {
                    if hydrated.id() != id || hydrated.version() != reference.version {
                        return Err(
                            corruption("hydrated record differs from selected archive").into()
                        );
                    }
                    point = PrimaryPoint::Live(hydrated.clone());
                }
                return lend(point, retained);
            }
        }
        lend(
            PrimaryPoint::resident(self.collection(), id, state.revision)?,
            0,
        )
    }

    /// Transfer an archive reference to the query ledger while its decode
    /// workspace is still held. Live and missing points need no history I/O.
    pub(crate) fn history_reference(
        &self,
        id: &str,
        cancellation: &QueryCancellation,
        reserve: impl FnOnce(u64) -> Result<()>,
    ) -> ReadResult<Option<Arc<kasumi_types::ArchivedDocument>>, DocumentSourceFailure> {
        cancellation.check()?;
        self.with_primary_point(id, cancellation, |point, retained| {
            cancellation.check()?;
            self.check_deadline()?;
            if let PrimaryPoint::Archived(reference) = point {
                reserve(retained)?;
                Ok(Some(reference))
            } else {
                Ok(None)
            }
        })
    }

    pub(crate) fn visit_history_scan(
        &self,
        cancellation: &QueryCancellation,
        mut visit: impl FnMut(&str, bool) -> Result<()>,
    ) -> ReadResult<(), DocumentSourceFailure> {
        let mut checked = |id: &str, archived| {
            cancellation.check()?;
            self.check_deadline()?;
            visit(id, archived)
        };
        if let Some(selection) = self.generation.application_selection.get() {
            let mut failure = None;
            let selected = selection.with_serving_primary(
                self.directory_reader(),
                &self.generation.state,
                |tree, _, _| {
                    crate::application_records::visit_history_scan(
                        tree,
                        &self.collection,
                        |id, archived| {
                            failure = checked(id, archived).err();
                            Ok(failure.is_none())
                        },
                    )
                },
            );
            let selected = selected
                .map_err(|e| kasumi_query::ReadFailure::Source(DocumentSourceFailure(e)))?;
            if let Some(error) = failure {
                return Err(error.into());
            }
            if selected.is_some() {
                return Ok(());
            }
        }
        let collection = self.collection();
        for id in collection.documents.keys() {
            checked(id, false)?;
        }
        for id in collection.archived_documents.keys() {
            checked(id, true)?;
        }
        Ok(())
    }
}

impl GenerationDocumentSource<'_> {
    fn visit_selected_headers(
        &self,
        cancellation: &QueryCancellation,
        mut lend: impl FnMut(&str, u64) -> ReadResult<(), DocumentSourceFailure>,
    ) -> ReadResult<bool, DocumentSourceFailure> {
        if let Some(selection) = self.generation.application_selection.get() {
            // Release the header loan before lending a row to a caller using the same
            // selected reader. Both the page and the exclusive cursor are bounded.
            const ROWS: usize = 32;
            let state = &self.generation.state;
            let mut cursor = [0; 256];
            let mut length = 0;
            loop {
                let after = (length != 0).then(|| {
                    std::str::from_utf8(&cursor[..length]).expect("validated document ID")
                });
                cancellation.check()?;
                let selected = selection
                    .with_serving_primary(self.directory_reader(), state, |tree, memory, layout| {
                        if layout < kasumi_store::application_manifest::DOCUMENT_HEADERS_LAYOUT {
                            return Ok(None);
                        }
                        let grant = crate::document_restore::ReadAdmissionFailure::reserve(
                            memory,
                            (ROWS * (256 + std::mem::size_of::<(String, u64)>()) + 2048) as u64,
                        )?;
                        let mut page = Vec::with_capacity(ROWS);
                        crate::application_records::visit_snapshot_headers(
                            tree,
                            &self.collection,
                            after,
                            state.revision,
                            |id, version, _| {
                                self.check_deadline()?;
                                page.push((id.to_owned(), version));
                                Ok(page.len() < ROWS)
                            },
                        )?;
                        Ok(Some((page, grant)))
                    })
                    .map_err(|e| kasumi_query::ReadFailure::Source(DocumentSourceFailure(e)))?;
                let Some((page, _grant)) = selected.flatten() else {
                    if length != 0 {
                        return Err(corruption(
                            "selected record enumeration lost its primary directory",
                        )
                        .into());
                    }
                    return Ok(false);
                };
                for (id, version) in &page {
                    cancellation.check()?;
                    self.check_deadline()?;
                    lend(id, *version)?;
                }
                if page.len() < ROWS {
                    return Ok(true);
                }
                let id = page.last().expect("full record window").0.as_bytes();
                length = id.len();
                cursor[..length].copy_from_slice(id);
            }
        }
        Ok(false)
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
        self.check_deadline()?;
        let cancellation = QueryCancellation::default();
        if self.visit_selected_headers(&cancellation, |id, version| {
            self.with_record(id, Some(version), &cancellation, |record| {
                lend(
                    id,
                    record.ok_or_else(|| corruption("selected primary header lost its record"))?,
                )
            })
        })? {
            return Ok(());
        }
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

    fn visit_primary_ids(
        &self,
        cancellation: &QueryCancellation,
        mut lend: impl FnMut(&str) -> Result<()>,
    ) -> ReadResult<bool, Self::Failure> {
        self.visit_selected_headers(cancellation, |id, _| Ok(lend(id)?))
    }

    fn has_ordered_unique_source(&self) -> bool {
        self.generation.application_selection.get().is_some()
    }
    fn ranked_compound_count(
        &self,
        index: usize,
        cancel: &QueryCancellation,
    ) -> ReadResult<Option<u64>, Self::Failure> {
        self.with_ranked_compounds(cancel, |tree| {
            crate::application_structured::ranked::count(tree, &self.collection, index)
        })
        .map(Option::flatten)
    }
    fn ranked_compound_window(
        &self,
        index: usize,
        start: u64,
        end: u64,
        descending: bool,
        cancel: &QueryCancellation,
    ) -> ReadResult<Option<Vec<kasumi_query::RankedOwner>>, Self::Failure> {
        self.with_ranked_compounds(cancel, |tree| {
            crate::application_structured::ranked::window(
                tree,
                &self.collection,
                index,
                start,
                end,
                descending,
                || Ok(()),
            )
        })
    }
    fn ordered_unique_window(
        &self,
        index: usize,
        lower: std::ops::Bound<&[u8]>,
        upper: std::ops::Bound<&[u8]>,
        descending: bool,
        cancellation: &QueryCancellation,
    ) -> ReadResult<Option<kasumi_query::OrderedTupleWindow>, Self::Failure> {
        self.check_deadline()?;
        cancellation.check()?;
        if index >= self.generation.indexes.compound_count(&self.collection) {
            return Ok(None);
        }
        let Some(selection) = self.generation.application_selection.get() else {
            return Ok(None);
        };
        let mut interrupted = None;
        let result = selection.with_ordered_tuples(
            self.directory_reader(),
            &self.generation.state,
            || self.generation.indexes.structured_layout_sha256(),
            std::iter::once(self.collection.as_str()),
            |tree, _| {
                crate::application_structured::ordered_unique_window(
                    tree,
                    &self.collection,
                    index,
                    lower,
                    upper,
                    descending,
                    || {
                        interrupted = cancellation
                            .check()
                            .and_then(|()| self.check_deadline())
                            .err();
                        interrupted.is_none()
                    },
                )
            },
        );
        let result =
            result.map_err(|e| kasumi_query::ReadFailure::Source(DocumentSourceFailure(e)))?;
        if let Some(error) = interrupted {
            return Err(error.into());
        }
        Ok(result)
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
        let Some(selection) = self.generation.application_selection.get() else {
            return Ok(false);
        };
        let mut failure = None;
        // The ordinary structured directory follows every write, so it
        // serves any generation it is current for. Only a generation without
        // one falls back to the ranked dictionaries of its exact snapshot.
        let ordinary = selection
            .with_structured_records(
                self.directory_reader(),
                state,
                || self.generation.indexes.structured_layout_sha256(),
                |tree| {
                    let check = || {
                        cancellation.check()?;
                        self.check_deadline()
                    };
                    crate::application_structured::visit_posting(
                        tree,
                        &self.collection,
                        field,
                        predicate,
                        || Ok(check()?),
                        |id| {
                            failure = check().and_then(|()| lend(id)).err();
                            Ok(failure.is_none())
                        },
                    )
                },
            )
            .map_err(|error| kasumi_query::ReadFailure::Source(DocumentSourceFailure(error)))?;
        if let Some(error) = failure {
            return Err(error.into());
        }
        if ordinary.is_some() {
            self.check_deadline()?;
            cancellation.check()?;
            return Ok(true);
        }
        if !selection.has_exact_snapshot(state.revision_base, state.revision) {
            return Ok(false);
        }
        let selected = selection
            .with_snapshot_records(self.directory_reader(), state, |tree, _, layout| {
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

    fn with_text_shards<T>(
        &self,
        search: impl FnOnce(&dyn kasumi_query::TextShardSet) -> Result<T>,
    ) -> ReadResult<Option<T>, Self::Failure> {
        self.check_deadline()?;
        let state = &self.generation.state;
        let Some(selection) = self.generation.application_selection.get() else {
            return Ok(None);
        };
        let selected = selection
            .with_text_records(
                self.directory_reader(),
                state,
                |tree, source, manifest, memory| {
                    let primary = selection.current_primary_manifest(source, state)?;
                    let primary = primary
                        .as_ref()
                        .map(|manifest| {
                            kasumi_store::ordered_pages::TreeReader::new(
                                source,
                                &manifest.page_space,
                                manifest.records,
                                None,
                            )
                        })
                        .transpose()?;
                    let collection = self.collection();
                    crate::application_text::search_collection(
                        tree,
                        source,
                        manifest,
                        &collection.definition,
                        |id, version| match &primary {
                            Some(primary) => crate::application_records::current_text_row(
                                primary,
                                &self.collection,
                                id,
                                version,
                                state.revision,
                            ),
                            None => Ok(crate::application_text::live_version(collection, id)
                                == Some(version)),
                        },
                        memory,
                        search,
                    )
                },
            )
            .map_err(|error| kasumi_query::ReadFailure::Source(DocumentSourceFailure(error)))?;
        self.check_deadline()?;
        match selected {
            None => Ok(None),
            Some(found) => Ok(Some(found?)),
        }
    }

    fn with_record<T>(
        &self,
        id: &str,
        expected_version: Option<u64>,
        cancellation: &QueryCancellation,
        lend: impl for<'a> FnOnce(Option<Record<'a>>) -> Result<T>,
    ) -> ReadResult<T, Self::Failure> {
        cancellation.check()?;
        self.with_primary_point(id, cancellation, |point, _| {
            cancellation.check()?;
            self.check_deadline()?;
            let version = match &point {
                PrimaryPoint::Live(slot) => Some(slot.version()),
                PrimaryPoint::Archived(reference) => Some(reference.version),
                PrimaryPoint::Missing => None,
            };
            if expected_version.is_some_and(|expected| version != Some(expected)) {
                return Err(corruption("source document expected version differs").into());
            }
            let body;
            let record = match &point {
                PrimaryPoint::Live(slot) => {
                    body = slot
                        .load_owned(self.resolver())
                        .map_err(|e| kasumi_query::ReadFailure::Source(DocumentSourceFailure(e)))?;
                    Some(Record::Live(body.as_ref()))
                }
                PrimaryPoint::Archived(reference) => Some(Record::Archived(reference)),
                PrimaryPoint::Missing => None,
            };
            cancellation.check()?;
            self.check_deadline()?;
            let result = lend(record)?;
            cancellation.check()?;
            Ok(result)
        })
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
        if let Some(selection) = self.generation.application_selection.get() {
            let selected = selection
                .with_serving_primary(self.directory_reader(), state, |tree, memory, layout| {
                    if layout < kasumi_store::application_manifest::DOCUMENT_HEADERS_LAYOUT {
                        return Ok(None);
                    }
                    let workspace =
                        crate::document_restore::ReadAdmissionFailure::reserve(memory, 2048)?;
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
