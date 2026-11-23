//! Snapshot cursor ownership after the first page has been served.
use super::*;
use crate::application_records::PrimaryPoint;
use crate::application_sources::{SelectedApplication, SnapshotBoundary};
use crate::document_store::{GenerationDocuments, SharedRead};
use std::time::Instant;

pub(super) enum CursorDocuments {
    Generation(Arc<crate::Generation>),
    Disk(Box<DiskCursor>),
}

pub(super) struct DiskCursor {
    selection: SelectedApplication,
    boundary: SnapshotBoundary<String>,
    collection: String,
    pub(super) resolver: Arc<dyn GenerationDocuments>,
}

impl CursorDocuments {
    pub(super) fn capture(
        generation: &Arc<crate::Generation>,
        collection: &str,
        available: u64,
        memory: &mut QueryMemory<Reservation>,
    ) -> Result<(Self, u64)> {
        if let (Some(selection), Some(resolver)) = (
            generation.cursor_primary(),
            generation.document_sources.get(),
        ) {
            // Covers the boxed reader, its three copied strings and allocations.
            let bytes = (std::mem::size_of::<DiskCursor>()
                + 128
                + collection.len()
                + generation.state.tenant.len()
                + generation.state.incarnation.len()) as u64;
            if bytes > available {
                return Err(cursor_budget_exceeded());
            }
            memory.reserve(bytes)?;
            return Ok((
                Self::Disk(Box::new(DiskCursor {
                    selection: selection.clone(),
                    boundary: (&generation.state).into(),
                    collection: collection.to_owned(),
                    resolver: resolver.clone(),
                })),
                bytes,
            ));
        }
        Ok((Self::Generation(generation.clone()), 0))
    }

    pub(super) fn revision(&self) -> u64 {
        match self {
            Self::Generation(generation) => generation.state.revision,
            Self::Disk(disk) => disk.boundary.revision,
        }
    }

    pub(super) fn visit_versions(
        &self,
        collection: &str,
        remaining: kasumi_query::RemainingRows<'_>,
        reads: &DocumentReads,
        cancellation: &QueryCancellation,
        mut visit: impl FnMut(&str, Option<f32>, u64, u64) -> Result<()>,
    ) -> Result<()> {
        let check = || {
            cancellation.check()?;
            reads.check_deadline()
        };
        let unavailable = || {
            Error::new(
                ErrorCode::Unavailable,
                "selected archived content requires bounded hydration",
            )
        };
        check()?;
        match self {
            Self::Generation(generation) => {
                let documents = &generation.state.collections[collection].documents;
                for (id, score) in remaining {
                    check()?;
                    let slot = documents.get(id).ok_or_else(unavailable)?;
                    visit(id, score, slot.version(), pinned_slot_bytes(slot)?)?;
                }
            }
            Self::Disk(disk) => {
                let visit_headers =
                    |tree: &kasumi_store::ordered_pages::TreeReader<'_>| -> Result<()> {
                        for (id, score) in remaining {
                            check()?;
                            let header = crate::application_records::primary_header(
                                tree,
                                collection,
                                id,
                                disk.boundary.revision,
                            )
                            .map_err(document_load_error)?;
                            let Some((version, kasumi_query::RecordKind::Live)) = header else {
                                return Err(unavailable());
                            };
                            visit(id, score, version, 0)?;
                        }
                        Ok(())
                    };
                disk.selection
                    .with_primary_boundary(
                        reads.shared().map(SharedRead::selected),
                        &disk.boundary,
                        |tree, memory, _| {
                            let _workspace =
                                crate::document_restore::ReadAdmissionFailure::reserve(
                                    memory, 2048,
                                )?;
                            Ok(visit_headers(tree))
                        },
                    )
                    .map_err(document_load_error)?
                    .ok_or_else(|| {
                        Error::new(
                            ErrorCode::Corruption,
                            "cursor lost its verified primary directory",
                        )
                    })??;
            }
        }
        check()
    }

    pub(super) fn copy_page(
        &self,
        request: &QueryRequest,
        rows: &[PinnedRow],
        bound: kasumi_query::PageBound,
        cancellation: &QueryCancellation,
        deadline: Instant,
        memory: &mut QueryMemory<Reservation>,
    ) -> Result<Vec<QueryRow>> {
        let rows = rows
            .iter()
            .map(|row| (row.id.as_ref(), row.version, row.score));
        match self {
            Self::Generation(generation) => with_document_reads(generation, deadline, |reads| {
                kasumi_query::copy_page_from_source(
                    &reads.source(&request.collection)?,
                    rows,
                    &request.select,
                    bound,
                    cancellation,
                    memory,
                )
                .map_err(source_read_error)
            }),
            Self::Disk(disk) => {
                if disk.collection != request.collection {
                    return Err(Error::new(
                        ErrorCode::Corruption,
                        "cursor collection differs",
                    ));
                }
                let check = || {
                    cancellation.check()?;
                    if Instant::now() >= deadline {
                        return Err(DocumentReads::deadline_error());
                    }
                    Ok(())
                };
                check()?;
                let shared = disk.resolver.shared_read().map_err(document_load_error)?;
                let result = kasumi_query::copy_page_with_reader(
                    rows,
                    &request.select,
                    bound,
                    cancellation,
                    memory,
                    |id, version, copy| {
                        check()?;
                        let selected = disk
                            .selection
                            .with_primary_boundary(
                                shared.as_deref().map(SharedRead::selected),
                                &disk.boundary,
                                |tree, memory, _| {
                                    crate::application_records::admitted_snapshot_point(
                                        tree,
                                        memory,
                                        &disk.collection,
                                        id,
                                        disk.boundary.revision,
                                        || Ok(check()?),
                                    )
                                },
                            )
                            .map_err(document_load_error)?;
                        let Some((PrimaryPoint::Live(slot), _leases, _)) = selected else {
                            return Err(Error::new(
                                ErrorCode::Corruption,
                                "cursor lost its selected live point",
                            ));
                        };
                        if !slot.has_id(id) || slot.version() != version {
                            return Err(Error::new(
                                ErrorCode::Corruption,
                                "cursor live point identity differs",
                            ));
                        }
                        check()?;
                        let resolver: &dyn DocumentResolver = match shared.as_deref() {
                            Some(read) => read,
                            None => disk.resolver.as_ref(),
                        };
                        let document = slot
                            .load_owned(Some(resolver))
                            .map_err(document_load_error)?;
                        check()?;
                        let result = copy(document.as_ref())?;
                        check()?;
                        Ok(result)
                    },
                );
                retire_document_read(result, shared.map_or(Ok(()), SharedRead::finish))
            }
        }
    }
}
