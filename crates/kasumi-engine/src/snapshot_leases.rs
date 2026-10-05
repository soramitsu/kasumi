//! Coherent pages hold only their bounded selection outside the root manager.
use super::*;
use crate::state::lease_retention::{LeaseHandle, PageAccess, PageSelection, SelectedSnapshot};

// Keep selected payloads ahead of their admission owner on every preparation
// error and cancellation, including before a blocking worker is spawned.
struct SelectedPageInput {
    handle: Arc<LeaseHandle>,
    generation: Arc<crate::Generation>,
    scan_ids: Vec<String>,
    scan_has_more: bool,
    selected_input_bytes: u64,
    memory: kasumi_query::QueryMemory<Reservation>,
}
impl SelectedPageInput {
    fn new(selected: SelectedSnapshot) -> Self {
        Self {
            handle: selected.handle,
            generation: selected.generation,
            scan_ids: selected.scan_ids,
            scan_has_more: selected.scan_has_more,
            selected_input_bytes: selected.selected_input_bytes,
            memory: kasumi_query::QueryMemory::empty(selected.reservation),
        }
    }
}

impl Database {
    // Publication and selection share a mutex. Waiting for it, walking a changed
    // payload, and dropping retained roots run on owned blocking work, so they
    // cannot starve the async replication and credential-renewal tasks.
    async fn snapshot_retention_work<T: Send + 'static>(
        &self,
        cancellation: QueryCancellation,
        action: impl FnOnce(Arc<crate::TenantEngine>) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        self.access()?;
        let registration = self.work.begin(cancellation.clone())?;
        let engine = self.engine.clone();
        let worker = tokio::task::spawn_blocking(move || {
            let result = action(engine);
            (result, registration)
        });
        let (result, _registration) = tokio::select! {
            result = tokio::time::timeout(Duration::from_secs(5), worker) => result
                .map_err(|_| Error::new(ErrorCode::ResourceExhausted, "snapshot retention deadline exceeded"))?
                .map_err(|_| Error::new(ErrorCode::Unavailable, "snapshot retention worker failed"))?,
            _ = cancelled(&cancellation) => return Err(cancelled_error()),
        };
        result
    }

    pub async fn open_snapshot_lease(
        &self,
        context: &RequestContext,
        request: OpenSnapshotLease,
    ) -> Result<SnapshotLease> {
        let result = self.open_snapshot_lease_inner(context, request).await;
        self.audit_result(context, result).await
    }

    async fn open_snapshot_lease_inner(
        &self,
        context: &RequestContext,
        request: OpenSnapshotLease,
    ) -> Result<SnapshotLease> {
        self.engine
            .authorize_discovery(context, Action::Read, None)?;
        self.barrier().await?;
        let cancellation = QueryCancellation::default();
        let _cancel_on_drop = CancelOnDrop(cancellation.clone());
        let admitted_context = context.clone();
        let clock = self.clock.clone();
        let term = self.group.raft().metrics().borrow().current_term;
        let node = self.admission().clone();
        let lease = self
            .snapshot_retention_work(cancellation, move |engine| {
                engine.leases.open(
                    &engine,
                    &admitted_context,
                    request.ttl_ms,
                    clock,
                    term,
                    &node,
                )
            })
            .await?;
        let header = lease.header.clone();
        let release = self
            .release_event(
                context,
                None,
                header.revision,
                lease.strict_read_audit,
                header.policy_epoch,
                "discovery",
            )
            .await;
        if let Err(error) = release {
            // Closing is also owned blocking work; cancellation may detach it,
            // but it retains the engine and registration until actual completion.
            let _ = self
                .close_snapshot_lease_inner(context, &header.lease_id)
                .await;
            return Err(error);
        }
        self.checked_snapshot_lease(context, &header.lease_id)
            .await?;
        Ok(header)
    }

    pub(super) async fn checked_snapshot_lease(
        &self,
        context: &RequestContext,
        lease_id: &str,
    ) -> Result<Arc<LeaseHandle>> {
        let context = context.clone();
        let lease_id = lease_id.to_owned();
        let term = self.group.raft().metrics().borrow().current_term;
        self.snapshot_retention_work(QueryCancellation::default(), move |engine| {
            engine
                .leases
                .checked_handle(&engine, &context, &lease_id, term)
        })
        .await
    }

    pub async fn close_snapshot_lease(
        &self,
        context: &RequestContext,
        lease_id: &str,
    ) -> Result<()> {
        let result = self.close_snapshot_lease_inner(context, lease_id).await;
        self.audit_result(context, result).await
    }

    async fn close_snapshot_lease_inner(
        &self,
        context: &RequestContext,
        lease_id: &str,
    ) -> Result<()> {
        let context = context.clone();
        let lease_id = lease_id.to_owned();
        self.snapshot_retention_work(QueryCancellation::default(), move |engine| {
            engine.authorize_discovery(&context, Action::Read, None)?;
            engine.leases.close(&context, &lease_id)
        })
        .await
    }

    async fn select_snapshot_page(
        &self,
        context: &RequestContext,
        lease_id: &str,
        request: PageSelection,
        cancellation: &QueryCancellation,
    ) -> Result<SelectedSnapshot> {
        let context = context.clone();
        let lease_id = lease_id.to_owned();
        let term = self.group.raft().metrics().borrow().current_term;
        let node = self.admission().clone();
        let token = cancellation.clone();
        self.snapshot_retention_work(cancellation.clone(), move |engine| {
            engine.leases.select(
                &engine,
                &lease_id,
                request,
                PageAccess {
                    context: &context,
                    term,
                    node: &node,
                    cancellation: &token,
                },
            )
        })
        .await
    }

    pub async fn read_snapshot_page(
        &self,
        context: &RequestContext,
        request: ReadSnapshotPage,
    ) -> Result<AdmittedOutput<SnapshotReadResponse>> {
        let result = self.read_snapshot_page_inner(context, request).await;
        self.audit_result(context, result)
            .await
            .map(|output| output.response)
    }

    async fn read_snapshot_page_inner(
        &self,
        context: &RequestContext,
        request: ReadSnapshotPage,
    ) -> Result<RegisteredOutput<SnapshotReadResponse>> {
        self.barrier().await?;
        let cancellation = QueryCancellation::default();
        let _cancel_on_drop = CancelOnDrop(cancellation.clone());
        let registration = Arc::new(self.work.begin(cancellation.clone())?);
        let permit = self.query_slots.clone().try_acquire_owned().map_err(|_| {
            Error::new(
                ErrorCode::ResourceExhausted,
                "snapshot concurrency limit reached",
            )
        })?;
        let mut input = SelectedPageInput::new(
            self.select_snapshot_page(
                context,
                &request.lease_id,
                PageSelection::Points(request.documents.clone()),
                &cancellation,
            )
            .await?,
        );
        input.memory.reserve(input.selected_input_bytes)?;
        let point_metadata_bytes = request.documents.iter().try_fold(1024u64, |bytes, key| {
            bytes
                .checked_add(key.collection.len() as u64)
                .and_then(|bytes| bytes.checked_add(key.id.len() as u64))
                .and_then(|bytes| bytes.checked_add(1024))
                .ok_or_else(|| {
                    Error::new(
                        ErrorCode::ResourceExhausted,
                        "snapshot point workspace overflow",
                    )
                })
        })?;
        input.memory.reserve(point_metadata_bytes)?;
        let collections = request
            .documents
            .iter()
            .map(|key| {
                let strict = input.generation.state.policy.strict_read_audit
                    || input.generation.state.collections[&key.collection]
                        .definition
                        .strict_read_audit;
                (key.collection.clone(), strict)
            })
            .collect();
        let snapshot = ReadSnapshotRequest {
            documents: request.documents,
            queries: vec![],
            time_bounds: None,
        };
        let work = SnapshotWork {
            generation: self
                .hydrate_history(
                    input.generation,
                    &snapshot.documents,
                    &[],
                    &cancellation,
                    &mut input.memory,
                )
                .await?,
            request: snapshot,
            cancellation: cancellation.clone(),
            _permit: permit,
            memory: input.memory,
            registration,
        };
        let worker = tokio::task::spawn_blocking(move || work.run());
        let output = tokio::select! {
            result = tokio::time::timeout(Duration::from_secs(5), worker) => result
                .map_err(|_| Error::new(ErrorCode::ResourceExhausted, "snapshot page deadline exceeded"))?
                .map_err(|_| Error::new(ErrorCode::Unavailable, "snapshot page worker failed"))?,
            _ = cancelled(&cancellation) => return Err(cancelled_error()),
        };
        let output = output.into_admitted()?;
        self.release_snapshot_page(context, &input.handle, &collections, &cancellation)
            .await?;
        Ok(output)
    }

    async fn release_snapshot_page(
        &self,
        context: &RequestContext,
        lease: &LeaseHandle,
        collections: &BTreeMap<String, bool>,
        cancellation: &QueryCancellation,
    ) -> Result<()> {
        for (collection, strict) in collections {
            self.release(
                context,
                collection,
                lease.header.revision,
                *strict,
                lease.header.policy_epoch,
            )
            .await?;
        }
        self.checked_snapshot_lease(context, &lease.header.lease_id)
            .await?;
        if !lease.live() {
            return Err(Error::new(
                ErrorCode::CursorExpired,
                "snapshot lease expired before response release",
            ));
        }
        self.admission().check_release(cancellation)?;
        for collection in collections.keys() {
            self.engine.authorize_release(
                context,
                Some(collection),
                Action::Read,
                lease.header.policy_epoch,
            )?;
        }
        Ok(())
    }

    pub async fn scan_snapshot_page(
        &self,
        context: &RequestContext,
        request: ScanSnapshotPage,
    ) -> Result<AdmittedOutput<SnapshotScanPage>> {
        let result = self.scan_snapshot_page_inner(context, request).await;
        self.audit_result(context, result)
            .await
            .map(|output| output.response)
    }

    async fn scan_snapshot_page_inner(
        &self,
        context: &RequestContext,
        request: ScanSnapshotPage,
    ) -> Result<RegisteredOutput<SnapshotScanPage>> {
        self.barrier().await?;
        let cancellation = QueryCancellation::default();
        let _cancel_on_drop = CancelOnDrop(cancellation.clone());
        let registration = Arc::new(self.work.begin(cancellation.clone())?);
        let permit = self.query_slots.clone().try_acquire_owned().map_err(|_| {
            Error::new(
                ErrorCode::ResourceExhausted,
                "snapshot concurrency limit reached",
            )
        })?;
        let mut input = SelectedPageInput::new(
            self.select_snapshot_page(
                context,
                &request.lease_id,
                PageSelection::Scan(request.clone()),
                &cancellation,
            )
            .await?,
        );
        input.memory.reserve(input.selected_input_bytes)?;
        // Admit the page worker's keys and request clone before creating them.
        let key_bytes = input.scan_ids.iter().try_fold(1024u64, |bytes, id| {
            bytes
                .checked_add(request.collection.len() as u64)
                .and_then(|bytes| bytes.checked_add(id.len() as u64))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<DocumentKey>() as u64))
                .ok_or_else(|| {
                    Error::new(
                        ErrorCode::ResourceExhausted,
                        "snapshot scan workspace overflow",
                    )
                })
        })?;
        let request_bytes = crate::accounting::encoded_len(&request)?
            .checked_mul(3)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<ScanSnapshotPage>()))
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::ResourceExhausted,
                    "snapshot scan workspace overflow",
                )
            })?;
        input
            .memory
            .reserve(key_bytes.checked_add(request_bytes as u64).ok_or_else(|| {
                Error::new(
                    ErrorCode::ResourceExhausted,
                    "snapshot scan workspace overflow",
                )
            })?)?;
        let keys = input
            .scan_ids
            .iter()
            .map(|id| DocumentKey {
                collection: request.collection.clone(),
                id: id.clone(),
            })
            .collect::<Vec<_>>();
        let strict = input.generation.state.policy.strict_read_audit
            || input.generation.state.collections[&request.collection]
                .definition
                .strict_read_audit;
        let work = ScanWork {
            lease: input.handle.clone(),
            generation: self
                .hydrate_history(
                    input.generation,
                    &keys,
                    &[],
                    &cancellation,
                    &mut input.memory,
                )
                .await?,
            ids: input.scan_ids,
            has_more: input.scan_has_more,
            request: request.clone(),
            cancellation: cancellation.clone(),
            _permit: permit,
            memory: input.memory,
            registration,
        };
        let worker = tokio::task::spawn_blocking(move || work.run());
        let output = tokio::select! {
            result = tokio::time::timeout(Duration::from_secs(5), worker) => result
                .map_err(|_| Error::new(ErrorCode::ResourceExhausted, "snapshot scan deadline exceeded"))?
                .map_err(|_| Error::new(ErrorCode::Unavailable, "snapshot scan worker failed"))?,
            _ = cancelled(&cancellation) => return Err(cancelled_error()),
        };
        let output = output.into_admitted()?;
        self.release_snapshot_page(
            context,
            &input.handle,
            &BTreeMap::from([(request.collection, strict)]),
            &cancellation,
        )
        .await?;
        Ok(output)
    }
}

struct ScanWork {
    lease: Arc<LeaseHandle>,
    generation: Arc<crate::Generation>,
    ids: Vec<String>,
    has_more: bool,
    request: ScanSnapshotPage,
    cancellation: QueryCancellation,
    _permit: tokio::sync::OwnedSemaphorePermit,
    memory: kasumi_query::QueryMemory<Reservation>,
    registration: Arc<WorkRegistration>,
}
struct ScanOutput {
    response: Result<SnapshotScanPage>,
    memory: kasumi_query::QueryMemory<Reservation>,
    _registration: Arc<WorkRegistration>,
}
impl ScanOutput {
    fn into_admitted(mut self) -> Result<RegisteredOutput<SnapshotScanPage>> {
        self.response.as_ref().map_err(|error| error.clone())?;
        self.memory.reserve(OUTPUT_CHARGE_BYTES)?;
        let mut reservation = self.memory.into_workspace();
        reservation.retain_workspace();
        let charge = Arc::new(reservation);
        Ok(RegisteredOutput {
            response: AdmittedOutput::new(self.response.expect("checked scan response"), charge),
            _registration: self._registration,
        })
    }
}
impl ScanWork {
    fn run(mut self) -> ScanOutput {
        let response = self.evaluate();
        ScanOutput {
            response,
            memory: self.memory,
            _registration: self.registration,
        }
    }
    fn evaluate(&mut self) -> Result<SnapshotScanPage> {
        let state = &self.generation.state;
        let collection = &state.collections[&self.request.collection];
        let source = self.generation.document_source(&self.request.collection)?;
        let request = &self.request;
        let cancellation = &self.cancellation;
        let ids = &self.ids;
        let lease = &self.lease;
        let has_more = self.has_more;
        let baseline = self.memory.live_bytes();
        self.memory.scope(|memory| {
            cancellation.check()?;
            // Keep the selected input charged while allocating a page. The header
            // allowance is provisional; document bodies use the allocation-free
            // heap walk shared by point pages and lease selection.
            let metadata_bytes = crate::accounting::encoded_len(&lease.header)?
                .checked_mul(3)
                .and_then(|bytes| bytes.checked_add(request.collection.len()))
                .and_then(|bytes| bytes.checked_add(1024))
                .and_then(|bytes| {
                    ids.len()
                        .checked_mul(std::mem::size_of::<Document>())
                        .and_then(|slots| bytes.checked_add(slots))
                })
                .ok_or_else(|| {
                    Error::new(
                        ErrorCode::ResourceExhausted,
                        "snapshot scan workspace overflow",
                    )
                })?;
            memory.reserve(metadata_bytes as u64)?;
            let mut response = SnapshotScanPage {
                snapshot: lease.header.clone(),
                collection: request.collection.clone(),
                data_epoch: collection.data_epoch,
                documents: Vec::with_capacity(ids.len()),
                next_after_id: None,
            };
            // Reserve space for the continuation ID before cloning document bodies.
            let mut bytes = crate::accounting::encoded_len(&response)?.saturating_add(256);
            for id in ids {
                let page_full = source
                    .with_record(id, None, cancellation, |record| {
                        let document = match record {
                            Some(Record::Live(document)) => document,
                            Some(Record::Archived(_)) => {
                                return Err(Error::new(
                                    ErrorCode::Unavailable,
                                    "snapshot archived content requires bounded hydration",
                                ));
                            }
                            None => {
                                return Err(Error::new(
                                    ErrorCode::Corruption,
                                    "snapshot ID index has no document",
                                ));
                            }
                        };
                        let additional =
                            crate::accounting::encoded_len(document)?.saturating_add(1);
                        if response.documents.len() == request.limit
                            || bytes.saturating_add(additional) > state.limits.max_result_bytes
                        {
                            let last = response.documents.last().ok_or_else(|| {
                                Error::new(
                                    ErrorCode::ResourceExhausted,
                                    "snapshot scan document cannot fit one page",
                                )
                            })?;
                            response.next_after_id = Some(last.id.clone());
                            return Ok(true);
                        }
                        memory.reserve(crate::state::lease_retention::document_heap(
                            document,
                            usize::MAX,
                        )? as u64)?;
                        bytes = bytes.saturating_add(additional);
                        response.documents.push(document.clone());
                        Ok(false)
                    })
                    .map_err(ReadFailure::into_query_error)?;
                if page_full {
                    break;
                }
            }
            if has_more {
                response.next_after_id = response
                    .documents
                    .last()
                    .map(|document| document.id.clone());
            }
            if crate::accounting::encoded_len(&response)? > state.limits.max_result_bytes {
                return Err(Error::new(
                    ErrorCode::ResourceExhausted,
                    "snapshot scan response exceeds byte limit",
                ));
            }
            cancellation.check()?;
            Ok((response, memory.live_bytes() - baseline))
        })
    }
}

#[cfg(test)]
#[path = "snapshot_page_workspace_tests.rs"]
mod workspace_tests;
