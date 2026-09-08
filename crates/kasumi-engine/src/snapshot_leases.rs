//! Coherent pages hold only their bounded selection outside the root manager.
use super::*;
use crate::state::lease_retention::{LeaseHandle, PageAccess, PageSelection, SelectedSnapshot};

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
    ) -> Result<SnapshotReadResponse> {
        let result = self.read_snapshot_page_inner(context, request).await;
        self.audit_result(context, result).await
    }

    async fn read_snapshot_page_inner(
        &self,
        context: &RequestContext,
        request: ReadSnapshotPage,
    ) -> Result<SnapshotReadResponse> {
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
        let SelectedSnapshot {
            handle,
            generation,
            reservation,
            ..
        } = self
            .select_snapshot_page(
                context,
                &request.lease_id,
                PageSelection::Points(request.documents.clone()),
                &cancellation,
            )
            .await?;
        let collections = request
            .documents
            .iter()
            .map(|key| {
                let strict = generation.state.policy.strict_read_audit
                    || generation.state.collections[&key.collection]
                        .definition
                        .strict_read_audit;
                (key.collection.clone(), strict)
            })
            .collect();
        let snapshot = ReadSnapshotRequest {
            documents: request.documents,
            queries: vec![],
        };
        let work = SnapshotWork {
            generation: self
                .hydrate_history(generation, &snapshot.documents, &[], &cancellation)
                .await?,
            request: snapshot,
            cancellation: cancellation.clone(),
            _permit: permit,
            reservation,
            registration,
        };
        let worker = tokio::task::spawn_blocking(move || work.run());
        let SnapshotOutput {
            response,
            mut reservation,
            _registration,
        } = tokio::select! {
            result = tokio::time::timeout(Duration::from_secs(5), worker) => result
                .map_err(|_| Error::new(ErrorCode::ResourceExhausted, "snapshot page deadline exceeded"))?
                .map_err(|_| Error::new(ErrorCode::Unavailable, "snapshot page worker failed"))?,
            _ = cancelled(&cancellation) => return Err(cancelled_error()),
        };
        let response = response?;
        reservation.retain_workspace();
        self.release_snapshot_page(context, &handle, &collections, &cancellation)
            .await?;
        Ok(response)
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
    ) -> Result<SnapshotScanPage> {
        let result = self.scan_snapshot_page_inner(context, request).await;
        self.audit_result(context, result).await
    }

    async fn scan_snapshot_page_inner(
        &self,
        context: &RequestContext,
        request: ScanSnapshotPage,
    ) -> Result<SnapshotScanPage> {
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
        let SelectedSnapshot {
            handle,
            generation,
            scan_ids,
            scan_has_more,
            reservation,
        } = self
            .select_snapshot_page(
                context,
                &request.lease_id,
                PageSelection::Scan(request.clone()),
                &cancellation,
            )
            .await?;
        let keys = scan_ids
            .iter()
            .map(|id| DocumentKey {
                collection: request.collection.clone(),
                id: id.clone(),
            })
            .collect::<Vec<_>>();
        let strict = generation.state.policy.strict_read_audit
            || generation.state.collections[&request.collection]
                .definition
                .strict_read_audit;
        let work = ScanWork {
            lease: handle.clone(),
            generation: self
                .hydrate_history(generation, &keys, &[], &cancellation)
                .await?,
            ids: scan_ids,
            has_more: scan_has_more,
            request: request.clone(),
            cancellation: cancellation.clone(),
            _permit: permit,
            reservation,
            registration,
        };
        let worker = tokio::task::spawn_blocking(move || work.run());
        let ScanOutput {
            response,
            mut reservation,
            _registration,
        } = tokio::select! {
            result = tokio::time::timeout(Duration::from_secs(5), worker) => result
                .map_err(|_| Error::new(ErrorCode::ResourceExhausted, "snapshot scan deadline exceeded"))?
                .map_err(|_| Error::new(ErrorCode::Unavailable, "snapshot scan worker failed"))?,
            _ = cancelled(&cancellation) => return Err(cancelled_error()),
        };
        let response = response?;
        reservation.retain_workspace();
        self.release_snapshot_page(
            context,
            &handle,
            &BTreeMap::from([(request.collection, strict)]),
            &cancellation,
        )
        .await?;
        Ok(response)
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
    reservation: Reservation,
    registration: Arc<WorkRegistration>,
}
struct ScanOutput {
    response: Result<SnapshotScanPage>,
    reservation: Reservation,
    _registration: Arc<WorkRegistration>,
}
impl ScanWork {
    fn run(self) -> ScanOutput {
        let response = self.evaluate();
        ScanOutput {
            response,
            reservation: self.reservation,
            _registration: self.registration,
        }
    }
    fn evaluate(&self) -> Result<SnapshotScanPage> {
        let state = &self.generation.state;
        let collection = &state.collections[&self.request.collection];
        let mut response = SnapshotScanPage {
            snapshot: self.lease.header.clone(),
            collection: self.request.collection.clone(),
            data_epoch: collection.data_epoch,
            documents: vec![],
            next_after_id: None,
        };
        // Reserve space for the continuation ID before cloning document bodies.
        let mut bytes = crate::accounting::encoded_len(&response)?.saturating_add(256);
        for id in &self.ids {
            let document = collection.documents.get(id).ok_or_else(|| {
                Error::new(ErrorCode::Corruption, "snapshot ID index has no document")
            })?;
            self.cancellation.check()?;
            let additional = crate::accounting::encoded_len(document)?.saturating_add(1);
            if response.documents.len() == self.request.limit
                || bytes.saturating_add(additional) > state.limits.max_result_bytes
            {
                let last = response.documents.last().ok_or_else(|| {
                    Error::new(
                        ErrorCode::ResourceExhausted,
                        "snapshot scan document cannot fit one page",
                    )
                })?;
                response.next_after_id = Some(last.id.clone());
                break;
            }
            bytes = bytes.saturating_add(additional);
            response.documents.push(document.as_ref().clone());
        }
        if self.has_more {
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
        self.cancellation.check()?;
        Ok(response)
    }
}
