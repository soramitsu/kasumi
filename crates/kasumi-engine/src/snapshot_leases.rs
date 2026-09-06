//! Coherent, bounded point and collection pages from one retained generation.
use super::*;

pub(super) struct RetainedSnapshot {
    generation: Arc<crate::Generation>,
    principal: String,
    created: Duration,
    ttl: Duration,
    term: u64,
    bytes: usize,
    _reservation: Reservation,
}

impl RetainedSnapshot {
    fn header(&self, lease_id: &str) -> SnapshotLease {
        let state = &self.generation.state;
        SnapshotLease {
            lease_id: lease_id.into(),
            revision: state.revision,
            incarnation: state.incarnation.clone(),
            policy_epoch: state.policy_epoch,
            schema_epoch: state.schema_epoch,
            ttl_ms: self.ttl.as_millis() as u64,
        }
    }
    pub(super) fn retain(&self, now: Duration, pressured: bool) -> bool {
        !pressured && now.saturating_sub(self.created) < self.ttl
    }
}

impl Database {
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
        self.access()?;
        let _registration = self.work.begin(QueryCancellation::default())?;
        self.engine
            .authorize_discovery(context, Action::Read, None)?;
        self.barrier().await?;
        let generation = self.engine.generation()?;
        self.engine.authorize_discovery(
            context,
            Action::Read,
            Some(generation.state.policy_epoch),
        )?;
        if request.ttl_ms == 0 || request.ttl_ms > generation.state.limits.cursor_ttl_ms {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "snapshot lease TTL outside bounds",
            ));
        }
        // This estimate charges the entire retained generation, including its
        // metadata. RSS admission still measures actual resident allocations.
        let bytes = generation.snapshot_bytes()?.saturating_mul(3);
        if bytes > generation.state.limits.atomic.max_snapshot_lease_bytes {
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                "snapshot generation exceeds lease byte quota",
            ));
        }
        let mut reservation = self.admission().reserve(bytes as u64, None)?;
        reservation.retain(bytes as u64);
        let lease_id = uuid::Uuid::new_v4().to_string();
        let lease = Arc::new(RetainedSnapshot {
            generation,
            principal: context.principal.clone(),
            created: self.clock.now(),
            ttl: Duration::from_millis(request.ttl_ms),
            term: self.group.raft().metrics().borrow().current_term,
            bytes,
            _reservation: reservation,
        });
        let header = lease.header(&lease_id);
        {
            let mut leases = self.snapshot_leases.lock().map_err(|_| {
                Error::new(ErrorCode::Unavailable, "snapshot lease storage unavailable")
            })?;
            leases.retain(|_, lease| lease.retain(self.clock.now(), false));
            let retained = leases
                .values()
                .try_fold(bytes, |total, lease| total.checked_add(lease.bytes))
                .ok_or_else(|| {
                    Error::new(ErrorCode::ResourceExhausted, "snapshot lease byte overflow")
                })?;
            let limits = &lease.generation.state.limits.atomic;
            if leases.len() >= limits.max_snapshot_leases
                || retained > limits.max_snapshot_lease_bytes
            {
                return Err(Error::new(
                    ErrorCode::ResourceExhausted,
                    "snapshot lease quota exhausted",
                ));
            }
            leases.insert(lease_id.clone(), lease.clone());
        }
        let release = self
            .release_event(
                context,
                None,
                header.revision,
                lease.generation.state.policy.strict_read_audit,
                header.policy_epoch,
                "discovery",
            )
            .await;
        if let Err(error) = release {
            self.snapshot_leases
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&lease_id);
            return Err(error);
        }
        if let Err(error) = self.checked_snapshot_lease(context, &lease_id) {
            self.snapshot_leases
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&lease_id);
            return Err(error);
        }
        Ok(header)
    }

    fn checked_snapshot_lease(
        &self,
        context: &RequestContext,
        lease_id: &str,
    ) -> Result<Arc<RetainedSnapshot>> {
        self.access()?;
        self.engine
            .authorize_discovery(context, Action::Read, None)?;
        let generation = self.engine.generation()?;
        let lease = self
            .snapshot_leases
            .lock()
            .map_err(|_| Error::new(ErrorCode::Unavailable, "snapshot lease storage unavailable"))?
            .get(lease_id)
            .cloned()
            .ok_or_else(|| Error::new(ErrorCode::CursorExpired, "snapshot lease unavailable"))?;
        if !lease.retain(self.clock.now(), false)
            || lease.principal != context.principal
            || lease.generation.state.incarnation != generation.state.incarnation
            || lease.generation.state.policy_epoch != generation.state.policy_epoch
            || lease.generation.state.schema_epoch != generation.state.schema_epoch
            || lease.term != self.group.raft().metrics().borrow().current_term
        {
            return Err(Error::new(
                ErrorCode::CursorExpired,
                "snapshot lease expired or authority changed",
            ));
        }
        Ok(lease)
    }

    pub async fn close_snapshot_lease(
        &self,
        context: &RequestContext,
        lease_id: &str,
    ) -> Result<()> {
        let result = (|| {
            self.access()?;
            self.engine
                .authorize_discovery(context, Action::Read, None)?;
            let mut leases = self.snapshot_leases.lock().map_err(|_| {
                Error::new(ErrorCode::Unavailable, "snapshot lease storage unavailable")
            })?;
            if leases
                .get(lease_id)
                .is_some_and(|lease| lease.principal != context.principal)
            {
                return Err(Error::new(
                    ErrorCode::Forbidden,
                    "snapshot lease belongs to another principal",
                ));
            }
            leases.remove(lease_id);
            Ok(())
        })();
        self.audit_result(context, result).await
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
        let lease = self.checked_snapshot_lease(context, &request.lease_id)?;
        if request.documents.is_empty() || request.documents.len() > 256 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "snapshot point page outside bounds",
            ));
        }
        let mut keys = BTreeSet::new();
        let mut collections = BTreeSet::new();
        for key in &request.documents {
            validate_name(&key.collection)?;
            validate_name(&key.id)?;
            if !keys.insert(key) {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "duplicate snapshot point",
                ));
            }
            self.engine.authorize_release(
                context,
                Some(&key.collection),
                Action::Read,
                lease.generation.state.policy_epoch,
            )?;
            if !lease
                .generation
                .state
                .collections
                .contains_key(&key.collection)
            {
                return Err(Error::new(
                    ErrorCode::NotFound,
                    "snapshot collection not found",
                ));
            }
            collections.insert(key.collection.clone());
        }
        let cancellation = QueryCancellation::default();
        let _cancel_on_drop = CancelOnDrop(cancellation.clone());
        let registration = Arc::new(self.work.begin(cancellation.clone())?);
        let snapshot = ReadSnapshotRequest {
            documents: request.documents,
            queries: vec![],
        };
        let reservation = self.admission().reserve(
            snapshot_workspace(&lease.generation.state.limits, &snapshot),
            Some(cancellation.clone()),
        )?;
        let permit = self.query_slots.clone().try_acquire_owned().map_err(|_| {
            Error::new(
                ErrorCode::ResourceExhausted,
                "snapshot concurrency limit reached",
            )
        })?;
        let work = SnapshotWork {
            generation: lease.generation.clone(),
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
        self.release_snapshot_page(
            context,
            &request.lease_id,
            &lease,
            &collections,
            &cancellation,
        )
        .await?;
        Ok(response)
    }

    async fn release_snapshot_page(
        &self,
        context: &RequestContext,
        lease_id: &str,
        lease: &RetainedSnapshot,
        collections: &BTreeSet<String>,
        cancellation: &QueryCancellation,
    ) -> Result<()> {
        let state = &lease.generation.state;
        for collection in collections {
            self.release(
                context,
                collection,
                state.revision,
                state.policy.strict_read_audit
                    || state.collections[collection].definition.strict_read_audit,
                state.policy_epoch,
            )
            .await?;
        }
        self.checked_snapshot_lease(context, lease_id)?;
        self.admission().check_release(cancellation)?;
        for collection in collections {
            self.engine.authorize_release(
                context,
                Some(collection),
                Action::Read,
                state.policy_epoch,
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
        let lease = self.checked_snapshot_lease(context, &request.lease_id)?;
        validate_name(&request.collection)?;
        if let Some(after) = &request.after_id {
            validate_name(after)?;
        }
        self.engine.authorize_release(
            context,
            Some(&request.collection),
            Action::Read,
            lease.generation.state.policy_epoch,
        )?;
        if !lease
            .generation
            .state
            .collections
            .contains_key(&request.collection)
        {
            return Err(Error::new(
                ErrorCode::NotFound,
                "snapshot collection not found",
            ));
        }
        if request.limit == 0 || request.limit > lease.generation.state.limits.max_page_size {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "snapshot scan limit outside bounds",
            ));
        }
        let cancellation = QueryCancellation::default();
        let _cancel_on_drop = CancelOnDrop(cancellation.clone());
        let registration = Arc::new(self.work.begin(cancellation.clone())?);
        let reservation = self.admission().reserve(
            lease
                .generation
                .state
                .limits
                .max_result_bytes
                .saturating_mul(3) as u64,
            Some(cancellation.clone()),
        )?;
        let permit = self.query_slots.clone().try_acquire_owned().map_err(|_| {
            Error::new(
                ErrorCode::ResourceExhausted,
                "snapshot concurrency limit reached",
            )
        })?;
        let work = ScanWork {
            lease: lease.clone(),
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
            &request.lease_id,
            &lease,
            &BTreeSet::from([request.collection]),
            &cancellation,
        )
        .await?;
        Ok(response)
    }
}

struct ScanWork {
    lease: Arc<RetainedSnapshot>,
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
        let state = &self.lease.generation.state;
        let collection = &state.collections[&self.request.collection];
        let mut response = SnapshotScanPage {
            snapshot: self.lease.header(&self.request.lease_id),
            collection: self.request.collection.clone(),
            data_epoch: collection.data_epoch,
            documents: vec![],
            next_after_id: None,
        };
        let ids = self.lease.generation.indexes.document_ids_after(
            &self.request.collection,
            self.request.after_id.as_deref(),
            self.request.limit + 1,
        )?;
        // Reserve space for the continuation ID before cloning document bodies.
        let mut bytes = crate::accounting::encoded_len(&response)?.saturating_add(256);
        for id in ids {
            let document = collection.documents.get(&id).ok_or_else(|| {
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
