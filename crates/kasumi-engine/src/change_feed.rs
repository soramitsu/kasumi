//! Pull-based durable change delivery. The caller controls page cadence; no
//! unbounded server stream, subscriber queue or per-subscriber resident state.
use super::*;

// Request, output and source precede every charge; the registration is last.
// This owner retains its own Arc during all release checks, so a failed check
// cannot retire credit while an input or source is still being destroyed.
struct FeedRead {
    request: ReadChangeFeed,
    page: Option<ChangeFeedPage>,
    generation: Arc<crate::Generation>,
    _permit: tokio::sync::OwnedSemaphorePermit,
    memory: Option<QueryMemory<Reservation>>,
    charge: Option<Arc<Reservation>>,
    registration: Arc<WorkRegistration>,
}
impl FeedRead {
    fn prepare_release(&mut self) -> Result<()> {
        let memory = self.memory.as_mut().expect("feed workspace present");
        memory.reserve(OUTPUT_CHARGE_BYTES)?;
        let mut reservation = self
            .memory
            .take()
            .expect("feed workspace present")
            .into_workspace();
        reservation.retain_workspace();
        self.charge = Some(Arc::new(reservation));
        Ok(())
    }

    fn into_admitted(mut self) -> RegisteredOutput<ChangeFeedPage> {
        RegisteredOutput {
            response: AdmittedOutput::new(
                self.page.take().expect("completed feed page"),
                self.charge.as_ref().expect("retained feed charge").clone(),
            ),
            _registration: self.registration.clone(),
        }
    }
}

impl Database {
    pub async fn read_change_feed(
        &self,
        context: &RequestContext,
        request: ReadChangeFeed,
    ) -> Result<AdmittedOutput<ChangeFeedPage>> {
        let result = self.read_change_feed_inner(context, request).await;
        self.audit_result(context, result)
            .await
            .map(|output| output.response)
    }

    async fn read_change_feed_inner(
        &self,
        context: &RequestContext,
        request: ReadChangeFeed,
    ) -> Result<RegisteredOutput<ChangeFeedPage>> {
        self.access()?;
        if request.collections.is_empty() || request.collections.len() > 16 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "change feed collection scope outside bounds",
            ));
        }
        for collection in &request.collections {
            validate_name(collection)?;
            self.engine
                .authorize(context, Some(collection), Action::Read)?;
        }
        let cancellation = QueryCancellation::default();
        let _cancel_on_drop = CancelOnDrop(cancellation.clone());
        let registration = Arc::new(self.work.begin(cancellation.clone())?);
        let permit = self.query_slots.clone().try_acquire_owned().map_err(|_| {
            Error::new(
                ErrorCode::ResourceExhausted,
                "change feed concurrency limit reached",
            )
        })?;
        tokio::select! {
            result = self.barrier() => result?,
            _ = cancelled(&cancellation) => return Err(cancelled_error()),
        }
        let generation = self.engine.generation()?;
        let state = &generation.state;
        if request.limit == 0 || request.limit > state.limits.max_page_size {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "change feed page limit outside bounds",
            ));
        }
        // Preserve the existing physical floor. Typed page clones grow this
        // same reservation; the floor is not a bound on the resulting JSON heap.
        let workspace = (state.limits.max_result_bytes as u64)
            .checked_mul(3)
            .ok_or_else(query_workspace_overflow)?;
        let reservation = self
            .admission()
            .reserve(workspace, Some(cancellation.clone()))?;
        let mut read = FeedRead {
            request,
            page: None,
            generation,
            _permit: permit,
            memory: Some(QueryMemory::empty(reservation)),
            charge: None,
            registration,
        };
        // Request ownership remains provisionally accounted like other service
        // inputs; page vectors, cursor fields and after-image clones are typed.
        read.memory
            .as_mut()
            .expect("feed workspace present")
            .reserve(query_input_workspace(&read.request, 1)?)?;
        let state = &read.generation.state;
        for collection in &read.request.collections {
            self.engine.authorize_release(
                context,
                Some(collection),
                Action::Read,
                state.policy_epoch,
            )?;
            if !state.collections.contains_key(collection) {
                return Err(Error::new(
                    ErrorCode::NotFound,
                    "change feed collection missing",
                ));
            }
        }
        read.page = Some(build_change_feed_page(
            state,
            context,
            &read.request,
            &cancellation,
            read.memory.as_mut().expect("feed workspace present"),
        )?);
        // No page allocation follows this transition. Strict auditing gets the
        // completed operation slot while its immutable output retains the bytes.
        read.prepare_release()?;
        let state = &read.generation.state;
        for collection in &read.request.collections {
            self.release_event(
                context,
                Some(collection),
                state.revision,
                state.policy.strict_read_audit
                    || state.collections[collection].definition.strict_read_audit,
                state.policy_epoch,
                "change_feed",
            )
            .await?;
        }
        cancellation.check()?;
        self.admission().check_release(&cancellation)?;
        for collection in &read.request.collections {
            self.engine.authorize_release(
                context,
                Some(collection),
                Action::Read,
                state.policy_epoch,
            )?;
        }
        self.access()?;
        Ok(read.into_admitted())
    }
}

// Borrow the complete typed fields to perform wire admission before cloning
// any rejected event. Document serialization preserves canonical literal JSON.
#[derive(serde::Serialize)]
struct BorrowedEvent<'a> {
    sequence: u64,
    revision: u64,
    ordinal: usize,
    commit_event_count: usize,
    collection: &'a str,
    id: &'a str,
    document: Option<&'a Document>,
}
#[derive(serde::Serialize)]
struct BorrowedEnvelope<'a> {
    kind: &'static str,
    revision: u64,
    first_available_sequence: u64,
    head_sequence: u64,
    events: &'a [ChangeEvent],
    next: &'a ChangeFeedCursor,
    caught_up: bool,
}

pub(super) fn build_change_feed_page<W: kasumi_query::QueryWorkspace>(
    state: &TenantState,
    context: &RequestContext,
    request: &ReadChangeFeed,
    cancellation: &QueryCancellation,
    memory: &mut QueryMemory<W>,
) -> Result<ChangeFeedPage> {
    memory.scope(|memory| {
        cancellation.check()?;
        let baseline = memory.live_bytes();
        let feed = &state.change_feed;
        let head_sequence = feed
            .next_sequence
            .checked_sub(1)
            .ok_or_else(|| Error::new(ErrorCode::Corruption, "change feed sequence is invalid"))?;
        let after = match &request.start {
            ChangeFeedStart::Beginning => 0,
            ChangeFeedStart::Now => head_sequence,
            ChangeFeedStart::After { cursor } => {
                if cursor.tenant != context.tenant
                    || cursor.principal != context.principal
                    || cursor.incarnation != state.incarnation
                    || cursor.collections != request.collections
                {
                    return Err(Error::new(
                        ErrorCode::CursorExpired,
                        "change feed cursor identity or collection scope changed",
                    ));
                }
                if cursor.after_sequence > head_sequence {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "change feed cursor is beyond committed head",
                    ));
                }
                cursor.after_sequence
            }
        };
        let first_available_sequence = feed.first_available_sequence();
        if after + 1 < first_available_sequence {
            return Ok((
                ChangeFeedPage::RetentionGap {
                    first_available_sequence,
                    head_sequence,
                    requested_after_sequence: after,
                },
                0,
            ));
        }
        let capacity = if after == head_sequence {
            0
        } else {
            request.limit.min(feed.event_count).min(1000)
        };
        memory.reserve(kasumi_query::change_feed_page_workspace_bytes(
            &context.tenant,
            &state.incarnation,
            &context.principal,
            &request.collections,
            capacity,
        )?)?;
        let mut next = ChangeFeedCursor {
            tenant: context.tenant.clone(),
            incarnation: state.incarnation.clone(),
            principal: context.principal.clone(),
            collections: request.collections.clone(),
            after_sequence: after,
        };
        let mut events = Vec::with_capacity(capacity);
        let mut bytes = crate::accounting::encoded_len(&BorrowedEnvelope {
            kind: "events",
            revision: state.revision,
            first_available_sequence,
            head_sequence,
            events: &[],
            next: &next,
            caught_up: false,
        })?
        .checked_add(32)
        .ok_or_else(query_workspace_overflow)?;
        if bytes > state.limits.max_result_bytes {
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                "change feed cursor exceeds result budget",
            ));
        }
        let start = feed
            .commits
            .range(..=after + 1)
            .next_back()
            .map_or(after + 1, |(&sequence, _)| sequence);
        let mut examined = 0usize;
        'commits: for (_, commit) in feed.commits.range(start..) {
            for (ordinal, record) in commit.records.iter().enumerate() {
                let sequence = commit.first_sequence + ordinal as u64;
                if sequence <= after {
                    continue;
                }
                cancellation.check()?;
                if examined >= 1000 || events.len() >= request.limit {
                    break 'commits;
                }
                examined += 1;
                if !request.collections.contains(&record.collection) {
                    next.after_sequence = sequence;
                    continue;
                }
                let borrowed = BorrowedEvent {
                    sequence,
                    revision: commit.revision,
                    ordinal,
                    commit_event_count: commit.records.len(),
                    collection: &record.collection,
                    id: &record.id,
                    document: record.document.as_deref(),
                };
                let event_bytes = crate::accounting::encoded_len(&borrowed)?
                    .checked_add(1)
                    .ok_or_else(query_workspace_overflow)?;
                if bytes
                    .checked_add(event_bytes)
                    .is_none_or(|total| total > state.limits.max_result_bytes)
                {
                    if events.is_empty() {
                        return Err(Error::new(
                            ErrorCode::ResourceExhausted,
                            "change event exceeds page byte budget",
                        ));
                    }
                    break 'commits;
                }
                if events.len() == capacity {
                    return Err(Error::new(
                        ErrorCode::Corruption,
                        "change feed event count differs from committed metadata",
                    ));
                }
                memory.reserve(kasumi_query::change_event_clone_bytes(record)?)?;
                let event = ChangeEvent {
                    sequence,
                    revision: commit.revision,
                    ordinal,
                    commit_event_count: commit.records.len(),
                    collection: record.collection.clone(),
                    id: record.id.clone(),
                    document: record.document.as_deref().cloned(),
                };
                bytes += event_bytes;
                next.after_sequence = sequence;
                events.push(event);
            }
        }
        cancellation.check()?;
        let page = ChangeFeedPage::Events {
            revision: state.revision,
            first_available_sequence,
            head_sequence,
            caught_up: next.after_sequence == head_sequence,
            events,
            next,
        };
        Ok((page, memory.live_bytes() - baseline))
    })
}
