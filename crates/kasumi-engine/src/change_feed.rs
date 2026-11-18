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
    fn build(
        &mut self,
        actor: &RequestContext,
        token: &QueryCancellation,
        source: Option<crate::application_records::SnapshotFeed<'_, '_>>,
    ) -> Result<ChangeFeedPage> {
        build_change_feed_page(
            &self.generation.state,
            self.generation.document_resolver(),
            actor,
            &self.request,
            token,
            self.memory.as_mut().expect("feed workspace present"),
            source,
        )
    }

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
        // Resolving an after-image can enter the native store. Hold the page's
        // original workspace, source, registration and permit in the child.
        let memory = read.memory.as_mut().expect("feed workspace present");
        memory.reserve(
            crate::snapshot_codec::inspect_typed_json_work(context)
                .map_err(|e| Error::new(ErrorCode::ResourceExhausted, e.to_string()))?,
        )?;
        let actor = context.clone();
        let owner = memory.workspace().blocking_owner();
        let read = tokio::select! {
            result = owner.read_child(cancellation.clone(), None, move |token| {
                let generation = read.generation.clone();
                let state = &generation.state;
                let selection = generation.application_selection.get().filter(|s| {
                    s.has_exact_snapshot(state.revision_base, state.revision)
                });
                // A deployed pre-directory snapshot and an ordinary entry still
                // use their own pinned generation. A bad installed tree fails.
                let result = if let Some(selection) = selection {
                    selection.with_snapshot_records(state, |tree, memory, _| {
                        Ok(read.build(&actor, token, Some(crate::application_records::SnapshotFeed { tree, memory })))
                    }).map_err(document_load_error)?
                } else { None };
                read.page = Some(match result { Some(page) => page?, None => read.build(&actor, token, None)? });
                read.prepare_release()?;
                Ok(read)
            }) => result?,
            _ = cancelled(&cancellation) => return Err(cancelled_error()),
        };
        let state = &read.generation.state;
        let releases = read
            .request
            .collections
            .iter()
            .map(|collection| {
                let strict = state.policy.strict_read_audit
                    || state.collections[collection].definition.strict_read_audit;
                (collection.as_str(), strict)
            })
            .collect::<Vec<_>>();
        self.release_collections(
            context,
            &releases,
            state.revision,
            state.policy_epoch,
            "change_feed",
        )
        .await?;
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
    resolver: Option<&dyn DocumentResolver>,
    context: &RequestContext,
    request: &ReadChangeFeed,
    cancellation: &QueryCancellation,
    memory: &mut QueryMemory<W>,
    disk: Option<crate::application_records::SnapshotFeed<'_, '_>>,
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
        let first_available_sequence = feed
            .next_sequence
            .checked_sub(feed.event_count as u64)
            .filter(|sequence| *sequence > 0)
            .ok_or_else(|| Error::new(ErrorCode::Corruption, "invalid change feed bounds"))?;
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
        let mut examined = 0usize;
        let mut append =
            |sequence, revision, ordinal, count, record: &ChangeRecord| -> Result<bool> {
                cancellation.check()?;
                if examined >= 1000 || events.len() >= request.limit {
                    return Ok(false);
                }
                examined += 1;
                if !request.collections.contains(&record.collection) {
                    next.after_sequence = sequence;
                    return Ok(examined < 1000);
                }
                let document = record
                    .document
                    .as_ref()
                    .map(|slot| match slot.as_ref() {
                        DocumentSlot::Pending(document) => Ok(DocumentLoan::Pending(document)),
                        DocumentSlot::Stored(document) => {
                            let resolver = resolver.ok_or_else(|| {
                                Error::new(
                                    ErrorCode::Unavailable,
                                    "change feed document resolver is unavailable",
                                )
                            })?;
                            document
                                .load(resolver)
                                .map(DocumentLoan::Stored)
                                .map_err(document_load_error)
                        }
                    })
                    .transpose()?;
                let decoded = document.as_ref().map(AsRef::as_ref);
                let borrowed = BorrowedEvent {
                    sequence,
                    revision,
                    ordinal,
                    commit_event_count: count,
                    collection: &record.collection,
                    id: &record.id,
                    document: decoded,
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
                    return Ok(false);
                }
                if events.len() == capacity {
                    return Err(Error::new(
                        ErrorCode::Corruption,
                        "change feed event count differs from committed metadata",
                    ));
                }
                memory.reserve(kasumi_query::change_event_clone_bytes(record, decoded)?)?;
                let event = ChangeEvent {
                    sequence,
                    revision,
                    ordinal,
                    commit_event_count: count,
                    collection: record.collection.clone(),
                    id: record.id.clone(),
                    document: decoded.cloned(),
                };
                bytes += event_bytes;
                next.after_sequence = sequence;
                events.push(event);
                Ok(examined < 1000 && events.len() < request.limit)
            };
        if let Some(disk) = disk {
            disk.visit(
                first_available_sequence,
                after + 1,
                feed.next_sequence,
                state.revision,
                append,
            )?;
        } else {
            let start = feed
                .commits
                .range(..=after + 1)
                .next_back()
                .map_or(after + 1, |(&sequence, _)| sequence);
            'commits: for (_, commit) in feed.commits.range(start..) {
                for (ordinal, record) in commit.records.iter().enumerate() {
                    let sequence = commit.first_sequence + ordinal as u64;
                    if sequence > after
                        && !append(
                            sequence,
                            commit.revision,
                            ordinal,
                            commit.records.len(),
                            record,
                        )?
                    {
                        break 'commits;
                    }
                }
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
