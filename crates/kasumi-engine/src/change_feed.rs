//! Pull-based durable change delivery. The caller controls page cadence; no
//! unbounded server stream, subscriber queue or per-subscriber resident state.
use super::*;
use crate::application_sources::SnapshotBoundary;

const MAX_EXAMINED: usize = 1000;

/// A page holds only commits intersecting its scan window and its own resolver.
pub(super) struct FeedPageSource {
    next_sequence: u64,
    event_count: usize,
    commits: Vec<Arc<ChangeCommit>>,
    max_result_bytes: usize,
    resolver: Option<Arc<dyn DocumentResolver>>,
}

impl FeedPageSource {
    pub(super) fn capture(
        generation: &crate::Generation,
        start: &ChangeFeedStart,
        verified_disk_end: Option<u64>,
        reserve: impl FnOnce(u64) -> Result<()>,
    ) -> Result<Self> {
        let feed = &generation.state.change_feed;
        let first = match start {
            ChangeFeedStart::Beginning => Some(1),
            ChangeFeedStart::After { cursor } => cursor.after_sequence.checked_add(1),
            ChangeFeedStart::Now => None,
        };
        let mut commits = Vec::new();
        let floor = feed.next_sequence.saturating_sub(feed.event_count as u64);
        if let Some(first) = first.filter(|&n| n >= floor && n < feed.next_sequence) {
            let last = first.saturating_add(MAX_EXAMINED as u64 - 1);
            let first_tail = first.max(verified_disk_end.unwrap_or(first));
            if first_tail <= last && first_tail < feed.next_sequence {
                // A continuation may start in the middle of one atomic commit.
                let lower = feed
                    .commits
                    .range(..=first_tail)
                    .next_back()
                    .map_or(first_tail, |(&n, _)| n);
                let count = feed.commits.range(lower..=last).count();
                reserve((count * std::mem::size_of::<Arc<ChangeCommit>>()) as u64)?;
                commits
                    .try_reserve_exact(count)
                    .map_err(|_| query_workspace_overflow())?;
                commits.extend(
                    feed.commits
                        .range(lower..=last)
                        .map(|(_, commit)| commit.clone()),
                );
            }
        }

        let resolver = generation
            .document_sources
            .get()
            .map(|owner| owner.clone() as Arc<dyn DocumentResolver>)
            .or_else(|| {
                generation
                    .staged_documents
                    .as_ref()
                    .map(|owner| Arc::new(owner.clone()) as Arc<dyn DocumentResolver>)
            });
        Ok(Self {
            next_sequence: feed.next_sequence,
            event_count: feed.event_count,
            commits,
            max_result_bytes: generation.state.limits.max_result_bytes,
            resolver,
        })
    }
}

// Request, output and source precede every charge; the registration is last.
// This owner retains its own Arc during all release checks, so a failed check
// cannot retire credit while an input or source is still being destroyed.
struct FeedRead {
    request: ReadChangeFeed,
    page: Option<ChangeFeedPage>,
    _permit: tokio::sync::OwnedSemaphorePermit,
    memory: Option<QueryMemory<Reservation>>,
    charge: Option<Arc<Reservation>>,
    registration: Arc<WorkRegistration>,
}
impl FeedRead {
    fn build(
        &mut self,
        boundary: &SnapshotBoundary<String>,
        input: &FeedPageSource,
        actor: &RequestContext,
        token: &QueryCancellation,
        source: Option<crate::application_records::SnapshotFeed<'_, '_>>,
    ) -> Result<ChangeFeedPage> {
        build_change_feed_page(
            boundary,
            input,
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
        let mut strict = [false; 16];
        let (revision, policy_epoch) = (state.revision, state.policy_epoch);
        for (slot, collection) in strict.iter_mut().zip(&read.request.collections) {
            self.engine.authorize_release(
                context,
                Some(collection),
                Action::Read,
                state.policy_epoch,
            )?;
            let definition = &state
                .collections
                .get(collection)
                .ok_or_else(|| Error::new(ErrorCode::NotFound, "change feed collection missing"))?
                .definition;
            *slot = state.policy.strict_read_audit || definition.strict_read_audit;
        }
        // Resolving an after-image can enter the native store. Hold the page's
        // original workspace, source, registration and permit in the child.
        let memory = read.memory.as_mut().expect("feed workspace present");
        memory.reserve(
            crate::snapshot_codec::inspect_typed_json_work(context)
                .map_err(|e| Error::new(ErrorCode::ResourceExhausted, e.to_string()))?,
        )?;
        memory.reserve(
            (std::mem::size_of::<FeedPageSource>()
                + std::mem::size_of::<SnapshotBoundary<String>>()
                + state.tenant.len()
                + state.incarnation.len()
                + 128) as u64,
        )?;
        let boundary = SnapshotBoundary::<String>::from(state);
        let selection = generation.application_selection.get().cloned();
        let verified_disk_end = selection
            .as_ref()
            .and_then(|s| s.verified_feed_end(state.revision_base, state.revision));
        let mut input = FeedPageSource::capture(
            &generation,
            &read.request.start,
            verified_disk_end,
            |bytes| memory.reserve(bytes),
        )?;
        drop(generation);
        let actor = context.clone();
        let owner = memory.workspace().blocking_owner();
        let read = tokio::select! {
            result = owner.read_child(cancellation.clone(), None, move |token| {
                let result = if let Some(selection) = selection {
                    selection.with_snapshot_feed(&boundary, input.next_sequence, |disk| {
                        input.commits.retain(|commit| commit.first_sequence.saturating_add(commit.records.len() as u64) > disk.end_sequence);
                        Ok(read.build(&boundary, &input, &actor, token, Some(disk)))
                    }).map_err(document_load_error)?
                } else { None };
                read.page = Some(match result { Some(page) => page?, None => read.build(&boundary, &input, &actor, token, None)? });
                drop(input);
                read.prepare_release()?;
                Ok(read)
            }) => result?,
            _ = cancelled(&cancellation) => return Err(cancelled_error()),
        };
        let releases = read
            .request
            .collections
            .iter()
            .map(String::as_str)
            .zip(strict)
            .collect::<Vec<_>>();
        self.release_collections(context, &releases, revision, policy_epoch, "change_feed")
            .await?;
        cancellation.check()?;
        self.admission().check_release(&cancellation)?;
        for collection in &read.request.collections {
            self.engine
                .authorize_release(context, Some(collection), Action::Read, policy_epoch)?;
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
    state: &SnapshotBoundary<String>,
    input: &FeedPageSource,
    context: &RequestContext,
    request: &ReadChangeFeed,
    cancellation: &QueryCancellation,
    memory: &mut QueryMemory<W>,
    disk: Option<crate::application_records::SnapshotFeed<'_, '_>>,
) -> Result<ChangeFeedPage> {
    memory.scope(|memory| {
        cancellation.check()?;
        let baseline = memory.live_bytes();
        let head_sequence = input
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
        let first_available_sequence = input
            .next_sequence
            .checked_sub(input.event_count as u64)
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
            request.limit.min(input.event_count).min(MAX_EXAMINED)
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
        if bytes > input.max_result_bytes {
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                "change feed cursor exceeds result budget",
            ));
        }
        let mut examined = 0usize;
        let mut append =
            |sequence, revision, ordinal, count, record: &ChangeRecord| -> Result<bool> {
                cancellation.check()?;
                if examined >= MAX_EXAMINED || events.len() >= request.limit {
                    return Ok(false);
                }
                examined += 1;
                if !request.collections.contains(&record.collection) {
                    next.after_sequence = sequence;
                    return Ok(examined < MAX_EXAMINED);
                }
                let document = record
                    .document
                    .as_ref()
                    .map(|slot| match slot.as_ref() {
                        DocumentSlot::Pending(document) => Ok(DocumentLoan::Pending(document)),
                        DocumentSlot::Stored(document) => {
                            let resolver = input.resolver.as_deref().ok_or_else(|| {
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
                    .is_none_or(|total| total > input.max_result_bytes)
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
                Ok(examined < MAX_EXAMINED && events.len() < request.limit)
            };
        // Appends never change an earlier commit within an incarnation.
        // The current retention floor applies to both halves. If a page ends
        // inside the disk prefix, leave the log tail for its continuation.
        let first_requested = after + 1;
        let tail = match disk {
            Some(disk) if first_requested < disk.end_sequence => {
                let complete =
                    disk.visit(first_available_sequence, first_requested, &mut append)?;
                complete.then_some(disk.end_sequence)
            }
            _ => Some(first_requested),
        };
        if let Some(tail) = tail.filter(|&start| start < input.next_sequence) {
            'commits: for commit in &input.commits {
                let skip = tail.saturating_sub(commit.first_sequence);
                let skip = usize::try_from(skip).unwrap_or(usize::MAX);
                for (ordinal, record) in commit.records.iter().enumerate().skip(skip) {
                    if !append(
                        commit.first_sequence + ordinal as u64,
                        commit.revision,
                        ordinal,
                        commit.records.len(),
                        record,
                    )? {
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
