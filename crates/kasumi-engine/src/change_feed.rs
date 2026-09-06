//! Pull-based durable change delivery. The caller controls page cadence; no
//! unbounded server stream, subscriber queue or per-subscriber resident state.
use super::*;

impl Database {
    pub async fn read_change_feed(
        &self,
        context: &RequestContext,
        request: ReadChangeFeed,
    ) -> Result<ChangeFeedPage> {
        let result = self.read_change_feed_inner(context, request).await;
        self.audit_result(context, result).await
    }

    async fn read_change_feed_inner(
        &self,
        context: &RequestContext,
        request: ReadChangeFeed,
    ) -> Result<ChangeFeedPage> {
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
        let _registration = self.work.begin(cancellation.clone())?;
        let _permit = self.query_slots.clone().try_acquire_owned().map_err(|_| {
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
        let _reservation = self.admission().reserve(
            state.limits.max_result_bytes.saturating_mul(3) as u64,
            Some(cancellation.clone()),
        )?;
        for collection in &request.collections {
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
        let feed = &state.change_feed;
        let head_sequence = feed.next_sequence - 1;
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
        let page = if after + 1 < first_available_sequence {
            ChangeFeedPage::RetentionGap {
                first_available_sequence,
                head_sequence,
                requested_after_sequence: after,
            }
        } else {
            let mut next = ChangeFeedCursor {
                tenant: context.tenant.clone(),
                incarnation: state.incarnation.clone(),
                principal: context.principal.clone(),
                collections: request.collections.clone(),
                after_sequence: after,
            };
            let mut events = Vec::new();
            let mut bytes = crate::accounting::encoded_len(&ChangeFeedPage::Events {
                revision: state.revision,
                first_available_sequence,
                head_sequence,
                events: vec![],
                next: next.clone(),
                caught_up: false,
            })?
            .saturating_add(32);
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
                    let event = ChangeEvent {
                        sequence,
                        revision: commit.revision,
                        ordinal,
                        commit_event_count: commit.records.len(),
                        collection: record.collection.clone(),
                        id: record.id.clone(),
                        document: record.document.clone(),
                    };
                    let event_bytes = crate::accounting::encoded_len(&event)?.saturating_add(1);
                    if bytes.saturating_add(event_bytes) > state.limits.max_result_bytes {
                        if events.is_empty() {
                            return Err(Error::new(
                                ErrorCode::ResourceExhausted,
                                "change event exceeds page byte budget",
                            ));
                        }
                        break 'commits;
                    }
                    bytes += event_bytes;
                    next.after_sequence = sequence;
                    events.push(event);
                }
            }
            ChangeFeedPage::Events {
                revision: state.revision,
                first_available_sequence,
                head_sequence,
                caught_up: next.after_sequence == head_sequence,
                events,
                next,
            }
        };
        for collection in &request.collections {
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
        for collection in &request.collections {
            self.engine.authorize_release(
                context,
                Some(collection),
                Action::Read,
                state.policy_epoch,
            )?;
        }
        self.access()?;
        Ok(page)
    }
}
