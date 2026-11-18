//! Read a chronological, fixed-range export. Each call checks the preceding event and decodes at most one additional
//! archive segment or a page of hot events. Signed continuations survive hot
//! records moving into archives and expire on restart or an authority change.
use super::*;
use ring::hmac;

const OUTPUT_WORK: u64 = 4 << 20;

fn expired() -> Error {
    Error::new(
        ErrorCode::CursorExpired,
        "tenant audit export expired or its source changed",
    )
}

fn tag_input(
    context: &RequestContext,
    epoch: u64,
    expires: u64,
    unsigned: &TenantAuditCursor,
) -> Result<String> {
    staged_digest(&(
        "kasumi.tenant.audit.export.v1",
        &context.principal,
        &context.scopes,
        &context.authorization,
        epoch,
        expires,
        unsigned,
    ))
    .map(|digest| digest.0)
}

fn open_ticket(
    key: &hmac::Key,
    context: &RequestContext,
    epoch: u64,
    token: &str,
    unsigned: &TenantAuditCursor,
) -> Result<u64> {
    let mut bytes = [0u8; 40];
    hex::decode_to_slice(token, &mut bytes).map_err(|_| expired())?;
    let expires = u64::from_be_bytes(bytes[..8].try_into().map_err(|_| expired())?);
    let digest = tag_input(context, epoch, expires, unsigned)?;
    hmac::verify(key, digest.as_bytes(), &bytes[8..]).map_err(|_| expired())?;
    Ok(expires)
}

fn read_error(error: anyhow::Error) -> Error {
    error.downcast_ref::<Error>().cloned().unwrap_or_else(|| {
        Error::new(
            ErrorCode::AuditUnavailable,
            "tenant audit archive or historical provider is unavailable",
        )
    })
}

fn initial(state: &TenantState) -> Result<TenantAuditCursor> {
    let retention = &state.audit_retention;
    let cursor = TenantAuditCursor {
        tenant: state.tenant.clone(),
        incarnation: state.incarnation.clone(),
        stream_id: retention.stream_id,
        next_sequence: 0,
        through_sequence: retention.next_sequence,
        snapshot_segments: retention.archive_segments,
        snapshot_head: retention.archive_head.as_ref().map(|r| r.object.clone()),
        snapshot_tail_sha256: state
            .audits
            .back()
            .map(|event| staged_digest(event).map(|r| r.0))
            .transpose()?,
        previous_record_sha256: None,
        ticket: None,
    };
    cursor.validate()?;
    Ok(cursor)
}

fn events(
    store: &TenantStore,
    state: &TenantState,
    cursor: &TenantAuditCursor,
    limit: u16,
    check: impl Fn() -> Result<()>,
) -> Result<Vec<TenantAuditRecord>> {
    let mut result = Vec::new();
    let mut bytes = 0usize;
    let mut append = |sequence, event: AuditEvent| -> Result<bool> {
        check()?;
        let record = TenantAuditRecord { sequence, event };
        let size = crate::accounting::encoded_len(&record)?;
        // All envelope fields (names, canonical links, digests and ticket)
        // together fit in 8 KiB. Check the exact final size before handoff.
        if bytes.saturating_add(size + 1) > MAX_TENANT_AUDIT_PAGE_BYTES - (8 << 10) {
            return Ok(false);
        }
        bytes += size + 1;
        result.push(record);
        Ok(true)
    };
    let start = cursor.next_sequence;
    let end = start
        .saturating_add(u64::from(limit))
        .min(cursor.through_sequence);
    if end == start {
        return Ok(result);
    }
    let retention = &state.audit_retention;
    if start >= retention.pruned_before {
        for sequence in start..end {
            let index =
                usize::try_from(sequence - retention.pruned_before).map_err(|_| expired())?;
            let event = state.audits.get(index).ok_or_else(expired)?;
            if !append(sequence, event.clone())? {
                break;
            }
        }
    } else {
        let head = retention.archive_head.as_ref().ok_or_else(expired)?;
        let reference = crate::tenant_audit_directory::containing(
            store,
            head,
            retention.archive_segments,
            start,
            || check().map_err(Into::into),
        )
        .map_err(read_error)?;
        let placement = store.tenant_audit_archive().map_err(read_error)?;
        let ciphertext = placement
            .cache()
            .read_blocking(&reference.object)
            .map_err(read_error)?;
        let inspected =
            kasumi_store::InspectedAuditDependency::from_link(&ciphertext, &reference.object)
                .map_err(|_| {
                    Error::new(
                        ErrorCode::Corruption,
                        "tenant audit archive digest or framing differs",
                    )
                })?;
        let segment = crate::state::snapshot_bundle::verify_inspected_dependency(
            state,
            store.storage_access().purpose(),
            store,
            &inspected,
        )
        .map_err(read_error)?;
        if segment.reference() != &reference {
            return Err(Error::new(
                ErrorCode::Corruption,
                "audit directory reference differs",
            ));
        }
        let mut full = false;
        segment
            .visit(|sequence, encoded| {
                check()?;
                if !full && (start..end).contains(&sequence) {
                    let event = kasumi_types::exact_json::decode_exact(
                        encoded,
                        MAX_AUDIT_EVENT_BYTES,
                        "tenant audit event",
                    )?;
                    full = !append(sequence, event)?;
                }
                Ok(())
            })
            .map_err(read_error)?;
    }
    if result.is_empty() {
        return Err(Error::new(
            ErrorCode::Corruption,
            "tenant audit page did not advance",
        ));
    }
    Ok(result)
}

impl Database {
    pub async fn export_tenant_audit(
        &self,
        context: &RequestContext,
        request: TenantAuditExportRequest,
    ) -> Result<AdmittedOutput<TenantAuditPage>> {
        let result = self.export_tenant_audit_inner(context, request).await;
        self.audit_result(context, result).await
    }

    async fn export_tenant_audit_inner(
        &self,
        context: &RequestContext,
        request: TenantAuditExportRequest,
    ) -> Result<AdmittedOutput<TenantAuditPage>> {
        self.access()?;
        self.engine.authorize(context, None, Action::Audit)?;
        request.validate()?;
        let token = QueryCancellation::default();
        let _cancel = CancelOnDrop(token.clone());
        let registration = self.work.begin(token.clone())?;
        let mut reservation = self.admission().reserve(OUTPUT_WORK, Some(token.clone()))?;
        self.barrier().await?;
        let generation = self.engine.generation()?;
        let state = &generation.state;
        self.engine
            .authorize_release(context, None, Action::Audit, state.policy_epoch)?;
        let (epoch, revision, strict) = (
            state.policy_epoch,
            state.revision,
            state.policy.strict_read_audit,
        );
        let key = self.audit_token_key()?;
        let now = u64::try_from(self.clock.now().as_millis()).map_err(|_| expired())?;
        let mut cursor = match &request.cursor {
            Some(cursor) => cursor.clone(),
            None => initial(state)?,
        };
        let expires = if let Some(ticket) = cursor.ticket.take() {
            open_ticket(key, context, epoch, &ticket, &cursor)?
        } else {
            if request.cursor.is_some() && cursor != initial(state)? {
                return Err(expired());
            }
            now.checked_add(state.limits.cursor_ttl_ms)
                .ok_or_else(expired)?
        };
        if now >= expires
            || cursor.tenant != state.tenant
            || cursor.incarnation != state.incarnation
            || cursor.stream_id != state.audit_retention.stream_id
            || cursor.through_sequence > state.audit_retention.next_sequence
        {
            return Err(expired());
        }
        let store = self.store.clone();
        let limit = request.limit;
        let clock = self.clock.clone();
        if cursor.next_sequence.saturating_sub(1) < state.audit_retention.pruned_before {
            reservation.reserve_additional(4 * MAX_AUDIT_SEGMENT_BYTES as u64)?;
        }
        let (mut page, mut reservation) = reservation
            .retained_read(token, move |reservation, token| {
                let _registration = registration;
                let state = &generation.state;
                let check = || {
                    token.check()?;
                    if clock.now() >= Duration::from_millis(expires) {
                        return Err(expired());
                    }
                    Ok(())
                };
                check()?;
                // Appends and new pruning preserve a captured root. Verify its
                // last range still names the same immutable prefix on this replica.
                if let Some(root) = &cursor.snapshot_head {
                    let retention = &state.audit_retention;
                    let head = retention.archive_head.as_ref().ok_or_else(expired)?;
                    let selected = crate::tenant_audit_directory::containing(
                        &store,
                        head,
                        retention.archive_segments,
                        root.next_sequence.checked_sub(1).ok_or_else(expired)?,
                        || check().map_err(Into::into),
                    )
                    .map_err(read_error)?;
                    if selected.object != *root {
                        return Err(expired());
                    }
                }
                if let Some(previous_sequence) = cursor.next_sequence.checked_sub(1) {
                    let previous = TenantAuditCursor {
                        next_sequence: previous_sequence,
                        ..cursor.clone()
                    };
                    let records = events(&store, state, &previous, 1, check)?;
                    let record = records.first().ok_or_else(expired)?;
                    if Some(record.event_sha256()?) != cursor.previous_record_sha256 {
                        return Err(expired());
                    }
                }
                let rows = events(&store, state, &cursor, limit, check)?;
                let previous = match rows.last() {
                    Some(row) => Some(row.event_sha256()?),
                    None => cursor.previous_record_sha256,
                };
                let next = cursor
                    .next_sequence
                    .checked_add(rows.len() as u64)
                    .ok_or_else(expired)?;
                Ok::<_, Error>((
                    TenantAuditPage {
                        tenant: cursor.tenant,
                        incarnation: cursor.incarnation,
                        stream_id: cursor.stream_id,
                        through_sequence: cursor.through_sequence,
                        next_sequence: next,
                        snapshot_head: cursor.snapshot_head,
                        snapshot_segments: cursor.snapshot_segments,
                        snapshot_tail_sha256: cursor.snapshot_tail_sha256,
                        previous_record_sha256: previous,
                        ticket: None,
                        records: rows,
                    },
                    reservation,
                ))
            })
            .await?;
        if page.next_sequence < page.through_sequence {
            let digest = tag_input(context, epoch, expires, &page.resumed())?;
            page.ticket = Some(hex::encode(
                [
                    expires.to_be_bytes().as_slice(),
                    hmac::sign(key, digest.as_bytes()).as_ref(),
                ]
                .concat(),
            ));
        }
        page.validate(&request)
            .map_err(|e| Error::new(ErrorCode::Corruption, e.message))?;
        if crate::accounting::encoded_len(&page)? > MAX_TENANT_AUDIT_PAGE_BYTES {
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                "tenant audit export exceeds page budget",
            ));
        }
        self.finish_tenant_audit_read(context, revision, epoch, strict, "tenant_audit_export")
            .await?;
        if self.clock.now() >= Duration::from_millis(expires) {
            return Err(expired());
        }
        reservation.retain(OUTPUT_WORK);
        Ok(AdmittedOutput::new(page, Arc::new(reservation)))
    }
}
