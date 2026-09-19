//! Ordered large-transaction lifecycle. All payload storage is replicated and
//! encrypted with its tenant, and remains outside the document/index namespace.
use super::*;

pub(crate) fn identity(principal: &str, transaction_id: &str) -> Result<String> {
    validate_name(principal)?;
    validate_name(transaction_id)?;
    Ok(staged_digest(&(principal, transaction_id))?.0)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) fn validate_manifest(manifest: &StagedManifest, limits: &Limits) -> Result<()> {
    if manifest.chunk_digests.is_empty()
        || manifest.chunk_digests.len() > MAX_STAGED_CHUNKS
        || manifest
            .chunk_digests
            .iter()
            .any(|digest| !valid_digest(digest))
        || manifest.operation_count == 0
        || manifest.operation_count > limits.atomic.max_operations
        || manifest.read_assertion_count > limits.atomic.max_read_assertions
        || manifest.encoded_chunk_bytes == 0
        || manifest.encoded_chunk_bytes > limits.atomic.max_transaction_bytes
        || manifest.write_collections.is_empty()
        || manifest.write_collections.len() > 1024
        || manifest.read_collections.len() > 1024
        || manifest.write_collections.len() > limits.max_collections
        || manifest.read_collections.len() > limits.max_collections
    {
        return Err(Error::new(
            ErrorCode::ResourceExhausted,
            "staged manifest outside bounds",
        ));
    }
    for collection in manifest
        .read_collections
        .iter()
        .chain(&manifest.write_collections)
    {
        validate_name(collection)?;
    }
    Ok(())
}

pub(crate) fn authorize_manifest(
    state: &TenantState,
    context: &RequestContext,
    manifest: &StagedManifest,
) -> Result<()> {
    for collection in &manifest.write_collections {
        authorize_state(state, context, Some(collection), Action::Write)?;
    }
    for collection in &manifest.read_collections {
        authorize_state(state, context, Some(collection), Action::Read)?;
    }
    Ok(())
}

fn historical_limits() -> Limits {
    Limits {
        max_collections: 1024,
        atomic: AtomicLimits::default(),
        ..Limits::default()
    }
}

// Current credentials authorize access; caller-supplied scope only narrows it.
pub(crate) fn authorize_scope(
    state: &TenantState,
    context: &RequestContext,
    scope: &StagedTransactionScope,
) -> Result<()> {
    authorize_discovery_state(state, context, Action::Write)?;
    scope.validate()?;
    if scope.tenant != state.tenant
        || scope.tenant != context.tenant
        || scope.principal != context.principal
    {
        return Err(Error::new(
            ErrorCode::Forbidden,
            "staged original scope differs from verified principal or tenant",
        ));
    }
    validate_scope_lineage(state, scope)
}

fn validate_scope_lineage(state: &TenantState, scope: &StagedTransactionScope) -> Result<()> {
    scope.validate()?;
    if scope.tenant != state.tenant
        || (scope.incarnation != state.incarnation
            && !state
                .restore_lineage
                .iter()
                .any(|link| link.checkpoint.source_incarnation == scope.incarnation))
    {
        return Err(Error::new(
            ErrorCode::Conflict,
            "staged original incarnation is outside retained lineage",
        ));
    }
    Ok(())
}

fn require_current_creation(state: &TenantState, scope: &StagedTransactionScope) -> Result<()> {
    if scope.incarnation != state.incarnation {
        return Err(Error::new(
            ErrorCode::Conflict,
            "cannot create an absent historical staged identity",
        ));
    }
    Ok(())
}

fn require_upload_incarnation(state: &TenantState, stage: &StagedTransaction) -> Result<()> {
    if stage.is_active() && stage.scope.incarnation != state.incarnation {
        return Err(Error::new(
            ErrorCode::Conflict,
            "historical staged upload may only be observed, stopped or expired",
        ));
    }
    Ok(())
}

pub(crate) fn authorize_begin(
    state: &TenantState,
    context: &RequestContext,
    request: &BeginStagedTransaction,
) -> Result<()> {
    authorize_scope(state, context, &request.scope)?;
    authorize_manifest(state, context, &request.manifest)?;
    let key = identity(&context.principal, &request.transaction_id)?;
    if let Some(stage) = state.staged_transactions.get(&key) {
        if stage.scope != request.scope {
            return Err(Error::new(
                ErrorCode::Conflict,
                "staged permanent identity belongs to a different original scope",
            ));
        }
        require_upload_incarnation(state, stage)
    } else {
        require_current_creation(state, &request.scope)
    }
}

pub(crate) fn authorize_upload(
    state: &TenantState,
    context: &RequestContext,
    reference: &StagedTransactionRef,
) -> Result<()> {
    require_upload_incarnation(state, lookup(state, context, reference)?)
}

pub(crate) fn authorize_stop_envelope(
    state: &TenantState,
    context: &RequestContext,
    request: &StopStagedTransaction,
) -> Result<()> {
    authorize_scope(state, context, &request.original.scope)?;
    validate_name(&request.original.transaction_id)?;
    if request.original.ttl_ms == 0 || request.original.ttl_ms > 86_400_000 {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "staged upload TTL outside bounds",
        ));
    }
    validate_manifest(&request.original.manifest, &historical_limits())?;
    authorize_manifest(state, context, &request.original.manifest)
}

pub(crate) fn authorize_stop(
    state: &TenantState,
    context: &RequestContext,
    request: &StopStagedTransaction,
) -> Result<()> {
    authorize_scope(state, context, &request.original.scope)?;
    let key = identity(&context.principal, &request.original.transaction_id)?;
    if let Some(stage) = state.staged_transactions.get(&key) {
        if stage.scope != request.original.scope {
            return Err(Error::new(
                ErrorCode::Conflict,
                "staged permanent identity belongs to a different original scope",
            ));
        }
    } else {
        require_current_creation(state, &request.original.scope)?;
    }
    authorize_stop_envelope(state, context, request)
}

pub(crate) fn validate_admission(
    state: &TenantState,
    context: &RequestContext,
    assertions: &[ReadAssertion],
    evaluated_at_ms: u64,
) -> Result<()> {
    if assertions.len() > state.limits.atomic.max_read_assertions {
        return Err(Error::new(
            ErrorCode::ResourceExhausted,
            "staged stop admission exceeds assertion limit",
        ));
    }
    if !assertions
        .iter()
        .any(|a| matches!(a, ReadAssertion::Snapshot { .. }))
        || !assertions
            .iter()
            .any(|a| matches!(a, ReadAssertion::Before { .. }))
    {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "staged stop requires snapshot and deadline assertions",
        ));
    }
    for assertion in assertions {
        if let ReadAssertion::Document { collection, .. }
        | ReadAssertion::Collection { collection, .. } = assertion
        {
            authorize_state(state, context, Some(collection), Action::Read)?;
        }
    }
    validate_read_assertions(
        state,
        &assertions.iter().collect::<Vec<_>>(),
        evaluated_at_ms,
        state.limits.atomic.max_read_assertions,
    )
}

pub(crate) fn lookup<'a>(
    state: &'a TenantState,
    context: &RequestContext,
    reference: &StagedTransactionRef,
) -> Result<&'a StagedTransaction> {
    authorize_scope(state, context, &reference.scope)?;
    if !valid_digest(&reference.manifest_digest) {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "invalid staged manifest digest",
        ));
    }
    let key = identity(&context.principal, &reference.transaction_id)?;
    let transaction = state
        .staged_transactions
        .get(&key)
        .ok_or_else(|| Error::new(ErrorCode::NotFound, "staged transaction not found"))?;
    authorize_manifest(state, context, &transaction.manifest)?;
    if transaction.scope != reference.scope
        || transaction.manifest_digest != reference.manifest_digest
    {
        return Err(Error::new(
            ErrorCode::Conflict,
            "staged manifest identity mismatch",
        ));
    }
    Ok(transaction)
}

/// Canonical permanent header bytes and outstanding capacity owned by an active
/// identity. Chunk payloads have their own budget and never enter these totals.
pub(crate) fn permanent_charge(key: &str, stage: &StagedTransaction) -> Result<(u64, u64)> {
    let used = crate::accounting::staged_header(key, stage)?;
    if !stage.is_active() {
        return Ok((used, 0));
    }
    // These counters may grow while receiving chunks. Normalize to their maximum
    // widths so every append transfers existing reservation rather than requiring
    // fresh permanent capacity. The expiry and immutable identity stay unchanged.
    let mut maximum = stage.clone();
    maximum.chunks.clear();
    maximum.stored_chunk_bytes = usize::MAX;
    maximum.uploaded_payload_bytes = usize::MAX;
    maximum.uploaded_operations = usize::MAX;
    maximum.uploaded_read_assertions = usize::MAX;
    let capacity = crate::accounting::staged_header(key, &maximum)?
        .checked_add(STAGED_OUTCOME_HEADROOM as u64)
        .ok_or_else(|| Error::new(ErrorCode::Corruption, "staged terminal capacity overflow"))?;
    let reserve = capacity
        .checked_sub(used)
        .ok_or_else(|| Error::new(ErrorCode::Corruption, "staged terminal capacity mismatch"))?;
    Ok((used, reserve))
}

/// Commit one permanent point record, both totals, and its active index together.
/// A terminal transition must fit the capacity admitted by its own original Begin.
pub(crate) fn replace_record(
    state: &mut TenantState,
    key: String,
    stage: StagedTransaction,
) -> Result<()> {
    let old = state.staged_transactions.get(&key);
    let (old_used, old_reserved) = old
        .map(|s| permanent_charge(&key, s))
        .transpose()?
        .unwrap_or((0, 0));
    let (new_used, new_reserved) = permanent_charge(&key, &stage)?;
    if old.is_some_and(StagedTransaction::is_active)
        && !stage.is_active()
        && old_used
            .checked_add(old_reserved)
            .is_none_or(|n| new_used > n)
    {
        return Err(Error::new(
            ErrorCode::Corruption,
            "staged outcome exceeded its original reservation",
        ));
    }
    let used = state
        .permanent_staged_bytes
        .checked_sub(old_used)
        .and_then(|n| n.checked_add(new_used))
        .ok_or_else(|| {
            Error::new(
                ErrorCode::Corruption,
                "permanent staged accounting mismatch",
            )
        })?;
    let reserved = state
        .reserved_staged_terminal_bytes
        .checked_sub(old_reserved)
        .and_then(|n| n.checked_add(new_reserved))
        .ok_or_else(|| {
            Error::new(
                ErrorCode::Corruption,
                "staged terminal reservation mismatch",
            )
        })?;
    if used
        .checked_add(reserved)
        .is_none_or(|n| n > state.limits.atomic.max_permanent_staged_bytes)
    {
        return Err(Error::new(
            ErrorCode::QuotaExceeded,
            "permanent staged byte quota exhausted",
        ));
    }
    if stage.is_active() {
        state.active_staged_transactions.insert(key.clone());
    } else {
        state.active_staged_transactions.remove(&key);
    }
    state.staged_transactions.insert(key, stage);
    state.permanent_staged_bytes = used;
    state.reserved_staged_terminal_bytes = reserved;
    Ok(())
}

fn clear_payload(transaction: &mut StagedTransaction) {
    transaction.chunks.clear();
    transaction.stored_chunk_bytes = 0;
    transaction.uploaded_payload_bytes = 0;
    transaction.uploaded_operations = 0;
    transaction.uploaded_read_assertions = 0;
}

fn terminal(transaction: &mut StagedTransaction, outcome: Result<WriteReceipt>) {
    clear_payload(transaction);
    transaction.outcome = StagedOutcome::Finished { outcome };
}

fn expire_active(state: &mut TenantState, now: u64, revision: u64) -> Result<()> {
    let expired: Vec<_> = state
        .active_staged_transactions
        .iter()
        .filter(|key| {
            state
                .staged_transactions
                .get(*key)
                .is_some_and(|stage| stage.expires_at_ms.is_some_and(|expires| expires <= now))
        })
        .cloned()
        .collect();
    for key in expired {
        let mut transaction = state.staged_transactions[&key].clone();
        clear_payload(&mut transaction);
        transaction.outcome = StagedOutcome::Expired {
            receipt: WriteReceipt {
                revision,
                versions: BTreeMap::new(),
            },
        };
        replace_record(state, key, transaction)?;
    }
    Ok(())
}

pub(super) fn validate_budget(state: &TenantState, limits: &Limits) -> Result<()> {
    if state
        .permanent_staged_bytes
        .checked_add(state.reserved_staged_terminal_bytes)
        .is_none_or(|n| n > limits.atomic.max_permanent_staged_bytes)
        || state.active_staged_transactions.len() > limits.atomic.max_active_transactions
    {
        return Err(Error::new(
            ErrorCode::QuotaExceeded,
            "permanent staged bytes or active transaction quota exceeded",
        ));
    }
    let mut reserved = 0usize;
    for key in &state.active_staged_transactions {
        let stage = state
            .staged_transactions
            .get(key)
            .ok_or_else(|| Error::new(ErrorCode::Corruption, "active staged identity missing"))?;
        validate_manifest(&stage.manifest, limits)?;
        reserved = reserved
            .checked_add(stage.manifest.encoded_chunk_bytes)
            .ok_or_else(|| Error::new(ErrorCode::QuotaExceeded, "staging reservation overflow"))?;
    }
    if reserved > limits.atomic.max_reserved_staging_bytes {
        return Err(Error::new(
            ErrorCode::QuotaExceeded,
            "reserved staging byte quota exceeded",
        ));
    }
    Ok(())
}

pub(super) fn validate_new_limits(state: &TenantState, limits: &Limits) -> Result<()> {
    validate_budget(state, limits)?;
    // Uploaded chunks must remain valid under an administrator's replacement
    // limits, including after encrypted snapshot recovery.
    for key in &state.active_staged_transactions {
        for chunk in state.staged_transactions[key].chunks.values() {
            validate_chunk(chunk, limits)?;
        }
    }
    Ok(())
}

pub(super) fn apply(
    state: &mut TenantState,
    command: &Command,
    revision: u64,
    indexes: &QueryIndexes,
) -> Result<(Result<WriteReceipt>, bool)> {
    authorize_discovery_state(state, &command.context, Action::Write)?;
    let receipt = || WriteReceipt {
        revision,
        versions: BTreeMap::new(),
    };
    match &command.operation {
        Operation::BeginStaged(request) => authorize_begin(state, &command.context, request)?,
        Operation::AppendStaged(request) => {
            authorize_upload(state, &command.context, &request.transaction)?
        }
        Operation::FinalizeStaged(reference) => {
            authorize_upload(state, &command.context, reference)?
        }
        _ => {}
    }
    if let Operation::StopStaged(request) = &command.operation {
        authorize_stop(state, &command.context, request)?;
        validate_admission(
            state,
            &command.context,
            &request.admission,
            command.timestamp_ms,
        )?;
    }
    // Expiry affects only invisible payloads and preserves their permanent ID.
    // All replicas consume the same trusted admission timestamp.
    expire_active(state, command.timestamp_ms, revision)?;
    match &command.operation {
        Operation::BeginStaged(request) => {
            authorize_manifest(state, &command.context, &request.manifest)?;
            if request.ttl_ms == 0 || request.ttl_ms > 86_400_000 {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "staged upload TTL outside bounds",
                ));
            }
            let key = identity(&command.context.principal, &request.transaction_id)?;
            let manifest_digest = staged_digest(&request.manifest)?.0;
            if let Some(existing) = state.staged_transactions.get(&key) {
                if existing.manifest_digest != manifest_digest || existing.ttl_ms != request.ttl_ms
                {
                    return Err(Error::new(
                        ErrorCode::Conflict,
                        "staged transaction ID reused for different input",
                    ));
                }
                return Ok((
                    existing.outcome.resolved().unwrap_or_else(|| Ok(receipt())),
                    false,
                ));
            }
            validate_manifest(&request.manifest, &state.limits)?;
            // Reject exhausted permanent identity capacity before receiving any
            // chunk payload. Begin owns a bounded terminal-outcome reservation.
            let mut staged = state.clone();
            replace_record(
                &mut staged,
                key,
                StagedTransaction {
                    scope: request.scope.clone(),
                    transaction_id: request.transaction_id.clone(),
                    manifest_digest,
                    manifest: request.manifest.clone(),
                    chunks: BTreeMap::new(),
                    stored_chunk_bytes: 0,
                    uploaded_payload_bytes: 0,
                    uploaded_operations: 0,
                    uploaded_read_assertions: 0,
                    expires_at_ms: Some(
                        command
                            .timestamp_ms
                            .checked_add(request.ttl_ms)
                            .ok_or_else(|| {
                                Error::new(ErrorCode::InvalidArgument, "staged expiry overflow")
                            })?,
                    ),
                    ttl_ms: request.ttl_ms,
                    outcome: StagedOutcome::Uploading,
                },
            )?;
            validate_budget(&staged, &staged.limits)?;
            *state = staged;
            Ok((Ok(receipt()), false))
        }
        Operation::AppendStaged(request) => {
            let stage = lookup(state, &command.context, &request.transaction)?;
            if request.index >= stage.manifest.chunk_digests.len() {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "staged chunk index outside manifest",
                ));
            }
            validate_chunk(&request.chunk, &state.limits)?;
            let (digest, bytes) = staged_digest(&request.chunk)?;
            if stage.manifest.chunk_digests[request.index] != digest {
                return Err(Error::new(
                    ErrorCode::Conflict,
                    "staged chunk digest mismatch",
                ));
            }
            for mutation in &request.chunk.operations {
                if !stage
                    .manifest
                    .write_collections
                    .contains(mutation.target().0)
                {
                    return Err(Error::new(
                        ErrorCode::Conflict,
                        "staged write collection outside manifest",
                    ));
                }
            }
            for assertion in &request.chunk.read_set {
                if let ReadAssertion::Document { collection, .. }
                | ReadAssertion::Collection { collection, .. } = assertion
                    && !stage.manifest.read_collections.contains(collection)
                {
                    return Err(Error::new(
                        ErrorCode::Conflict,
                        "staged read collection outside manifest",
                    ));
                }
            }
            if let Some(outcome) = stage.outcome.resolved() {
                return Ok((outcome, false));
            }
            if stage.chunks.contains_key(&request.index) {
                return Ok((Ok(receipt()), false));
            }
            let uploaded = stage
                .uploaded_payload_bytes
                .checked_add(bytes)
                .ok_or_else(|| Error::new(ErrorCode::QuotaExceeded, "staging byte overflow"))?;
            let operations = stage.uploaded_operations + request.chunk.operations.len();
            let assertions = stage.uploaded_read_assertions + request.chunk.read_set.len();
            if uploaded > stage.manifest.encoded_chunk_bytes
                || operations > stage.manifest.operation_count
                || assertions > stage.manifest.read_assertion_count
            {
                return Err(Error::new(
                    ErrorCode::Conflict,
                    "staged payload exceeds manifest declaration",
                ));
            }
            let key = identity(
                &command.context.principal,
                &request.transaction.transaction_id,
            )?;
            let mut stage = state.staged_transactions[&key].clone();
            stage.stored_chunk_bytes = stage
                .stored_chunk_bytes
                .checked_add(encoded_len(&request.index.to_string())? + 1 + bytes)
                .ok_or_else(|| Error::new(ErrorCode::QuotaExceeded, "staging byte overflow"))?;
            stage.uploaded_payload_bytes = uploaded;
            stage.uploaded_operations = operations;
            stage.uploaded_read_assertions = assertions;
            stage
                .chunks
                .insert(request.index, Arc::new(request.chunk.clone()));
            replace_record(state, key, stage)?;
            Ok((Ok(receipt()), false))
        }
        Operation::FinalizeStaged(reference) => {
            let stage = lookup(state, &command.context, reference)?.clone();
            if let Some(outcome) = stage.outcome.resolved() {
                return Ok((outcome, false));
            }
            if stage.chunks.len() != stage.manifest.chunk_digests.len() {
                return Err(Error::new(
                    ErrorCode::Conflict,
                    "staged transaction is incomplete",
                ));
            }
            let key = identity(&command.context.principal, &reference.transaction_id)?;
            let mut staged = state.clone();
            let outcome = validate_complete(&stage).and_then(|()| {
                let operations: Vec<_> = stage
                    .chunks
                    .values()
                    .flat_map(|chunk| &chunk.operations)
                    .collect();
                let assertions: Vec<_> = stage
                    .chunks
                    .values()
                    .flat_map(|chunk| &chunk.read_set)
                    .collect();
                validate_read_assertions(
                    &staged,
                    &assertions,
                    command.timestamp_ms,
                    staged.limits.atomic.max_read_assertions,
                )?;
                let receipt = apply_mutations(&mut staged, &operations, revision, false, indexes)?;
                indexes.validate_unique_changes(
                    &state.collections,
                    &staged.collections,
                    &changes(&stage),
                )?;
                Ok(receipt)
            });
            if outcome.is_err() {
                staged = state.clone();
            }
            let mut completed = stage;
            terminal(&mut completed, outcome.clone());
            replace_record(&mut staged, key, completed)?;
            *state = staged;
            Ok((outcome.clone(), outcome.is_ok()))
        }
        Operation::StopStaged(request) => {
            let original = &request.original;
            let reference = original.reference()?;
            let key = identity(&command.context.principal, &reference.transaction_id)?;
            if let Some(stage) = state.staged_transactions.get(&key) {
                authorize_manifest(state, &command.context, &stage.manifest)?;
                if stage.manifest_digest != reference.manifest_digest
                    || stage.ttl_ms != original.ttl_ms
                {
                    return Err(Error::new(
                        ErrorCode::Conflict,
                        "staged transaction ID reused for different input",
                    ));
                }
                // This is an acknowledgement of the guarded resolution attempt.
                // The service separately returns the original permanent status.
                if !stage.is_active() {
                    return Ok((Ok(receipt()), false));
                }
                let mut stage = stage.clone();
                clear_payload(&mut stage);
                stage.outcome = StagedOutcome::Aborted { receipt: receipt() };
                replace_record(state, key, stage)?;
            } else {
                replace_record(
                    state,
                    key,
                    StagedTransaction {
                        scope: original.scope.clone(),
                        transaction_id: original.transaction_id.clone(),
                        manifest_digest: reference.manifest_digest,
                        manifest: original.manifest.clone(),
                        chunks: BTreeMap::new(),
                        stored_chunk_bytes: 0,
                        uploaded_payload_bytes: 0,
                        uploaded_operations: 0,
                        uploaded_read_assertions: 0,
                        expires_at_ms: None,
                        ttl_ms: original.ttl_ms,
                        outcome: StagedOutcome::Aborted { receipt: receipt() },
                    },
                )?;
            }
            Ok((Ok(receipt()), false))
        }
        _ => Err(Error::new(
            ErrorCode::InvalidArgument,
            "operation is not staged",
        )),
    }
}

pub(super) fn validate_chunk(chunk: &StagedChunk, limits: &Limits) -> Result<()> {
    if chunk.operations.len() > limits.max_batch_operations
        || chunk.read_set.len() > 512
        || (chunk.operations.is_empty() && chunk.read_set.is_empty())
        || encoded_len(chunk)? > limits.max_batch_bytes
    {
        return Err(Error::new(
            ErrorCode::ResourceExhausted,
            "staged chunk exceeds request limits",
        ));
    }
    for mutation in &chunk.operations {
        validate_name(mutation.target().0)?;
        validate_name(mutation.target().1)?;
        if let Mutation::Put { body, .. } = mutation
            && encoded_len(body)? > limits.max_document_bytes
        {
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                "staged document exceeds byte limit",
            ));
        }
    }
    Ok(())
}

fn validate_complete(stage: &StagedTransaction) -> Result<()> {
    let mut bytes = 0usize;
    let mut operations = 0usize;
    let mut assertions = 0usize;
    let mut reads = BTreeSet::new();
    let mut writes = BTreeSet::new();
    for (index, chunk) in &stage.chunks {
        let (digest, chunk_bytes) = staged_digest(chunk)?;
        if stage.manifest.chunk_digests.get(*index) != Some(&digest) {
            return Err(Error::new(
                ErrorCode::Corruption,
                "stored staged chunk digest mismatch",
            ));
        }
        bytes += chunk_bytes;
        operations += chunk.operations.len();
        assertions += chunk.read_set.len();
        for mutation in &chunk.operations {
            writes.insert(mutation.target().0.to_owned());
        }
        for assertion in &chunk.read_set {
            if let ReadAssertion::Document { collection, .. }
            | ReadAssertion::Collection { collection, .. } = assertion
            {
                reads.insert(collection.clone());
            }
        }
    }
    if bytes != stage.manifest.encoded_chunk_bytes
        || operations != stage.manifest.operation_count
        || assertions != stage.manifest.read_assertion_count
        || reads != stage.manifest.read_collections
        || writes != stage.manifest.write_collections
    {
        return Err(Error::new(
            ErrorCode::Conflict,
            "complete staged payload does not match manifest",
        ));
    }
    Ok(())
}

pub(super) fn changes(stage: &StagedTransaction) -> BTreeMap<String, BTreeSet<String>> {
    let mut changes = BTreeMap::<String, BTreeSet<String>>::new();
    for mutation in stage.chunks.values().flat_map(|chunk| &chunk.operations) {
        changes
            .entry(mutation.target().0.into())
            .or_default()
            .insert(mutation.target().1.into());
    }
    changes
}

/// Counters for independently bounded chunks, shared by resident and indexed
/// restore validation. No staged payload needs to remain resident between chunks.
#[derive(Default, serde::Serialize, serde::Deserialize)]
pub(crate) struct SnapshotChunks {
    stored: usize,
    payload: usize,
    operations: usize,
    assertions: usize,
    chunks: usize,
}
impl SnapshotChunks {
    pub(super) fn add(
        &mut self,
        index: usize,
        chunk: &StagedChunk,
        stage: &StagedTransaction,
        limits: &Limits,
    ) -> Result<()> {
        validate_chunk(chunk, limits)?;
        let (digest, bytes) = staged_digest(chunk)?;
        if stage.manifest.chunk_digests.get(index) != Some(&digest) {
            return Err(Error::new(
                ErrorCode::Corruption,
                "restored staged chunk mismatch",
            ));
        }
        let entry = encoded_len(&index.to_string())?
            .checked_add(1)
            .and_then(|n| n.checked_add(bytes))
            .ok_or_else(|| Error::new(ErrorCode::Corruption, "staged accounting overflow"))?;
        for (count, increment) in [
            (&mut self.stored, entry),
            (&mut self.payload, bytes),
            (&mut self.operations, chunk.operations.len()),
            (&mut self.assertions, chunk.read_set.len()),
            (&mut self.chunks, 1),
        ] {
            *count = count
                .checked_add(increment)
                .ok_or_else(|| Error::new(ErrorCode::Corruption, "staged accounting overflow"))?;
        }
        Ok(())
    }
}

pub(crate) fn validate_snapshot_record(
    key: &str,
    stage: &StagedTransaction,
    state: &TenantState,
    chunks: &SnapshotChunks,
) -> Result<bool> {
    // Permanent terminal identities describe historic requests. Lower limits
    // apply to future/active work and cannot invalidate those durable outcomes.
    validate_manifest(&stage.manifest, &historical_limits())?;
    validate_scope_lineage(state, &stage.scope)?;
    let revision = state.revision;
    if identity(&stage.scope.principal, &stage.transaction_id)? != key
        || staged_digest(&stage.manifest)?.0 != stage.manifest_digest
        || stage.ttl_ms == 0
        || stage.ttl_ms > 86_400_000
        || stage
            .expires_at_ms
            .is_some_and(|expires| expires < stage.ttl_ms)
        || (stage.expires_at_ms.is_none()
            && !matches!(stage.outcome, StagedOutcome::Aborted { .. }))
    {
        return Err(Error::new(
            ErrorCode::Corruption,
            "invalid staged identity or expiry",
        ));
    }
    if chunks.stored != stage.stored_chunk_bytes
        || chunks.payload != stage.uploaded_payload_bytes
        || chunks.operations != stage.uploaded_operations
        || chunks.assertions != stage.uploaded_read_assertions
        || chunks.payload > stage.manifest.encoded_chunk_bytes
        || chunks.operations > stage.manifest.operation_count
        || chunks.assertions > stage.manifest.read_assertion_count
    {
        return Err(Error::new(
            ErrorCode::Corruption,
            "staged chunk accounting mismatch",
        ));
    }
    match &stage.outcome {
        StagedOutcome::Uploading => Ok(true),
        StagedOutcome::Aborted { receipt } | StagedOutcome::Expired { receipt } => {
            if chunks.chunks != 0 || receipt.revision > revision || !receipt.versions.is_empty() {
                return Err(Error::new(
                    ErrorCode::Corruption,
                    "invalid canceled staged outcome",
                ));
            }
            Ok(false)
        }
        StagedOutcome::Finished { outcome } => {
            if chunks.chunks != 0
                || outcome.as_ref().is_ok_and(|receipt| {
                    receipt.revision > revision || !receipt.versions.is_empty()
                })
            {
                return Err(Error::new(
                    ErrorCode::Corruption,
                    "invalid terminal staged outcome",
                ));
            }
            Ok(false)
        }
    }
}

pub(super) fn validate_restored(state: &TenantState) -> Result<()> {
    validate_budget(state, &state.limits)?;
    let mut active = BTreeSet::new();
    let mut used = state.staged_terminal_head.encoded_bytes;
    let mut reserved = 0u64;
    for (key, stage) in &state.staged_transactions {
        if !stage.is_active() {
            return Err(Error::new(
                ErrorCode::Corruption,
                "resident staging contains a terminal identity",
            ));
        }
        let charge = permanent_charge(key, stage)?;
        used = used
            .checked_add(charge.0)
            .ok_or_else(|| Error::new(ErrorCode::Corruption, "permanent staged bytes overflow"))?;
        reserved = reserved
            .checked_add(charge.1)
            .ok_or_else(|| Error::new(ErrorCode::Corruption, "staged terminal reserve overflow"))?;
        let mut chunks = SnapshotChunks::default();
        for (index, chunk) in &stage.chunks {
            chunks.add(*index, chunk, stage, &state.limits)?;
        }
        if validate_snapshot_record(key, stage, state, &chunks)? {
            active.insert(key.clone());
        }
    }
    if used != state.permanent_staged_bytes || reserved != state.reserved_staged_terminal_bytes {
        return Err(Error::new(
            ErrorCode::Corruption,
            "permanent staged counters mismatch",
        ));
    }
    if active != state.active_staged_transactions {
        return Err(Error::new(
            ErrorCode::Corruption,
            "staged active index mismatch",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "staging_capacity_tests.rs"]
mod capacity_tests;
