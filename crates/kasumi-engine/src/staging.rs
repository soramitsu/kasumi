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

pub(crate) fn lookup<'a>(
    state: &'a TenantState,
    context: &RequestContext,
    reference: &StagedTransactionRef,
) -> Result<&'a StagedTransaction> {
    authorize_discovery_state(state, context, Action::Write)?;
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
    if transaction.manifest_digest != reference.manifest_digest {
        return Err(Error::new(
            ErrorCode::Conflict,
            "staged manifest identity mismatch",
        ));
    }
    Ok(transaction)
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

fn expire_active(state: &mut TenantState, now: u64, revision: u64) {
    let expired: Vec<_> = state
        .active_staged_transactions
        .iter()
        .filter(|key| {
            state
                .staged_transactions
                .get(*key)
                .is_some_and(|stage| stage.expires_at_ms <= now)
        })
        .cloned()
        .collect();
    for key in expired {
        if let Some(transaction) = state.staged_transactions.get_mut(&key) {
            clear_payload(transaction);
            transaction.outcome = StagedOutcome::Expired {
                receipt: WriteReceipt {
                    revision,
                    versions: BTreeMap::new(),
                },
            };
        }
        state.active_staged_transactions.remove(&key);
    }
}

pub(super) fn validate_budget(state: &TenantState, limits: &Limits) -> Result<()> {
    if state.staged_transactions.len() > limits.atomic.max_transaction_records
        || state.active_staged_transactions.len() > limits.atomic.max_active_transactions
    {
        return Err(Error::new(
            ErrorCode::QuotaExceeded,
            "staged transaction record quota exceeded",
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
    // Expiry affects only invisible payloads and preserves their permanent ID.
    // All replicas consume the same trusted admission timestamp.
    expire_active(state, command.timestamp_ms, revision);
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
            if state.staged_transactions.len() >= state.limits.atomic.max_transaction_records {
                return Err(Error::new(
                    ErrorCode::QuotaExceeded,
                    "permanent staged identity quota exhausted",
                ));
            }
            let mut staged = state.clone();
            staged.staged_transactions.insert(
                key.clone(),
                StagedTransaction {
                    principal: command.context.principal.clone(),
                    transaction_id: request.transaction_id.clone(),
                    manifest_digest,
                    manifest: request.manifest.clone(),
                    chunks: BTreeMap::new(),
                    stored_chunk_bytes: 0,
                    uploaded_payload_bytes: 0,
                    uploaded_operations: 0,
                    uploaded_read_assertions: 0,
                    expires_at_ms: command
                        .timestamp_ms
                        .checked_add(request.ttl_ms)
                        .ok_or_else(|| {
                            Error::new(ErrorCode::InvalidArgument, "staged expiry overflow")
                        })?,
                    ttl_ms: request.ttl_ms,
                    outcome: StagedOutcome::Uploading,
                },
            );
            staged.active_staged_transactions.insert(key);
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
            let stage = state
                .staged_transactions
                .get_mut(&key)
                .expect("staged identity validated");
            stage.stored_chunk_bytes += encoded_len(&request.index.to_string())? + 1 + bytes;
            stage.uploaded_payload_bytes = uploaded;
            stage.uploaded_operations = operations;
            stage.uploaded_read_assertions = assertions;
            stage
                .chunks
                .insert(request.index, Arc::new(request.chunk.clone()));
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
                let receipt = apply_mutations(&mut staged, &operations, revision, false)?;
                indexes.validate_unique_changes(
                    &state.collections,
                    &staged.collections,
                    &changes(&stage),
                )?;
                Ok(receipt)
            });
            if outcome.is_ok() {
                *state = staged;
            }
            terminal(
                state
                    .staged_transactions
                    .get_mut(&key)
                    .expect("staged identity validated"),
                outcome.clone(),
            );
            state.active_staged_transactions.remove(&key);
            Ok((outcome.clone(), outcome.is_ok()))
        }
        Operation::AbortStaged(reference) => {
            let stage = lookup(state, &command.context, reference)?;
            if let StagedOutcome::Aborted { receipt } = &stage.outcome {
                return Ok((Ok(receipt.clone()), false));
            }
            if let Some(outcome) = stage.outcome.resolved() {
                return Ok((outcome, false));
            }
            let key = identity(&command.context.principal, &reference.transaction_id)?;
            let stage = state
                .staged_transactions
                .get_mut(&key)
                .expect("staged identity validated");
            clear_payload(stage);
            stage.outcome = StagedOutcome::Aborted { receipt: receipt() };
            state.active_staged_transactions.remove(&key);
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

pub(super) fn validate_restored(state: &TenantState) -> Result<()> {
    validate_budget(state, &state.limits)?;
    // Permanent terminal identities describe historic requests. Lower limits
    // apply to future/active work and cannot invalidate those durable outcomes.
    let historical_limits = Limits {
        max_collections: 1024,
        atomic: AtomicLimits::default(),
        ..Limits::default()
    };
    let mut active = BTreeSet::new();
    for (key, stage) in &state.staged_transactions {
        validate_manifest(&stage.manifest, &historical_limits)?;
        if identity(&stage.principal, &stage.transaction_id)? != *key
            || staged_digest(&stage.manifest)?.0 != stage.manifest_digest
            || stage.ttl_ms == 0
            || stage.ttl_ms > 86_400_000
            || stage.expires_at_ms < stage.ttl_ms
        {
            return Err(Error::new(
                ErrorCode::Corruption,
                "invalid staged identity or expiry",
            ));
        }
        let mut stored = 0usize;
        let mut payload = 0usize;
        let mut operations = 0usize;
        let mut assertions = 0usize;
        for (index, chunk) in &stage.chunks {
            validate_chunk(chunk, &state.limits)?;
            let (digest, bytes) = staged_digest(chunk)?;
            if stage.manifest.chunk_digests.get(*index) != Some(&digest) {
                return Err(Error::new(
                    ErrorCode::Corruption,
                    "restored staged chunk mismatch",
                ));
            }
            stored += encoded_len(&index.to_string())? + 1 + bytes;
            payload += bytes;
            operations += chunk.operations.len();
            assertions += chunk.read_set.len();
        }
        if stored != stage.stored_chunk_bytes
            || payload != stage.uploaded_payload_bytes
            || operations != stage.uploaded_operations
            || assertions != stage.uploaded_read_assertions
            || payload > stage.manifest.encoded_chunk_bytes
            || operations > stage.manifest.operation_count
            || assertions > stage.manifest.read_assertion_count
        {
            return Err(Error::new(
                ErrorCode::Corruption,
                "staged chunk accounting mismatch",
            ));
        }
        match &stage.outcome {
            StagedOutcome::Uploading => {
                active.insert(key.clone());
            }
            StagedOutcome::Aborted { receipt } | StagedOutcome::Expired { receipt } => {
                if !stage.chunks.is_empty()
                    || receipt.revision > state.revision
                    || !receipt.versions.is_empty()
                {
                    return Err(Error::new(
                        ErrorCode::Corruption,
                        "invalid canceled staged outcome",
                    ));
                }
            }
            StagedOutcome::Finished { outcome } => {
                if !stage.chunks.is_empty()
                    || outcome.as_ref().is_ok_and(|receipt| {
                        receipt.revision > state.revision || !receipt.versions.is_empty()
                    })
                {
                    return Err(Error::new(
                        ErrorCode::Corruption,
                        "invalid terminal staged outcome",
                    ));
                }
            }
        }
    }
    if active != state.active_staged_transactions {
        return Err(Error::new(
            ErrorCode::Corruption,
            "staged active index mismatch",
        ));
    }
    Ok(())
}
