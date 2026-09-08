//! Ordered activation of a bounded set of schema/index definitions. The retained
//! identity is operational metadata; both success and deterministic rejection
//! survive receipt expiry, encrypted restart, and full restore.
use super::*;

pub(crate) fn authorize(
    state: &TenantState,
    context: &RequestContext,
    request: &SchemaChangeSet,
) -> Result<()> {
    authorize_discovery_state(state, context, Action::Admin)?;
    authorize_dependencies(state, context, &request.read_set)?;
    for change in &request.changes {
        authorize_state(
            state,
            context,
            Some(&change.definition().name),
            Action::Admin,
        )?;
    }
    Ok(())
}

pub(crate) fn authorize_dependencies(
    state: &TenantState,
    context: &RequestContext,
    assertions: &[ReadAssertion],
) -> Result<()> {
    if assertions.len() > MAX_SCHEMA_READ_ASSERTIONS {
        return Err(Error::new(
            ErrorCode::ResourceExhausted,
            "schema read assertion limit exceeded",
        ));
    }
    for assertion in assertions {
        if let ReadAssertion::Document { collection, .. }
        | ReadAssertion::Collection { collection, .. } = assertion
        {
            authorize_state(state, context, Some(collection), Action::Read)?;
        }
    }
    Ok(())
}

pub(crate) fn validate_admission(
    state: &TenantState,
    context: &RequestContext,
    assertions: &[ReadAssertion],
    evaluated_at_ms: u64,
) -> Result<()> {
    authorize_dependencies(state, context, assertions)?;
    validate_read_assertions(
        state,
        &assertions.iter().collect::<Vec<_>>(),
        evaluated_at_ms,
        MAX_SCHEMA_READ_ASSERTIONS,
    )
}

fn identity(principal: &str, activation_id: &str) -> Result<String> {
    validate_name(principal)?;
    validate_name(activation_id)?;
    Ok(staged_digest(&(principal, activation_id))?.0)
}

pub(crate) fn lookup<'a>(
    state: &'a TenantState,
    context: &RequestContext,
    reference: &SchemaActivationRef,
) -> Result<&'a StoredSchemaActivation> {
    authorize_discovery_state(state, context, Action::Admin)?;
    if !valid_digest(&reference.request_digest) {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "invalid schema request digest",
        ));
    }
    let key = identity(&context.principal, &reference.activation_id)?;
    let record = state
        .schema_activations
        .get(&key)
        .ok_or_else(|| Error::new(ErrorCode::NotFound, "schema activation identity not found"))?;
    for collection in &record.collections {
        authorize_state(state, context, Some(collection), Action::Admin)?;
    }
    for collection in &record.read_collections {
        authorize_state(state, context, Some(collection), Action::Read)?;
    }
    if record.request_digest != reference.request_digest {
        return Err(Error::new(
            ErrorCode::Conflict,
            "schema activation identity mismatch",
        ));
    }
    Ok(record)
}

pub(super) fn apply(
    state: &mut TenantState,
    context: &RequestContext,
    request: &SchemaChangeSet,
    revision: u64,
    evaluated_at_ms: u64,
) -> Result<(Result<WriteReceipt>, bool)> {
    authorize(state, context, request)?;
    let key = identity(&context.principal, &request.activation_id)?;
    let reference = request.reference()?;
    if state.schema_activations.contains_key(&key) {
        return Ok((lookup(state, context, &reference)?.outcome.clone(), false));
    }
    if request.changes.is_empty()
        || request.changes.len() > MAX_SCHEMA_CHANGESET_COLLECTIONS
        || encoded_len(request)? > MAX_SCHEMA_CHANGESET_BYTES
    {
        return Err(Error::new(
            ErrorCode::ResourceExhausted,
            "schema change set outside bounds",
        ));
    }
    validate_name(&request.expected_incarnation)?;
    let mut collections = BTreeSet::new();
    for change in &request.changes {
        let name = &change.definition().name;
        validate_name(name)?;
        if !collections.insert(name.clone()) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "duplicate schema target",
            ));
        }
    }
    if state.schema_activations.len() >= state.limits.max_schema_activations {
        return Err(Error::new(
            ErrorCode::QuotaExceeded,
            "permanent schema activation quota exhausted",
        ));
    }

    let mut next = state.clone();
    let outcome = validate_admission(&next, context, &request.read_set, evaluated_at_ms)
        .and_then(|()| activate(&mut next, request))
        .map(|()| WriteReceipt {
            revision,
            versions: BTreeMap::new(),
        });
    let changed = outcome.is_ok();
    if changed {
        *state = next;
    }
    store(
        state,
        key,
        StoredSchemaActivation {
            principal: context.principal.clone(),
            activation_id: request.activation_id.clone(),
            request_digest: reference.request_digest,
            collections,
            read_collections: request
                .read_set
                .iter()
                .filter_map(|a| match a {
                    ReadAssertion::Document { collection, .. }
                    | ReadAssertion::Collection { collection, .. } => Some(collection.clone()),
                    _ => None,
                })
                .collect(),
            outcome: outcome.clone(),
        },
    )?;
    Ok((outcome, changed))
}

fn activate(state: &mut TenantState, request: &SchemaChangeSet) -> Result<()> {
    if state.incarnation != request.expected_incarnation
        || state.schema_epoch != request.expected_schema_epoch
    {
        return Err(Error::new(
            ErrorCode::Conflict,
            "schema activation source changed",
        ));
    }
    for change in &request.changes {
        let definition = change.definition();
        let current = state.collections.get(&definition.name);
        if let SchemaChange::Replace {
            expected_data_epoch,
            ..
        } = change
            && current.is_some_and(|collection| collection.data_epoch != *expected_data_epoch)
        {
            return Err(Error::new(
                ErrorCode::Conflict,
                "schema activation document epoch changed",
            ));
        }
        let collection = prepare_collection(
            current,
            definition,
            matches!(change, SchemaChange::Create { .. }),
        )?;
        state
            .collections
            .insert(definition.name.clone(), collection);
    }
    validate_metadata_budget(&state.collections, &state.limits)?;
    state.schema_epoch = next_policy_epoch(state.schema_epoch)?;
    state.policy_epoch = next_policy_epoch(state.policy_epoch)?;
    Ok(())
}

/// Shared semantics for explicit single-collection administration and atomic
/// application activation. Never change document versions or data epochs.
pub(super) fn prepare_collection(
    current: Option<&CollectionState>,
    definition: &CollectionDefinition,
    create: bool,
) -> Result<CollectionState> {
    validate_name(&definition.name)?;
    if definition.retention_class == CollectionRetentionClass::ArchivableHistory
        && definition.write_mode != CollectionWriteMode::AppendOnly
    {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "archivable history must be append-only",
        ));
    }
    if current.is_some_and(|collection| {
        collection.definition.retention_class != definition.retention_class
    }) {
        return Err(Error::new(
            ErrorCode::Forbidden,
            "collection retention class is immutable",
        ));
    }
    if current.is_some_and(|collection| !collection.archived_documents.is_empty()) {
        return Err(Error::new(
            ErrorCode::Conflict,
            "archived collection schema/index definitions are sealed",
        ));
    }
    if create && current.is_some() {
        return Err(Error::new(ErrorCode::AlreadyExists, "collection exists"));
    }
    if !create && current.is_none() {
        return Err(Error::new(ErrorCode::NotFound, "collection not found"));
    }
    if current.is_some_and(|collection| {
        collection.definition.write_mode == CollectionWriteMode::AppendOnly
            && definition.write_mode != CollectionWriteMode::AppendOnly
    }) {
        return Err(Error::new(
            ErrorCode::Forbidden,
            "append-only protection cannot be weakened",
        ));
    }
    let documents = current
        .map(|collection| collection.documents.clone())
        .unwrap_or_default();
    validate_collection(definition, &documents)?;
    let collection = CollectionState {
        definition: definition.clone(),
        data_epoch: current.map_or(0, |collection| collection.data_epoch),
        documents,
        archived_documents: Default::default(),
        archived_document_bytes: 0,
    };
    check_unique(&collection)?;
    Ok(collection)
}

fn entry_bytes(key: &str, record: &StoredSchemaActivation) -> Result<usize> {
    let value_bytes = encoded_len(record)?;
    encoded_len(&key)?
        .checked_add(1)
        .and_then(|n| n.checked_add(value_bytes))
        .ok_or_else(|| {
            Error::new(
                ErrorCode::Corruption,
                "schema activation accounting overflow",
            )
        })
}

pub(super) fn store(
    state: &mut TenantState,
    key: String,
    record: StoredSchemaActivation,
) -> Result<()> {
    let old = state
        .schema_activations
        .get(&key)
        .map(|old| entry_bytes(&key, old))
        .transpose()?
        .unwrap_or(0);
    let new = entry_bytes(&key, &record)?;
    state.schema_activation_bytes = state
        .schema_activation_bytes
        .checked_sub(old)
        .and_then(|n| n.checked_add(new))
        .ok_or_else(|| {
            Error::new(
                ErrorCode::Corruption,
                "schema activation accounting mismatch",
            )
        })?;
    state.schema_activations.insert(key, record);
    Ok(())
}

pub(super) fn reject_budget(
    previous: &TenantState,
    next: &TenantState,
    rejected: &mut TenantState,
    command: &Command,
    error: &Error,
) -> Result<()> {
    if let Operation::ActivateSchema(request) = &command.operation {
        let key = staged_digest(&(&command.context.principal, &request.activation_id))?.0;
        if !previous.schema_activations.contains_key(&key)
            && let Some(record) = next.schema_activations.get(&key)
        {
            let mut record = record.clone();
            record.outcome = Err(error.clone());
            store(rejected, key, record)?;
        }
    }
    Ok(())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) fn validate_restored(state: &TenantState) -> Result<()> {
    let mut bytes = 0usize;
    if state.schema_activations.len() > state.limits.max_schema_activations {
        return Err(Error::new(
            ErrorCode::Corruption,
            "schema activation record quota exceeded",
        ));
    }
    for (key, record) in &state.schema_activations {
        bytes = bytes
            .checked_add(validate_snapshot_record(key, record, state.revision)?)
            .ok_or_else(|| Error::new(ErrorCode::Corruption, "schema activation bytes overflow"))?;
    }
    if bytes != state.schema_activation_bytes {
        return Err(Error::new(
            ErrorCode::Corruption,
            "schema activation byte accounting mismatch",
        ));
    }
    Ok(())
}

pub(super) fn validate_snapshot_record(
    key: &str,
    record: &StoredSchemaActivation,
    revision: u64,
) -> Result<usize> {
    if identity(&record.principal, &record.activation_id)? != *key
        || !valid_digest(&record.request_digest)
        || record.collections.is_empty()
        || record.collections.len() > MAX_SCHEMA_CHANGESET_COLLECTIONS
        || record.read_collections.len() > MAX_SCHEMA_READ_ASSERTIONS
        || record.outcome.as_ref().is_ok_and(|receipt| {
            receipt.revision == 0 || receipt.revision > revision || !receipt.versions.is_empty()
        })
    {
        return Err(Error::new(
            ErrorCode::Corruption,
            "invalid schema activation record",
        ));
    }
    for collection in record.collections.iter().chain(&record.read_collections) {
        validate_name(collection)?;
    }
    entry_bytes(key, record)
}
