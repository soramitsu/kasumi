//! Bounded permanent-stage point reads run under owned blocking work. Outputs
//! retain only headers and authorization metadata, never document/index roots or
//! uploaded payloads after the worker has completed.
use super::*;

// Covers bounded physical reads before their plaintext length is known. Decoded
// metadata has a separate charge, acquired before any corresponding clone.
const POINT_READ_BYTES: u64 = 8 << 20;
// These typed records contain strings, vectors and ordered trees. This bound
// includes container/allocator overhead and temporary validation copies, rather
// than treating encoded bytes as their resident allocation size.
const DECODED_BYTES_PER_ENCODED_BYTE: u64 = 32;

pub(super) struct StagedRead {
    pub state: TenantState,
    pub status: Option<StagedTransactionStatus>,
    pub strict_collections: BTreeSet<String>,
    _reservation: Reservation,
    _registration: Arc<WorkRegistration>,
}
impl Database {
    pub(super) async fn read_staged_identity(
        &self,
        context: &RequestContext,
        scope: &StagedTransactionScope,
        transaction_id: &str,
    ) -> Result<StagedRead> {
        context.authorization.check_live()?;
        self.access()?;
        let generation = self.engine.generation()?;
        crate::state::staging::authorize_scope(&generation.state, context, scope)?;
        let cancellation = QueryCancellation::default();
        let _cancel = CancelOnDrop(cancellation.clone());
        let mut reservation = self
            .admission()
            .reserve(POINT_READ_BYTES, Some(cancellation.clone()))?;
        let registration = Arc::new(self.work.begin(cancellation.clone())?);
        let key = crate::state::staging::identity(&context.principal, transaction_id)?;
        let selected = generation.state.staged_transactions.get(&key);
        reservation.reserve_additional(metadata_workspace(
            &generation.state,
            context,
            scope,
            selected,
        )?)?;
        cancellation.check()?;
        context.authorization.check_live()?;
        // Select the header and terminal namespace without retaining the full
        // document/index generation while the blocking job waits for storage.
        // Sizing and copying both use this original generation; admission never
        // resamples the state or silently advances the selected terminal prefix.
        let terminals = generation.terminals.clone();
        let selected_status = selected.map(StagedTransaction::status);
        let selected = selected.map(header);
        let mut state = crate::snapshot_codec::metadata(&generation.state);
        state.restore_lineage = generation.state.restore_lineage.clone();
        // Scope and manifest authorization do not read target lifecycle history.
        // Retaining that persistent map would unnecessarily pin old history.
        let strict_collections = generation
            .state
            .collections
            .iter()
            .filter(|(_, collection)| collection.definition.strict_read_audit)
            .map(|(name, _)| name.clone())
            .collect();
        drop(generation);
        let context = context.clone();
        let scope = scope.clone();
        let worker = tokio::task::spawn_blocking(move || -> Result<StagedRead> {
            cancellation.check()?;
            context.authorization.check_live()?;
            crate::state::staging::authorize_scope(&state, &context, &scope)?;
            let (stage, status) = if let Some(active) = selected {
                (Some(active), selected_status)
            } else {
                let stage = terminals
                    .get_charged(&key, |encoded_bytes| {
                        cancellation.check()?;
                        context.authorization.check_live()?;
                        // The raw bounded row belongs to POINT_READ_BYTES. Its
                        // decoded header, status and release metadata must be
                        // admitted before deserialization or response cloning.
                        reservation.reserve_additional(decoded_workspace(encoded_bytes, 2)?)?;
                        Ok(())
                    })
                    .map_err(point_error)?
                    .map(|row| {
                        row.validate(&state).map_err(point_error)?;
                        Ok::<_, Error>(row.stage)
                    })
                    .transpose()?;
                let status = stage.as_ref().map(StagedTransaction::status);
                (stage, status)
            };
            if let Some(mut stage) = stage {
                stage.chunks.clear();
                state.staged_transactions.insert(key, stage);
            }
            cancellation.check()?;
            context.authorization.check_live()?;
            drop(terminals);
            Ok(StagedRead {
                state,
                status,
                strict_collections,
                _reservation: reservation,
                _registration: registration,
            })
        });
        tokio::time::timeout(Duration::from_secs(10), worker)
            .await
            .map_err(|_| {
                Error::new(
                    ErrorCode::Unavailable,
                    "staged point read deadline exceeded",
                )
            })?
            .map_err(|_| Error::new(ErrorCode::Unavailable, "staged point read worker failed"))?
    }
    pub(super) async fn staged_operation_read(
        &self,
        context: &RequestContext,
        operation: &Operation,
    ) -> Result<Option<StagedRead>> {
        let (scope, id) = match operation {
            Operation::BeginStaged(request) => (&request.scope, &request.transaction_id),
            Operation::AppendStaged(request) => (
                &request.transaction.scope,
                &request.transaction.transaction_id,
            ),
            Operation::FinalizeStaged(reference) => (&reference.scope, &reference.transaction_id),
            Operation::StopStaged(request) => {
                (&request.original.scope, &request.original.transaction_id)
            }
            _ => return Ok(None),
        };
        self.read_staged_identity(context, scope, id)
            .await
            .map(Some)
    }
}

fn workspace_overflow() -> Error {
    Error::new(
        ErrorCode::ResourceExhausted,
        "staged read workspace overflow",
    )
}
fn decoded_workspace(encoded_bytes: usize, copies: u64) -> Result<u64> {
    u64::try_from(encoded_bytes)
        .ok()
        .and_then(|bytes| bytes.checked_mul(DECODED_BYTES_PER_ENCODED_BYTE))
        .and_then(|bytes| bytes.checked_mul(copies))
        .ok_or_else(workspace_overflow)
}
fn metadata_workspace(
    state: &TenantState,
    context: &RequestContext,
    scope: &StagedTransactionScope,
    selected: Option<&StagedTransaction>,
) -> Result<u64> {
    // Match all dynamically allocated fields copied by snapshot metadata(), plus
    // this read's lineage and credential/scope. Counting writes no encoded buffer
    // and borrows every input. Control's bounded installation metadata is counted
    // independently of its expandable intent/change history, which is not copied.
    let bytes = crate::accounting::encoded_len(&(
        &state.tenant,
        &state.incarnation,
        &state.pending_restore,
        &state.restored_from,
        &state.restore_lineage,
        &state.policy,
        &state.limits,
        &state.staged_terminal_head,
        &state.audit_retention,
        context,
        scope,
    ))?;
    let mut workspace = decoded_workspace(bytes, 1)?;
    if let Some(control) = &state.lifecycle_control {
        workspace = workspace
            .checked_add(decoded_workspace(
                crate::accounting::encoded_len(&(
                    &control.installation,
                    &control.installation_policy,
                ))?,
                1,
            )?)
            .ok_or_else(workspace_overflow)?;
    }
    for (name, collection) in &state.collections {
        if collection.definition.strict_read_audit {
            // One retained BTreeSet entry. Extra copies of collection names in
            // release events are covered by the selected manifest charge below.
            workspace = workspace
                .checked_add(decoded_workspace(name.len(), 1)?)
                .and_then(|bytes| bytes.checked_add(128))
                .ok_or_else(workspace_overflow)?;
        }
    }
    if let Some(stage) = selected {
        let bytes = crate::accounting::encoded_len(&(
            &stage.scope,
            &stage.transaction_id,
            &stage.manifest_digest,
            &stage.manifest,
            &stage.outcome,
        ))?;
        workspace = workspace
            .checked_add(decoded_workspace(bytes, 2)?)
            .and_then(|bytes| {
                stage
                    .chunks
                    .len()
                    .checked_mul(std::mem::size_of::<usize>())
                    .and_then(|count| u64::try_from(count).ok())
                    .and_then(|count| bytes.checked_add(count))
            })
            .ok_or_else(workspace_overflow)?;
    }
    Ok(workspace)
}

// Never clone the uploaded chunk map just to clear it. Only the admitted header
// and the separately sized received-index response leave the selected generation.
fn header(stage: &StagedTransaction) -> StagedTransaction {
    StagedTransaction {
        scope: stage.scope.clone(),
        transaction_id: stage.transaction_id.clone(),
        manifest_digest: stage.manifest_digest.clone(),
        manifest: stage.manifest.clone(),
        chunks: Default::default(),
        stored_chunk_bytes: stage.stored_chunk_bytes,
        uploaded_payload_bytes: stage.uploaded_payload_bytes,
        uploaded_operations: stage.uploaded_operations,
        uploaded_read_assertions: stage.uploaded_read_assertions,
        expires_at_ms: stage.expires_at_ms,
        ttl_ms: stage.ttl_ms,
        outcome: stage.outcome.clone(),
    }
}
fn point_error(error: anyhow::Error) -> Error {
    error
        .downcast_ref::<Error>()
        .cloned()
        .unwrap_or_else(|| Error::new(ErrorCode::Corruption, error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::AdmissionConfig;

    #[test]
    fn metadata_growth_requires_additional_admission_before_copying() {
        let context = RequestContext {
            authorization: RequestAuthorization::service_identity(),
            tenant: "tenant".into(),
            principal: "owner".into(),
            scopes: BTreeSet::from([Action::Write, Action::Admin]),
            request_id: "stage-read".into(),
        };
        let engine = TenantEngine::new(
            context.tenant.clone(),
            "incarnation".into(),
            Policy {
                grants: vec![Grant {
                    principal: context.principal.clone(),
                    collection: None,
                    actions: context.scopes.clone(),
                }],
                strict_read_audit: false,
            },
            Limits::default(),
        )
        .unwrap();
        let mut state = engine.generation().unwrap().state.clone();
        let scope = StagedTransactionScope {
            tenant: context.tenant.clone(),
            incarnation: state.incarnation.clone(),
            principal: context.principal.clone(),
        };
        let initial = metadata_workspace(&state, &context, &scope, None).unwrap();
        // This isolates read admission; no production maintenance lane is
        // installed and this fixture is not a production capacity acceptance.
        let node = NodeAdmission::new(AdmissionConfig {
            high_water_bytes: Some(8 << 30),
            low_water_bytes: Some(7 << 30),
            max_inflight_bytes: Some(POINT_READ_BYTES + initial),
            ..Default::default()
        })
        .unwrap();
        let mut reservation = node.reserve(POINT_READ_BYTES, None).unwrap();
        state.policy.grants.extend((0..1024).map(|i| Grant {
            principal: format!("{i:04}{}", "p".repeat(252)),
            collection: Some("c".repeat(256)),
            actions: BTreeSet::from([Action::Read, Action::Write]),
        }));
        let required = metadata_workspace(&state, &context, &scope, None).unwrap();
        assert!(required > POINT_READ_BYTES);
        assert_eq!(
            reservation.reserve_additional(required).unwrap_err().code,
            ErrorCode::ResourceExhausted
        );
        assert_eq!(node.snapshot().reserved_bytes, POINT_READ_BYTES);
        drop(reservation);
        assert_eq!(node.snapshot().reserved_bytes, 0);
    }
}
