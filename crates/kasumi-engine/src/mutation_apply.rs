//! One bounded receipt admission owns all deterministic mutation outcomes.
//! This path cannot enter generic quota rejection, which may publish only a
//! revision cursor. An admitted identity always selects one immutable point row.
use super::*;
use crate::mutation_receipt::{Absent, Lookup, Pending, Row, View};

fn audit(command: &Command, state: &TenantState, outcome: &str) -> AuditEvent {
    AuditEvent {
        event_id: format!("{}:{}", state.incarnation, state.revision),
        principal: command.context.principal.clone(),
        action: "mutation".into(),
        request_id: command.context.request_id.clone(),
        timestamp_ms: command.timestamp_ms,
        data_revision: Some(state.revision),
        outcome: outcome.into(),
        collection: None,
    }
}

/// The closed ErrorCode representation is at most RESOURCE_EXHAUSTED bytes;
/// every message byte can require at most a six-byte JSON escape. This real
/// bounded error exercises that maximum, including JSON structure and tags.
fn maximum_error() -> Error {
    Error::new(
        ErrorCode::ResourceExhausted,
        "\u{0001}".repeat(Error::MAX_MESSAGE_BYTES),
    )
}

struct Permit {
    template: StoredReceipt,
    maximum_row_bytes: u64,
    maximum_head: MutationReceiptHead,
}
impl Permit {
    fn prepare(
        state: &TenantState,
        command: &Command,
        batch: &MutationBatch,
        applied: &crate::staged_terminal::AppliedIdentity,
        digest: String,
    ) -> Result<Self> {
        let template = StoredReceipt {
            scope: MutationReceiptScope {
                tenant: state.tenant.clone(),
                incarnation: state.incarnation.clone(),
                principal: command.context.principal.clone(),
            },
            idempotency_key: batch.idempotency_key.clone(),
            recorded_revision: state.revision,
            request_digest: digest,
            collections: batch
                .operations
                .iter()
                .map(|op| op.target().0.to_owned())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            outcome: Err(maximum_error()),
        };
        let ordinal = state
            .mutation_receipt_head
            .count
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorCode::QuotaExceeded, "receipt ordinal exhausted"))?;
        let mut row = Row {
            ordinal,
            key: staged_digest(&(&template.scope.principal, &template.idempotency_key))?.0,
            previous_sha256: state.mutation_receipt_head.sha256.clone(),
            applied: applied.clone(),
            receipt: template.clone(),
        };
        let rejected_bytes = row.validate(state).map_err(terminal_error)?;
        row.receipt.outcome = Ok(WriteReceipt {
            revision: state.revision,
            versions: batch
                .operations
                .iter()
                .map(|op| {
                    let (collection, id) = op.target();
                    (document_path(collection, id), state.revision)
                })
                .collect(),
        });
        let maximum_row_bytes = rejected_bytes.max(row.validate(state).map_err(terminal_error)?);
        let mut maximum_head = state.mutation_receipt_head.clone();
        maximum_head.count = ordinal;
        maximum_head.last_applied_revision = state.revision;
        maximum_head.encoded_bytes = maximum_head
            .encoded_bytes
            .checked_add(maximum_row_bytes)
            .ok_or_else(|| {
                Error::new(ErrorCode::QuotaExceeded, "receipt byte counter exhausted")
            })?;
        if maximum_head.encoded_bytes > state.limits.max_mutation_receipt_bytes {
            return Err(Error::new(
                ErrorCode::QuotaExceeded,
                "permanent mutation receipt byte budget exhausted",
            ));
        }
        // The digest is fixed-width. Only count/byte decimal widths can grow,
        // and this maximum checked head dominates every possible final outcome.
        maximum_head.sha256 = "f".repeat(64);
        Ok(Self {
            template,
            maximum_row_bytes,
            maximum_head,
        })
    }
    fn finalize(
        &self,
        owner: &View,
        absent: &Absent,
        state: &mut TenantState,
        outcome: &Result<WriteReceipt>,
        applied: &crate::staged_terminal::AppliedIdentity,
    ) -> anyhow::Result<Pending> {
        let mut receipt = self.template.clone();
        receipt.outcome = outcome.clone();
        let pending = Pending::prepare(owner, state, Some((receipt, absent)), applied)?;
        let bytes = pending
            .head()
            .encoded_bytes
            .checked_sub(owner.head().encoded_bytes)
            .ok_or_else(|| Error::new(ErrorCode::Corruption, "receipt reserved bytes decreased"))?;
        if bytes > self.maximum_row_bytes
            || pending.head().count != self.maximum_head.count
            || pending.head().encoded_bytes > self.maximum_head.encoded_bytes
        {
            return Err(Error::new(
                ErrorCode::Corruption,
                "admitted receipt exceeded its terminal reservation",
            )
            .into());
        }
        state.mutation_receipt_head = pending.head().clone();
        Ok(pending)
    }
}

impl TenantEngine {
    pub(super) fn prepare_mutation_ordered(
        &self,
        apply: &ApplyOwner<'_>,
        command: &Command,
        batch: &MutationBatch,
        applied: &crate::staged_terminal::AppliedIdentity,
        scope: &ApplyScope,
    ) -> std::result::Result<PreparedCommand, kasumi_store::ScratchOperationFailure> {
        let previous = apply.current();
        let revision = applied.revision;
        let state = &previous.state;
        let authorization = (|| {
            if command.context.tenant != state.tenant {
                return Err(Error::new(ErrorCode::Forbidden, "tenant access denied"));
            }
            command
                .context
                .authorization
                .check_admitted_at(command.timestamp_ms)?;
            authorize_resource(state, &command.context)?;
            lifecycle::guard(state, &command.operation)?;
            for mutation in &batch.operations {
                authorize_state(
                    state,
                    &command.context,
                    Some(mutation.target().0),
                    Action::Write,
                )?;
            }
            for assertion in &batch.read_set {
                if let ReadAssertion::Document { collection, .. }
                | ReadAssertion::Collection { collection, .. } = assertion
                {
                    authorize_state(state, &command.context, Some(collection), Action::Read)?;
                }
            }
            // Canonical permanent records have the same immutable per-operation
            // envelope even after an administrator lowers current batch limits.
            validate_name(&command.context.principal)?;
            validate_name(&batch.idempotency_key)?;
            if batch.operations.is_empty() || batch.operations.len() > 256 {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "invalid mutation operation count",
                ));
            }
            for mutation in &batch.operations {
                let (collection, id) = mutation.target();
                validate_name(collection)?;
                validate_name(id)?;
            }
            Ok(())
        })();
        if let Err(error) = authorization {
            return self
                .prepare_mutation_observation(previous, command, revision, Err(error))
                .map_err(Into::into);
        }
        let (digest, lookup) = kasumi_store::ScratchOperationFailure::ordinary(|| {
            let key = staged_digest(&(&command.context.principal, &batch.idempotency_key))?.0;
            let digest = batch.digest()?;
            let lookup = previous.receipts.lookup(&key)?;
            if let Lookup::Found(row) = &lookup {
                row.validate(state)?;
            }
            Ok((digest, lookup))
        })?;
        let absent = match lookup {
            Lookup::Absent(absent) => absent,
            Lookup::Found(row) => {
                let result = if row.receipt.request_digest == digest {
                    row.receipt.outcome
                } else {
                    Err(Error::new(
                        ErrorCode::Conflict,
                        "idempotency key reused for different input",
                    ))
                };
                return self
                    .prepare_mutation_observation(previous, command, revision, result)
                    .map_err(Into::into);
            }
        };
        let owner = match scope {
            ApplyScope::Committed => previous.receipts.clone(),
            #[cfg(any(test, feature = "test-utils"))]
            ApplyScope::Fixture(disk) => previous.receipts.fixture_owner(disk, state)?,
        };
        kasumi_store::ScratchOperationFailure::ordinary(|| {
            let mut reserved = state.clone();
            reserved.revision = revision;
            let permit = match Permit::prepare(&reserved, command, batch, applied, digest) {
                Ok(permit) => permit,
                Err(error) if error.code == ErrorCode::QuotaExceeded => {
                    return self.prepare_mutation_observation(
                        previous,
                        command,
                        revision,
                        Err(error),
                    );
                }
                Err(error) => return Err(error.into()),
            };
            // Prove the entire rejection can publish BEFORE document changes. Use
            // the longer audit outcome plus maximum head decimal widths. Unrelated
            // staged/target/control completion reservations are included by fits.
            reserved.mutation_receipt_head = permit.maximum_head.clone();
            let committed_audit = audit(command, &reserved, "committed");
            append_audit(&mut reserved, committed_audit.clone())?;
            let accounting = previous.snapshot_accounting.updated(
                state,
                &reserved,
                &BTreeMap::new(),
                &BTreeSet::new(),
            )?;
            if !crate::accounting::audit_fits(&reserved)
                || !accounting.fits(&reserved)?
                || !lifecycle::completion_fits(&reserved, &accounting)?
            {
                return self.prepare_mutation_observation(
                    previous,
                    command,
                    revision,
                    Err(Error::new(
                        ErrorCode::AuditUnavailable,
                        "required mutation terminal and audit capacity unavailable",
                    )),
                );
            }
            drop(reserved);
            // From this point every deterministic outcome selects exactly one row.
            // A storage/invariant failure is outer failure: no Generation publishes.
            let mut next = state.clone();
            next.revision = revision;
            apply.begin_mutation_change_tree(batch)?;
            let changed = batch_changes(batch);
            let attempt = (|| -> SourceResult<WriteReceipt> {
                let receipt = apply_batch(
                    &mut next,
                    batch,
                    revision,
                    command.timestamp_ms,
                    &previous.indexes,
                    previous.document_resolver(),
                )?;
                crate::index_source::validate_changes_with_resolvers(
                    &previous.indexes,
                    state,
                    &next,
                    &changed,
                    previous.document_resolver(),
                    previous.document_resolver(),
                )?;
                crate::change_feed_state::append(state, &mut next, &changed)?;
                Ok(receipt)
            })();
            // Captured state/index disagreements are replica failures. They cannot
            // select a permanent rejection receipt or advance the text writer.
            let attempt = match attempt {
                Err(ReadFailure::Source(error)) => return Err(error.0),
                Err(ReadFailure::Query(error)) if error.code == ErrorCode::Corruption => {
                    return Err(error.into());
                }
                Err(ReadFailure::Query(error)) => Err(error),
                Ok(receipt) => Ok(receipt),
            };
            if let Ok(receipt) = attempt.as_ref() {
                let outcome = Ok(receipt.clone());
                let pending = permit.finalize(&owner, &absent, &mut next, &outcome, applied)?;
                append_audit(&mut next, committed_audit)?;
                let accounting = previous.snapshot_accounting.updated(
                    state,
                    &next,
                    &changed,
                    &BTreeSet::new(),
                )?;
                if crate::accounting::audit_fits(&next)
                    && accounting.fits(&next)?
                    && lifecycle::completion_fits(&next, &accounting)?
                {
                    // Deterministic document/index validation and every acceptance
                    // budget check have finished. Text materialization advances a
                    // shared writer generation, so it cannot precede a rejection.
                    // Any error from here is an outer replica failure; do not select
                    // a rejection receipt and continue with the old text writer.
                    let indexes = Arc::new(
                        crate::index_source::update_with_resolvers(
                            &previous.indexes,
                            state,
                            &next,
                            &changed,
                            previous.document_resolver(),
                            previous.document_resolver(),
                        )
                        .map_err(crate::index_source::into_anyhow)?,
                    );
                    let (receipts, receipt_publication) = match self.application_sources.get() {
                        Some(roots) => pending.prepare_publication(roots)?,
                        None => (pending.stage()?, None),
                    };
                    let candidate = Arc::new(Generation {
                        state: next,
                        receipts,
                        backup_bindings: previous.backup_bindings.clone(),
                        terminals: previous.terminals.clone(),
                        target_resolutions: previous.target_resolutions.clone(),
                        indexes,
                        snapshot_accounting: accounting,
                        application_selection: std::sync::OnceLock::new(),
                        staged_documents: previous.staged_documents.clone(),
                        document_sources: std::sync::OnceLock::new(),
                        _read_reservations: vec![],
                    });
                    return Ok(PreparedCommand {
                        receipt_publication,
                        generation: Some(candidate),
                        changed,
                        outcome,
                    });
                }
            }
            let error = match attempt {
                Err(error) => error,
                Ok(_) => Error::new(
                    ErrorCode::QuotaExceeded,
                    "serialized tenant snapshot byte budget exhausted",
                ),
            };
            drop(next);
            let mut rejected = state.clone();
            rejected.revision = revision;
            let outcome = Err(error);
            let pending = permit.finalize(&owner, &absent, &mut rejected, &outcome, applied)?;
            let event = audit(command, &rejected, "rejected");
            append_audit(&mut rejected, event)?;
            let accounting = previous.snapshot_accounting.updated(
                state,
                &rejected,
                &BTreeMap::new(),
                &BTreeSet::new(),
            )?;
            if !crate::accounting::audit_fits(&rejected)
                || !accounting.fits(&rejected)?
                || !lifecycle::completion_fits(&rejected, &accounting)?
            {
                return Err(Error::new(
                    ErrorCode::Corruption,
                    "reserved mutation terminal cannot publish",
                )
                .into());
            }
            let (receipts, receipt_publication) = match self.application_sources.get() {
                Some(roots) => pending.prepare_publication(roots)?,
                None => (pending.stage()?, None),
            };
            let candidate = Arc::new(Generation {
                state: rejected,
                receipts,
                backup_bindings: previous.backup_bindings.clone(),
                terminals: previous.terminals.clone(),
                target_resolutions: previous.target_resolutions.clone(),
                indexes: previous.indexes.clone(),
                snapshot_accounting: accounting,
                application_selection: std::sync::OnceLock::new(),
                staged_documents: previous.staged_documents.clone(),
                document_sources: std::sync::OnceLock::new(),
                _read_reservations: vec![],
            });
            Ok(PreparedCommand {
                receipt_publication,
                generation: Some(candidate),
                changed: ChangedIds::new(),
                outcome,
            })
        })
    }

    /// No new identity was admitted (or this is exact replay/conflict). Required
    /// audit failure can reject release but cannot modify the selected receipt.
    fn prepare_mutation_observation(
        &self,
        previous: &Generation,
        command: &Command,
        revision: u64,
        mut outcome: Result<WriteReceipt>,
    ) -> anyhow::Result<PreparedCommand> {
        let mut next = previous.state.clone();
        next.revision = revision;
        let event = audit(
            command,
            &next,
            if outcome.is_ok() {
                "committed"
            } else {
                "rejected"
            },
        );
        append_audit(&mut next, event)?;
        let accounting = previous.snapshot_accounting.updated(
            &previous.state,
            &next,
            &BTreeMap::new(),
            &BTreeSet::new(),
        )?;
        let accounting = if crate::accounting::audit_fits(&next)
            && accounting.fits(&next)?
            && lifecycle::completion_fits(&next, &accounting)?
        {
            accounting
        } else {
            next = previous.state.clone();
            next.revision = revision;
            outcome = Err(Error::new(
                ErrorCode::AuditUnavailable,
                "required mutation observation audit capacity unavailable",
            ));
            let event = audit(command, &next, "rejected");
            append_audit(&mut next, event)?;
            let rejected = previous.snapshot_accounting.updated(
                &previous.state,
                &next,
                &BTreeMap::new(),
                &BTreeSet::new(),
            )?;
            if crate::accounting::audit_fits(&next)
                && rejected.fits(&next)?
                && lifecycle::completion_fits(&next, &rejected)?
            {
                rejected
            } else {
                next = previous.state.clone();
                next.revision = revision;
                previous.snapshot_accounting.clone()
            }
        };
        let candidate = Arc::new(Generation {
            state: next,
            receipts: previous.receipts.clone(),
            backup_bindings: previous.backup_bindings.clone(),
            terminals: previous.terminals.clone(),
            target_resolutions: previous.target_resolutions.clone(),
            indexes: previous.indexes.clone(),
            snapshot_accounting: accounting,
            application_selection: std::sync::OnceLock::new(),
            staged_documents: previous.staged_documents.clone(),
            document_sources: std::sync::OnceLock::new(),
            _read_reservations: vec![],
        });
        Ok(PreparedCommand {
            receipt_publication: None,
            generation: Some(candidate),
            changed: ChangedIds::new(),
            outcome,
        })
    }
}

#[cfg(test)]
#[path = "mutation_apply_tests.rs"]
mod tests;
