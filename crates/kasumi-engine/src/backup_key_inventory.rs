//! Authenticate tenant session records retained by the installed Control owner.
use super::*;

impl Database {
    pub(super) async fn binding_key_inventory(
        &self,
        context: &RequestContext,
        request: &ReadKeyRetentionRequest,
        cancellation: &QueryCancellation,
        entries: &mut BTreeSet<KeyRetentionEntry>,
        missing: &mut BTreeSet<MissingKeyDependency>,
        truncated: &mut bool,
    ) -> Result<Option<String>> {
        let (control, operator) = match self.backup_authority() {
            Ok(Some(binding)) => binding,
            Ok(None) => return Ok(None),
            Err(error) if error.code == ErrorCode::Unavailable => return Ok(None),
            Err(error) => return Err(error),
        };
        let tenant_fence = self.response_fence(context)?;
        control.engine.authorize(&operator, None, Action::Admin)?;
        let control_fence = control.response_fence(&operator)?;
        let registration = Arc::new(control.work.begin(cancellation.clone())?);
        control.barrier().await?;
        let generation = control.engine.generation()?;
        let mut digest = Sha256::new();
        for ordinal in 1..=generation.state.backup_binding_head.count {
            cancellation.check()?;
            tenant_fence.check()?;
            control_fence.check()?;
            let workspace = control
                .admission()
                .reserve(8 << 20, Some(cancellation.clone()))?;
            let selected = generation.clone();
            let owner = registration.clone();
            let tenant = context.tenant.clone();
            let row = workspace
                .retained_read(cancellation.clone(), move |workspace, token| {
                    let _owner = owner;
                    token.check()?;
                    let read = || -> anyhow::Result<_> {
                        let row = selected.backup_bindings.row(ordinal)?;
                        if row.terminal.is_some() || row.record.claim.tenant != tenant {
                            return Ok(None);
                        }
                        let decision = selected
                            .backup_bindings
                            .terminal(row.record.claim.session_id)?;
                        Ok(Some((
                            row.record,
                            decision.and_then(|row| row.terminal),
                            workspace,
                        )))
                    };
                    read().map_err(|_| {
                        Error::new(
                            ErrorCode::Corruption,
                            "Control binding inventory read failed",
                        )
                    })
                })
                .await?;
            let Some((record, terminal, _row_workspace)) = row else {
                continue;
            };
            let id = record.claim.session_id;
            digest.update(
                staged_digest(&(
                    id,
                    &record.claim.intent_ciphertext_sha256,
                    terminal.as_ref().map(|t| &t.ciphertext_sha256),
                ))?
                .0
                .as_bytes(),
            );
            let observed = self
                .store
                .with_verified_binding_keys(&record, terminal.as_ref(), |keys| {
                    let mut observed = BTreeSet::new();
                    let mut key_digest = Sha256::new();
                    for (provider, key_ref, version) in keys {
                        cancellation.check()?;
                        anyhow::ensure!(
                            provider.len() <= MAX_KEY_PROVIDER_BYTES
                                && key_ref.len() <= MAX_KEY_REF_BYTES,
                            "session key identity exceeds bound"
                        );
                        let entry = KeyRetentionEntry {
                            key: KeyVersionRef {
                                provider: provider.into(),
                                key_ref: key_ref.into(),
                                version,
                            },
                            reference: KeyReference::BackupSession { session_id: id },
                        };
                        key_digest.update(staged_digest(&entry)?.0.as_bytes());
                        consider_entry(request, &mut observed, entry)?;
                    }
                    Ok((observed, key_digest.finalize()))
                })
                .await;
            cancellation.check()?;
            self.access()?;
            match observed {
                Ok((observed, keys)) => {
                    digest.update([1]);
                    digest.update(keys);
                    for entry in observed {
                        consider_entry(request, entries, entry)?;
                    }
                }
                Err(error) => {
                    if let Some(error) = error.downcast_ref::<Error>()
                        && error.code == ErrorCode::ResourceExhausted
                    {
                        return Err(error.clone());
                    }
                    tracing::warn!(%id, %error, "could not authenticate retained backup session keys");
                    digest.update([0]);
                    add_missing(
                        missing,
                        truncated,
                        MissingKeyDependency::RecordUnreadable {
                            record_kind: KeyReferenceKind::BackupSession,
                            id: id.to_string(),
                        },
                    );
                }
            }
            if terminal.is_some_and(|t| matches!(t.outcome, BackupSessionOutcome::Complete { .. }))
            {
                // The session's wrapping catalog proves nothing about the separately stored
                // checkpoint objects. Retain the exact dependency until those are read.
                add_missing(
                    missing,
                    truncated,
                    MissingKeyDependency::RecordUnreadable {
                        record_kind: KeyReferenceKind::CompletedBackup,
                        id: id.to_string(),
                    },
                );
            }
        }
        control_fence.check()?;
        tenant_fence.check()?;
        Ok(Some(hex::encode(digest.finalize())))
    }
}
