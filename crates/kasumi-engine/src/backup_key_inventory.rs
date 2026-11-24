//! Authenticate tenant session records retained by the installed Control owner.
use super::*;

impl Database {
    async fn checkpoint_key_inventory(
        &self,
        context: &RequestContext,
        request: &ReadKeyRetentionRequest,
        cancellation: &QueryCancellation,
        alias: Option<&str>,
        checkpoint: &FullBackupCheckpoint,
        recovery: Option<(uuid::Uuid, &str)>,
    ) -> Result<Option<BTreeSet<KeyRetentionEntry>>> {
        let Some(destination) = alias.and_then(|alias| self.archive_destination(alias).ok()) else {
            return Ok(None);
        };
        let reference = match recovery {
            Some((operation_id, _)) => KeyReference::RecoveryRecord { operation_id },
            None => KeyReference::CompletedBackup {
                backup_id: checkpoint.backup_id,
                checkpoint_sha256: staged_digest(checkpoint)?.0,
            },
        };
        let page = std::sync::Mutex::new(BTreeSet::new());
        let observe = |provider: &str, key_ref: &str, version| -> anyhow::Result<()> {
            cancellation.check()?;
            anyhow::ensure!(
                provider.len() <= MAX_KEY_PROVIDER_BYTES && key_ref.len() <= MAX_KEY_REF_BYTES,
                "backup key identity exceeds bound"
            );
            let mut entries = page.lock().unwrap_or_else(|poison| poison.into_inner());
            consider_entry(
                request,
                &mut entries,
                KeyRetentionEntry {
                    key: KeyVersionRef {
                        provider: provider.into(),
                        key_ref: key_ref.into(),
                        version,
                    },
                    reference: reference.clone(),
                },
            )?;
            Ok(())
        };
        let verified = self
            .verified_checkpoint_keys(
                context,
                destination.as_ref(),
                checkpoint.clone(),
                recovery.map(|(_, purpose)| purpose.to_owned()),
                &observe,
            )
            .await;
        cancellation.check()?;
        self.access()?;
        match verified {
            Ok(()) => Ok(Some(
                page.into_inner()
                    .unwrap_or_else(|poison| poison.into_inner()),
            )),
            Err(error) => {
                if let Some(cause) = error.operation_error()
                    && cause.code == ErrorCode::ResourceExhausted
                {
                    return Err(cause.clone());
                }
                if error.admission_refusal().is_some() {
                    return Err(Error::new(
                        ErrorCode::ResourceExhausted,
                        "backup dependency inventory admission exhausted",
                    ));
                }
                tracing::warn!(backup_id = %checkpoint.backup_id, %error, "could not authenticate completed backup key graph");
                Ok(None)
            }
        }
    }

    pub(super) async fn binding_key_inventory(
        &self,
        context: &RequestContext,
        request: &ReadKeyRetentionRequest,
        cancellation: &QueryCancellation,
        entries: &mut BTreeSet<KeyRetentionEntry>,
        missing: &mut BTreeSet<MissingKeyDependency>,
        truncated: &mut bool,
    ) -> Result<Option<String>> {
        let mut fold = InventoryFold {
            context,
            request,
            cancellation,
            entries,
            missing,
            truncated,
            digest: Sha256::new(),
        };
        if let Some(transport) = self.remote_backup.get() {
            return fold.remote(self, transport).await;
        }
        let (control, operator) = match self.backup_authority() {
            Ok(Some(binding)) => binding,
            Ok(None) => return Ok(None),
            Err(error) if error.code == ErrorCode::Unavailable => return Ok(None),
            Err(error) => return Err(error),
        };
        // These gates only recheck the two original owners. The caller funds
        // the bounded page and identities; each row and backup verification
        // separately retains its own workspace across the asynchronous reads.
        let tenant_fence =
            ResponseFence::capture_workspace(ResponseDatabase::Borrowed(self), context, true)?;
        control.engine.authorize(&operator, None, Action::Admin)?;
        let control_fence = control.admitted_response_fence(&operator)?;
        let registration = Arc::new(control.work.begin(cancellation.clone())?);
        control.control_binding_barrier().await?;
        let generation = control.engine.generation()?;
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
            let (row, _workspace) = workspace
                .retained_read(cancellation.clone(), move |workspace, token| {
                    let _owner = owner;
                    token.check()?;
                    let row = backup_control_service::read_tenant_binding(
                        &selected.backup_bindings,
                        &tenant,
                        ordinal,
                    )
                    .map_err(Error::from_physical_source)?;
                    Ok((row, workspace))
                })
                .await?;
            if let Some(row) = row {
                fold.binding(self, &row).await?;
            }
        }
        for (id, operation) in &generation.state.recovery_control.operations {
            cancellation.check()?;
            if operation.request.tenant == context.tenant {
                tenant_fence.check()?;
                control_fence.check()?;
                backup_control_service::check_inventory_recovery(id, operation)?;
                fold.recovery(
                    self,
                    &operation.request,
                    &operation.request_sha256,
                    operation.updated_revision,
                )
                .await?;
            }
        }
        control_fence.check()?;
        tenant_fence.check()?;
        Ok(Some(hex::encode(fold.digest.finalize())))
    }
}

struct InventoryFold<'a> {
    context: &'a RequestContext,
    request: &'a ReadKeyRetentionRequest,
    cancellation: &'a QueryCancellation,
    entries: &'a mut BTreeSet<KeyRetentionEntry>,
    missing: &'a mut BTreeSet<MissingKeyDependency>,
    truncated: &'a mut bool,
    digest: Sha256,
}
impl InventoryFold<'_> {
    async fn remote(
        mut self,
        db: &Database,
        transport: &Arc<dyn RemoteBackupTransport>,
    ) -> Result<Option<String>> {
        let fence =
            ResponseFence::capture_workspace(ResponseDatabase::Borrowed(db), self.context, true)?;
        let position = backup_control_service::SourceQuorum::observe(&db.group)
            .await?
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::Unavailable,
                    "remote backup inventory requires data quorum",
                )
            })?;
        let scan = uuid::Uuid::new_v4();
        let mut cursor = BackupInventoryCursor::FIRST;
        let mut selection = None;
        let mut binding_count = None;
        loop {
            self.cancellation.check()?;
            position.check()?;
            fence.check()?;
            let _workspace = db.admission().reserve(
                3 * MAX_REMOTE_BACKUP_BYTES as u64,
                Some(self.cancellation.clone()),
            )?;
            let read = BackupInventoryRead {
                scan,
                cursor,
                selection: selection.clone(),
            };
            let page = match db
                .remote_inventory_page(transport, self.context, read)
                .await
            {
                Ok(page) => page,
                Err(error) if selection.is_none() && error.code == ErrorCode::Unavailable => {
                    tracing::warn!(%error,"remote backup session inventory unavailable");
                    return Ok(None);
                }
                Err(error) => return Err(error),
            };
            if binding_count
                .replace(page.binding_count)
                .is_some_and(|old| old != page.binding_count)
            {
                return Err(Error::new(
                    ErrorCode::Corruption,
                    "remote backup inventory count differs",
                ));
            }
            match page.record {
                Some(BackupInventoryRecord::Binding { selected }) => {
                    self.binding(db, &selected).await?
                }
                Some(BackupInventoryRecord::Recovery {
                    request,
                    request_sha256,
                    updated_revision,
                }) => {
                    self.recovery(db, &request, &request_sha256, updated_revision)
                        .await?
                }
                None => {}
            }
            self.cancellation.check()?;
            position.check()?;
            fence.check()?;
            selection = Some(page.selection);
            match page.next {
                Some(next) => cursor = next,
                None => return Ok(Some(hex::encode(self.digest.finalize()))),
            }
        }
    }

    async fn binding(&mut self, db: &Database, selected: &RemoteBackupRecord) -> Result<()> {
        let RemoteBackupRecord { record, terminal } = selected;
        let context = self.context;
        let request = self.request;
        let cancellation = self.cancellation;
        let entries = &mut *self.entries;
        let missing = &mut *self.missing;
        let truncated = &mut *self.truncated;
        let digest = &mut self.digest;
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
        let observed = db
            .store
            .with_verified_binding_keys(record, terminal.as_ref(), |keys| {
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
        db.access()?;
        let authenticated = match observed {
            Ok((observed, keys)) => {
                digest.update([1]);
                digest.update(keys);
                for entry in observed {
                    consider_entry(request, entries, entry)?;
                }
                true
            }
            Err(error) => {
                if let Some(error) = error.downcast_ref::<Error>()
                    && error.code == ErrorCode::ResourceExhausted
                {
                    return Err(error.clone());
                }
                tracing::warn!("could not authenticate retained backup session keys");
                digest.update([0]);
                add_missing(
                    missing,
                    truncated,
                    MissingKeyDependency::RecordUnreadable {
                        record_kind: KeyReferenceKind::BackupSession,
                        id: id.to_string(),
                    },
                );
                false
            }
        };
        if let Some(BackupSessionOutcome::Complete { checkpoint, .. }) =
            terminal.as_ref().map(|t| &t.outcome)
        {
            let observed = if authenticated {
                db.checkpoint_key_inventory(
                    context,
                    request,
                    cancellation,
                    record.claim.destination_alias.as_deref(),
                    checkpoint,
                    None,
                )
                .await?
            } else {
                None
            };
            digest.update([u8::from(observed.is_some())]);
            if let Some(observed) = observed {
                for entry in observed {
                    consider_entry(request, entries, entry)?;
                }
            } else {
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
        Ok(())
    }

    async fn recovery(
        &mut self,
        db: &Database,
        start: &RecoveryStart,
        request_sha256: &str,
        updated_revision: u64,
    ) -> Result<()> {
        let context = self.context;
        let request = self.request;
        let cancellation = self.cancellation;
        let entries = &mut *self.entries;
        let missing = &mut *self.missing;
        let truncated = &mut *self.truncated;
        let digest = &mut self.digest;
        let id = start.operation_id.to_string();
        digest.update(
            staged_digest(&(&id, request_sha256, updated_revision))?
                .0
                .as_bytes(),
        );
        let observed = db
            .checkpoint_key_inventory(
                context,
                request,
                cancellation,
                Some(&start.materialization.destination_alias),
                &start.checkpoint,
                Some((start.operation_id, &start.source_purpose_sha256)),
            )
            .await?;
        digest.update([u8::from(observed.is_some())]);
        if let Some(observed) = observed {
            for entry in observed {
                consider_entry(request, entries, entry)?;
            }
        } else {
            add_missing(
                missing,
                truncated,
                MissingKeyDependency::RecordUnreadable {
                    record_kind: KeyReferenceKind::RecoveryRecord,
                    id,
                },
            );
        }
        Ok(())
    }
}
