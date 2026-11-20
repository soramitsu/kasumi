//! A page is an observation of the authenticated local catalogs and retained
//! tenant archive chain. Every source outside that observation is explicit in
//! coverage. A page grants no provider mutation or retirement authority.
use super::*;
#[path = "backup_key_inventory.rs"]
mod backup_keys;
#[path = "key_retirement_service.rs"]
mod retirement;

/// One observation of a whole scope at one selected generation. The page
/// holds the entries the request selected; the coverage, dependency position
/// and retirement state describe the entire scope, whatever the page shows.
pub(super) struct KeyRetentionObservation {
    pub(super) page: KeyRetentionPage,
    /// Replicated dependency position of the observed generation.
    pub(super) dependency_sha256: String,
    pub(super) retirements: KeyRetirementState,
    revision: u64,
    strict: bool,
    epoch: u64,
}

fn consider_entry(
    request: &ReadKeyRetentionRequest,
    entries: &mut BTreeSet<KeyRetentionEntry>,
    entry: KeyRetentionEntry,
) -> Result<()> {
    entry.validate()?;
    if request
        .cursor
        .as_ref()
        .is_none_or(|cursor| entry > cursor.after)
    {
        entries.insert(entry);
        if entries.len() > usize::from(request.limit) + 1 {
            entries.pop_last();
        }
    }
    Ok(())
}

fn add_missing(
    missing: &mut BTreeSet<MissingKeyDependency>,
    truncated: &mut bool,
    entry: MissingKeyDependency,
) {
    missing.insert(entry);
    if missing.len() > MAX_MISSING_KEY_DEPENDENCIES {
        missing.pop_last();
        *truncated = true;
    }
}

impl Database {
    pub async fn read_key_retention(
        &self,
        context: &RequestContext,
        request: ReadKeyRetentionRequest,
    ) -> Result<AdmittedOutput<KeyRetentionPage>> {
        let result = self.key_retention_page(context, &request).await;
        self.audit_result(context, result).await
    }

    /// Whether the scope is this database's own: `true` for Control. Every
    /// other scope has an independent installed owner.
    fn key_retention_scope(
        &self,
        context: &RequestContext,
        scope: &KeyRetentionScope,
    ) -> Result<bool> {
        match scope {
            KeyRetentionScope::Tenant { tenant }
                if tenant == &context.tenant && tenant != crate::control::CONTROL_TENANT =>
            {
                Ok(false)
            }
            KeyRetentionScope::Control {} if context.tenant == crate::control::CONTROL_TENANT => {
                Ok(true)
            }
            KeyRetentionScope::Tenant { .. } | KeyRetentionScope::Control {} => Err(Error::new(
                ErrorCode::Forbidden,
                "key retention scope differs from authorization",
            )),
            _ => Err(Error::new(
                ErrorCode::Unavailable,
                "requested key retention scope requires its independent installed owner",
            )),
        }
    }

    async fn observe_history_object_keys(
        &self,
        archive: &RetainedHistoryArchive,
        object: (&str, &str, Option<&ArchiveChunkDescriptor>),
        destination: Option<&dyn BackupDestination>,
        request: &ReadKeyRetentionRequest,
        cancellation: &QueryCancellation,
    ) -> Result<(BTreeSet<KeyRetentionEntry>, [u8; 32])> {
        let (object_id, hash, chunk) = object;
        let destination = destination
            .ok_or_else(|| Error::new(ErrorCode::Unavailable, "history destination unavailable"))?;
        let limit = chunk.map_or(MAX_ARCHIVE_MANIFEST_BYTES, |c| c.plaintext_bytes);
        if chunk.is_some() && limit > MAX_ARCHIVE_CHUNK_BYTES {
            return Err(Error::new(
                ErrorCode::Corruption,
                "retained history chunk exceeds its bound",
            ));
        }
        let _workspace = self
            .admission()
            .reserve((limit * 6 + (4 << 20)) as u64, Some(cancellation.clone()))?;
        let (id, bytes) = self
            .history_ciphertext(destination, object_id, hash, limit, cancellation)
            .await?;
        self.store
            .with_verified_object_keys(&bytes, id, limit, |contents, keys| {
                contents.source_purpose.validate_application_identity(
                    &archive.manifest.tenant,
                    &archive.manifest.source_incarnation,
                )?;
                if let Some(chunk) = chunk {
                    anyhow::ensure!(
                        contents.snapshot.len() == chunk.plaintext_bytes
                            && hex::encode(Sha256::digest(&contents.snapshot))
                                == chunk.plaintext_sha256,
                        "history chunk differs from committed descriptor"
                    );
                } else {
                    let manifest: HistoryArchiveManifest =
                        serde_json::from_slice(&contents.snapshot)?;
                    anyhow::ensure!(
                        manifest == archive.manifest,
                        "history manifest differs from committed catalog"
                    );
                }
                let mut entries = BTreeSet::new();
                let mut digest = Sha256::new();
                for (provider, key_ref, version) in keys {
                    cancellation.check()?;
                    anyhow::ensure!(
                        provider.len() <= MAX_KEY_PROVIDER_BYTES
                            && key_ref.len() <= MAX_KEY_REF_BYTES,
                        "history key identity exceeds bound"
                    );
                    let entry = KeyRetentionEntry {
                        key: KeyVersionRef {
                            provider: provider.into(),
                            key_ref: key_ref.into(),
                            version,
                        },
                        reference: KeyReference::HistoryArchive {
                            archive_id: archive.manifest.archive_id.clone(),
                            object_id: object_id.to_owned(),
                        },
                    };
                    digest.update(staged_digest(&entry)?.0.as_bytes());
                    consider_entry(request, &mut entries, entry)?;
                }
                Ok((entries, digest.finalize().into()))
            })
            .await
            .map_err(|error| {
                error
                    .downcast_ref::<Error>()
                    .cloned()
                    .unwrap_or_else(|| Error::new(ErrorCode::Unavailable, error.to_string()))
            })
    }

    async fn history_key_inventory(
        &self,
        state: &TenantState,
        context: &RequestContext,
        request: &ReadKeyRetentionRequest,
        cancellation: &QueryCancellation,
        missing: &mut BTreeSet<MissingKeyDependency>,
        truncated: &mut bool,
    ) -> Result<(BTreeSet<KeyRetentionEntry>, [u8; 32])> {
        let mut entries = BTreeSet::new();
        let mut history_digest = Sha256::new();
        for (archive_id, archive) in &state.history_archives {
            if archive_id != &archive.manifest.archive_id {
                return Err(Error::new(
                    ErrorCode::Corruption,
                    "retained archive identity differs from its catalog",
                ));
            }
            let destination = self.archive_destination(&archive.storage_destination);
            let scoped = destination
                .as_ref()
                .ok()
                .and_then(|d| {
                    archive
                        .storage_backup_session
                        .map(|session| kasumi_store::BackupSessionObjects::new(d.as_ref(), session))
                })
                .transpose()
                .map_err(|_| {
                    Error::new(ErrorCode::Corruption, "invalid retained history session")
                })?;
            let resolved: Option<&dyn BackupDestination> = scoped
                .as_ref()
                .map(|d| d as _)
                .or_else(|| destination.as_ref().ok().map(Arc::as_ref));
            let manifest = std::iter::once((
                &archive.manifest_object_id,
                &archive.manifest_ciphertext_sha256,
                None,
            ));
            let chunks = archive
                .manifest
                .chunks
                .iter()
                .map(|chunk| (&chunk.object_id, &chunk.ciphertext_sha256, Some(chunk)));
            for (object_id, hash, chunk) in manifest.chain(chunks) {
                cancellation.check()?;
                self.engine
                    .authorize_release(context, None, Action::Admin, state.policy_epoch)?;
                history_digest.update(
                    staged_digest(&(
                        archive_id,
                        &archive.storage_destination,
                        archive.storage_backup_session,
                        object_id,
                        hash,
                    ))?
                    .0
                    .as_bytes(),
                );
                let observe = self.observe_history_object_keys(
                    archive,
                    (object_id, hash, chunk),
                    resolved,
                    request,
                    cancellation,
                );
                let observation = tokio::select! {
                    result = observe => result,
                    _ = cancelled(cancellation) => return Err(cancelled_error()),
                };
                cancellation.check()?;
                self.access()?;
                match observation {
                    Ok((observed, object_digest)) => {
                        history_digest.update([1]);
                        history_digest.update(object_digest);
                        for entry in observed {
                            consider_entry(request, &mut entries, entry)?;
                        }
                    }
                    Err(error) => {
                        if error.code == ErrorCode::ResourceExhausted {
                            return Err(error);
                        }
                        tracing::warn!(%archive_id, %object_id, %error, "could not authenticate retained history key dependencies");
                        history_digest.update([0]);
                        add_missing(
                            missing,
                            truncated,
                            MissingKeyDependency::RecordUnreadable {
                                record_kind: KeyReferenceKind::HistoryArchive,
                                id: object_id.clone(),
                            },
                        );
                    }
                }
            }
        }
        Ok((entries, history_digest.finalize().into()))
    }

    async fn key_retention_page(
        &self,
        context: &RequestContext,
        request: &ReadKeyRetentionRequest,
    ) -> Result<AdmittedOutput<KeyRetentionPage>> {
        request.validate()?;
        let (observation, mut reservation) =
            self.observe_key_retention(context, request, false).await?;
        reservation.retain_workspace();
        self.release_event(
            context,
            None,
            observation.revision,
            observation.strict,
            observation.epoch,
            "read_key_retention",
        )
        .await?;
        self.engine
            .authorize_release(context, None, Action::Admin, observation.epoch)?;
        self.access()?;
        Ok(AdmittedOutput::new(observation.page, Arc::new(reservation)))
    }

    /// Observe every source of the scope once. A `probe` is this owner's own
    /// selection of entries: its cursor is a lower bound that no page issued,
    /// so it is neither checked against the inventory nor continued.
    pub(super) async fn observe_key_retention(
        &self,
        context: &RequestContext,
        request: &ReadKeyRetentionRequest,
        probe: bool,
    ) -> Result<(KeyRetentionObservation, crate::admission::Reservation)> {
        request.scope.validate()?;
        self.access()?;
        self.engine.authorize(context, None, Action::Admin)?;
        let control = self.key_retention_scope(context, &request.scope)?;
        let cancellation = QueryCancellation::default();
        let _cancel = CancelOnDrop(cancellation.clone());
        let registration = self.work.begin(cancellation.clone())?;
        // One extra ordered entry decides whether a continuation is needed.
        // Fund the original tree, cloned cursor, result vector and the largest
        // transient identity before reading either catalog.
        let budget = (u64::from(request.limit) + 4)
            * 2
            * (MAX_KEY_REF_BYTES + MAX_KEY_PROVIDER_BYTES + 1024) as u64
            + (256 << 10);
        let reservation = self
            .admission()
            .reserve(budget, Some(cancellation.clone()))?;
        self.barrier().await?;
        let generation = self.engine.generation()?;
        let state = &generation.state;
        if control {
            context.authorization.require_control(&state.incarnation)?;
        }
        let epoch = state.policy_epoch;
        self.engine
            .authorize_release(context, None, Action::Admin, epoch)?;
        let metrics = self.group.metrics();
        let membership = &metrics.membership_config;
        let membership_epoch = membership
            .log_id()
            .as_ref()
            .map_or(0, |position| position.index);
        if membership_epoch > metrics.last_applied.map_or(0, |position| position.index) {
            return Err(Error::new(
                ErrorCode::Unavailable,
                "membership has not reached its applied position",
            ));
        }
        let local = self.group.node_id();
        if !membership.membership().nodes().any(|(&id, _)| id == local) {
            return Err(Error::new(
                ErrorCode::Unavailable,
                "local node lacks a current membership report",
            ));
        }
        let mut missing = BTreeSet::new();
        let mut truncated = false;
        if !self
            .stores
            .sessions_bound_from_creation()
            .map_err(|_| Error::new(ErrorCode::Unavailable, "session catalog origin unavailable"))?
        {
            missing.insert(MissingKeyDependency::SessionIndexUnavailable {});
        }
        for (&node_id, _) in membership.membership().nodes() {
            if node_id != local {
                add_missing(
                    &mut missing,
                    &mut truncated,
                    MissingKeyDependency::MemberUnreported { node_id },
                );
            }
        }
        let (mut entries, history_digest) = self
            .history_key_inventory(
                state,
                context,
                request,
                &cancellation,
                &mut missing,
                &mut truncated,
            )
            .await?;
        let session_digest = if control {
            // Each tenant enumerates its own Control-bound session ciphertext.
            None
        } else {
            let observe = self.binding_key_inventory(
                context,
                request,
                &cancellation,
                &mut entries,
                &mut missing,
                &mut truncated,
            );
            let digest = tokio::select! {
                result = observe => result?,
                _ = cancelled(&cancellation) => return Err(cancelled_error()),
            };
            // Without its installed Control owner this scope has no
            // authoritative index of its backup sessions and checkpoints.
            if digest.is_none() {
                add_missing(
                    &mut missing,
                    &mut truncated,
                    MissingKeyDependency::SessionIndexUnavailable {},
                );
            }
            digest
        };
        let scope_hash = request.scope.sha256()?;
        let request = request.clone();
        let stores = self.stores.clone();
        let revision = state.revision;
        let strict = state.policy.strict_read_audit;
        let (observation, reservation) = reservation
            .retained_read(cancellation, move |reservation, token| {
                let _registration = registration;
                let mut consider = |entry| {
                    token.check()?;
                    consider_entry(&request, &mut entries, entry)
                };
                let digest = stores
                    .visit_key_retention_catalogs(
                        |custody, catalog_id, provider, key_ref, version| {
                            anyhow::ensure!(
                                provider.len() <= MAX_KEY_PROVIDER_BYTES
                                    && key_ref.len() <= MAX_KEY_REF_BYTES,
                                "catalog identity exceeds key retention bounds"
                            );
                            let domain = if custody {
                                KeyCatalogDomain::RetirementCustody
                            } else if control {
                                KeyCatalogDomain::NodeControl
                            } else {
                                KeyCatalogDomain::Application
                            };
                            consider(KeyRetentionEntry {
                                key: KeyVersionRef {
                                    provider: provider.into(),
                                    key_ref: key_ref.into(),
                                    version,
                                },
                                reference: KeyReference::Catalog {
                                    node_id: local,
                                    catalog_id,
                                    domain,
                                },
                            })?;
                            Ok(())
                        },
                    )
                    .map_err(|error| {
                        error.downcast_ref::<Error>().cloned().unwrap_or_else(|| {
                            Error::new(ErrorCode::Unavailable, error.to_string())
                        })
                    })?;
                let state = &generation.state;
                let mut archive_digest = Sha256::new();
                let unreadable = crate::tenant_audit_directory::visit_key_references(
                    stores.application(),
                    &state.audit_retention,
                    |reference| {
                        token.check()?;
                        archive_digest.update(staged_digest(reference)?.0.as_bytes());
                        consider(KeyRetentionEntry {
                            key: KeyVersionRef::from(&reference.key),
                            reference: KeyReference::AuditArchive {
                                stream_id: reference.stream_id,
                                first_sequence: reference.object.first_sequence,
                            },
                        })
                    },
                )?;
                token.check()?;
                if let Some(object_id) = unreadable {
                    add_missing(
                        &mut missing,
                        &mut truncated,
                        MissingKeyDependency::RecordUnreadable {
                            record_kind: KeyReferenceKind::AuditArchive,
                            id: object_id.to_string(),
                        },
                    );
                }
                // Each accepted recovery transition advances its operation revision.
                // Retain the identity of every unknown checkpoint, even when the
                // bounded missing list omits it. Audit-only revisions need not
                // invalidate an unrelated cursor.
                let mut recovery_digest = Sha256::new();
                for (id, operation) in &state.recovery_control.operations {
                    token.check()?;
                    if *id != operation.request.operation_id.to_string() {
                        return Err(Error::new(
                            ErrorCode::Corruption,
                            "recovery dependency identity differs",
                        ));
                    }
                    recovery_digest.update(
                        staged_digest(&(
                            id,
                            operation.updated_revision,
                            &operation.request_sha256,
                            &operation.request.checkpoint,
                        ))?
                        .0
                        .as_bytes(),
                    );
                    add_missing(
                        &mut missing,
                        &mut truncated,
                        MissingKeyDependency::RecordUnreadable {
                            record_kind: KeyReferenceKind::RecoveryRecord,
                            id: id.clone(),
                        },
                    );
                }
                let inventory_sha256 = staged_digest(&(
                    // The fence and floors are part of what a page observed.
                    ("kasumi.key-retention.local.v6", &state.key_retirements),
                    &scope_hash,
                    &state.incarnation,
                    epoch,
                    membership_epoch,
                    local,
                    digest,
                    hex::encode(history_digest),
                    session_digest,
                    &state.backup_binding_head,
                    hex::encode(recovery_digest.finalize()),
                    state.audit_retention.archive_segments,
                    hex::encode(archive_digest.finalize()),
                    &missing,
                    truncated,
                ))?
                .0;
                // Strict read auditing may advance the application revision between
                // pages. Keep the original revision only if the observed inventory
                // and membership still match, including catalog-only rotations.
                let coverage_revision =
                    if let Some(cursor) = request.cursor.as_ref().filter(|_| !probe) {
                        if cursor.inventory_sha256 != inventory_sha256
                            || cursor.membership_epoch != membership_epoch
                            || cursor.coverage_revision > revision
                        {
                            return Err(Error::new(
                                ErrorCode::CursorExpired,
                                "key retention inventory changed",
                            ));
                        }
                        cursor.coverage_revision
                    } else {
                        revision
                    };
                // Every current member reported and every referenced record
                // authenticated: the digest commits to the whole scope listing,
                // not to the entries this request selected.
                let coverage_sha256 =
                    staged_digest(&("kasumi.key-retention.coverage.v1", &inventory_sha256))?.0;
                let mut page_entries =
                    Vec::with_capacity(entries.len().min(usize::from(request.limit)));
                let mut bytes = 0;
                let mut more = false;
                for entry in entries {
                    let encoded = crate::accounting::encoded_len(&entry)?;
                    // Leave room for the full cursor (which repeats the final
                    // entry), missing-dependency list and framing. Strings may
                    // expand sixfold under JSON escaping.
                    if page_entries.len() == usize::from(request.limit)
                        || bytes + encoded + 1 > MAX_KEY_RETENTION_PAGE_BYTES - (128 << 10)
                    {
                        more = true;
                        break;
                    }
                    bytes += encoded + 1;
                    page_entries.push(entry);
                }
                let next_cursor = if more && !probe {
                    Some(KeyRetentionCursor {
                        scope_sha256: scope_hash,
                        inventory_sha256,
                        membership_epoch,
                        coverage_revision,
                        after: page_entries
                            .last()
                            .ok_or_else(|| {
                                Error::new(
                                    ErrorCode::ResourceExhausted,
                                    "key retention entry exceeds response bound",
                                )
                            })?
                            .clone(),
                    })
                } else {
                    None
                };
                let coverage = if missing.is_empty() {
                    KeyRetentionCoverage::Complete {
                        coverage_revision,
                        membership_epoch,
                        coverage_sha256,
                    }
                } else {
                    KeyRetentionCoverage::Incomplete {
                        coverage_revision,
                        membership_epoch,
                        missing: missing.into_iter().collect(),
                        truncated,
                    }
                };
                let page = KeyRetentionPage {
                    entries: page_entries,
                    next_cursor,
                    coverage,
                };
                if crate::accounting::encoded_len(&page)? > MAX_KEY_RETENTION_PAGE_BYTES {
                    return Err(Error::new(
                        ErrorCode::ResourceExhausted,
                        "key retention page exceeds response bound",
                    ));
                }
                if !probe {
                    page.validate(&request)?;
                }
                let observation = KeyRetentionObservation {
                    page,
                    dependency_sha256: state.key_dependency_sha256()?,
                    retirements: state.key_retirements.clone(),
                    revision,
                    strict,
                    epoch,
                };
                Ok((observation, reservation))
            })
            .await?;
        self.engine
            .authorize_release(context, None, Action::Admin, epoch)?;
        self.access()?;
        Ok((observation, reservation))
    }
}
