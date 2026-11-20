//! A page is an observation of the authenticated local catalogs and retained
//! tenant archive chain. Every source outside that observation is explicit in
//! coverage. A page grants no provider mutation or retirement authority.
use super::*;
#[path = "backup_key_inventory.rs"]
mod backup_keys;
#[path = "key_retention_member.rs"]
mod member;
#[path = "key_retirement_service.rs"]
mod retirement;
#[path = "key_retention_security_audit.rs"]
mod security_audit;
pub use security_audit::SignerCatalog;

/// Installed standalone journal interpretation. Only references from the
/// already-opened security store enter this administrative read.
pub enum LocalRecoveryKeyFinding {
    Entry(KeyRetentionEntry),
    Missing(MissingKeyDependency),
}

/// Source facts selected from a physically authenticated standalone journal row.
pub struct LocalRecoveryCheckpoint<'a> {
    pub checkpoint: &'a FullBackupCheckpoint,
    pub source_purpose: &'a kasumi_store::StoragePurpose,
    pub keys: Arc<dyn kasumi_store::KeyProvider>,
    pub destination: &'a str,
}

/// The installed source of one serving target's historical backup. The journal
/// and the serving database must independently identify the original operation.
pub struct TargetCheckpointSource {
    pub control: Arc<Database>,
    pub target: Arc<Database>,
    pub destination_alias: String,
    pub destination: Arc<dyn BackupDestination>,
    pub keys: Arc<dyn kasumi_store::KeyProvider>,
}

pub trait TargetCheckpointInventory: Send + Sync {
    fn source(
        &self,
        target: uuid::Uuid,
        checkpoint: &FullBackupCheckpoint,
    ) -> anyhow::Result<Option<TargetCheckpointSource>>;
}

pub(super) enum CheckpointPurpose<'a> {
    Exact(&'a kasumi_store::StoragePurpose),
    Digest(&'a str),
}

pub(super) struct RecoveryGraph<'a> {
    pub(super) checkpoint: &'a FullBackupCheckpoint,
    pub(super) purpose: CheckpointPurpose<'a>,
    pub(super) keys: Arc<dyn kasumi_store::KeyProvider>,
    pub(super) destination: Arc<dyn BackupDestination>,
}

pub struct LocalRecoveryKeyRead<'a> {
    context: &'a RequestContext,
    request: &'a ReadKeyRetentionRequest,
    security: &'a SecurityAudit,
    token: &'a QueryCancellation,
}

impl LocalRecoveryKeyRead<'_> {
    pub fn cancellation(&self) -> &QueryCancellation {
        self.token
    }

    /// Invoked by the coordinator on the retained physical census worker. Keep
    /// partial keys private until the whole authenticated graph matches.
    pub fn visit_checkpoint(
        &self,
        control: &Database,
        tenant: &Database,
        selected: LocalRecoveryCheckpoint<'_>,
        visit: impl FnMut(KeyRetentionEntry) -> anyhow::Result<()>,
    ) -> anyhow::Result<Option<[u8; 32]>> {
        self.token.check()?;
        anyhow::ensure!(
            matches!(self.request.scope, KeyRetentionScope::LocalRecovery {}),
            "standalone journal scope required"
        );
        selected.source_purpose.validate_application_identity(
            &selected.checkpoint.tenant,
            &selected.checkpoint.source_incarnation,
        )?;
        let destination = match tenant.archive_destination(selected.destination) {
            Ok(destination) => destination,
            Err(original) => {
                tracing::warn!(backup_id = %selected.checkpoint.backup_id, %original, "original recovery backup destination unavailable");
                return Ok(None);
            }
        };
        self.visit_graph(
            control,
            tenant,
            RecoveryGraph {
                checkpoint: selected.checkpoint,
                purpose: CheckpointPurpose::Exact(selected.source_purpose),
                keys: selected.keys,
                destination,
            },
            visit,
        )
    }

    fn target_checkpoint(
        &self,
        journal: &crate::TargetJournal,
        inventory: &dyn TargetCheckpointInventory,
        target: uuid::Uuid,
        checkpoint: &FullBackupCheckpoint,
        visit: impl FnMut(KeyRetentionEntry) -> anyhow::Result<()>,
    ) -> anyhow::Result<Option<[u8; 32]>> {
        self.token.check()?;
        anyhow::ensure!(
            matches!(self.request.scope, KeyRetentionScope::TargetJournal {}),
            "target journal scope required"
        );
        let Some(source) = inventory.source(target, checkpoint)? else {
            return Ok(None);
        };
        anyhow::ensure!(
            source
                .control
                .target_keys
                .get()
                .and_then(std::sync::Weak::upgrade)
                .is_some_and(|installed| std::ptr::eq(installed.as_ref(), journal)),
            "target source belongs to another Control journal"
        );
        let generation = source.target.engine.generation()?;
        let state = &generation.state;
        let id = target.to_string();
        let origin = &state
            .target_lifecycle
            .get(&id)
            .ok_or_else(|| anyhow::anyhow!("target database has no enrolled genesis"))?
            .origin;
        anyhow::ensure!(
            state.tenant == checkpoint.tenant
                && state.incarnation == id
                && state.restored_from.as_ref() == Some(checkpoint)
                && origin.materialization.request.checkpoint == *checkpoint
                && origin.input.destination_alias == source.destination_alias,
            "target checkpoint differs from the serving genesis or installed backup alias"
        );
        journal.require_checkpoint_origin(origin, &source.target.store)?;
        let digest = self.visit_graph(
            &source.control,
            &source.target,
            RecoveryGraph {
                checkpoint,
                purpose: CheckpointPurpose::Digest(&origin.input.source_purpose_sha256),
                keys: source.keys,
                destination: source.destination,
            },
            visit,
        )?;
        journal.require_checkpoint_origin(origin, &source.target.store)?;
        self.token.check()?;
        Ok(digest)
    }

    fn visit_graph(
        &self,
        control: &Database,
        tenant: &Database,
        selected: RecoveryGraph<'_>,
        mut visit: impl FnMut(KeyRetentionEntry) -> anyhow::Result<()>,
    ) -> anyhow::Result<Option<[u8; 32]>> {
        self.token.check()?;
        anyhow::ensure!(
            control.store.tenant() == crate::control::CONTROL_TENANT
                && self.context.tenant == control.store.tenant()
                && Arc::ptr_eq(self.security.store(), control.security_audit.store())
                && Arc::ptr_eq(self.security.store(), tenant.security_audit.store())
                && Arc::ptr_eq(
                    control.store.persistent_disk(),
                    tenant.store.persistent_disk()
                ),
            "local recovery key reader belongs to another installation"
        );
        control
            .engine
            .authorize(self.context, None, Action::Admin)?;
        let fence = ResponseFence::capture_workspace(
            ResponseDatabase::Borrowed(control),
            self.context,
            true,
        )?;
        let _page = control.admission().reserve(
            (u64::from(self.request.limit) + 2)
                * (MAX_KEY_REF_BYTES + MAX_KEY_PROVIDER_BYTES + 1024) as u64,
            Some(self.token.clone()),
        )?;
        let rows = Mutex::new(BTreeSet::new());
        let reference = KeyReference::CompletedBackup {
            backup_id: selected.checkpoint.backup_id,
            checkpoint_sha256: staged_digest(selected.checkpoint)?.0,
        };
        let observe = |provider: &str, key_ref: &str, version| -> anyhow::Result<()> {
            self.token.check()?;
            anyhow::ensure!(
                provider.len() <= MAX_KEY_PROVIDER_BYTES && key_ref.len() <= MAX_KEY_REF_BYTES,
                "backup key identity exceeds bound"
            );
            consider_entry(
                self.request,
                &mut rows.lock().unwrap_or_else(|e| e.into_inner()),
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
        let outcome = tokio::runtime::Handle::try_current()?.block_on(Box::pin(
            tenant.recovery_checkpoint_keys(&fence, &selected, self.token, &observe),
        ));
        self.token.check()?;
        fence.check()?;
        let digest = match outcome {
            Ok(digest) => digest,
            Err(error) => {
                if let Some(original) = error.operation_error()
                    && original.code == ErrorCode::ResourceExhausted
                {
                    return Err(original.clone().into());
                }
                if error.admission_refusal().is_some() {
                    return Err(Error::new(
                        ErrorCode::ResourceExhausted,
                        "recovery key inventory admission exhausted",
                    )
                    .into());
                }
                tracing::warn!(backup_id = %selected.checkpoint.backup_id, %error, "could not authenticate the original local recovery backup");
                return Ok(None);
            }
        };
        for entry in rows.into_inner().unwrap_or_else(|e| e.into_inner()) {
            visit(entry)?;
        }
        Ok(Some(digest))
    }
}

pub trait LocalRecoveryKeyInventory: Send + Sync {
    fn visit_keys(
        &self,
        store: &Arc<TenantStore>,
        node_id: u64,
        read: &LocalRecoveryKeyRead<'_>,
        visit: &mut dyn FnMut(LocalRecoveryKeyFinding) -> anyhow::Result<()>,
    ) -> anyhow::Result<[u8; 32]>;
}

/// A complete observation from the pinned members of one installed issuer.
pub struct AuthoritySignerKeys {
    pub inventory_sha256: [u8; 32],
    pub entries: Vec<KeyRetentionEntry>,
    /// The full installed catalog-to-stream mapping, independent of the entry cursor.
    pub audit_owners: BTreeMap<uuid::Uuid, uuid::Uuid>,
}

#[async_trait::async_trait]
pub trait AuthoritySignerKeyInventory: Send + Sync {
    async fn read_partition(
        &self,
        authority_id: uuid::Uuid,
        partition: u16,
        request: &ReadKeyRetentionRequest,
    ) -> anyhow::Result<AuthoritySignerKeys>;
}

/// One observation of a whole scope at one selected generation. The page
/// holds the entries the request selected; the coverage, dependency position
/// and retirement state describe the entire scope, whatever the page shows.
pub(super) struct KeyRetentionObservation {
    pub(super) page: KeyRetentionPage,
    /// Replicated dependency position of the observed generation.
    pub(super) dependency_sha256: String,
    pub(super) retirements: KeyRetirementState,
    term: u64,
    membership: Option<kasumi_raft::LogId<u64>>,
    revision: u64,
    strict: bool,
    epoch: u64,
}

impl KeyRetentionObservation {
    /// The members that supplied the page must still be the applied group
    /// when the leader releases it, including after mandatory read auditing.
    fn check_group(&self, group: &RaftGroup) -> Result<()> {
        let current = group.metrics();
        if current.current_leader != Some(current.id)
            || current.current_term != self.term
            || current.membership_config.log_id() != &self.membership
        {
            return Err(Error::new(
                ErrorCode::Unavailable,
                "key retention leadership or membership changed during observation",
            ));
        }
        Ok(())
    }
}

struct InventoryWindow {
    entries: BTreeSet<KeyRetentionEntry>,
    missing: BTreeSet<MissingKeyDependency>,
    truncated: bool,
    inventory_sha256: String,
    revision: u64,
    membership_epoch: u64,
}

impl InventoryWindow {
    fn page(
        self,
        request: &ReadKeyRetentionRequest,
        page_limit: u16,
        probe: bool,
    ) -> Result<KeyRetentionPage> {
        let Self {
            entries,
            missing,
            truncated,
            inventory_sha256,
            revision,
            membership_epoch,
        } = self;
        // Strict read auditing may advance the application revision between
        // pages. Keep the original revision only if the observed inventory
        // and membership still match, including catalog-only rotations.
        let coverage_revision = if let Some(cursor) = request.cursor.as_ref().filter(|_| !probe) {
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
        let mut page_entries = Vec::with_capacity(entries.len().min(usize::from(page_limit)));
        let mut bytes = 0;
        let mut more = false;
        for entry in entries {
            let encoded = crate::accounting::encoded_len(&entry)?;
            // Leave room for the full cursor (which repeats the final
            // entry), missing-dependency list and framing. Strings may
            // expand sixfold under JSON escaping.
            if page_entries.len() == usize::from(page_limit)
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
                scope_sha256: request.scope.sha256()?,
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
            page.validate(request)?;
        }
        Ok(page)
    }
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
        observation.check_group(&self.group)?;
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
        let independent = matches!(
            request.scope,
            KeyRetentionScope::SecurityAudit {}
                | KeyRetentionScope::Signer {}
                | KeyRetentionScope::TargetJournal {}
                | KeyRetentionScope::LocalRecovery {}
        );
        let control = if independent && !probe {
            if context.tenant != crate::control::CONTROL_TENANT
                || self.store.tenant() != context.tenant
            {
                return Err(Error::new(
                    ErrorCode::Forbidden,
                    "independent key inventory requires Control administration",
                ));
            }
            true
        } else {
            self.key_retention_scope(context, &request.scope)?
        };
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
        if independent {
            context.authorization.require_control(&state.incarnation)?;
            let audit = self.security_audit.clone();
            let signer = self.signer_keys.get().cloned();
            let issuer_keys = if matches!(
                request.scope,
                KeyRetentionScope::Signer {} | KeyRetentionScope::SecurityAudit {}
            ) {
                let inventory = self
                    .authority_signer_keys
                    .get()
                    .and_then(std::sync::Weak::upgrade);
                if let (Some(owner), Some(inventory)) = (signer.as_deref(), inventory) {
                    let _wire = self.admission().reserve_resident(24 << 20)?;
                    let mut reports = security_audit::IssuerCoverage::default();
                    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
                    for &(id, partition) in &owner.partitions {
                        self.engine
                            .authorize_release(context, None, Action::Admin, epoch)?;
                        let report = tokio::select! {
                            value = inventory.read_partition(id, partition, request) => value,
                            _ = cancelled(&cancellation) => return Err(cancelled_error()),
                            _ = tokio::time::sleep_until(deadline) => Err(anyhow::anyhow!("issuer key inventory deadline elapsed")),
                        };
                        reports.observe((id, partition), request, report, self.admission())?;
                    }
                    Some(reports)
                } else {
                    None
                }
            } else {
                None
            };
            let journal = self.target_keys.get().and_then(std::sync::Weak::upgrade);
            let member_inventories =
                if matches!(
                    request.scope,
                    KeyRetentionScope::Signer {} | KeyRetentionScope::SecurityAudit {}
                ) && membership.membership().nodes().any(|(&id, _)| id != local)
                {
                    Some(
                        self.observe_service_members(&metrics, request, &cancellation)
                            .await?,
                    )
                } else {
                    None
                };
            let local_recovery = self.local_recovery_keys.get().cloned();
            let target_checkpoints = self.target_checkpoint_keys.get().cloned();
            let control_context = context.clone();
            let request = request.clone();
            let term = metrics.current_term;
            let membership = *membership.log_id();
            let (observation, reservation) = reservation
                .retained_read(cancellation, move |reservation, token| {
                    let _registration = registration;
                    let state = &generation.state;
                    let page = audit.key_inventory_page(
                        &generation,
                        &request,
                        &metrics,
                        security_audit::InstalledInventories {
                            context: &control_context,
                            signer: signer.as_deref(),
                            issuers: issuer_keys,
                            member_inventories,
                            journal: journal.as_deref(),
                            target_checkpoints: target_checkpoints.as_deref(),
                            local_recovery: local_recovery.as_deref(),
                        },
                        token,
                    )?;
                    let revision = state.revision;
                    Ok((
                        KeyRetentionObservation {
                            page,
                            dependency_sha256: state.key_dependency_sha256()?,
                            retirements: state.key_retirements.clone(),
                            term,
                            membership,
                            revision,
                            strict: state.policy.strict_read_audit,
                            epoch,
                        },
                        reservation,
                    ))
                })
                .await?;
            self.engine
                .authorize_release(context, None, Action::Admin, epoch)?;
            self.access()?;
            observation.check_group(&self.group)?;
            return Ok((observation, reservation));
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
        let distributed = membership.membership().nodes().any(|(&id, _)| id != local);
        let page_limit = if distributed {
            request
                .limit
                .min(kasumi_raft::member_catalog::MEMBER_CATALOG_LIMIT)
        } else {
            request.limit
        };
        let member_digest = self
            .observe_member_catalogs(
                &metrics,
                request,
                probe,
                &cancellation,
                &mut entries,
                (&mut missing, &mut truncated),
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
        let term = metrics.current_term;
        let membership_position = *membership.log_id();
        let scope_hash = request.scope.sha256()?;
        let request = request.clone();
        let stores = self.stores.clone();
        let revision = state.revision;
        let strict = state.policy.strict_read_audit;
        let archive_workspace = if state.audit_retention.archive_segments > 0 {
            Some(
                self.admission()
                    .reserve_resident(4 * MAX_AUDIT_SEGMENT_BYTES as u64)?,
            )
        } else {
            None
        };
        let (observation, reservation) = reservation
            .retained_read(cancellation, move |reservation, token| {
                let _registration = registration;
                let _archive_workspace = archive_workspace;
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
                        let (cache, destination, authenticated) = Self::check_tenant_audit_copies(
                            state,
                            stores.application(),
                            &reference.object,
                            token,
                        )?;
                        if authenticated
                            .as_ref()
                            .is_some_and(|actual| actual != reference)
                        {
                            return Err(Error::new(
                                ErrorCode::Corruption,
                                "tenant audit object differs from selected key reference",
                            ));
                        }
                        if cache != AuditObjectCheck::Verified
                            || destination != AuditObjectCheck::Verified
                        {
                            add_missing(
                                &mut missing,
                                &mut truncated,
                                MissingKeyDependency::RecordUnreadable {
                                    record_kind: KeyReferenceKind::AuditArchive,
                                    id: reference.object.object_id.to_string(),
                                },
                            );
                        }
                        archive_digest.update(
                            staged_digest(&(reference, cache, destination))?
                                .0
                                .as_bytes(),
                        );
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
                    ("kasumi.key-retention.members.v1", &state.key_retirements),
                    &scope_hash,
                    &state.incarnation,
                    epoch,
                    membership_epoch,
                    local,
                    (digest, member_digest),
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
                let page = InventoryWindow {
                    entries,
                    missing,
                    truncated,
                    inventory_sha256,
                    revision,
                    membership_epoch,
                }
                .page(&request, page_limit, probe)?;
                let observation = KeyRetentionObservation {
                    page,
                    dependency_sha256: state.key_dependency_sha256()?,
                    retirements: state.key_retirements.clone(),
                    term,
                    membership: membership_position,
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
        observation.check_group(&self.group)?;
        Ok((observation, reservation))
    }
}
