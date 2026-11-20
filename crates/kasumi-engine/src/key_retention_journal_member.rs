//! An enrolled Control peer reports only its own journal and physically verified historical backups.
use super::*;
use kasumi_raft::member_catalog::{
    CatalogPurpose, CatalogStart, MemberCatalogRequest, MemberJournalReport,
};

#[derive(Clone, Copy)]
pub(super) struct InventoryWindowSelection<'a> {
    pub(super) limit: u16,
    after: Option<&'a KeyRetentionEntry>,
    from_identity: Option<&'a KeyIdentityRef>,
}
impl<'a> InventoryWindowSelection<'a> {
    pub(super) fn from_page(request: &'a ReadKeyRetentionRequest) -> Self {
        Self {
            limit: request.limit,
            after: request.cursor.as_ref().map(|cursor| &cursor.after),
            from_identity: None,
        }
    }
    fn from_member(request: &'a MemberCatalogRequest) -> Result<Self> {
        let (after, from_identity) = match &request.start {
            CatalogStart::First => (None, None),
            CatalogStart::After { entry } => (Some(entry), None),
            CatalogStart::Identity { identity } => (None, Some(identity)),
        };
        Ok(Self {
            limit: request.limit,
            after,
            from_identity,
        })
    }
    pub(super) fn consider(
        self,
        entries: &mut BTreeSet<KeyRetentionEntry>,
        entry: KeyRetentionEntry,
    ) -> Result<()> {
        entry.validate()?;
        if self.after.is_none_or(|start| entry > *start)
            && self.from_identity.is_none_or(|from| {
                (&entry.key.provider, &entry.key.key_ref) >= (&from.provider, &from.key_ref)
            })
        {
            entries.insert(entry);
            if entries.len() > usize::from(self.limit) + 1 {
                entries.pop_last();
            }
        }
        Ok(())
    }
}

pub(super) enum RecoveryInventoryAuthority<'a> {
    Operator(&'a RequestContext),
    Member(&'a MemberCatalogRequest),
}
pub(in crate::service) enum RecoveryInventoryFence<'a> {
    Operator(Box<ResponseFence<'a>>),
    Member {
        database: &'a Database,
        request: &'a MemberCatalogRequest,
    },
}
impl RecoveryInventoryAuthority<'_> {
    pub(super) fn fence<'a>(
        &'a self,
        database: &'a Database,
    ) -> Result<RecoveryInventoryFence<'a>> {
        let fence = match self {
            Self::Operator(context) => {
                database.engine.authorize(context, None, Action::Admin)?;
                RecoveryInventoryFence::Operator(Box::new(ResponseFence::capture_workspace(
                    ResponseDatabase::Borrowed(database),
                    context,
                    true,
                )?))
            }
            Self::Member(request) => RecoveryInventoryFence::Member { database, request },
        };
        fence.check()?;
        Ok(fence)
    }
}
impl RecoveryInventoryFence<'_> {
    pub(in crate::service) fn check(&self) -> Result<()> {
        match self {
            Self::Operator(original) => original.check(),
            Self::Member { database, request } => {
                database.access()?;
                let journal = database
                    .target_keys
                    .get()
                    .and_then(std::sync::Weak::upgrade)
                    .ok_or_else(|| unavailable("target journal closed before graph release"))?;
                check_journal_position(
                    &database.group,
                    &database.engine,
                    &database.store,
                    &journal.key_inventory_owner().0.root,
                    request,
                )
            }
        }
    }
}
fn unavailable(message: &'static str) -> Error {
    Error::new(ErrorCode::Unavailable, message)
}
fn check_journal_position(
    group: &RaftGroup,
    engine: &TenantEngine,
    store: &TenantStore,
    root: &kasumi_types::ControlSigningRoot,
    request: &MemberCatalogRequest,
) -> Result<()> {
    request
        .check_position(group)
        .map_err(Error::from_physical_source)?;
    let generation = engine.generation()?;
    let state = &generation.state;
    let (control, expires_at_ms) = match request.purpose {
        CatalogPurpose::ControlJournal {
            control,
            policy_epoch,
            principal_sha256,
            expires_at_ms,
        } => {
            if state.tenant != crate::control::CONTROL_TENANT
                || state.incarnation != control.to_string()
                || state.policy_epoch != policy_epoch
                || state
                    .lifecycle_control
                    .as_ref()
                    .is_none_or(|installed| installed.installation.root != *root)
                || !state.policy.grants.iter().any(|grant| {
                    grant.collection.is_none()
                        && grant.actions.contains(&Action::Admin)
                        && <[u8; 32]>::from(Sha256::digest(grant.principal.as_bytes()))
                            == principal_sha256
                })
            {
                return Err(unavailable(
                    "Control target journal policy or installation changed",
                ));
            }
            (control, expires_at_ms)
        }
        CatalogPurpose::DataJournal {
            control,
            installation_id,
            expires_at_ms,
        } => {
            let access = store.storage_access();
            if !matches!(access.purpose(),kasumi_store::StoragePurpose::Serving{identity,..}
                if identity.tenant==state.tenant && identity.incarnation.to_string()==state.incarnation && identity.node.node_id==group.node_id()
                    && identity.node.verifier.installation_id==installation_id)
            {
                return Err(unavailable(
                    "Data target journal differs from the current serving installation",
                ));
            }
            access
                .check_serving()
                .map_err(Error::from_physical_source)?;
            (control, expires_at_ms)
        }
        _ => {
            return Err(unavailable(
                "physical target journal expected an enrolled peer request",
            ));
        }
    };
    if root.control_incarnation != control
        || group
            .metrics()
            .membership_config
            .membership()
            .get_joint_config()
            .len()
            != 1
    {
        return Err(unavailable(
            "target journal Control root or stable group membership differs",
        ));
    }
    if now_ms()? >= expires_at_ms {
        return Err(Error::new(
            ErrorCode::Unauthorized,
            "Control journal inventory credential expired",
        ));
    }
    Ok(())
}
pub(super) struct JournalRows {
    pub(super) catalog: uuid::Uuid,
    pub(super) digest: [u8; 32],
    pub(super) entries: BTreeSet<KeyRetentionEntry>,
    pub(super) unreadable: BTreeSet<uuid::Uuid>,
    pub(super) truncated: bool,
}
impl LocalRecoveryKeyRead<'_> {
    pub(super) fn journal_rows(
        &self,
        journal: &crate::TargetJournal,
        inventory: Option<&dyn TargetCheckpointInventory>,
    ) -> Result<JournalRows> {
        let entries = std::cell::RefCell::new(BTreeSet::new());
        let mut external = Sha256::new();
        let mut unreadable = BTreeSet::new();
        let mut truncated = false;
        let mut catalog = None;
        let digest = journal
            .visit_key_dependencies(
                self.token,
                |row| {
                    if let KeyReference::Catalog {
                        catalog_id,
                        domain: KeyCatalogDomain::TargetJournal,
                        ..
                    } = row.reference
                    {
                        anyhow::ensure!(
                            catalog
                                .replace(catalog_id)
                                .is_none_or(|original| original == catalog_id),
                            "journal has conflicting physical catalogs"
                        );
                    }
                    Ok(self.selection.consider(&mut entries.borrow_mut(), row)?)
                },
                |target, checkpoint| {
                    let graph = match inventory {
                        Some(inventory) => {
                            self.target_checkpoint(journal, inventory, target, checkpoint, |row| {
                                Ok(self.selection.consider(&mut entries.borrow_mut(), row)?)
                            })?
                        }
                        None => None,
                    };
                    serde_json::to_writer(&mut external, &(target, graph))?;
                    if graph.is_none() {
                        unreadable.insert(target);
                        if unreadable.len() > MAX_MISSING_KEY_DEPENDENCIES {
                            unreadable.pop_last();
                            truncated = true;
                        }
                    }
                    Ok(())
                },
            )
            .map_err(|error| {
                error
                    .downcast_ref::<Error>()
                    .cloned()
                    .unwrap_or_else(|| Error::from_physical_source(error))
            })?;
        external.update(digest);
        Ok(JournalRows {
            catalog: catalog
                .ok_or_else(|| unavailable("target journal has no wrapping catalog"))?,
            digest: external.finalize().into(),
            entries: entries.into_inner(),
            unreadable,
            truncated,
        })
    }
}

pub(super) enum InstalledJournal {
    Active(Box<ActiveJournal>),
    Excluded(Box<ExcludedJournal>),
}
impl InstalledJournal {
    pub(super) fn open(database: &Database, request: &MemberCatalogRequest) -> Result<Self> {
        if database.target_keys.get().is_none()
            && let Some(proof) = database.journal_exclusion.get()
            && matches!(request.purpose, CatalogPurpose::ControlJournal { .. })
        {
            let root = database
                .engine
                .generation()?
                .state
                .lifecycle_control
                .as_ref()
                .ok_or_else(|| unavailable("dedicated Control lifecycle absent"))?
                .installation
                .root
                .clone();
            let verifier = database
                .signer_keys
                .get()
                .ok_or_else(|| unavailable("dedicated Control verifier absent"))?
                .verifier
                .clone();
            if verifier.node_id != database.group.node_id()
                || database.group.is_local()
                || !Arc::ptr_eq(
                    database.security_audit.store().persistent_disk(),
                    database.store.persistent_disk(),
                )
            {
                return Err(unavailable(
                    "dedicated Control enrollment differs from its physical node",
                ));
            }
            check_journal_position(
                &database.group,
                &database.engine,
                &database.store,
                &root,
                request,
            )?;
            return Ok(Self::Excluded(Box::new(ExcludedJournal {
                group: database.group.clone(),
                engine: database.engine.clone(),
                store: database.store.clone(),
                security: database.security_audit.store().clone(),
                root,
                verifier,
                proof: proof.clone(),
            })));
        }
        Ok(Self::Active(Box::new(ActiveJournal::open(
            database, request,
        )?)))
    }

    pub(super) fn capture(
        &self,
        request: &MemberCatalogRequest,
        token: &QueryCancellation,
    ) -> Result<MemberJournalReport> {
        match self {
            Self::Active(owner) => owner.capture(request, token),
            Self::Excluded(position) => position.capture(request, token),
        }
    }
}
pub(super) struct ExcludedJournal {
    group: RaftGroup,
    engine: Arc<TenantEngine>,
    store: Arc<TenantStore>,
    security: Arc<TenantStore>,
    root: kasumi_types::ControlSigningRoot,
    verifier: TrustVerifierIdentity,
    proof: Arc<TargetJournalExclusion>,
}
impl ExcludedJournal {
    fn capture(
        &self,
        request: &MemberCatalogRequest,
        token: &QueryCancellation,
    ) -> Result<MemberJournalReport> {
        token.check()?;
        check_journal_position(&self.group, &self.engine, &self.store, &self.root, request)?;
        let enrollment = (self.proof)(&self.security, &self.verifier, &self.root, token)
            .map_err(Error::from_physical_source)?;
        let mut catalog = None;
        let keys = self
            .security
            .visit_wrapping_identities(|id, _, _, _| {
                token.check()?;
                anyhow::ensure!(
                    catalog.replace(id).is_none_or(|previous| previous == id),
                    "enrollment security catalog changed"
                );
                Ok(())
            })
            .map_err(Error::from_physical_source)?;
        let catalog = catalog
            .ok_or_else(|| unavailable("no physical dedicated Control enrollment catalog"))?;
        check_journal_position(&self.group, &self.engine, &self.store, &self.root, request)?;
        token.check()?;
        let mut dependencies = Sha256::new();
        serde_json::to_writer(
            &mut dependencies,
            &(
                "kasumi.journal-exclusion.v1",
                &self.root,
                &self.verifier,
                catalog,
                keys,
                enrollment,
            ),
        )
        .map_err(|error| Error::from_physical_source(error.into()))?;
        let report = MemberJournalReport {
            excluded_by_enrollment: Some(enrollment),
            writer_state_sha256: None,
            request_sha256: staged_digest(request)?.0,
            verifier: self.verifier.clone(),
            catalog,
            dependencies_sha256: dependencies.finalize().into(),
            entries: Vec::new(),
            unreadable_targets: Vec::new(),
            truncated: false,
        };
        report
            .validate(request, self.group.node_id())
            .map_err(Error::from_physical_source)?;
        Ok(report)
    }
}

pub(super) struct ActiveJournal {
    store: Arc<TenantStore>,
    engine: Arc<TenantEngine>,
    group: RaftGroup,
    journal: Arc<crate::TargetJournal>,
    checkpoints: Option<Arc<dyn TargetCheckpointInventory>>,
    audit: Arc<SecurityAudit>,
}
impl ActiveJournal {
    fn open(database: &Database, request: &MemberCatalogRequest) -> Result<Self> {
        let journal = database
            .target_keys
            .get()
            .and_then(std::sync::Weak::upgrade)
            .ok_or_else(|| unavailable("Control member has no installed target journal"))?;
        let (installed, store) = journal.key_inventory_owner();
        check_journal_position(
            &database.group,
            &database.engine,
            &database.store,
            &installed.root,
            request,
        )?;
        if database.group.is_local()
            || !Arc::ptr_eq(database.store.persistent_disk(), store.persistent_disk())
            || installed.node.node_id != database.group.node_id()
            || database
                .signer_keys
                .get()
                .is_none_or(|signer| signer.verifier != installed.node.verifier)
        {
            return Err(unavailable(
                "target journal differs from enrolled physical member",
            ));
        }
        Ok(Self {
            store: database.store.clone(),
            engine: database.engine.clone(),
            group: database.group.clone(),
            journal,
            checkpoints: database.target_checkpoint_keys.get().cloned(),
            audit: database.security_audit.clone(),
        })
    }
    pub(super) fn capture(
        &self,
        request: &MemberCatalogRequest,
        token: &QueryCancellation,
    ) -> Result<MemberJournalReport> {
        check_journal_position(
            &self.group,
            &self.engine,
            &self.store,
            &self.journal.key_inventory_owner().0.root,
            request,
        )?;
        let read = LocalRecoveryKeyRead {
            authority: RecoveryInventoryAuthority::Member(request),
            selection: InventoryWindowSelection::from_member(request)?,
            scope: &KeyRetentionScope::TargetJournal {},
            security: &self.audit,
            token,
        };
        let rows = read.journal_rows(&self.journal, self.checkpoints.as_deref())?;
        check_journal_position(
            &self.group,
            &self.engine,
            &self.store,
            &self.journal.key_inventory_owner().0.root,
            request,
        )?;
        let report = MemberJournalReport {
            excluded_by_enrollment: None,
            writer_state_sha256: Some(
                self.journal
                    .writer_state_sha256()
                    .map_err(Error::from_physical_source)?,
            ),
            request_sha256: staged_digest(request)?.0,
            verifier: self.journal.key_inventory_owner().0.node.verifier.clone(),
            catalog: rows.catalog,
            dependencies_sha256: rows.digest,
            entries: rows.entries.into_iter().collect(),
            unreadable_targets: rows.unreadable.into_iter().collect(),
            truncated: rows.truncated,
        };
        report
            .validate(request, self.group.node_id())
            .map_err(Error::from_physical_source)?;
        Ok(report)
    }
}

/// Installed, writable original recovery routes. Physical observations use the
/// separate read-only service census to confirm which journals actually fenced.
#[async_trait::async_trait]
pub trait TargetWriterNetwork: Send + Sync {
    fn verify_participant(&self, challenge: &SignedTargetWriterChallenge) -> anyhow::Result<()>;
    async fn synchronize(
        &self,
        context: &RequestContext,
        state_sha256: &str,
    ) -> anyhow::Result<BTreeSet<TargetWriterParticipant>>;
}
impl Database {
    pub fn install_target_writer_network(
        &self,
        network: std::sync::Weak<dyn TargetWriterNetwork>,
    ) -> Result<()> {
        if self.store.tenant() != crate::control::CONTROL_TENANT {
            return Err(unavailable("writer network requires installed Control"));
        }
        self.target_writer_network
            .set(network)
            .map_err(|_| unavailable("writer network already installed"))
    }
}
impl Database {
    /// A dedicated Control role may prove that its original encrypted enrollment
    /// excludes a target. Every physical read authenticates that source again.
    pub fn install_target_journal_exclusion(
        &self,
        source: Arc<TargetJournalExclusion>,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.store.tenant() == crate::control::CONTROL_TENANT
                && !self.group.is_local()
                && self.target_keys.get().is_none(),
            "journal exclusion requires a dedicated Control group"
        );
        self.journal_exclusion
            .set(source)
            .map_err(|_| anyhow::anyhow!("journal exclusion already installed"))
    }

    /// Data readers must be enrolled independently for this exact hosted generation
    /// and Control root. The installed target retains ownership of its journal.
    pub fn install_data_target_inventory(
        &self,
        journal: &Arc<crate::TargetJournal>,
        root: &kasumi_types::ControlSigningRoot,
        source: Arc<dyn TargetCheckpointInventory>,
    ) -> anyhow::Result<()> {
        let (installed, store) = journal.key_inventory_owner();
        let access = self.store.storage_access();
        anyhow::ensure!(
            !self.group.is_local()
                && &installed.root == root
                && installed.node.node_id == self.group.node_id()
                && Arc::ptr_eq(self.store.persistent_disk(), store.persistent_disk())
                && matches!(access.purpose(),kasumi_store::StoragePurpose::Serving{identity,..}
                if identity.node.verifier==installed.node.verifier && identity.tenant==self.store.tenant()),
            "target journal differs from the enrolled Data installation"
        );
        store.check_access()?;
        let original = Arc::downgrade(journal);
        anyhow::ensure!(
            self.target_keys
                .get_or_init(|| original.clone())
                .ptr_eq(&original),
            "Data node already owns a different target journal"
        );
        self.target_checkpoint_keys.get_or_init(|| source);
        Ok(())
    }
}
