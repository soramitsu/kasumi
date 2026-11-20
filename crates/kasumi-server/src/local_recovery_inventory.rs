//! Administrative read of the encrypted coordinator, held by the same exclusive
//! standalone installation that owns the recovery writer.
use super::*;
use kasumi_engine::{
    Database, LocalRecoveryCheckpoint, LocalRecoveryKeyFinding, LocalRecoveryKeyInventory,
    LocalRecoveryKeyRead, SecurityAudit,
};
use kasumi_query::QueryCancellation;
use kasumi_store::TenantReadView;
use kasumi_types::{
    KeyCatalogDomain, KeyReference, KeyReferenceKind, KeyRetentionEntry, KeyVersionRef,
    MAX_KEY_PROVIDER_BYTES, MAX_KEY_REF_BYTES, MissingKeyDependency,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub(crate) fn install(
    config: &RuntimeConfig,
    owner: &Arc<crate::standalone::InstalledStandaloneOwner>,
    audit: &SecurityAudit,
    database: &Arc<Database>,
    applications: BTreeMap<String, std::sync::Weak<Database>>,
    active: BTreeMap<Uuid, std::sync::Weak<kasumi_store::TenantStorageSet>>,
) -> Result<()> {
    ensure!(
        config.mode == crate::runtime::DeploymentMode::Standalone,
        "standalone coordinator required"
    );
    let identity = owner.identity_for(audit.store().persistent_disk())?;
    ensure!(
        identity.node_id == database.raft_group().node_id(),
        "local recovery coordinator belongs to another Control member"
    );
    let tenants = config
        .tenants
        .iter()
        .map(|tenant| {
            Ok((
                tenant.tenant.clone(),
                (
                    installation_id(config, &tenant.tenant)?,
                    config
                        .tenant_audit_placement(&tenant.tenant)?
                        .canonical_binding()?,
                ),
            ))
        })
        .collect::<Result<_>>()?;
    database.install_local_recovery_key_inventory(
        audit.store(),
        Arc::new(Coordinator {
            database_path: config.database_path.clone(),
            disk_settings: config.persistent_disk.clone(),
            tenants,
            active,
            control: Arc::downgrade(database),
            applications,
            owner: Arc::downgrade(owner),
            admission: audit.admission().clone(),
        }),
    )
}

struct OperationInventory {
    operation: Uuid,
    catalogs: Option<[u8; 32]>,
    external_checkpoint: Option<[u8; 32]>,
}

struct Coordinator {
    control: std::sync::Weak<Database>,
    applications: BTreeMap<String, std::sync::Weak<Database>>,
    owner: std::sync::Weak<crate::standalone::InstalledStandaloneOwner>,
    database_path: PathBuf,
    disk_settings: kasumi_store::NodeDiskConfig,
    tenants: BTreeMap<String, (Uuid, String)>,
    active: BTreeMap<Uuid, std::sync::Weak<kasumi_store::TenantStorageSet>>,
    admission: Arc<kasumi_engine::admission::NodeAdmission>,
}

fn uuid(bytes: &[u8]) -> Result<Uuid> {
    let id = Uuid::from_slice(bytes)?;
    ensure!(!id.is_nil(), "nil local recovery row identity");
    Ok(id)
}

fn entry(
    reference: KeyReference,
    provider: &str,
    key_ref: &str,
    version: u64,
) -> Result<LocalRecoveryKeyFinding> {
    ensure!(
        provider.len() <= MAX_KEY_PROVIDER_BYTES && key_ref.len() <= MAX_KEY_REF_BYTES,
        "local recovery wrapping identifier exceeds inventory limit"
    );
    Ok(LocalRecoveryKeyFinding::Entry(KeyRetentionEntry {
        key: KeyVersionRef {
            provider: provider.into(),
            key_ref: key_ref.into(),
            version,
        },
        reference,
    }))
}

type PhaseBinding = (
    LocalRecoveryPhase,
    LocalRecoveryStart,
    Uuid,
    PathBuf,
    PathBuf,
    String,
    serde_json::Value,
    serde_json::Value,
    serde_json::Value,
);

impl Coordinator {
    /// Both inputs to a cross-reference keep their own credit. A byte can begin
    /// a JSON container or a map slot; include container overhead, spare capacity
    /// and comparison output before constructing either typed value.
    fn decoding_workspace(
        &self,
        length: usize,
        token: &QueryCancellation,
    ) -> Result<kasumi_engine::admission::Reservation> {
        ensure!(
            length <= MAX_RECORD,
            "local recovery record exceeds its work limit"
        );
        let bytes = 65536 + 256 * u64::try_from(length)?;
        Ok(self.admission.reserve_waiting(bytes, Some(token.clone()))?)
    }

    fn journal_at(
        &self,
        view: &TenantReadView,
        operation: Uuid,
        token: &QueryCancellation,
    ) -> Result<(Journal, kasumi_engine::admission::Reservation)> {
        let value = view
            .get(OPERATIONS, operation.as_bytes(), MAX_RECORD)?
            .context("permanent local recovery operation missing")?;
        let charge = self.decoding_workspace(value.len(), token)?;
        let journal: Journal = decode(&value)?;
        ensure!(
            journal.format == 5 && journal.status.request.operation_id == operation,
            "substituted local recovery operation"
        );
        Ok((journal, charge))
    }

    fn operation(
        &self,
        view: &TenantReadView,
        key: &[u8],
        value: &[u8],
        node_id: u64,
        read: &LocalRecoveryKeyRead<'_>,
        visit: &mut dyn FnMut(LocalRecoveryKeyFinding) -> Result<()>,
    ) -> Result<OperationInventory> {
        let token = read.cancellation();
        let journal: Journal = decode(value)?;
        let request = &journal.status.request;
        request.validate()?;
        let operation = uuid(key)?;
        let placement = self
            .tenants
            .get(&request.tenant)
            .context("recorded local recovery tenant is not installed")?;
        ensure!(
            journal.format == 5
                && request.operation_id == operation
                && !journal.status.phase_id.is_nil()
                && journal.installation_id == placement.0
                && journal.audit_placement_binding == placement.1
                && journal.database_path == self.database_path
                && journal.target_directory
                    == self
                        .database_path
                        .parent()
                        .context("standalone data directory missing")?
                        .join("generations")
                        .join(request.target_incarnation.to_string()),
            "local recovery physical installation differs"
        );
        let phase = view
            .get(PHASES, journal.status.phase_id.as_bytes(), MAX_RECORD)?
            .context("permanent local recovery phase binding missing")?;
        ensure!(
            phase.as_ref() == phase_binding(&journal)?,
            "substituted local recovery phase"
        );
        ensure!(
            view.get(
                GENERATIONS,
                request.target_incarnation.as_bytes(),
                MAX_RECORD
            )?
            .is_some(),
            "permanent local recovery generation missing"
        );
        if let Some(publication) = &journal.publication {
            ensure!(
                !publication.id.is_nil()
                    && publication
                        .topology
                        .tenants
                        .get(&request.tenant)
                        .is_some_and(
                            |route| route.incarnation == request.target_incarnation.to_string()
                        )
                    && view
                        .get(PHASES, publication.id.as_bytes(), MAX_RECORD)?
                        .as_deref()
                        == Some(encoded(publication)?.as_slice()),
                "missing or substituted local recovery publication"
            );
            if let Some(owner) = view.get(PUBLICATION_OWNERS, publication.id.as_bytes(), 16)? {
                ensure!(uuid(&owner)? == operation, "conflicting publication owner");
            }
        }
        let external_checkpoint = self.checkpoint(&journal, read, visit)?;
        if external_checkpoint.is_none() {
            visit(LocalRecoveryKeyFinding::Missing(
                MissingKeyDependency::ArchiveUnavailable {
                    id: request.checkpoint.backup_id.to_string(),
                },
            ))?;
        }
        if journal.status.phase == LocalRecoveryPhase::Stopped {
            ensure!(
                journal.status.cleanup_evidence.as_deref()
                    == Some(cleanup_evidence(&journal)?.as_str()),
                "stopped local recovery lacks its installed cleanup evidence"
            );
        }
        if journal.target_preparation != TargetPreparation::Uncreated
            && journal.status.phase != LocalRecoveryPhase::Stopped
        {
            if let Some(owner) = self.active.get(&operation) {
                let stores = owner
                    .upgrade()
                    .context("active recovery stores have closed")?;
                let active: ActiveGeneration = decode(
                    &view
                        .get(ACTIVE, request.tenant.as_bytes(), MAX_RECORD)?
                        .context("active recovery journal binding missing")?,
                )?;
                ensure!(
                    active.operation_id == operation
                        && active.incarnation == request.target_incarnation
                        && active.checkpoint == request.checkpoint
                        && active.directory == journal.target_directory
                        && matches!(
                            journal.status.phase,
                            LocalRecoveryPhase::Publish | LocalRecoveryPhase::Finished
                        )
                        && matches!(stores.application().storage_access().purpose(),
                        StoragePurpose::Standalone { installation_id, tenant, incarnation }
                        if *installation_id == journal.installation_id && tenant == &request.tenant && *incarnation == request.target_incarnation),
                    "active recovery catalog belongs to a different installation or operation"
                );
                check_database_group(&journal)?;
                let physical = stores.application().node_store().physical_identity()?;
                ensure!(
                    journal.database_group.as_ref() == Some(&physical)
                        && stores.custody().store().node_store().physical_identity()? == physical,
                    "active recovery catalog descriptors belong to a different physical generation"
                );
                let catalogs = Self::active_catalogs(&stores, node_id, token, visit)?;
                check_database_group(&journal)?;
                return Ok(OperationInventory {
                    operation,
                    catalogs: Some(catalogs),
                    external_checkpoint,
                });
            }
            visit(LocalRecoveryKeyFinding::Missing(
                MissingKeyDependency::RecordUnreadable {
                    record_kind: KeyReferenceKind::LocalRecovery,
                    id: request.target_incarnation.to_string(),
                },
            ))?;
        }
        Ok(OperationInventory {
            operation,
            catalogs: None,
            external_checkpoint,
        })
    }

    fn checkpoint(
        &self,
        journal: &Journal,
        read: &LocalRecoveryKeyRead<'_>,
        visit: &mut dyn FnMut(LocalRecoveryKeyFinding) -> Result<()>,
    ) -> Result<Option<[u8; 32]>> {
        let request = &journal.status.request;
        let Some(application) = self
            .applications
            .get(&request.tenant)
            .and_then(std::sync::Weak::upgrade)
        else {
            return Ok(None);
        };
        ensure!(
            matches!(application.stores().application().storage_access().purpose(),
                StoragePurpose::Standalone {installation_id,tenant,..} if *installation_id == journal.installation_id && tenant == &request.tenant),
            "local backup reader is attached to another installation"
        );
        let keys = keys::RecoveryKeys::open(&request.source_keys, &request.historical_source_keys)
            .and_then(|keys| keys.bound(&request.source_keys, &journal.source_provider));
        let keys = match keys {
            Ok(keys) => keys,
            Err(error) => {
                tracing::warn!(operation = %request.operation_id, %error, "original recovery key provider unavailable");
                return Ok(None);
            }
        };
        let control = self
            .control
            .upgrade()
            .context("local recovery Control owner has closed")?;
        read.visit_checkpoint(
            &control,
            &application,
            LocalRecoveryCheckpoint {
                checkpoint: &request.checkpoint,
                source_purpose: &request.source_purpose,
                keys,
                destination: &request.destination,
            },
            |row| visit(LocalRecoveryKeyFinding::Entry(row)),
        )
    }

    fn active_catalogs(
        stores: &kasumi_store::TenantStorageSet,
        node_id: u64,
        token: &QueryCancellation,
        visit: &mut dyn FnMut(LocalRecoveryKeyFinding) -> Result<()>,
    ) -> Result<[u8; 32]> {
        let app = stores.application().read_view()?;
        let observed = (|| {
            let application = app.wrapping_inventory()?;
            let custody = stores.custody().store().read_view()?;
            let result = (|| {
                let physical = custody.wrapping_inventory()?;
                let mut fingerprint = Sha256::new();
                let mut application_id = None;
                for (inventory, domain) in [
                    (&application, KeyCatalogDomain::Application),
                    (&physical, KeyCatalogDomain::RetirementCustody),
                ] {
                    fingerprint.update(inventory.visit_catalog(
                        |catalog_id, provider, key_ref, version| {
                            token.check()?;
                            if domain == KeyCatalogDomain::Application {
                                application_id = Some(catalog_id);
                            } else {
                                ensure!(
                                    Some(catalog_id) != application_id,
                                    "active recovery catalogs are not independent"
                                );
                            }
                            visit(entry(
                                KeyReference::Catalog {
                                    node_id,
                                    catalog_id,
                                    domain,
                                },
                                provider,
                                key_ref,
                                version,
                            )?)
                        },
                    )?);
                }
                application.check_current()?;
                physical.check_current()?;
                Ok(fingerprint.finalize().into())
            })();
            finish(result, custody.close())
        })();
        finish(observed, app.close())
    }

    fn phase_owner(
        &self,
        view: &TenantReadView,
        token: &QueryCancellation,
        key: &[u8],
        value: &[u8],
    ) -> Result<Uuid> {
        if key.len() == 16 && value.first() == Some(&b'{') {
            let publication: Publication = decode(value)?;
            ensure!(
                uuid(key)? == publication.id,
                "substituted local publication ID"
            );
            if let Some(owner) = view.get(PUBLICATION_OWNERS, key, 16)? {
                return self.indexed_publication_owner(view, token, publication.id, &owner);
            }
            // Deployed journals can predate the reverse link. Read their original
            // authenticated operation records under a single pinned view.
            let mut owner = None;
            view.visit(OPERATIONS, MAX_RECORD, |operation, bytes| {
                token.check()?;
                let _charge = self.decoding_workspace(bytes.len(), token)?;
                let journal: Journal = decode(bytes)?;
                if let Some(link) = journal.publication.filter(|p| p.id == publication.id) {
                    let operation = uuid(operation)?;
                    ensure!(
                        journal.status.request.operation_id == operation
                            && encoded(&link)? == value
                            && owner.replace(operation).is_none(),
                        "conflicting historical publication owner"
                    );
                }
                Ok(())
            })?;
            return owner.context("orphan local recovery publication");
        }
        if key.len() == 16 {
            let id = uuid(key)?;
            let (phase, request, ..): PhaseBinding = decode(value)?;
            let (journal, _charge) = self.journal_at(view, request.operation_id, token)?;
            ensure!(
                !matches!(
                    phase,
                    LocalRecoveryPhase::Finished | LocalRecoveryPhase::Stopped
                ) && binding_for_phase(&journal, phase)? == value,
                "substituted historical local recovery phase"
            );
            if phase == LocalRecoveryPhase::Materialize {
                for (suffix, expected) in Self::materialization_records(id, &journal)? {
                    token.check()?;
                    let key = format!("{id}/{suffix}");
                    ensure!(
                        view.get(PHASES, key.as_bytes(), MAX_RECORD)?.as_deref()
                            == Some(expected.as_slice()),
                        "missing or substituted local materialization record"
                    );
                }
            }
            return Ok(request.operation_id);
        }
        let (phase_id, suffix) = std::str::from_utf8(key)?
            .split_once('/')
            .context("invalid local materialization key")?;
        let id = Uuid::parse_str(phase_id)?;
        ensure!(
            !id.is_nil() && id.to_string() == phase_id,
            "invalid materialization phase identity"
        );
        let row = view
            .get(PHASES, id.as_bytes(), MAX_RECORD)?
            .context("orphan local materialization record")?;
        let _phase_charge = self.decoding_workspace(row.len(), token)?;
        let (phase, request, ..): PhaseBinding = decode(&row)?;
        ensure!(
            phase == LocalRecoveryPhase::Materialize,
            "unrelated materialization phase"
        );
        let (journal, _charge) = self.journal_at(view, request.operation_id, token)?;
        ensure!(
            Self::materialization_records(id, &journal)?
                .into_iter()
                .any(|(name, expected)| suffix == name && expected == value),
            "substituted local materialization record"
        );
        Ok(request.operation_id)
    }

    fn indexed_publication_owner(
        &self,
        view: &TenantReadView,
        token: &QueryCancellation,
        publication: Uuid,
        owner: &[u8],
    ) -> Result<Uuid> {
        let operation = uuid(owner)?;
        let (journal, _charge) = self.journal_at(view, operation, token)?;
        ensure!(
            journal.publication.is_some_and(|p| p.id == publication),
            "substituted local recovery publication owner"
        );
        Ok(operation)
    }

    fn materialization_records(
        id: Uuid,
        journal: &Journal,
    ) -> Result<Vec<(&'static str, Vec<u8>)>> {
        let mut expected = Vec::with_capacity(5);
        if journal.archive_directory.is_some() {
            expected.push(("archive-directory", encoded(&journal.archive_directory)?));
        }
        if journal.database_group.is_some() {
            expected.push(("physical", encoded(&journal.database_group)?));
        }
        for (stage, suffix) in TargetPreparation::RECORDED {
            if stage <= journal.target_preparation {
                expected.push((suffix, stage.phase_record(id, journal)?));
            }
        }
        Ok(expected)
    }

    fn archive_owner(
        &self,
        view: &TenantReadView,
        store: &TenantStore,
        token: &QueryCancellation,
        row: (&[u8], &[u8]),
        visit: &mut dyn FnMut(LocalRecoveryKeyFinding) -> Result<()>,
    ) -> Result<(Uuid, Option<bool>)> {
        let (operation, object) = archives::RetainedObject::read(row.0, row.1)?;
        let (journal, _charge) = self.journal_at(view, operation, token)?;
        let reference = object.reference();
        if journal.status.phase == LocalRecoveryPhase::Stopped {
            ensure!(
                journal.status.cleanup_evidence.as_deref()
                    == Some(cleanup_evidence(&journal)?.as_str()),
                "stopped local archive lacks cleanup evidence"
            );
            // The journal's own envelope remains retained after physical deletion.
            match std::fs::symlink_metadata(&journal.target_directory) {
                Err(error) if error.kind() == ErrorKind::NotFound => return Ok((operation, None)),
                Err(error) => return Err(error.into()),
                Ok(_) => anyhow::bail!("stopped local archive generation is still present"),
            }
        }
        visit(entry(
            KeyReference::AuditArchive {
                stream_id: reference.stream_id,
                first_sequence: reference.object.first_sequence,
            },
            &reference.key.provider,
            &reference.key.key_ref,
            reference.key.version,
        )?)?;
        let _bytes = self
            .admission
            .reserve_waiting(65536 + 4 * reference.ciphertext_bytes, Some(token.clone()))?;
        let authentic = object.inspect(&journal, &self.disk_settings, store, token)?;
        if !authentic {
            visit(LocalRecoveryKeyFinding::Missing(
                MissingKeyDependency::RecordUnreadable {
                    record_kind: KeyReferenceKind::AuditArchive,
                    id: reference.object.object_id.to_string(),
                },
            ))?;
        }
        Ok((operation, Some(authentic)))
    }

    fn row_owner(
        &self,
        view: &TenantReadView,
        token: &QueryCancellation,
        namespace: &str,
        row: (&[u8], &[u8]),
    ) -> Result<Uuid> {
        let (key, value) = row;
        match namespace {
            PHASES => self.phase_owner(view, token, key, value),
            PUBLICATION_OWNERS => self.indexed_publication_owner(view, token, uuid(key)?, value),
            GENERATIONS => {
                let incarnation = uuid(key)?;
                let outcome: GenerationRecord = decode(value)?;
                let operation = match outcome {
                    GenerationRecord::Reserved { operation_id }
                    | GenerationRecord::Active { operation_id }
                    | GenerationRecord::Stopped { operation_id } => operation_id,
                };
                let (journal, _charge) = self.journal_at(view, operation, token)?;
                ensure!(
                    journal.status.request.target_incarnation == incarnation
                        || matches!(outcome, GenerationRecord::Stopped { .. })
                            && journal.status.request.expected_active_incarnation == incarnation,
                    "local recovery generation differs from operation"
                );
                Ok(operation)
            }
            ACTIVE => {
                let active: ActiveGeneration = decode(value)?;
                let (journal, _charge) = self.journal_at(view, active.operation_id, token)?;
                let request = &journal.status.request;
                ensure!(
                    request.tenant.as_bytes() == key
                        && active.incarnation == request.target_incarnation
                        && active.directory == journal.target_directory
                        && active.checkpoint == request.checkpoint
                        && active.application_provider == journal.application_provider
                        && active.custody_provider == journal.custody_provider,
                    "substituted active local recovery generation"
                );
                Ok(active.operation_id)
            }
            INSTALLATION => {
                let operation: Uuid = decode(value)?;
                let (journal, _charge) = self.journal_at(view, operation, token)?;
                ensure!(
                    key == b"pending"
                        && !matches!(
                            journal.status.phase,
                            LocalRecoveryPhase::Finished | LocalRecoveryPhase::Stopped
                        ),
                    "substituted local recovery pending owner"
                );
                Ok(operation)
            }
            _ => anyhow::bail!("unknown local recovery namespace"),
        }
    }
}

impl LocalRecoveryKeyInventory for Coordinator {
    fn visit_keys(
        &self,
        store: &Arc<TenantStore>,
        node_id: u64,
        read: &LocalRecoveryKeyRead<'_>,
        visit: &mut dyn FnMut(LocalRecoveryKeyFinding) -> Result<()>,
    ) -> Result<[u8; 32]> {
        let token = read.cancellation();
        token.check()?;
        let owner = self
            .owner
            .upgrade()
            .context("standalone coordinator has closed")?;
        let identity = owner.identity_for(store.persistent_disk())?;
        ensure!(
            identity.node_id == node_id,
            "standalone coordinator member differs"
        );
        let view = store.read_view()?;
        let result = (|| {
            let physical = view.wrapping_inventory()?;
            let mut digest = Sha256::new();
            digest.update(b"kasumi.standalone-recovery-key-inventory.v1\0");
            digest.update(
                physical.visit_catalog(|catalog_id, provider, key_ref, version| {
                    token.check()?;
                    visit(entry(
                        KeyReference::Catalog {
                            node_id,
                            catalog_id,
                            domain: KeyCatalogDomain::SecurityAudit,
                        },
                        provider,
                        key_ref,
                        version,
                    )?)
                })?,
            );
            let mut active_reports = 0;
            for namespace in [
                OPERATIONS,
                PHASES,
                PUBLICATION_OWNERS,
                GENERATIONS,
                ACTIVE,
                INSTALLATION,
                archives::OBJECTS,
            ] {
                digest.update(namespace.as_bytes());
                physical.visit_records(
                    namespace,
                    MAX_RECORD,
                    |key, value, provider, key_ref, version| {
                        token.check()?;
                        let _decoded = self.decoding_workspace(value.len(), token)?;
                        let operation_id = if namespace == OPERATIONS {
                            let observed =
                                self.operation(&view, key, value, node_id, read, visit)?;
                            active_reports += usize::from(observed.catalogs.is_some());
                            serde_json::to_writer(
                                &mut digest,
                                &(observed.catalogs, observed.external_checkpoint),
                            )?;
                            observed.operation
                        } else if namespace == archives::OBJECTS {
                            let (operation, observed) =
                                self.archive_owner(&view, store, token, (key, value), visit)?;
                            serde_json::to_writer(&mut digest, &observed)?;
                            operation
                        } else {
                            self.row_owner(&view, token, namespace, (key, value))?
                        };
                        visit(entry(
                            KeyReference::LocalRecovery { operation_id },
                            provider,
                            key_ref,
                            version,
                        )?)?;
                        serde_json::to_writer(&mut digest, &(provider, key_ref, version))?;
                        for field in [key, value] {
                            digest.update((field.len() as u64).to_be_bytes());
                            digest.update(field);
                        }
                        Ok(())
                    },
                )?;
            }
            token.check()?;
            ensure!(
                active_reports == self.active.len(),
                "active standalone catalog has no matching recovery operation"
            );
            physical.check_current()?;
            ensure!(
                owner.identity_for(store.persistent_disk())? == identity,
                "standalone coordinator changed"
            );
            Ok(digest.finalize().into())
        })();
        finish(result, view.close())
    }
}

fn finish<T>(result: Result<T>, close: Result<()>) -> Result<T> {
    match (result, close) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(close)) => Err(error.context(close)),
    }
}
