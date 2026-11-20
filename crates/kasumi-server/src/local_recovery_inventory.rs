//! Administrative read of the encrypted coordinator, held by the same exclusive
//! standalone installation that owns the recovery writer.
use super::*;
use kasumi_engine::{Database, LocalRecoveryKeyFinding, LocalRecoveryKeyInventory, SecurityAudit};
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
    database: &Database,
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
            tenants,
            owner: Arc::downgrade(owner),
            admission: audit.admission().clone(),
        }),
    )
}

struct Coordinator {
    owner: std::sync::Weak<crate::standalone::InstalledStandaloneOwner>,
    database_path: PathBuf,
    tenants: BTreeMap<String, (Uuid, String)>,
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
        visit: &mut dyn FnMut(LocalRecoveryKeyFinding) -> Result<()>,
    ) -> Result<Uuid> {
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
        // The authenticated checkpoint binds its external graph by digest. Its
        // wrapping versions require an independent read by the backup owner.
        visit(LocalRecoveryKeyFinding::Missing(
            MissingKeyDependency::ArchiveUnavailable {
                id: request.checkpoint.backup_id.to_string(),
            },
        ))?;
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
            visit(LocalRecoveryKeyFinding::Missing(
                MissingKeyDependency::RecordUnreadable {
                    record_kind: KeyReferenceKind::LocalRecovery,
                    id: request.target_incarnation.to_string(),
                },
            ))?;
        }
        Ok(operation)
    }

    fn row_owner(
        &self,
        view: &TenantReadView,
        token: &QueryCancellation,
        namespace: &str,
        key: &[u8],
        value: &[u8],
        visit: &mut dyn FnMut(LocalRecoveryKeyFinding) -> Result<()>,
    ) -> Result<Uuid> {
        match namespace {
            OPERATIONS => self.operation(view, key, value, visit),
            PHASES => {
                uuid(key)?;
                let (phase, request, ..): PhaseBinding = decode(value)?;
                let (journal, _charge) = self.journal_at(view, request.operation_id, token)?;
                ensure!(
                    !matches!(
                        phase,
                        LocalRecoveryPhase::Finished | LocalRecoveryPhase::Stopped
                    ) && binding_for_phase(&journal, phase)? == value,
                    "substituted historical local recovery phase"
                );
                Ok(request.operation_id)
            }
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
        token: &QueryCancellation,
        visit: &mut dyn FnMut(LocalRecoveryKeyFinding) -> Result<()>,
    ) -> Result<[u8; 32]> {
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
            for namespace in [OPERATIONS, PHASES, GENERATIONS, ACTIVE, INSTALLATION] {
                digest.update(namespace.as_bytes());
                physical.visit_records(
                    namespace,
                    MAX_RECORD,
                    |key, value, provider, key_ref, version| {
                        token.check()?;
                        let _decoded = self.decoding_workspace(value.len(), token)?;
                        let operation_id =
                            self.row_owner(&view, token, namespace, key, value, visit)?;
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
            physical.check_current()?;
            ensure!(
                owner.identity_for(store.persistent_disk())? == identity,
                "standalone coordinator changed"
            );
            Ok(digest.finalize().into())
        })();
        let close = view.close();
        match (result, close) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
            (Err(error), Err(close)) => Err(error.context(close)),
        }
    }
}
