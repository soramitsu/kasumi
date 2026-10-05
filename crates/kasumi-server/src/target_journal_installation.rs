//! Explicit first installation of an independently encrypted target journal.
//! A partially created installation is never adopted by normal daemon startup.
use crate::{
    runtime::{RuntimeConfig, file_secret},
    target_runtime_config::TargetRecoveryConfig,
};
use anyhow::{Context, Result};
use kasumi_engine::{TargetJournal, TargetJournalInstallation};
use kasumi_store::{NodeStore, StorageAccess, TenantStore, node_store_ids};
use std::{path::Path, sync::Arc};

pub(crate) fn installation(installed: &TargetRecoveryConfig) -> Result<TargetJournalInstallation> {
    let installation = TargetJournalInstallation {
        root: installed.control_root.clone(),
        node: installed.node.clone(),
        audit_placement_bindings: installed
            .tenants
            .iter()
            .map(|(tenant, template)| {
                Ok((
                    tenant.clone(),
                    template.audit_placement.canonical_binding()?,
                ))
            })
            .collect::<Result<_>>()?,
    };
    installation.validate()?;
    Ok(installation)
}

pub async fn initialize_from_file(path: &Path) -> Result<()> {
    initialize(RuntimeConfig::load(path)?).await
}

/// The owned initializer retains its actual file/store owners through drain if
/// its caller is cancelled. Existing, partial or uncertain files are not reset.
pub async fn initialize(config: RuntimeConfig) -> Result<()> {
    config.validate()?;
    let storage = crate::runtime_memory::RuntimeStorage::installed(&config.admission)?;
    initialize_with_storage(config, storage).await
}

pub(crate) async fn initialize_with_storage(
    config: RuntimeConfig,
    storage: crate::runtime_memory::RuntimeStorage,
) -> Result<()> {
    config.validate()?;
    storage.require_policy(&config.admission)?;
    crate::startup_owner::open(
        crate::startup_owner::Kind::TargetJournal,
        initialize_owned(config, storage),
    )
    .await?;
    Ok(())
}

/// Join cancelled installation attempts and preserve their original failures.
pub async fn drain_initializations() -> Result<()> {
    crate::startup_owner::drain(crate::startup_owner::Kind::TargetJournal).await
}

struct Initialized;
impl crate::startup_owner::Runtime for Initialized {
    fn close(
        &mut self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = kasumi_types::drain::DrainResult> + Send + '_>,
    > {
        Box::pin(async { Ok(()) })
    }
}

#[allow(
    clippy::result_large_err,
    reason = "the native constructor returns whole inline custody into the same preadmitted inventory before any foreign marker; boxing the error would allocate outside that boundary"
)]
async fn initialize_owned(
    config: RuntimeConfig,
    storage: crate::runtime_memory::RuntimeStorage,
) -> Result<Initialized> {
    let installed: &TargetRecoveryConfig = config
        .target_recovery
        .as_ref()
        .context("target recovery is not configured")?;
    let journal_installation = installation(installed)?;
    let admission = storage.facade(&config.admission)?;
    let mut pending = crate::startup_resources::Resources::default();
    pending.owned_admissions.push(admission.clone());
    pending.original_recoveries = Some(crate::administration::OriginalRecoveries::new(
        &admission,
        crate::administration::OriginalRecoveryParticipants::configured(&config),
    )?);
    let scratch = storage.open_scratch(&config.scratch_disk)?;
    let id = node_store_ids::target_journal(
        installed.control_root.control_incarnation,
        &installed.node.verifier,
    )?;
    let prepared = crate::startup_preparation::capture("target journal installation", async {
        let persistent = crate::persistent_disk::open(&config.persistent_disk, &storage)?;
        let node = {
            let mut seat = pending
                .original_recoveries
                .as_ref()
                .expect("initializer owns the same installed constructor inventory")
                .claim(0)
                .await;
            seat.begin_node()
                .map_err(|observed| observed.foreign_error())?
                .run_node(|| {
                    NodeStore::create_new(
                        &installed.journal_path,
                        id,
                        persistent.clone(),
                        scratch.clone(),
                        persistent.native_storage_config(),
                    )
                })
                .map_err(|observed| observed.foreign_error())?
        };
        pending.owned_nodes.push(node.clone());
        let store = TenantStore::initialize_catalog(
            node.clone(),
            format!(
                "kasumi.target.{}.{}",
                installed.control_root.control_incarnation, installed.node.node_id
            ),
            installed.journal_keys.provider(Arc::new(file_secret))?,
            StorageAccess::target_journal(&installed.control_root, &installed.node)?,
        )
        .await?;
        pending.stores.push(store.clone());
        node.drain_initializers()
            .await
            .map_err(|failure| failure.observation())?;
        let journal = TargetJournal::create_new(
            store,
            journal_installation,
            installed.limits.journal.clone(),
            admission,
        )?;
        pending.journals.push(journal);
        Ok(())
    })
    .await;
    let drained = crate::startup_owner::finish(&mut pending).await;
    match (prepared, drained) {
        (Ok(()), Ok(())) => Ok(Initialized),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(drain)) => Err(drain.into()),
        (Err(error), Err(drain)) => Err(error.context(drain)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        audit_destination::{AuditDestinationConfig, TenantAuditPlacementConfig},
        target_runtime_config::{TargetRunnerLimits, TargetTenantTemplate},
    };
    use kasumi_store::AuditArchiveDestination;
    use std::collections::BTreeMap;
    use uuid::Uuid;

    #[tokio::test]
    async fn target_templates_keep_independent_same_name_and_target_only_audit_choices()
    -> Result<()> {
        let directory = kasumi_store::test_utils::private_tempdir()?;
        let physical =
            crate::runtime_storage_fixtures::physical(directory.path(), Default::default())?;
        let config = crate::runtime::example_config(
            kasumi_store::DirectoryPolicy::fixture(),
            kasumi_store::FileAllocationPolicy::fixture(),
        )?;
        let external = directory.path().join("persistent/target-external-audit");
        let template = |placement| TargetTenantTemplate {
            authority: "target-issuer".into(),
            audit_placement: placement,
            application_keys: config.tenants[0].keys.clone(),
            custody_keys: config.tenants[0].custody_keys.clone(),
            source_backups: BTreeMap::new(),
        };
        let installed = TargetRecoveryConfig {
            control_root: kasumi_types::ControlSigningRoot {
                control_incarnation: Uuid::new_v4(),
                public_key: "ab".repeat(32),
            },
            control_endpoints: BTreeMap::new(),
            control_tls: config.native.tls.clone(),
            control_ca: directory.path().join("ca.pem"),
            node: kasumi_serving::NodeIdentity {
                node_id: 1,
                verifier: kasumi_serving::test_utils::fixture_verifier(1),
                principal: "target-node".into(),
                certificate_sha256: "cd".repeat(32),
            },
            attestation_key: directory.path().join("target.pk8"),
            issuer_admin_bearer_file: BTreeMap::new(),
            journal_path: directory.path().join("persistent/journal.kv"),
            journal_keys: config.security_audit.keys.clone(),
            generation_root: directory.path().join("persistent/generations"),
            tenants: BTreeMap::from([
                (
                    "acme".into(),
                    template(TenantAuditPlacementConfig::External {
                        destination: AuditDestinationConfig::Filesystem {
                            directory: external.clone(),
                        },
                    }),
                ),
                (
                    "target-only".into(),
                    template(TenantAuditPlacementConfig::LocalReplicaOnly),
                ),
            ]),
            limits: TargetRunnerLimits {
                journal: kasumi_types::TargetJournalLimits {
                    max_metadata_bytes: 4 << 20,
                },
                max_live_generations: 2,
                operation_timeout_ms: 1_000,
            },
        };
        let binding = installation(&installed)?;
        assert_eq!(binding.audit_placement_bindings.len(), 2);
        assert_ne!(
            binding.audit_placement_bindings["acme"],
            config.tenant_audit_placement("acme")?.canonical_binding()?
        );
        assert!(!config.tenant_audit_placements.contains_key("target-only"));
        assert!(
            !external.exists(),
            "binding must not open the external destination"
        );
        let path = directory.path().join("persistent/target.kv");
        let original_recoveries = crate::administration::OriginalRecoveries::new(
            &physical.admission,
            crate::administration::OriginalRecoveryParticipants::one(
                crate::runtime::CONTROL_TENANT,
            ),
        )?;
        let node = {
            let mut seat = original_recoveries.claim(0).await;
            seat.begin_node()
                .map_err(|observed| observed.foreign_error())?
                .run_node(|| physical.create_new(&path, kasumi_store::test_utils::NODE_STORE_ID))
                .map_err(|observed| observed.foreign_error())?
        };
        for (index, tenant) in ["acme", "target-only"].into_iter().enumerate() {
            let store = TenantStore::initialize_catalog_fixture(
                node.clone(),
                tenant.into(),
                Arc::new(kasumi_store::test_utils::LocalKeyProvider::new(
                    [80 + index as u8; 32],
                )),
            )
            .await?;
            let template = &installed.tenants[tenant];
            template.audit_placement.install(&store, None)?;
            let placement = store.tenant_audit_archive()?;
            if tenant == "acme" {
                assert_eq!(
                    placement.destination_identity(),
                    format!("filesystem:{}", external.display())
                );
                assert_ne!(
                    placement.destination_identity(),
                    placement.cache().identity()
                );
            } else {
                assert_eq!(
                    placement.destination_identity(),
                    placement.cache().identity()
                );
            }
            assert!(
                config.install_tenant_audit_archive(&store, None).is_err(),
                "ordinary source placement must not supply or replace a target choice"
            );
            template
                .audit_placement
                .install(&store, Some(placement.cache().clone()))?;
            store.shutdown().await?;
        }
        node.shutdown().await?;
        Ok(())
    }
}
