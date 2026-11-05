//! Moving the private tenant audit cache of the installation's own node to the
//! configured `tenant_audit_cache`, which may be on another filesystem. The
//! cache is a reopen dependency, so no object is deleted before its copy has
//! been verified against every local tenant's archive chain:
//!
//! 1. Copy and verify, with every placement still installed at the source.
//!    Each object is copied through exact publication (staging name, file and
//!    directory sync, rename, complete readback against the source digest).
//!    Control's and each local tenant's engine then opens on the source and
//!    authenticates its whole archive chain in the copy. Only then is the
//!    verified move recorded in security storage.
//! 2. Switch and remove. Every source object must still equal its copy. Each
//!    store's installed placement is rewritten to the copy, each source object
//!    is deleted only while it still equals its copy, the source directory is
//!    removed and the record is cleared.
//!
//! Running the command again resumes after a crash: copies are idempotent, and
//! a recorded verified move continues at the second step.
use super::*;
use kasumi_store::{
    AuditArchiveDestination as _, AuditCacheEntry, FilesystemAuditArchive, WriteOp,
};

const MOVES: &str = "standalone-tenant-audit-cache-moves";
const MOVE: &[u8] = b"move";

/// A copy verified against every local chain, recorded before any switch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifiedMove {
    operation: String,
    from: PathBuf,
    to: PathBuf,
}

/// What a completed move did.
#[derive(Debug, Default, Serialize)]
pub struct TenantAuditCacheMove {
    pub from: PathBuf,
    pub to: PathBuf,
    /// Objects copied to the destination by this run, or already there.
    pub copied_objects: u64,
    /// Archive segments of each store's chain authenticated in the copy.
    pub verified_segments: BTreeMap<String, u64>,
    /// Stores whose installed placement this run moved to the destination.
    pub switched_stores: Vec<String>,
    /// Source objects and interrupted staging names removed.
    pub removed_objects: u64,
    pub removed_staging: u64,
    /// The configuration already named the installed cache: nothing moved.
    pub already_installed: bool,
}

/// Move the cache now installed at `from` to the configuration's
/// `tenant_audit_cache` (or the default location when it is absent). Requires
/// the stopped installation's exclusive operator ownership. Run it as its own
/// process: it opens every tenant as `serve --local-snapshot-archive reference`
/// does. An opened tenant then keeps a by-reference snapshot as it is; an
/// embedded reopen would first publish an embedded snapshot, copying the whole
/// archive into the node file the move is meant to relieve. Opening for this
/// verification appends nothing, so no snapshot of either form is written.
pub async fn move_tenant_audit_cache(
    configuration: &Path,
    from: &Path,
) -> Result<TenantAuditCacheMove> {
    let config = RuntimeConfig::load(configuration)?;
    let storage = crate::runtime_memory::RuntimeStorage::installed(&config.admission)?;
    kasumi_engine::set_reference_local_snapshots(true);
    move_tenant_audit_cache_with_storage(configuration, from, storage).await
}

async fn move_tenant_audit_cache_with_storage(
    configuration: &Path,
    from: &Path,
    storage: crate::runtime_memory::RuntimeStorage,
) -> Result<TenantAuditCacheMove> {
    let finish = |storage: crate::runtime_memory::RuntimeStorage| {
        let (configuration, from) = (configuration.to_owned(), from.to_owned());
        operator::run(async move { finish_recorded(&configuration, &from, storage).await })
    };
    let copied = match finish(storage.clone()).await? {
        Step::Finished(report) => return Ok(report),
        Step::CopyFirst => {
            let (configuration, from) = (configuration.to_owned(), from.to_owned());
            let storage = storage.clone();
            operator::run(async move { copy_and_verify(&configuration, &from, storage).await })
                .await?
        }
    };
    match finish(storage).await? {
        Step::Finished(report) => Ok(TenantAuditCacheMove {
            copied_objects: copied.copied_objects,
            verified_segments: copied.verified_segments,
            ..report
        }),
        Step::CopyFirst => anyhow::bail!("the verified tenant audit cache copy was not recorded"),
    }
}

enum Step {
    /// Nothing is recorded and every local placement is still at the source.
    CopyFirst,
    Finished(TenantAuditCacheMove),
}

/// The configured destination of the installation's own node.
fn destination(config: &RuntimeConfig) -> Result<PathBuf> {
    Ok(match &config.tenant_audit_cache {
        Some(directory) => directory.clone(),
        None => config
            .database_path
            .parent()
            .context("installed data directory missing")?
            .join(crate::audit_destination::TENANT_AUDIT_CACHE),
    })
}

/// The same configuration with its placements resolving to `directory`.
fn installed_at(config: &RuntimeConfig, directory: &Path) -> Result<RuntimeConfig> {
    let mut config = config.clone();
    let default = config
        .database_path
        .parent()
        .context("installed data directory missing")?
        .join(crate::audit_destination::TENANT_AUDIT_CACHE);
    config.tenant_audit_cache = (directory != default).then(|| directory.to_owned());
    config.validate().with_context(|| {
        format!(
            "the current tenant audit cache {} must stay inside an installed persistent root \
             until the move finishes",
            directory.display()
        )
    })?;
    Ok(config)
}

fn recorded(store: &TenantStore) -> Result<Option<VerifiedMove>> {
    store
        .get(MOVES, MOVE)?
        .map(|bytes| serde_json::from_slice(&bytes).context("tenant audit cache move record"))
        .transpose()
}

/// Every local store holding a tenant audit placement on the installation's
/// own node, opened without installing one: Control, then each enrolled
/// tenant that is not served from a restored local generation.
async fn local_stores(
    config: &RuntimeConfig,
    owner: &OperatorState,
) -> Result<Vec<Arc<kasumi_store::TenantStorageSet>>> {
    let audit = owner.audit.store();
    let source = Arc::new(crate::runtime::file_secret);
    let mut stores = vec![
        kasumi_store::TenantStorageSet::open_existing(
            owner.node.clone(),
            crate::runtime::CONTROL_TENANT.into(),
            config.control.keys.provider(source.clone())?,
            config.control.custody_keys.provider(source.clone())?,
            StorageAccess::node_control(),
        )
        .await?,
    ];
    owner.retain_stores(&stores[0]);
    for tenant in &config.tenants {
        let Some(record) = crate::node_enrollment::tenant_record(audit, &tenant.tenant)? else {
            continue;
        };
        if record.stage != crate::node_enrollment::Stage::Prepared
            || crate::local_recovery::active_generation(config, audit, &tenant.tenant)?.is_some()
        {
            continue;
        }
        ensure!(
            tenant
                .incarnation
                .as_deref()
                .map(Uuid::parse_str)
                .transpose()?
                == Some(record.incarnation),
            "operator tenant differs from original enrollment"
        );
        let TenantServingConfig::Standalone { installation_id } = tenant.serving else {
            anyhow::bail!("tenant audit cache moves require standalone tenants");
        };
        let opened = kasumi_store::TenantStorageSet::open_existing(
            owner.node.clone(),
            tenant.tenant.clone(),
            tenant.keys.provider(source.clone())?,
            tenant.custody_keys.provider(source.clone())?,
            StorageAccess::standalone(installation_id, &tenant.tenant, record.incarnation)?,
        )
        .await?;
        owner.retain_stores(&opened);
        stores.push(opened);
    }
    Ok(stores)
}

/// Finish a recorded verified move, or report what the first step must do.
async fn finish_recorded(
    configuration: &Path,
    from: &Path,
    storage: crate::runtime_memory::RuntimeStorage,
) -> Result<Step> {
    let config = RuntimeConfig::load(configuration)?;
    let to = destination(&config)?;
    ensure!(
        from.is_absolute() && from != to,
        "move-tenant-audit-cache needs the absolute directory the cache is installed in now; \
         the configuration names {} as its new location",
        to.display()
    );
    let mut owner = OperatorState::open(&config, storage).await?;
    let result = async {
        let audit = owner.audit.clone();
        crate::local_recovery::require_runtime_ready(audit.store())?;
        let disk = owner.node.persistent_disk().clone();
        let from_identity = kasumi_store::filesystem_archive_identity(from);
        let to_identity = kasumi_store::filesystem_archive_identity(&to);
        let stores = local_stores(&config, &owner).await?;
        let mut installed = Vec::new();
        for stores in &stores {
            let store = stores.application();
            if let Some((cache, _)) = store.installed_tenant_audit_placement()? {
                installed.push((store.tenant().to_owned(), cache));
            }
        }
        let record = match recorded(audit.store())? {
            Some(record) if record.from == from && record.to == to => Some(record),
            // Abandoned before any placement switched: nothing depends on it.
            Some(record)
                if installed.iter().all(|(_, cache)| {
                    *cache == kasumi_store::filesystem_archive_identity(&record.from)
                }) =>
            {
                audit.store().write_batch(&[WriteOp::delete(MOVES, MOVE)])?;
                None
            }
            Some(record) => anyhow::bail!(
                "an interrupted tenant audit cache move from {} to {} is recorded; finish it by \
                 configuring tenant_audit_cache {} and running the move from {}",
                record.from.display(),
                record.to.display(),
                record.to.display(),
                record.from.display()
            ),
            None => None,
        };
        let Some(record) = record else {
            if installed.iter().all(|(_, cache)| *cache == to_identity) {
                return Ok(Step::Finished(TenantAuditCacheMove {
                    from: from.to_owned(),
                    to,
                    already_installed: true,
                    ..Default::default()
                }));
            }
            for (tenant, cache) in &installed {
                ensure!(
                    *cache == from_identity,
                    "the tenant audit cache of {tenant} is installed at {cache}, not {}; run the \
                     move with the directory it is installed in",
                    from.display()
                );
            }
            return Ok(Step::CopyFirst);
        };
        let target = Arc::new(FilesystemAuditArchive::open(&to, disk.clone())?);
        let mut report = TenantAuditCacheMove {
            from: from.to_owned(),
            to: to.clone(),
            ..Default::default()
        };
        let source = match std::fs::symlink_metadata(from) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            _ => Some(FilesystemAuditArchive::open(from, disk)?),
        };
        let mut copies = BTreeMap::new();
        if let Some(source) = &source {
            // Nothing written since the verification may be left behind.
            let unchanged = (|| -> Result<()> {
                for entry in source.entries()? {
                    if let AuditCacheEntry::Object(object) = entry {
                        let copy = target.object_link(object)?;
                        ensure!(
                            source.object_link(object)? == copy,
                            "source object {object} differs from its copy"
                        );
                        copies.insert(object, copy);
                    }
                }
                Ok(())
            })();
            if let Err(error) = unchanged {
                if installed.iter().all(|(_, cache)| *cache == from_identity) {
                    audit.store().write_batch(&[WriteOp::delete(MOVES, MOVE)])?;
                }
                return Err(error.context(format!(
                    "{} changed after its copy was verified; run the move again",
                    from.display()
                )));
            }
        } else {
            ensure!(
                installed.iter().all(|(_, cache)| *cache == to_identity),
                "the move source {} is gone but a placement still names it",
                from.display()
            );
        }
        for stores in &stores {
            let store = stores.application();
            // A store that never installed a placement records the new one
            // when it installs below, as at its first startup.
            if store.installed_tenant_audit_placement()?.is_some()
                && store.relocate_tenant_audit_cache(&from_identity, &target)?
            {
                report.switched_stores.push(store.tenant().to_owned());
            }
            config.install_tenant_audit_archive(store, None)?;
        }
        if let Some(source) = source {
            for entry in source.entries()? {
                match entry {
                    AuditCacheEntry::Object(object) => {
                        let copy = copies
                            .get(&object)
                            .with_context(|| format!("source object {object} has no copy"))?;
                        source.delete_object(copy)?;
                        report.removed_objects += 1;
                    }
                    AuditCacheEntry::Staging(object) => {
                        source.delete_staging(object)?;
                        report.removed_staging += 1;
                    }
                }
            }
            source.remove_empty()?;
        }
        audit.store().write_batch(&[WriteOp::delete(MOVES, MOVE)])?;
        audit
            .record(operator_event(
                &record.operation,
                kasumi_engine::SecurityOutcome::Succeeded,
            ))
            .await?;
        Ok(Step::Finished(report))
    }
    .await;
    owner.finish(result).await
}

struct Copied {
    copied_objects: u64,
    verified_segments: BTreeMap<String, u64>,
}

/// With every placement still at `from`, copy each object to the configured
/// destination and authenticate every local chain in the copy. Records the
/// verified move only after every check passed.
async fn copy_and_verify(
    configuration: &Path,
    from: &Path,
    storage: crate::runtime_memory::RuntimeStorage,
) -> Result<Copied> {
    let loaded = RuntimeConfig::load(configuration)?;
    let to = destination(&loaded)?;
    let config = installed_at(&loaded, from)?;
    let mut owner = OperatorState::open(&config, storage).await?;
    let result = async {
        let audit = owner.audit.clone();
        crate::local_recovery::require_runtime_ready(audit.store())?;
        ensure!(
            recorded(audit.store())?.is_none(),
            "a verified tenant audit cache move is already recorded"
        );
        let operation = Uuid::new_v4().to_string();
        audit
            .record(operator_event(
                &operation,
                kasumi_engine::SecurityOutcome::Started,
            ))
            .await?;
        let (tenants, _) = operator_tenants(&config, audit.store(), &owner).await?;
        let control = owner.control().await?;
        let mut databases = vec![control.clone()];
        let source = Arc::new(crate::runtime::file_secret);
        for tenant in &tenants {
            if crate::local_recovery::active_generation(&config, audit.store(), &tenant.tenant)?
                .is_some()
            {
                continue;
            }
            let TenantServingConfig::Standalone { installation_id } = tenant.serving else {
                anyhow::bail!("tenant audit cache moves require standalone tenants");
            };
            let incarnation = Uuid::parse_str(
                tenant
                    .incarnation
                    .as_deref()
                    .context("tenant incarnation missing")?,
            )?;
            let stores = kasumi_store::TenantStorageSet::open_existing(
                owner.node.clone(),
                tenant.tenant.clone(),
                tenant.keys.provider(source.clone())?,
                tenant.custody_keys.provider(source.clone())?,
                StorageAccess::standalone(installation_id, &tenant.tenant, incarnation)?,
            )
            .await?;
            owner.retain_stores(&stores);
            config.install_tenant_audit_archive(stores.application(), None)?;
            let database = owner
                .snapshot(
                    &tenant.tenant,
                    kasumi_engine::open_existing_local(stores, audit.clone(), incarnation),
                )
                .await?;
            owner.retain_database(database.clone());
            databases.push(database);
        }
        let cache = control
            .stores()
            .application()
            .tenant_audit_archive()?
            .cache()
            .clone();
        ensure!(
            cache.directory() == from,
            "Control's tenant audit cache is installed at {}, not {}",
            cache.directory().display(),
            from.display()
        );
        // A destination deeper than its root gets its missing parents through
        // the installed owner, exactly as configured directories do.
        drop(crate::persistent_disk::open_or_create_directory(
            &config.persistent_disk,
            owner.node.persistent_disk(),
            to.parent().context("tenant audit cache has no parent")?,
        )?);
        let target = Arc::new(FilesystemAuditArchive::open(
            &to,
            owner.node.persistent_disk().clone(),
        )?);
        let store = control.stores().application().clone();
        let copied = {
            let (cache, target) = (cache.clone(), target.clone());
            tokio::task::spawn_blocking(move || -> Result<u64> {
                let mut copied = 0;
                for entry in cache.entries()? {
                    if let AuditCacheEntry::Object(object) = entry {
                        cache.copy_object(&store, object, &target)?;
                        copied += 1;
                    }
                }
                Ok(copied)
            })
            .await??
        };
        let mut verified_segments = BTreeMap::new();
        for database in databases {
            let tenant = database.stores().application().tenant().to_owned();
            ensure!(
                database
                    .stores()
                    .application()
                    .tenant_audit_archive()?
                    .cache()
                    .identity()
                    == cache.identity(),
                "{tenant} installed a different tenant audit cache"
            );
            let engine = database.engine().clone();
            let target = target.clone();
            let segments =
                tokio::task::spawn_blocking(move || engine.verify_audit_archive_copy(&target))
                    .await?
                    .with_context(|| {
                        format!(
                            "the copy in {} does not hold the archive chain of {tenant}",
                            to.display()
                        )
                    })?;
            verified_segments.insert(tenant, segments);
        }
        audit.store().write_batch(&[WriteOp::put(
            MOVES,
            MOVE,
            serde_json::to_vec(&VerifiedMove {
                operation,
                from: from.to_owned(),
                to: to.clone(),
            })?,
        )])?;
        Ok(Copied {
            copied_objects: copied,
            verified_segments,
        })
    }
    .await;
    owner.finish(result).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_destination::TENANT_AUDIT_CACHE;

    /// Publish one object no chain names, and leave one interrupted staging
    /// name, in the cache the configuration installs.
    async fn seed(
        config: &RuntimeConfig,
        storage: crate::runtime_memory::RuntimeStorage,
    ) -> Result<(kasumi_types::AuditArchiveLink, Uuid)> {
        let config = config.clone();
        operator::run(async move {
            let mut owner = OperatorState::open(&config, storage).await?;
            let result = async {
                let control = owner.control().await?;
                let store = control.stores().application().clone();
                let cache = store.tenant_audit_archive()?.cache().clone();
                let mut builder = kasumi_store::AuditSegmentBuilder::new(Uuid::new_v4(), 0, None)?;
                let event = kasumi_types::AuditEvent {
                    event_id: "moved".into(),
                    principal: "operator".into(),
                    action: "read".into(),
                    request_id: "request".into(),
                    timestamp_ms: 1_000,
                    data_revision: None,
                    outcome: "authorized_release".into(),
                    collection: None,
                };
                ensure!(builder.push(0, &serde_json::to_vec(&event)?)?);
                let segment = store.encrypt_audit_segment(builder)?;
                cache.publish_blocking(&segment)?;
                let staging = Uuid::new_v4();
                let disk = store.persistent_disk().clone();
                let path = cache.directory().join(format!("{staging}.audit.pending"));
                let (root, relative) = config.persistent_disk.binding(&path)?;
                disk.create_file(root, relative, DiskWork::Maintenance)?
                    .close()?;
                Ok((segment.reference.object.clone(), staging))
            }
            .await;
            owner.finish(result).await
        })
        .await
    }

    /// Installing Control's placement under `config`, which must fail.
    async fn refused(
        config: &RuntimeConfig,
        storage: crate::runtime_memory::RuntimeStorage,
    ) -> Result<String> {
        let config = config.clone();
        operator::run(async move {
            let mut owner = OperatorState::open(&config, storage).await?;
            let error = match owner.control().await {
                Ok(_) => anyhow::bail!("a placement elsewhere was installed"),
                Err(error) => format!("{error:#}"),
            };
            owner.finish(Ok(error)).await
        })
        .await
    }

    /// The object and its link through the cache Control installs now.
    async fn installed_link(
        config: &RuntimeConfig,
        storage: crate::runtime_memory::RuntimeStorage,
        object: Uuid,
    ) -> Result<(PathBuf, kasumi_types::AuditArchiveLink)> {
        let config = config.clone();
        operator::run(async move {
            let mut owner = OperatorState::open(&config, storage).await?;
            let result = async {
                let control = owner.control().await?;
                let cache = control
                    .stores()
                    .application()
                    .tenant_audit_archive()?
                    .cache()
                    .clone();
                Ok((cache.directory().to_owned(), cache.object_link(object)?))
            }
            .await;
            owner.finish(result).await
        })
        .await
    }

    fn write(configuration: &Path, config: &RuntimeConfig) -> Result<()> {
        private_files::replace(configuration, &serde_json::to_vec_pretty(config)?)
    }

    #[test]
    fn a_verified_move_switches_every_placement_and_the_old_location_fails_closed() -> Result<()> {
        super::ownership_tests::run_large_fixture("tenant audit cache move", || async {
            let root = kasumi_store::test_utils::private_tempdir()?;
            let directory = std::fs::canonicalize(root.path())?.join("kasumi");
            let (installation, storage) =
                crate::runtime_storage_fixtures::initialize_standalone(&directory, "tenant-a")
                    .await?;
            let configuration = installation.configuration.clone();
            let original = RuntimeConfig::load(&configuration)?;
            let from = original
                .database_path
                .parent()
                .unwrap()
                .join(TENANT_AUDIT_CACHE);
            // Another installed root; a second filesystem is just another root.
            let to = original.persistent_disk.roots["backups"].join("audit-cache");
            let (link, staging) = seed(&original, storage.clone()).await?;
            let object = link.object_id;

            // A configuration naming another cache is refused before the new
            // directory exists, with the command that moves the history.
            let mut moved = original.clone();
            moved.tenant_audit_cache = Some(to.clone());
            write(&configuration, &moved)?;
            let error = refused(&moved, storage.clone()).await?;
            assert!(error.contains("move-tenant-audit-cache"), "{error}");
            assert!(error.contains(&from.display().to_string()), "{error}");
            assert!(!to.exists());

            // A source that no placement names is refused before any copy.
            let elsewhere = original.persistent_disk.roots["backups"].join("elsewhere");
            let error =
                move_tenant_audit_cache_with_storage(&configuration, &elsewhere, storage.clone())
                    .await
                    .unwrap_err();
            assert!(format!("{error:#}").contains("not"), "{error:#}");
            assert!(!to.exists());

            // A crash after the verified copy resumes at the switch, and a
            // source that changed after verification is never removed.
            let (copy_configuration, copy_from) = (configuration.clone(), from.clone());
            let copied = operator::run({
                let storage = storage.clone();
                async move { copy_and_verify(&copy_configuration, &copy_from, storage).await }
            })
            .await?;
            assert_eq!(copied.copied_objects, 1);
            assert_eq!(
                copied.verified_segments,
                BTreeMap::from([
                    (crate::runtime::CONTROL_TENANT.to_owned(), 0),
                    ("tenant-a".to_owned(), 0)
                ])
            );
            let (late, _) = seed(&installed_at(&moved, &from)?, storage.clone()).await?;
            let error =
                move_tenant_audit_cache_with_storage(&configuration, &from, storage.clone())
                    .await
                    .unwrap_err();
            assert!(
                format!("{error:#}").contains("changed after its copy was verified"),
                "{error:#}"
            );
            assert!(from.join(format!("{}.audit", late.object_id)).is_file());
            assert_eq!(
                installed_link(&original, storage.clone(), object).await?.0,
                from
            );

            // A verified copy that is then abandoned (here: the destination
            // changes before any placement switched) is discarded, and the
            // move to the new destination copies, verifies, switches and
            // removes the source.
            let copy_configuration = configuration.clone();
            let copy_from = from.clone();
            operator::run({
                let storage = storage.clone();
                async move { copy_and_verify(&copy_configuration, &copy_from, storage).await }
            })
            .await?;
            let to = original.persistent_disk.roots["backups"].join("audit-cache-2");
            moved.tenant_audit_cache = Some(to.clone());
            write(&configuration, &moved)?;
            let report =
                move_tenant_audit_cache_with_storage(&configuration, &from, storage.clone())
                    .await?;
            assert_eq!(report.copied_objects, 2);
            assert_eq!(
                report.switched_stores,
                [crate::runtime::CONTROL_TENANT, "tenant-a"]
            );
            assert_eq!(report.removed_objects, 2);
            assert_eq!(report.removed_staging, 2);
            assert!(!report.already_installed);
            assert!(!from.exists());
            assert!(!to.join(format!("{staging}.audit.pending")).exists());

            // The moved cache reopens from its new location with the same bytes.
            assert_eq!(
                installed_link(&moved, storage.clone(), object).await?,
                (to.clone(), link)
            );
            assert_eq!(
                installed_link(&moved, storage.clone(), late.object_id)
                    .await?
                    .1,
                late
            );

            // The old location now fails closed.
            write(&configuration, &original)?;
            let error = refused(&original, storage.clone()).await?;
            assert!(error.contains("move-tenant-audit-cache"), "{error}");
            assert!(error.contains(&to.display().to_string()), "{error}");
            assert!(!from.exists());

            // Once moved, the same command has nothing left to do.
            write(&configuration, &moved)?;
            let again =
                move_tenant_audit_cache_with_storage(&configuration, &from, storage.clone())
                    .await?;
            assert!(again.already_installed);
            Ok(())
        })
    }
}
