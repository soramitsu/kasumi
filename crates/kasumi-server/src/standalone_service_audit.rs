//! Offline export and pruning of the node's service audit, for a stopped
//! standalone installation whose audit already refuses records. The online
//! path cannot reach such a node: `kasumid audit prune` needs the CLI's own TLS
//! accept and authentication recorded first, and the daemon records its own
//! start before it serves. These commands hold the stopped installation's
//! exclusive operator ownership instead of a Control credential. They record
//! nothing but the prune's own `archive_pruned` record, which the hot log's
//! prune reserve always fits. They open neither Control nor any tenant, and
//! unlike the other offline commands they also run while a local recovery is
//! pending: finishing that recovery records audit events too.
//!
//! 1. `export-service-audit` writes `kasumid audit export` pages through the
//!    same engine export, from a request's cursor, or from a snapshot fixed at
//!    its start, to the end of that range.
//! 2. `prune-service-audit` prunes through the same engine prune and checks as
//!    `kasumid audit prune` and publishes its result in the same format. It
//!    then finishes deleting the pruned objects and archives the hot log to its
//!    drain target, so the daemon starts with room to record.
use super::*;
use kasumi_types::{
    ErrorCode, MAX_SECURITY_AUDIT_PAGE_BYTES, SecurityAuditExportRequest, SecurityAuditPage,
    SecurityAuditPruneRequest, SecurityAuditPruneResult, SecurityAuditStatus,
};

/// What an offline export wrote.
#[derive(Debug, Serialize)]
pub struct ServiceAuditExport {
    pub directory: PathBuf,
    /// Pages written, `page-00000000.json` onwards, each a `SecurityAuditPage`.
    pub pages: u64,
    pub records: u64,
    /// The page whose anchors `prune-service-audit` checks.
    pub last_page: PathBuf,
    /// The service audit when the export started. Without a request cursor
    /// the pages cover this status's snapshot. A prune keeps at least the
    /// newest segment, so its index is at most `archive_segments - 1`.
    pub status: SecurityAuditStatus,
}

/// What an offline prune did.
#[derive(Debug, Serialize)]
pub struct ServiceAuditPrune {
    /// Where `result` was published, in the format of `kasumid audit prune`.
    pub output: PathBuf,
    pub result: SecurityAuditPruneResult,
    /// The service audit once the pruned objects were deleted and the hot log
    /// was archived to its drain target.
    pub status: SecurityAuditStatus,
}

/// An absolute path that does not exist yet, beneath an existing owner-only
/// directory. A published page or result is never overwritten.
fn new_output(path: &Path, what: &str) -> Result<()> {
    ensure!(path.is_absolute(), "{what} must be absolute");
    private_files::check_directory(
        path.parent()
            .with_context(|| format!("{what} has no parent"))?,
    )?;
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => anyhow::bail!(
            "{what} {} already exists; choose a new path",
            path.display()
        ),
    }
}

/// Export the stopped installation's service audit into the new owner-only
/// directory `output`, one `kasumid audit export` page per file. `request` is
/// that command's request: the export starts at its cursor or, without one, at
/// the first retained record of a snapshot fixed now, and ends with that
/// range. Requires the installation's exclusive operator ownership. It reads
/// only and records nothing, so it also runs while the audit refuses records.
pub async fn export_service_audit(
    configuration: &Path,
    request: &Path,
    output: &Path,
) -> Result<ServiceAuditExport> {
    let config = RuntimeConfig::load(configuration)?;
    let storage = crate::runtime_memory::RuntimeStorage::installed(&config.admission)?;
    export_service_audit_with_storage(configuration, request, output, storage).await
}

async fn export_service_audit_with_storage(
    configuration: &Path,
    request: &Path,
    output: &Path,
    storage: crate::runtime_memory::RuntimeStorage,
) -> Result<ServiceAuditExport> {
    let request: SecurityAuditExportRequest = serde_json::from_slice(
        &crate::runtime::read_bounded(request, MAX_SECURITY_AUDIT_PAGE_BYTES)?,
    )?;
    request.validate()?;
    new_output(output, "service audit export directory")?;
    let (configuration, output) = (configuration.to_owned(), output.to_owned());
    operator::run(async move { export_owned(&configuration, request, &output, storage).await })
        .await
}

async fn export_owned(
    configuration: &Path,
    request: SecurityAuditExportRequest,
    output: &Path,
    storage: crate::runtime_memory::RuntimeStorage,
) -> Result<ServiceAuditExport> {
    let config = RuntimeConfig::load(configuration)?;
    let mut owner = OperatorState::open(&config, storage).await?;
    let result = async {
        let audit = owner.audit.clone();
        let status = audit.status()?;
        let SecurityAuditExportRequest { cursor, limit } = request;
        let mut cursor = cursor.unwrap_or_else(|| status.snapshot_cursor());
        private_files::create_directory(output)?;
        let mut export = ServiceAuditExport {
            directory: output.to_owned(),
            pages: 0,
            records: 0,
            last_page: PathBuf::new(),
            status,
        };
        loop {
            let page = audit.export_page(Some(cursor.clone()), limit).await?;
            let bytes = serde_json::to_vec(&page)?;
            ensure!(
                bytes.len() <= MAX_SECURITY_AUDIT_PAGE_BYTES,
                "service audit page exceeds its byte limit"
            );
            let path = output.join(format!("page-{:08}.json", export.pages));
            private_files::publish(&path, &bytes)?;
            export.pages += 1;
            export.records += page.records.len() as u64;
            export.last_page = path;
            let Some(next) = page.cursor() else {
                return Ok(export);
            };
            ensure!(
                next.next_sequence > cursor.next_sequence,
                "service audit export made no progress"
            );
            cursor = next;
        }
    }
    .await;
    owner.finish(result).await
}

/// Prune the stopped installation's service-audit archive segments below
/// `through_index`, covered by the export whose last page is `exported`, with
/// the checks of `kasumid audit prune`, and publish the result to `output` in
/// its format. Then delete the pruned objects and archive the hot log to its
/// drain target, so the daemon can record its start again.
///
/// The `archive_pruned` record names principal `offline-operator` and the
/// Control tenant. The installation's exclusive operator ownership authorizes
/// the prune instead of a credential, and is checked again right before the
/// retirement commits. After a crash, repeat the command with a new output:
/// an already pruned range prunes nothing more, and what is left finishes.
pub async fn prune_service_audit(
    configuration: &Path,
    exported: &Path,
    through_index: u64,
    output: &Path,
) -> Result<ServiceAuditPrune> {
    let config = RuntimeConfig::load(configuration)?;
    let storage = crate::runtime_memory::RuntimeStorage::installed(&config.admission)?;
    prune_service_audit_with_storage(configuration, exported, through_index, output, storage).await
}

async fn prune_service_audit_with_storage(
    configuration: &Path,
    exported: &Path,
    through_index: u64,
    output: &Path,
    storage: crate::runtime_memory::RuntimeStorage,
) -> Result<ServiceAuditPrune> {
    // Checked before anything is pruned: the result must be publishable.
    new_output(output, "service audit prune output")?;
    let page: SecurityAuditPage = serde_json::from_slice(&crate::runtime::read_bounded(
        exported,
        MAX_SECURITY_AUDIT_PAGE_BYTES,
    )?)?;
    let request = SecurityAuditPruneRequest {
        stream_id: page.stream_id,
        through_index,
        exported: page.resumed(),
    };
    request.validate()?;
    let (configuration, output) = (configuration.to_owned(), output.to_owned());
    operator::run(async move { prune_owned(&configuration, request, &output, storage).await }).await
}

async fn prune_owned(
    configuration: &Path,
    request: SecurityAuditPruneRequest,
    output: &Path,
    storage: crate::runtime_memory::RuntimeStorage,
) -> Result<ServiceAuditPrune> {
    let config = RuntimeConfig::load(configuration)?;
    let mut owner = OperatorState::open(&config, storage).await?;
    let result = async {
        let audit = owner.audit.clone();
        let installed = owner.installed_owner.clone();
        let disk = owner.node.persistent_disk().clone();
        let result = audit
            .prune(
                request.clone(),
                kasumi_engine::ArchivePrune {
                    principal: "offline-operator".into(),
                    tenant: crate::runtime::CONTROL_TENANT.into(),
                    request_id: Uuid::new_v4().to_string(),
                    minimum_age: std::time::Duration::from_secs(
                        u64::from(config.security_audit.prune_minimum_age_days) * 86_400,
                    ),
                    // Still the installation this process exclusively owns.
                    authorize: Box::new(move || {
                        installed.identity_for(&disk).map(drop).map_err(|_| {
                            kasumi_types::Error::new(
                                ErrorCode::Unavailable,
                                "the stopped installation's operator ownership changed",
                            )
                        })
                    }),
                },
            )
            .await?;
        result.validate(&request)?;
        private_files::publish(output, &serde_json::to_vec(&result)?)?;
        let status = reclaim(&audit).await.with_context(|| {
            format!(
                "the prune committed and its result is in {}, but the service audit cannot \
                 archive its hot log yet; prune through a later index or raise \
                 security_audit.retention.archive_bytes before starting kasumid",
                output.display()
            )
        })?;
        Ok(ServiceAuditPrune {
            output: output.to_owned(),
            result,
            status,
        })
    }
    .await;
    owner.finish(result).await
}

/// Finish deleting pruned objects and archive the hot log to its drain target,
/// one maintenance turn at a time while each turn makes progress.
async fn reclaim(audit: &kasumi_engine::SecurityAudit) -> Result<SecurityAuditStatus> {
    loop {
        let before = audit.status()?;
        let deleting = before
            .retired
            .as_ref()
            .and_then(|retired| retired.deleting_from);
        let backlog = before
            .budget
            .archive_backlog_bytes(before.position.hot_bytes, before.position.draining);
        if deleting.is_none() && backlog == 0 {
            return Ok(before);
        }
        let turn = audit.maintain().await;
        let after = audit.status()?;
        if after
            .retired
            .as_ref()
            .and_then(|retired| retired.deleting_from)
            == deleting
            && after.archive_segments == before.archive_segments
        {
            return Err(turn.err().unwrap_or_else(|| {
                anyhow::anyhow!(
                    "service audit maintenance made no progress: {}",
                    after
                        .last_failure
                        .as_deref()
                        .unwrap_or("no failure reported")
                )
            }));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kasumi_engine::{SecurityAudit, SecurityEvent, SecurityEventKind, SecurityOutcome};
    use kasumi_types::{AuditRetentionBudget, SecurityAuditRecord};
    use std::time::Duration;

    /// Among the largest records an administrative event makes: JSON doubles
    /// each quote of its three 256-byte names.
    fn bulky(index: u64) -> SecurityEvent {
        SecurityEvent {
            kind: SecurityEventKind::Administration,
            principal: Some("\"".repeat(256)),
            tenant: Some("\"".repeat(256)),
            request_id: format!("{index:016}{}", "\"".repeat(240)),
            outcome: SecurityOutcome::Succeeded,
        }
    }

    fn event(kind: SecurityEventKind, request_id: &str) -> SecurityEvent {
        SecurityEvent {
            kind,
            principal: None,
            tenant: None,
            request_id: request_id.into(),
            outcome: SecurityOutcome::Succeeded,
        }
    }

    /// Record bulky events 64 at a time, archiving whenever the hot log
    /// refuses one, until the archive budget refuses the next segment. Then
    /// fill what is left of the hot log with the smallest records.
    async fn exhaust(audit: &Arc<SecurityAudit>) -> Result<()> {
        let mut index = 0;
        loop {
            let mut batch = tokio::task::JoinSet::new();
            for _ in 0..64 {
                index += 1;
                let (audit, event) = (audit.clone(), bulky(index));
                batch.spawn(async move { audit.record(event).await });
            }
            let mut refused = false;
            while let Some(outcome) = batch.join_next().await {
                refused |= outcome?.is_err();
            }
            if refused && let Err(error) = audit.maintain().await {
                let error = format!("{error:#}");
                ensure!(error.contains("archive disk budget exhausted"), "{error}");
                break;
            }
        }
        while audit
            .record(event(SecurityEventKind::Administration, "f"))
            .await
            .is_ok()
        {}
        Ok(())
    }

    fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
        Ok(serde_json::from_slice(&private_files::read(
            path,
            MAX_SECURITY_AUDIT_PAGE_BYTES,
        )?)?)
    }

    /// Every record of a fresh online export, page by page.
    async fn export_online(profile: &ClientProfile) -> Result<Vec<SecurityAuditRecord>> {
        let mut admin =
            kasumi_client::KasumiAdminClient::connect(&profile.connection(true)?).await?;
        let options = || -> Result<kasumi_client::JsonReadOptions> {
            Ok(kasumi_client::JsonReadOptions {
                resources: kasumi_client::ClientResources::new(64 << 20, 4)?,
                limits: kasumi_client::ClientDecodeLimits {
                    max_request_bytes: 64 << 10,
                    max_wire_bytes: 2 << 20,
                    max_json_bytes: 1 << 20,
                    max_decoded_bytes: 16 << 20,
                    max_rows: 1024,
                    ..Default::default()
                },
                deadline: tokio::time::Instant::now() + Duration::from_secs(30),
            })
        };
        let mut records = Vec::new();
        let mut cursor = None;
        loop {
            let page = admin
                .export_security_audit(
                    &profile.bearer()?,
                    &SecurityAuditExportRequest {
                        cursor: cursor.take(),
                        limit: 1024,
                    },
                    &options()?,
                )
                .await?;
            records.extend(page.records.iter().cloned());
            cursor = page.cursor();
            if cursor.is_none() {
                return Ok(records);
            }
        }
    }

    /// A node whose hot log is full and whose archive budget is exhausted
    /// cannot record its own start. Exported and pruned offline, it starts,
    /// serves and records again, and the retained history continues exactly
    /// where the saved pages left off.
    #[test]
    fn a_full_service_audit_is_exported_and_pruned_offline_and_records_again_on_restart()
    -> Result<()> {
        super::ownership_tests::run_large_fixture("offline service audit prune", || async {
            let root = kasumi_store::test_utils::private_tempdir()?;
            let directory = std::fs::canonicalize(root.path())?.join("kasumi");
            let (installation, storage) =
                crate::runtime_storage_fixtures::initialize_standalone(&directory, "tenant-a")
                    .await?;
            let configuration = installation.configuration.clone();
            let mut config = RuntimeConfig::load(&configuration)?;
            // Segments of about 512 KiB; 8 MiB is the smallest archive budget.
            config.security_audit.retention = AuditRetentionBudget {
                hot_bytes: 2 << 20,
                archive_bytes: 8 << 20,
            };
            let listeners = (0..3)
                .map(|_| std::net::TcpListener::bind("127.0.0.1:0"))
                .collect::<std::io::Result<Vec<_>>>()?;
            let addresses = listeners
                .iter()
                .map(std::net::TcpListener::local_addr)
                .collect::<std::io::Result<Vec<_>>>()?;
            config.mcp.listen = addresses[0];
            config.native.listen = addresses[1];
            config.admin.listen = addresses[2];
            config.mcp.protocol = crate::mcp::McpConfig::new(format!(
                "https://localhost:{}/mcp",
                addresses[0].port()
            ))?;
            private_files::replace(&configuration, &serde_json::to_vec_pretty(&config)?)?;
            let mut control = ClientProfile::load(&installation.control_profile)?;
            control.mcp_endpoint = config.mcp.protocol.public_url.clone();
            control.native_endpoint = format!("https://localhost:{}", addresses[1].port());
            control
                .administrative_members
                .get_mut(&1)
                .context("standalone profile has no administrative member")?
                .endpoint = format!("https://localhost:{}", addresses[2].port());
            private_files::replace(
                &installation.control_profile,
                &serde_json::to_vec(&control)?,
            )?;
            crate::standalone::configure_test_topology(&config, storage.clone()).await;

            let full = operator::run({
                let (config, storage) = (config.clone(), storage.clone());
                async move {
                    let mut owner = OperatorState::open(&config, storage).await?;
                    let result = async {
                        let audit = owner.audit.clone();
                        exhaust(&audit).await?;
                        // The daemon's start record no longer fits, and the
                        // hot log cannot drain into another segment.
                        let started = audit
                            .record(event(
                                SecurityEventKind::NodeStarted,
                                &Uuid::new_v4().to_string(),
                            ))
                            .await
                            .unwrap_err();
                        ensure!(
                            format!("{started:#}").contains("hot budget exhausted"),
                            "{started:#}"
                        );
                        let archive = audit.maintain().await.unwrap_err();
                        ensure!(
                            format!("{archive:#}").contains("archive disk budget exhausted"),
                            "{archive:#}"
                        );
                        audit.status()
                    }
                    .await;
                    owner.finish(result).await
                }
            })
            .await?;
            ensure!(full.retired.is_none() && full.archive_segments >= 3);
            ensure!(full.position.hot_bytes > full.budget.starts_at());

            // The export writes every record, from the first, into pages.
            let request = installation
                .control_profile
                .with_file_name("audit-request.json");
            private_files::create(
                &request,
                &serde_json::to_vec(&SecurityAuditExportRequest {
                    cursor: None,
                    limit: 1024,
                })?,
            )?;
            let exported = installation.control_profile.with_file_name("audit-export");
            let export = export_service_audit_with_storage(
                &configuration,
                &request,
                &exported,
                storage.clone(),
            )
            .await?;
            ensure!(export.status.position == full.position);
            ensure!(export.pages > 1);
            let mut saved = Vec::new();
            for index in 0..export.pages {
                let path = exported.join(format!("page-{index:08}.json"));
                let page: SecurityAuditPage = read(&path)?;
                ensure!(
                    page.stream_id == full.position.stream_id
                        && page.through_sequence == full.position.next_sequence
                        && page.next_sequence == saved.len() as u64 + page.records.len() as u64
                        && page
                            .records
                            .last()
                            .map(SecurityAuditRecord::sha256)
                            .transpose()?
                            == page.previous_record_sha256
                );
                ensure!((index + 1 == export.pages) == page.cursor().is_none());
                saved.extend(page.records);
                if index + 1 == export.pages {
                    ensure!(export.last_page == path);
                }
            }
            ensure!(saved.len() as u64 == full.position.next_sequence);
            ensure!(export.records == saved.len() as u64);
            ensure!(
                saved
                    .iter()
                    .enumerate()
                    .all(|(index, record)| record.sequence == index as u64)
            );
            let error = export_service_audit_with_storage(
                &configuration,
                &request,
                &exported,
                storage.clone(),
            )
            .await
            .unwrap_err();
            ensure!(format!("{error:#}").contains("already exists"), "{error:#}");

            // The prune refuses what the export does not vouch for, and an
            // output that already exists, before anything is pruned.
            let through = full.archive_segments - 1;
            let output = installation
                .control_profile
                .with_file_name("audit-prune.json");
            let first = exported.join("page-00000000.json");
            let error = prune_service_audit_with_storage(
                &configuration,
                &first,
                through,
                &output,
                storage.clone(),
            )
            .await
            .unwrap_err();
            ensure!(
                format!("{error:#}").contains("does not cover the pruned"),
                "{error:#}"
            );
            ensure!(!output.exists());
            let error = prune_service_audit_with_storage(
                &configuration,
                &export.last_page,
                through,
                &first,
                storage.clone(),
            )
            .await
            .unwrap_err();
            ensure!(format!("{error:#}").contains("already exists"), "{error:#}");

            // Pruned offline: one record is added, the pruned objects are
            // deleted and the hot log is archived to its drain target.
            let pruned = prune_service_audit_with_storage(
                &configuration,
                &export.last_page,
                through,
                &output,
                storage.clone(),
            )
            .await?;
            let published: SecurityAuditPruneResult = read(&output)?;
            ensure!(published == pruned.result && pruned.output == output);
            let retired = &pruned.result.retired;
            ensure!(
                pruned.result.pruned_segments == through
                    && retired.index == through
                    && retired.record_sha256 == saved[retired.sequence as usize - 1].sha256()?
            );
            let status = &pruned.status;
            ensure!(
                status.retired
                    == Some(kasumi_types::SecurityAuditRetirement {
                        deleting_from: None,
                        ..retired.clone()
                    })
            );
            ensure!(status.position.next_sequence == full.position.next_sequence + 1);
            ensure!(
                status
                    .budget
                    .archive_backlog_bytes(status.position.hot_bytes, status.position.draining)
                    == 0
            );
            ensure!(status.archived_bytes < full.archived_bytes);

            // The daemon starts, serves a Control administrator and records
            // its start, the TLS accept and the authentication again.
            drop(listeners);
            let runtime = crate::runtime::NodeRuntime::open_using_storage(
                config.clone(),
                crate::runtime::file_secret,
                storage.clone(),
            )
            .await?;
            let (stop, shutdown) = tokio::sync::watch::channel(false);
            let mut serving = tokio::spawn(runtime.serve(shutdown));
            let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
            let serves = loop {
                let attempt = async {
                    let mut admin =
                        kasumi_client::KasumiAdminClient::connect(&control.connection(true)?)
                            .await?;
                    anyhow::Ok(admin.security_audit_status(&control.bearer()?).await?)
                };
                tokio::select! {
                    stopped = &mut serving => anyhow::bail!("serving ended during startup: {stopped:?}"),
                    _ = tokio::time::sleep_until(deadline) => anyhow::bail!("the pruned node did not serve"),
                    status = attempt => match status {
                        Ok(status) => break status,
                        Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
                    },
                }
            };
            ensure!(serves.retired == status.retired);
            ensure!(serves.position.next_sequence > status.position.next_sequence);

            // A fresh export starts at the first retained record, anchored by
            // the last pruned one, and repeats the saved pages from there.
            let online = export_online(&control).await?;
            let boundary = retired.sequence as usize;
            let end = full.position.next_sequence as usize;
            ensure!(online.first().map(|record| record.sequence) == Some(retired.sequence));
            ensure!(online[..end - boundary] == saved[boundary..]);
            let prune = &online[end - boundary].event;
            ensure!(
                prune.kind
                    == SecurityEventKind::ArchivePruned {
                        retained_index: through,
                        retained_sequence: retired.sequence,
                        pruned_record_sha256: retired.record_sha256.clone(),
                        segments: through,
                        bytes: pruned.result.pruned_bytes,
                    }
                    && prune.principal.as_deref() == Some("offline-operator")
                    && prune.tenant.as_deref() == Some(crate::runtime::CONTROL_TENANT),
                "{prune:?}"
            );
            let after = &online[end - boundary + 1..];
            ensure!(
                after
                    .iter()
                    .any(|record| record.event.kind == SecurityEventKind::NodeStarted)
            );
            ensure!(
                after
                    .iter()
                    .any(|record| record.event.kind == SecurityEventKind::AuthenticationSucceeded)
            );
            stop.send_replace(true);
            serving.await??;
            Ok(())
        })
    }
}
