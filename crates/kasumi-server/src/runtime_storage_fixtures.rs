//! Explicit isolated storage policy for server installation fixtures.
use crate::{runtime::RuntimeConfig, runtime_memory::RuntimeStorage};
use anyhow::{Context, Result, ensure};
use kasumi_engine::admission::AdmissionConfig;
use kasumi_store::{NodeDiskConfig, ScratchDiskConfig};
use kasumi_types::AuditRetentionBudget;
use std::{collections::BTreeMap, path::Path};

/// Bound for a fixture's wait on an event that its own work produces: a paused
/// task entering its checkpoint, a released drain joining, a leader appearing.
/// The wait ends as soon as the event happens, so the bound only keeps a broken
/// fixture from hanging; it allows for a heavily loaded machine running the
/// rest of the suite in parallel. Waits whose length a test asserts keep their
/// own bounds.
pub(crate) const LIVENESS: std::time::Duration = std::time::Duration::from_secs(120);

/// Existing test policies already include bookkeeping. Add only the exact new
/// metadata owners, once, before creating either physical fixture disk.
pub(crate) fn configure(config: &mut RuntimeConfig) -> Result<RuntimeStorage> {
    let storage = RuntimeStorage::isolated_fixture(
        config.admission.clone(),
        &config.persistent_disk,
        &config.scratch_disk,
    )?;
    config.admission = storage.policy().clone();
    Ok(storage)
}

pub(crate) fn standalone_disks(directory: &Path) -> Result<(NodeDiskConfig, ScratchDiskConfig)> {
    ensure!(
        directory.is_absolute(),
        "fixture installation path must be absolute"
    );
    let parent = directory
        .parent()
        .context("fixture installation parent missing")?;
    let name = directory
        .file_name()
        .context("fixture installation name missing")?;
    let directory = std::fs::canonicalize(parent)?.join(name);
    let persistent = RuntimeStorage::fixture_installation_disk_config(BTreeMap::from([
        ("data".into(), directory.join("data")),
        ("backups".into(), directory.join("backups")),
    ]));
    let scratch = ScratchDiskConfig {
        directory: directory.join("scratch"),
        ..crate::runtime::example_config(
            kasumi_store::DirectoryPolicy::fixture(),
            kasumi_store::FileAllocationPolicy::fixture(),
        )
        .unwrap()
        .scratch_disk
    };
    Ok((persistent, scratch))
}

pub(crate) fn standalone_storage(
    directory: &Path,
    policy: AdmissionConfig,
) -> Result<RuntimeStorage> {
    let (persistent, scratch) = standalone_disks(directory)?;
    RuntimeStorage::isolated_fixture(policy, &persistent, &scratch)
}

pub(crate) fn initialize_standalone<'a>(
    directory: &'a Path,
    tenant: &'a str,
) -> impl std::future::Future<
    Output = Result<(crate::standalone::InitializedInstallation, RuntimeStorage)>,
> + 'a {
    // Construct this large cold-start future outside its caller's poll frame.
    // Boxing at the await site still leaves its inline construction temporary
    // on that frame while the nested startup-owner futures are polled.
    Box::pin(async move {
        // Keep the former fixture's ordinary budget after node audit maintenance
        // admits one 128 MiB native KV escrow and protects another 128 MiB for
        // maintenance writes. Both amounts remain charged or guarded by admission.
        let mut policy = AdmissionConfig::default();
        let former_total = policy.resolved_fixture_total_bytes()?;
        policy.max_inflight_bytes = Some(
            former_total
                .checked_add(4 * AuditRetentionBudget::MAINTENANCE_BYTES)
                .context("standalone fixture admission total overflow")?,
        );
        let storage = standalone_storage(directory, policy)?;
        let installed = crate::standalone::initialize_with_storage(
            directory,
            tenant,
            kasumi_store::DirectoryPolicy::fixture(),
            kasumi_store::FileAllocationPolicy::fixture(),
            crate::standalone::StandaloneNetwork::fixture(),
            crate::standalone::local_audit_placements(tenant),
            storage.clone(),
        )
        .await?;
        Ok((installed, storage))
    })
}

/// A low-level fixture owns its TempDir in the calling scope. Physical and
/// scratch roots are explicit siblings; the existing total receives only the
/// new installed metadata charges. The facade is admitted before either disk.
pub(crate) fn physical(
    directory: &Path,
    policy: AdmissionConfig,
) -> Result<kasumi_engine::test_utils::FixtureStorage> {
    let (persistent, scratch) = kasumi_engine::test_utils::fixture_disk_configs(directory)?;
    kasumi_engine::test_utils::FixtureStorage::open(&persistent, &scratch, policy)
}

/// Move an initialized standalone installation's listeners, and every profile
/// it generated, to fresh loopback ports, and commit the matching Control
/// topology. Returns the configuration to serve.
pub(crate) async fn retarget_standalone(
    installation: &crate::standalone::InitializedInstallation,
    storage: &RuntimeStorage,
) -> Result<RuntimeConfig> {
    let mut config = RuntimeConfig::load(&installation.configuration)?;
    let listeners = (0..3)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0"))
        .collect::<std::io::Result<Vec<_>>>()?;
    config.mcp.listen = listeners[0].local_addr()?;
    config.native.listen = listeners[1].local_addr()?;
    config.admin.listen = listeners[2].local_addr()?;
    config.mcp.protocol = crate::mcp::McpConfig::new(format!(
        "https://localhost:{}/mcp",
        config.mcp.listen.port()
    ))?;
    for path in [
        &installation.control_profile,
        &installation.tenant_profile,
        &installation.operator_profile,
        &installation.mcp_profile,
    ] {
        if !path.try_exists()? {
            continue;
        }
        let mut profile = crate::standalone::ClientProfile::load(path)?;
        profile.mcp_endpoint = config.mcp.protocol.public_url.clone();
        profile.native_endpoint = format!("https://localhost:{}", config.native.listen.port());
        profile
            .administrative_members
            .get_mut(&1)
            .context("generated administrative member")?
            .endpoint = format!("https://localhost:{}", config.admin.listen.port());
        kasumi_store::private_files::replace(path, &serde_json::to_vec_pretty(&profile)?)?;
    }
    crate::standalone::configure_test_topology(&config, storage.clone()).await;
    drop(listeners);
    Ok(config)
}
