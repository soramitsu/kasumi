//! Real file/keyring ownership regressions; no fixture storage capabilities.
use super::*;
use std::{
    collections::BTreeMap,
    future::Future,
    sync::{Mutex, OnceLock},
    task::Poll,
    time::Duration,
};

#[derive(Default)]
struct Checkpoint {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
    fail: bool,
}
type Checkpoints = Mutex<BTreeMap<(PathBuf, &'static str), Arc<Checkpoint>>>;
struct CheckpointControl(Arc<Checkpoint>);
impl std::ops::Deref for CheckpointControl {
    type Target = Checkpoint;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl Drop for CheckpointControl {
    fn drop(&mut self) {
        // A failed assertion must not strand another test's registry drain.
        self.0.release.notify_one();
    }
}
fn checkpoints() -> &'static Checkpoints {
    static CHECKPOINTS: OnceLock<Checkpoints> = OnceLock::new();
    CHECKPOINTS.get_or_init(Default::default)
}
pub(crate) fn drain_serial() -> &'static tokio::sync::Mutex<()> {
    static SERIAL: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    SERIAL.get_or_init(Default::default)
}
pub(super) fn run_large_fixture<F, Fut>(name: &'static str, make: F) -> Result<()>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = Result<()>> + 'static,
{
    // Keep the two-worker runtime used by these ownership cases, but build
    // their large encrypted-catalog futures outside libtest's small stack.
    std::thread::Builder::new()
        .name(name.into())
        .stack_size(16 << 20)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(16 << 20)
                .enable_all()
                .build()
                .unwrap()
                .block_on(Box::pin(make()))
        })?
        .join()
        .expect("standalone ownership fixture thread panicked")
}
fn install(path: &Path, phase: &'static str, fail: bool) -> CheckpointControl {
    let checkpoint = Arc::new(Checkpoint {
        fail,
        ..Default::default()
    });
    assert!(
        checkpoints()
            .lock()
            .unwrap()
            .insert((path.to_owned(), phase), checkpoint.clone())
            .is_none()
    );
    CheckpointControl(checkpoint)
}
pub(super) async fn checkpoint(path: &Path, phase: &'static str) -> Result<()> {
    let checkpoint = checkpoints()
        .lock()
        .unwrap()
        .remove(&(path.to_owned(), phase));
    if let Some(checkpoint) = checkpoint {
        checkpoint.entered.notify_one();
        checkpoint.release.notified().await;
        ensure!(
            !checkpoint.fail,
            "injected stopped-operator failure after {phase}"
        );
    }
    Ok(())
}
async fn pending(future: &mut std::pin::Pin<Box<impl Future>>) {
    std::future::poll_fn(|cx| {
        assert!(future.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
}
async fn physical_reopen(
    config: &RuntimeConfig,
    storage: &crate::runtime_memory::RuntimeStorage,
) -> Result<()> {
    let disk = storage.open_persistent(&config.persistent_disk)?;
    let _lock = claim(config, &disk)?.context("missing standalone lock")?;
    let node = NodeStore::open_existing(
        &config.database_path,
        config.database_id,
        disk,
        storage.open_scratch(&config.scratch_disk)?,
    )?;
    node.shutdown().await?;
    drop(node);
    Ok(())
}
fn physical_reopen_rejected(
    config: &RuntimeConfig,
    storage: &crate::runtime_memory::RuntimeStorage,
) {
    let disk = storage.open_persistent(&config.persistent_disk).unwrap();
    assert!(claim(config, &disk).is_err());
    assert!(
        NodeStore::open_existing(
            &config.database_path,
            config.database_id,
            disk,
            storage.open_scratch(&config.scratch_disk).unwrap(),
        )
        .is_err()
    );
}

#[test]
fn every_standalone_operator_retains_real_installation_through_cancelled_reply_and_drain()
-> Result<()> {
    run_large_fixture(
        "standalone operator ownership fixture",
        every_standalone_operator_impl,
    )
}

async fn every_standalone_operator_impl() -> Result<()> {
    let _serial = drain_serial().lock().await;
    let root = kasumi_store::test_utils::private_tempdir()?;
    let (installed, storage) = crate::runtime_storage_fixtures::initialize_standalone(
        &root.path().join("database"),
        "documents",
    )
    .await?;
    for operation in 0..5 {
        let config = RuntimeConfig::load(&installed.configuration)?;
        let paused = install(&config.database_path, "audit", false);
        let configuration = installed.configuration.clone();
        let output = root.path().join(format!("operator-output-{operation}"));
        let operation_storage = storage.clone();
        let mut request = Box::pin(async move {
            match operation {
                0 => recover_administrator_with_storage(
                    &configuration,
                    &output,
                    operation_storage.clone(),
                )
                .await
                .map(|_| ()),
                1 => {
                    rotate_wrapping_keys_with_storage(&configuration, operation_storage.clone())
                        .await
                }
                2 => rotate_signing_key_with_storage(&configuration, operation_storage.clone())
                    .await
                    .map(|_| ()),
                3 => rotate_certificates_with_storage(&configuration, operation_storage.clone())
                    .await
                    .map(|_| ()),
                4 => {
                    backup_operator_keys_with_storage(
                        &configuration,
                        &output,
                        operation_storage.clone(),
                    )
                    .await
                }
                _ => unreachable!(),
            }
        });
        pending(&mut request).await;
        tokio::time::timeout(Duration::from_secs(10), paused.entered.notified()).await?;
        drop(request);
        physical_reopen_rejected(&config, &storage);
        let mut first = Box::pin(drain_operations());
        pending(&mut first).await;
        drop(first);
        physical_reopen_rejected(&config, &storage);
        let mut retry = Box::pin(drain_operations());
        pending(&mut retry).await;
        paused.release.notify_one();
        tokio::time::timeout(Duration::from_secs(10), retry).await??;
        physical_reopen(&config, &storage).await?;
        // Reopen encrypted catalogs and credentials too, then drain their new owners.
        let mut owner = OperatorState::open(
            &RuntimeConfig::load(&installed.configuration)?,
            storage.clone(),
        )
        .await?;
        owner.audit.status()?;
        owner.finish(Ok(())).await?;
    }
    Ok(())
}

#[test]
fn cancelled_initialization_remains_joinable_before_its_first_catalog_publication() -> Result<()> {
    run_large_fixture(
        "standalone cancelled-initialization fixture",
        cancelled_initialization_impl,
    )
}

async fn cancelled_initialization_impl() -> Result<()> {
    let _serial = drain_serial().lock().await;
    let root = kasumi_store::test_utils::private_tempdir()?;
    let directory = std::fs::canonicalize(root.path())?.join("database");
    let path = directory.join("data/node.kv");
    let paused = install(&path, "initialize-node", false);
    let storage =
        crate::runtime_storage_fixtures::standalone_storage(&directory, Default::default())?;
    let mut request = Box::pin(initialize_with_storage(
        &directory,
        "documents",
        kasumi_store::DirectoryPolicy::fixture(),
        StandaloneNetwork::fixture(),
        storage.clone(),
    ));
    pending(&mut request).await;
    tokio::time::timeout(Duration::from_secs(10), paused.entered.notified()).await?;
    drop(request);
    assert!(
        private_files::ExclusiveLock::acquire(&directory.join("data/installation.lock")).is_err()
    );
    assert!(!directory.join("data/installation.json").exists());
    let mut first = Box::pin(drain_operations());
    pending(&mut first).await;
    drop(first);
    paused.release.notify_one();
    tokio::time::timeout(Duration::from_secs(10), drain_operations()).await??;
    physical_reopen(
        &RuntimeConfig::load(directory.join("kasumi.json"))?,
        &storage,
    )
    .await?;
    Ok(())
}

#[test]
fn singleton_open_failure_drains_node_before_releasing_operator_lock() -> Result<()> {
    run_large_fixture(
        "standalone singleton-open fixture",
        singleton_open_failure_impl,
    )
}

async fn singleton_open_failure_impl() -> Result<()> {
    let _serial = drain_serial().lock().await;
    let root = kasumi_store::test_utils::private_tempdir()?;
    let (installed, storage) = crate::runtime_storage_fixtures::initialize_standalone(
        &root.path().join("database"),
        "documents",
    )
    .await?;
    let config = RuntimeConfig::load(&installed.configuration)?;
    let mut rejected = config.clone();
    let wrong_ring = root.path().join("unrelated-security-keyring.json");
    FileKeyProvider::initialize(&wrong_ring, "unrelated-security")?;
    rejected.security_audit.keys = KeyProviderSettings::File { path: wrong_ring };
    rejected.validate()?;
    // Prove this reaches an actual node claim rather than failing validation.
    let claimed = install(&config.database_path, "node", false);
    claimed.release.notify_one();
    let incorrect = root.path().join("wrong-keyring.json");
    private_files::create(&incorrect, &serde_json::to_vec_pretty(&rejected)?)?;
    assert!(
        backup_operator_keys_with_storage(
            &incorrect,
            &root.path().join("unused-output"),
            storage.clone()
        )
        .await
        .is_err()
    );
    tokio::time::timeout(Duration::from_secs(10), claimed.entered.notified()).await?;
    physical_reopen(&config, &storage).await?;
    let mut owner = OperatorState::open(&config, storage.clone()).await?;
    owner.audit.status()?;
    owner.finish(Ok(())).await?;
    Ok(())
}

#[test]
fn early_control_pair_error_retains_and_drains_both_catalogs() -> Result<()> {
    run_large_fixture(
        "standalone control-pair ownership fixture",
        early_control_pair_error_impl,
    )
}

async fn early_control_pair_error_impl() -> Result<()> {
    let _serial = drain_serial().lock().await;
    let root = kasumi_store::test_utils::private_tempdir()?;
    let (installed, storage) = crate::runtime_storage_fixtures::initialize_standalone(
        &root.path().join("database"),
        "documents",
    )
    .await?;
    let config = RuntimeConfig::load(&installed.configuration)?;
    let failed = install(&config.database_path, "control-pair", true);
    failed.release.notify_one();
    let configured = config.clone();
    let operation_storage = storage.clone();
    let error = operator::run(async move {
        let mut owner = OperatorState::open(&configured, operation_storage.clone()).await?;
        let result = owner.control().await.map(|_| ());
        owner.finish(result).await
    })
    .await
    .unwrap_err();
    assert!(format!("{error:#}").contains("after control-pair"));
    physical_reopen(&config, &storage).await?;
    let mut owner = OperatorState::open(&config, storage.clone()).await?;
    owner.control().await?;
    owner.finish(Ok(())).await?;
    Ok(())
}

#[test]
fn early_initialization_audit_error_drains_without_publishing_completion() -> Result<()> {
    run_large_fixture(
        "standalone early-initialization fixture",
        early_initialization_audit_error_impl,
    )
}

async fn early_initialization_audit_error_impl() -> Result<()> {
    let _serial = drain_serial().lock().await;
    let root = kasumi_store::test_utils::private_tempdir()?;
    let directory = std::fs::canonicalize(root.path())?.join("database");
    let failed = install(&directory.join("data/node.kv"), "initialize-audit", true);
    failed.release.notify_one();
    let storage =
        crate::runtime_storage_fixtures::standalone_storage(&directory, Default::default())?;
    assert!(
        initialize_with_storage(
            &directory,
            "documents",
            kasumi_store::DirectoryPolicy::fixture(),
            StandaloneNetwork::fixture(),
            storage.clone()
        )
        .await
        .is_err()
    );
    assert!(!directory.join("kasumi.json").exists());
    assert!(!directory.join("data/installation.json").exists());
    let _lock = private_files::ExclusiveLock::acquire(&directory.join("data/installation.lock"))?;
    let prepared: Installation = serde_json::from_slice(&private_files::read(
        &directory.join("data/initialization.json"),
        16 << 10,
    )?)?;
    let (persistent, scratch) = crate::runtime_storage_fixtures::standalone_disks(&directory)?;
    let node = NodeStore::open_existing(
        &prepared.database_path,
        prepared.database_id,
        storage.open_persistent(&persistent)?,
        storage.open_scratch(&scratch)?,
    )?;
    node.shutdown().await?;
    drop(node);
    Ok(())
}
