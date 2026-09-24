//! Installed encryption domains for one application incarnation. Control access
//! never unwraps the application catalog and is not a data authorization bypass.
use super::*;
use std::collections::BTreeSet;

mod catalog_initialization;
mod existing_catalogs;

const BINDING_NS: &str = "kasumi.storage-domains";
const BINDING_KEY: &[u8] = b"binding";
const CUSTODY_PREFIX: &str = "kasumi.custody/";
const DEPLOYMENT_NS: &str = "engine.deployment";
const DEPLOYMENT_KEY: &[u8] = b"mode";
// The current writer prefixes a 36-byte UUID key ID with four length bytes;
// encryption adds 24 nonce and 16 tag bytes to the 12-byte record framing.
const MAX_DEPLOYMENT_ENVELOPE_BYTES: usize =
    MAX_DEPLOYMENT_BINDING_BYTES + DEPLOYMENT_NS.len() + DEPLOYMENT_KEY.len() + 4 + 36 + 12 + 40;

/// The plaintext remains charged to the installed memory provider until the
/// caller finishes validating and drops the exact admitted binding.
pub struct AdmittedDeploymentBinding {
    bytes: Vec<u8>,
    _charge: DiskMemoryLease,
}
impl AdmittedDeploymentBinding {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl TenantStore {
    fn deployment_at(
        &self,
        tx: &kasumi_kv::ReadTransaction,
        state: &KeyState,
    ) -> Result<Option<AdmittedDeploymentBinding>> {
        self.require_access(state)?;
        let disk_key = record_key(
            &self.tenant,
            DEPLOYMENT_NS,
            DEPLOYMENT_KEY,
            state.keys.get(INDEX_KEY).context("index key missing")?,
        );
        let table = tx.open_table(RECORDS)?;
        let Some(encrypted) = table.get(disk_key.as_slice())? else {
            return Ok(None);
        };
        let envelope = encrypted.value();
        ensure!(
            envelope.len() <= MAX_DEPLOYMENT_ENVELOPE_BYTES,
            "encrypted deployment envelope exceeds read budget"
        );
        check_encrypted_record_budget(
            envelope,
            DEPLOYMENT_NS.len(),
            DEPLOYMENT_KEY.len(),
            MAX_DEPLOYMENT_BINDING_BYTES,
        )?;
        // Native KV retains the encrypted guard's physical resident lease.
        // Fund the plaintext decrypt buffer and owned value before decryption.
        let workspace = u64::try_from(envelope.len())?
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(8192))
            .context("deployment plaintext workspace overflow")?;
        let charge = self
            .scratch_disk()
            .memory()
            .clone()
            .reserve_installed(workspace)
            .context("deployment plaintext admission denied")?;
        let mut record = self.decode_record(&disk_key, envelope, state)?;
        ensure!(
            record.namespace == DEPLOYMENT_NS
                && record.key == DEPLOYMENT_KEY
                && record.value.len() <= MAX_DEPLOYMENT_BINDING_BYTES,
            "deployment binding identity or size differs"
        );
        self.require_access(state)?;
        Ok(Some(AdmittedDeploymentBinding {
            bytes: std::mem::take(&mut record.value),
            _charge: charge,
        }))
    }
}

fn validate_application_tenant(tenant: &str) -> Result<()> {
    ensure!(
        !tenant.is_empty()
            && tenant.len() <= 1024 - CUSTODY_PREFIX.len()
            && !tenant.starts_with(CUSTODY_PREFIX),
        "invalid or reserved application storage identity"
    );
    Ok(())
}

/// Persisted identity, not a serving or retirement proof. The private fields are
/// derived from actual installed catalogs and checked on every domain open.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageBinding {
    application_tenant: String,
    application_catalog: Uuid,
    application_purpose: StoragePurpose,
    custody_catalog: Uuid,
    application_wrapping_policies: BTreeSet<String>,
    custody_wrapping_policies: BTreeSet<String>,
}

impl StorageBinding {
    pub fn tenant(&self) -> &str {
        &self.application_tenant
    }
    pub fn application_catalog(&self) -> Uuid {
        self.application_catalog
    }
    pub fn custody_catalog(&self) -> Uuid {
        self.custody_catalog
    }
    pub fn digest(&self) -> Result<String> {
        Ok(hex::encode(Sha256::digest(serde_json::to_vec(self)?)))
    }
}

/// Independently keyed source control storage. Opening this handle reads only
/// wrapped application metadata; it does not construct an application provider,
/// unwrap application keys, or read application records.
pub struct CustodyStore {
    store: Arc<TenantStore>,
    binding: StorageBinding,
}

impl CustodyStore {
    /// Wrapped-catalog probe only. No key provider is constructed or contacted.
    pub fn catalog_installed(node: &NodeStore, application_tenant: &str) -> Result<bool> {
        validate_application_tenant(application_tenant)?;
        Ok(node
            .catalog(&Self::catalog_name(application_tenant))?
            .is_some())
    }
    pub fn catalog_name(application_tenant: &str) -> String {
        format!("{CUSTODY_PREFIX}{application_tenant}")
    }

    /// Opens an already installed control domain. Missing binding fails closed;
    /// creating the application/control relationship requires both live stores.
    pub async fn open(
        node: Arc<NodeStore>,
        application_tenant: String,
        provider: Arc<dyn KeyProvider>,
    ) -> Result<Arc<Self>> {
        match existing_catalogs::open(node, application_tenant, provider, None).await? {
            existing_catalogs::Opened::Custody(store) => Ok(store),
            existing_catalogs::Opened::Pair(_) => {
                unreachable!("custody request cannot return an application pair")
            }
        }
    }

    pub fn binding(&self) -> &StorageBinding {
        &self.binding
    }
    pub fn store(&self) -> &Arc<TenantStore> {
        &self.store
    }
}

/// The normal serving path owns both domains. No same-key default or optional
/// custody provider exists. Native configuration must explicitly install both.
pub struct TenantStorageSet {
    application: Arc<TenantStore>,
    custody: Arc<CustodyStore>,
    shutdown_report: AsyncMutex<DrainReport>,
}

impl TenantStorageSet {
    /// Read both independently encrypted deployment copies from one immutable
    /// native KV generation. A concurrent paired publication cannot split them.
    pub fn deployment_binding(&self) -> Result<Option<AdmittedDeploymentBinding>> {
        let application = &self.application;
        let custody = &self.custody.store;
        let _app_access = AccessGuard(application);
        let _custody_access = AccessGuard(custody);
        self.check_access()?;
        let app_state = application.state.read();
        let custody_state = custody.state.read();
        application.require_access(&app_state)?;
        custody.require_access(&custody_state)?;
        let tx = application.node.db.begin_read()?;
        let app = application.deployment_at(&tx, &app_state)?;
        let peer = custody.deployment_at(&tx, &custody_state)?;
        application.require_access(&app_state)?;
        custody.require_access(&custody_state)?;
        match (app, peer) {
            (None, None) => Ok(None),
            (Some(app), Some(peer)) => {
                ensure!(
                    app.as_bytes() == peer.as_bytes(),
                    "deployment binding differs across domains"
                );
                Ok(Some(app))
            }
            _ => bail!("required deployment binding is absent from one domain"),
        }
    }

    /// Classify an unprovisioned tenant without constructing either key provider.
    /// A single catalog is an interrupted or corrupt installation, not a stage.
    pub fn catalogs_installed(node: &NodeStore, tenant: &str) -> Result<bool> {
        validate_application_tenant(tenant)?;
        let application = node.catalog(tenant)?.is_some();
        let custody = node.catalog(&CustodyStore::catalog_name(tenant))?.is_some();
        ensure!(
            application == custody,
            "application and custody catalogs are only partially installed"
        );
        Ok(application)
    }

    /// Open both existing catalogs and their authenticated immutable binding.
    /// Missing catalogs or binding are errors; this path never installs either.
    pub async fn open_existing(
        node: Arc<NodeStore>,
        tenant: String,
        application_provider: Arc<dyn KeyProvider>,
        custody_provider: Arc<dyn KeyProvider>,
        application_access: StorageAccess,
    ) -> Result<Arc<Self>> {
        match existing_catalogs::open(
            node,
            tenant,
            custody_provider,
            Some((application_provider, application_access)),
        )
        .await?
        {
            existing_catalogs::Opened::Pair(stores) => Ok(stores),
            existing_catalogs::Opened::Custody(_) => {
                unreachable!("pair request cannot return custody alone")
            }
        }
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub async fn open_existing_fixture(
        node: Arc<NodeStore>,
        tenant: String,
        application_provider: Arc<dyn KeyProvider>,
        custody_provider: Arc<dyn KeyProvider>,
    ) -> Result<Arc<Self>> {
        let access = StorageAccess::fixture_for(&tenant);
        Self::open_existing(node, tenant, application_provider, custody_provider, access).await
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub async fn initialize_catalogs_fixture(
        node: Arc<NodeStore>,
        tenant: String,
        application_provider: Arc<dyn KeyProvider>,
        custody_provider: Arc<dyn KeyProvider>,
    ) -> Result<Arc<Self>> {
        let access = StorageAccess::fixture_for(&tenant);
        Self::initialize_catalogs(node, tenant, application_provider, custody_provider, access)
            .await
    }

    /// Trusted installation boundary, useful for explicitly clocked embeddings.
    /// Existing bindings are immutable; these are not caller-selected namespaces.
    pub(crate) fn install(
        application: Arc<TenantStore>,
        custody: Arc<TenantStore>,
    ) -> Result<Arc<Self>> {
        validate_application_tenant(&application.tenant)?;
        ensure!(
            Arc::ptr_eq(&application.node, &custody.node),
            "storage domains use different nodes"
        );
        ensure!(
            custody.tenant == CustodyStore::catalog_name(&application.tenant),
            "custody catalog is not bound to this application tenant"
        );
        let _app_access = AccessGuard(&application);
        let _custody_access = AccessGuard(&custody);
        application.check_access()?;
        custody.check_access()?;
        // Every coordinator acquires application then custody. A standalone
        // domain mutation holds only one lock and never acquires its peer.
        let _app_mutation = application.mutations.lock();
        let _custody_mutation = custody.mutations.lock();
        let saved = custody.get(BINDING_NS, BINDING_KEY)?;
        let app_state = application.state.read();
        let custody_state = custody.state.read();
        application.require_access(&app_state)?;
        custody.require_access(&custody_state)?;
        let app_catalog = application.catalog.read();
        let custody_catalog = custody.catalog.read();
        validate_distinct_keys(&app_state, &custody_state)?;
        let binding = derive_binding(&app_catalog, &custody_catalog)?;
        let bytes = serde_json::to_vec(&binding)?;
        if let Some(saved) = saved {
            ensure!(
                saved == bytes,
                "installed storage domain binding bytes differ"
            );
        } else {
            let tx = application.node.db.begin_write()?;
            write_domain(
                &tx,
                &custody,
                &custody_state,
                &custody_catalog,
                &[WriteOp::put(BINDING_NS, BINDING_KEY, bytes)],
            )?;
            application.require_access(&app_state)?;
            custody.require_access(&custody_state)?;
            tx.commit()
                .context("storage domain installation outcome may be unknown")?;
            application.require_access(&app_state)?;
            custody.require_access(&custody_state)?;
        }
        drop(custody_catalog);
        drop(app_catalog);
        drop(custody_state);
        drop(app_state);
        drop(_custody_mutation);
        drop(_app_mutation);
        let result = Arc::new(Self {
            shutdown_report: AsyncMutex::new(DrainReport::default()),
            application: application.clone(),
            custody: Arc::new(CustodyStore {
                store: custody.clone(),
                binding,
            }),
        });
        Ok(result)
    }

    pub fn application(&self) -> &Arc<TenantStore> {
        &self.application
    }
    pub fn custody(&self) -> &Arc<CustodyStore> {
        &self.custody
    }
    /// Close both owned domains and retain every terminal outcome through a
    /// cancelled waiter. Borrowed provisional owners must use their own census.
    pub async fn shutdown(&self) -> DrainResult {
        let mut report = self.shutdown_report.lock().await;
        let mut retained = None;
        for store in [&self.application, &self.custody.store] {
            if let Err(failure) = store.shutdown().await {
                report.merge(&failure);
                if failure.completion() == kasumi_types::drain::DrainCompletion::Retained {
                    retained = Some(failure);
                }
            }
        }
        report.outcome(retained)
    }
    pub fn check_access(&self) -> Result<()> {
        self.application.check_access()?;
        self.custody.store.check_access()
    }

    /// Atomically seals/publishes a bounded write in both independent domains.
    /// Both leases are held through actual fsync, including on caller cancellation.
    /// The synchronous call must be owned by the caller's tracked blocking worker.
    pub fn write_batch(&self, application_ops: &[WriteOp], custody_ops: &[WriteOp]) -> Result<()> {
        self.write_batch_replacing(application_ops, custody_ops, &[], &[])
    }

    /// Publish first application state only into a pristine installed domain
    /// pair. The complete physical tenant prefixes are checked under the same
    /// mutation owners and transaction as publication, including unknown record
    /// namespaces. Custody may contain only its exact storage-domain binding.
    /// The caller owns authorization and the blocking operation through fsync.
    pub fn initialize_state(
        &self,
        application_ops: &[WriteOp],
        custody_ops: &[WriteOp],
    ) -> Result<()> {
        ensure!(
            !application_ops.is_empty() && !custody_ops.is_empty(),
            "initial publication requires state in both domains"
        );
        ensure!(
            application_ops
                .iter()
                .chain(custody_ops)
                .all(|operation| matches!(operation, WriteOp::Put { .. })),
            "initial publication accepts only inserted state"
        );
        for operation in custody_ops {
            let namespace = match operation {
                WriteOp::Put { namespace, .. } | WriteOp::Delete { namespace, .. } => namespace,
            };
            ensure!(
                namespace != BINDING_NS,
                "initial state cannot replace its domain binding"
            );
        }
        self.publish(application_ops, custody_ops, &[], &[], true)
    }

    /// Stream verified application and custody tables while publishing their
    /// manifests, namespace bindings and applied position in one durable commit.
    pub fn write_batch_replacing(
        &self,
        application_ops: &[WriteOp],
        custody_ops: &[WriteOp],
        application_replacements: &[(&str, &EncryptedTable)],
        custody_replacements: &[(&str, &EncryptedTable)],
    ) -> Result<()> {
        self.publish(
            application_ops,
            custody_ops,
            application_replacements,
            custody_replacements,
            false,
        )
    }

    fn publish(
        &self,
        application_ops: &[WriteOp],
        custody_ops: &[WriteOp],
        application_replacements: &[(&str, &EncryptedTable)],
        custody_replacements: &[(&str, &EncryptedTable)],
        initialize: bool,
    ) -> Result<()> {
        validate_batch(&[application_ops, custody_ops])?;
        crate::read_view::validate_replacements(application_replacements, application_ops)?;
        crate::read_view::validate_replacements(custody_replacements, custody_ops)?;
        let application = &self.application;
        let custody = &self.custody.store;
        let _app_access = AccessGuard(application);
        let _custody_access = AccessGuard(custody);
        self.check_access()?;
        let _app_mutation = application.mutations.lock();
        let _custody_mutation = custody.mutations.lock();
        {
            let app_state = application.state.read();
            let custody_state = custody.state.read();
            application.require_access(&app_state)?;
            custody.require_access(&custody_state)?;
            let app_catalog = application.catalog.read();
            let custody_catalog = custody.catalog.read();
            ensure!(
                derive_binding(&app_catalog, &custody_catalog)? == self.custody.binding,
                "storage key purpose changed"
            );
            validate_distinct_keys(&app_state, &custody_state)?;
        }
        let tx = application.node.db.begin_write()?;
        if initialize {
            require_pristine_domain(&tx, application, None)?;
            let binding = serde_json::to_vec(&self.custody.binding)?;
            require_pristine_domain(&tx, custody, Some(&binding))?;
        }
        crate::read_view::replace_domain(&tx, application, application_replacements)?;
        {
            let state = application.state.read();
            application.require_access(&state)?;
            let catalog = application.catalog.read();
            write_domain(&tx, application, &state, &catalog, application_ops)?;
        }
        crate::read_view::replace_domain(&tx, custody, custody_replacements)?;
        {
            let state = custody.state.read();
            custody.require_access(&state)?;
            let catalog = custody.catalog.read();
            write_domain(&tx, custody, &state, &catalog, custody_ops)?;
        }
        self.check_access()?;
        tx.commit()
            .context("durable domain transaction failed; outcome may be unknown")?;
        self.check_access().context(
            "domain transaction committed; access expired before acknowledgment; outcome unknown",
        )
    }
}

fn require_pristine_domain(
    tx: &kasumi_kv::WriteTransaction,
    store: &TenantStore,
    binding: Option<&[u8]>,
) -> Result<()> {
    let state = store.state.read();
    store.require_access(&state)?;
    let prefix = tenant_hash(&store.tenant);
    let table = tx.open_table(RECORDS)?;
    let mut records = table.range(prefix.as_slice()..)?;
    let first = records.next().transpose()?;
    let first = first.filter(|(key, _)| key.value().starts_with(&prefix));
    if let Some(expected) = binding {
        let (key, value) = first.context("initial custody domain binding absent")?;
        let index = state.keys.get(INDEX_KEY).context("index key missing")?;
        let expected_key = record_key(&store.tenant, BINDING_NS, BINDING_KEY, index);
        ensure!(
            key.value() == expected_key,
            "initial custody domain is not pristine"
        );
        check_encrypted_record_budget(
            value.value(),
            BINDING_NS.len(),
            BINDING_KEY.len(),
            expected.len(),
        )?;
        let record = store.decode_record(key.value(), value.value(), &state)?;
        ensure!(
            record.namespace == BINDING_NS && record.key == BINDING_KEY && record.value == expected,
            "initial custody domain binding differs"
        );
        if let Some((key, _)) = records.next().transpose()? {
            ensure!(
                !key.value().starts_with(&prefix),
                "initial custody domain is not pristine"
            );
        }
    } else {
        ensure!(
            first.is_none(),
            "initial application domain is not pristine"
        );
    }
    store.require_access(&state)
}

fn wrapping_policies(catalog: &KeyCatalog) -> Result<BTreeSet<String>> {
    catalog
        .keys
        .values()
        .map(|key| {
            ensure!(
                !key.provider.is_empty() && !key.key_ref.is_empty(),
                "missing wrapping policy identity"
            );
            // Context and version do not make a separate KMS permission boundary.
            Ok(hex::encode(Sha256::digest(serde_json::to_vec(&(
                &key.provider,
                &key.key_ref,
            ))?)))
        })
        .collect()
}

fn derive_binding(application: &KeyCatalog, custody: &KeyCatalog) -> Result<StorageBinding> {
    application.validate(&application.tenant)?;
    custody.validate(&CustodyStore::catalog_name(&application.tenant))?;
    ensure!(
        application.catalog_id != custody.catalog_id,
        "storage domains share a catalog identity"
    );
    let application_wrapping_policies = wrapping_policies(application)?;
    let custody_wrapping_policies = wrapping_policies(custody)?;
    ensure!(
        application_wrapping_policies.is_disjoint(&custody_wrapping_policies),
        "application and custody require independent wrapping policies"
    );
    Ok(StorageBinding {
        application_tenant: application.tenant.clone(),
        application_catalog: application.catalog_id,
        application_purpose: application.purpose.clone(),
        custody_catalog: custody.catalog_id,
        application_wrapping_policies,
        custody_wrapping_policies,
    })
}

fn validate_distinct_keys(application: &KeyState, custody: &KeyState) -> Result<()> {
    for app_key in application.keys.values() {
        for control_key in custody.keys.values() {
            ensure!(
                !same_key(app_key, control_key),
                "storage domains share plaintext key material"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "storage_domains_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "storage_existing_tests.rs"]
mod existing_tests;
