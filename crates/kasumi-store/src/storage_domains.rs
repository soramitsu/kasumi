//! Installed encryption domains for one application incarnation. Control access
//! never unwraps the application catalog and is not a data authorization bypass.
use super::*;
use redb::ReadableTable;
use std::collections::BTreeSet;

mod catalog_initialization;

const BINDING_NS: &str = "kasumi.storage-domains";
const BINDING_KEY: &[u8] = b"binding";
const CUSTODY_PREFIX: &str = "kasumi.custody/";

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
        validate_application_tenant(&application_tenant)?;
        let store = TenantStore::open_existing(
            node.clone(),
            Self::catalog_name(&application_tenant),
            provider,
            StorageAccess::custody(&application_tenant),
        )
        .await?;
        Self::from_installed(node, application_tenant, store)
    }

    fn from_installed(
        node: Arc<NodeStore>,
        application_tenant: String,
        store: Arc<TenantStore>,
    ) -> Result<Arc<Self>> {
        let application = node
            .catalog(&application_tenant)?
            .context("application catalog absent")?;
        let binding = derive_binding(&application, &store.catalog.read())?;
        let saved = store
            .get(BINDING_NS, BINDING_KEY)?
            .context("storage domain binding absent")?;
        ensure!(
            serde_json::from_slice::<StorageBinding>(&saved)? == binding,
            "installed storage domain binding differs"
        );
        Ok(Arc::new(Self { store, binding }))
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
}

impl TenantStorageSet {
    /// Open both existing catalogs and their authenticated immutable binding.
    /// Missing catalogs or binding are errors; this path never installs either.
    pub async fn open_existing(
        node: Arc<NodeStore>,
        tenant: String,
        application_provider: Arc<dyn KeyProvider>,
        custody_provider: Arc<dyn KeyProvider>,
        application_access: StorageAccess,
    ) -> Result<Arc<Self>> {
        validate_application_tenant(&tenant)?;
        application_access.validate_tenant(&tenant)?;
        let custody = CustodyStore::open(node.clone(), tenant.clone(), custody_provider).await?;
        ensure!(
            &custody.binding.application_purpose == application_access.purpose(),
            "current serving authority differs from authenticated installed binding"
        );
        let application =
            TenantStore::open_existing(node, tenant, application_provider, application_access)
                .await?;
        {
            let _app_access = AccessGuard(&application);
            let _custody_access = AccessGuard(&custody.store);
            application.check_access()?;
            custody.store.check_access()?;
            let app_state = application.state.read();
            let custody_state = custody.store.state.read();
            application.require_access(&app_state)?;
            custody.store.require_access(&custody_state)?;
            validate_distinct_keys(&app_state, &custody_state)?;
            ensure!(
                derive_binding(&application.catalog.read(), &custody.store.catalog.read())?
                    == custody.binding,
                "opened storage domains differ from authenticated installed binding"
            );
        }
        Ok(Arc::new(Self {
            application,
            custody,
        }))
    }

    pub async fn open(
        node: Arc<NodeStore>,
        tenant: String,
        application_provider: Arc<dyn KeyProvider>,
        custody_provider: Arc<dyn KeyProvider>,
        application_access: StorageAccess,
    ) -> Result<Arc<Self>> {
        validate_application_tenant(&tenant)?;
        application_access.validate_tenant(&tenant)?;
        // For an installed generation, authenticate the purpose/catalog binding
        // using only the independent custody provider before even constructing
        // application keys. Wrapped application metadata alone is not authority.
        if CustodyStore::catalog_installed(&node, &tenant)? {
            let custody =
                CustodyStore::open(node.clone(), tenant.clone(), custody_provider).await?;
            ensure!(
                &custody.binding.application_purpose == application_access.purpose(),
                "current serving authority differs from authenticated installed binding"
            );
            let application =
                TenantStore::open(node, tenant, application_provider, application_access).await?;
            return Ok(Arc::new(Self {
                application,
                custody,
            }));
        }
        let application = TenantStore::open(
            node.clone(),
            tenant.clone(),
            application_provider,
            application_access,
        )
        .await?;
        let custody = TenantStore::open(
            node,
            CustodyStore::catalog_name(&tenant),
            custody_provider,
            StorageAccess::custody(&tenant),
        )
        .await?;
        Self::install(application, custody)
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
    pub async fn open_fixture(
        node: Arc<NodeStore>,
        tenant: String,
        application_provider: Arc<dyn KeyProvider>,
        custody_provider: Arc<dyn KeyProvider>,
    ) -> Result<Arc<Self>> {
        let access = StorageAccess::fixture_for(&tenant);
        Self::open(node, tenant, application_provider, custody_provider, access).await
    }

    /// Trusted installation boundary, useful for explicitly clocked embeddings.
    /// Existing bindings are immutable; these are not caller-selected namespaces.
    pub fn install(application: Arc<TenantStore>, custody: Arc<TenantStore>) -> Result<Arc<Self>> {
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
                serde_json::from_slice::<StorageBinding>(&saved)? == binding,
                "installed storage domain binding differs"
            );
        } else {
            let mut tx = application.node.db.begin_write()?;
            tx.set_durability(Durability::Immediate)?;
            tx.set_two_phase_commit(true);
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
        let mut tx = application.node.db.begin_write()?;
        tx.set_durability(Durability::Immediate)?;
        tx.set_two_phase_commit(true);
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
    tx: &redb::WriteTransaction,
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
