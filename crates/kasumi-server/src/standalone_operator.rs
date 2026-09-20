//! Exclusive stopped-installation ownership shared by every local operator.
use super::*;
use crate::startup_resources::Resources;

/// Resource-bearing fields precede the scope that retains the installation lock.
/// Public operations execute in the LocalOperator registry; this owner never
/// escapes into an unregistered caller while acquisition or cleanup is pending.
pub(crate) struct OperatorState {
    pub(crate) config: RuntimeConfig,
    pub(crate) node: Arc<NodeStore>,
    pub(crate) audit: Arc<kasumi_engine::SecurityAudit>,
    pub(crate) credentials: Arc<LocalCredentials>,
    control: tokio::sync::Mutex<Option<Arc<kasumi_engine::Database>>>,
    resources: tokio::sync::Mutex<Resources>,
}
impl OperatorState {
    pub(crate) async fn open(config: &RuntimeConfig) -> Result<Self> {
        let mut pending = Resources::default();
        let opened = async {
            config.validate()?;
            let persistent_disk = crate::persistent_disk::open(&config.persistent_disk)?;
            pending.standalone_lock = Some(
                claim(config, &persistent_disk)?.context("operator requires standalone mode")?,
            );
            let AuthKeySource::Local { signer_file } = &config.auth.source else {
                anyhow::bail!("operator requires a local issuer");
            };
            let node = NodeStore::open_existing(
                &config.database_path,
                config.database_id,
                persistent_disk,
                kasumi_store::ScratchDisk::open(config.scratch_disk.clone())?,
            )?;
            pending.owned_nodes.push(node.clone());
            #[cfg(test)]
            super::ownership_tests::checkpoint(&config.database_path, "node").await?;
            let store = TenantStore::open_existing(
                node.clone(),
                kasumi_engine::SECURITY_TENANT.into(),
                config
                    .security_audit
                    .keys
                    .provider(Arc::new(crate::runtime::file_secret))?,
                StorageAccess::security_audit(),
            )
            .await?;
            pending.stores.push(store.clone());
            let admission = kasumi_engine::admission::NodeAdmission::new(config.admission.clone())?;
            pending.owned_admissions.push(admission.clone());
            let audit = config.security_audit.open(store.clone(), admission)?;
            pending.audits.push(audit.clone());
            crate::node_enrollment::require_complete(
                audit.store(),
                config.database_id,
                crate::node_enrollment::Kind::Data,
            )?;
            #[cfg(test)]
            super::ownership_tests::checkpoint(&config.database_path, "audit").await?;
            let credentials = LocalCredentials::open(
                store,
                signer_file.clone(),
                config.auth.issuer.clone(),
                config.auth.audience.clone(),
            )?;
            Ok::<_, anyhow::Error>((node, audit, credentials))
        }
        .await;
        match opened {
            Ok((node, audit, credentials)) => Ok(Self {
                config: config.clone(),
                node,
                audit,
                credentials,
                control: tokio::sync::Mutex::new(None),
                resources: tokio::sync::Mutex::new(pending),
            }),
            Err(error) => finish_resources(&mut pending, Err(error)).await,
        }
    }
    pub(crate) fn retain_node(&self, node: Arc<NodeStore>) {
        self.resources
            .try_lock()
            .expect("exclusive operator acquisition")
            .owned_nodes
            .push(node);
    }
    pub(crate) fn retain_stores(&self, stores: &kasumi_store::TenantStorageSet) {
        let mut resources = self
            .resources
            .try_lock()
            .expect("exclusive operator acquisition");
        resources.stores.push(stores.application().clone());
        resources.stores.push(stores.custody().store().clone());
    }
    pub(crate) fn retain_database(&self, database: Arc<kasumi_engine::Database>) {
        self.resources
            .try_lock()
            .expect("exclusive operator acquisition")
            .databases
            .push(database);
    }
    pub(crate) async fn control(&self) -> Result<Arc<kasumi_engine::Database>> {
        let mut control = self.control.lock().await;
        if let Some(database) = control.as_ref() {
            return Ok(database.clone());
        }
        let config = &self.config;
        let source = Arc::new(crate::runtime::file_secret);
        let stores = kasumi_store::TenantStorageSet::open_existing(
            self.node.clone(),
            crate::runtime::CONTROL_TENANT.into(),
            config.control.keys.provider(source.clone())?,
            config.control.custody_keys.provider(source)?,
            StorageAccess::node_control(),
        )
        .await?;
        self.retain_stores(&stores);
        #[cfg(test)]
        super::ownership_tests::checkpoint(&config.database_path, "control-pair").await?;
        config.install_tenant_audit_archive(stores.application(), None)?;
        let database = kasumi_engine::open_existing_local(
            stores,
            self.audit.clone(),
            Uuid::parse_str(
                config
                    .control
                    .incarnation
                    .as_deref()
                    .context("control incarnation missing")?,
            )?,
        )
        .await?;
        self.retain_database(database.clone());
        *control = Some(database.clone());
        Ok(database)
    }
    pub(crate) async fn finish<T>(&mut self, outcome: Result<T>) -> Result<T> {
        combine(outcome, crate::startup_owner::finish(self).await)
    }
}
impl crate::startup_owner::Runtime for OperatorState {
    fn close(
        &mut self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = kasumi_types::drain::DrainResult> + Send + '_>,
    > {
        Box::pin(async { self.resources.lock().await.close().await })
    }
}

pub(super) fn combine<T>(outcome: Result<T>, drained: Result<()>) -> Result<T> {
    match (outcome, drained) {
        (Err(error), Err(drain)) => {
            Err(error.context(format!("local operator drain failed: {drain:#}")))
        }
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(drain)) => Err(drain),
        (Ok(value), Ok(())) => Ok(value),
    }
}
pub(super) async fn finish_resources<T>(
    resources: &mut Resources,
    outcome: Result<T>,
) -> Result<T> {
    let drained = crate::startup_owner::finish(resources).await;
    combine(outcome, drained)
}

struct Drained<T: Send + 'static>(T);
impl<T: Send + 'static> crate::startup_owner::Runtime for Drained<T> {
    fn close(
        &mut self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = kasumi_types::drain::DrainResult> + Send + '_>,
    > {
        Box::pin(async { Ok(()) })
    }
}
/// Only values produced after physical work drains may enter this handoff.
pub(super) async fn run<T: Send + 'static>(
    operation: impl std::future::Future<Output = Result<T>> + Send + 'static,
) -> Result<T> {
    Ok(
        crate::startup_owner::open(crate::startup_owner::Kind::LocalOperator, async move {
            operation.await.map(Drained)
        })
        .await?
        .0,
    )
}
