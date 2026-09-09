//! Fresh catalog installation owns unpublished stores until synchronous handoff.
//! Existing composite opens have a different borrowed-owner contract and do not
//! use this path. Incomplete disk installation is never adopted by retrying it.
use super::*;
use tokio::sync::{Notify, OwnedMutexGuard, oneshot};

type Slot = OwnedMutexGuard<Weak<TenantStore>>;

struct Input {
    node: Arc<NodeStore>,
    tenant: String,
    application_provider: Arc<dyn KeyProvider>,
    custody_provider: Arc<dyn KeyProvider>,
    application_access: StorageAccess,
}

struct Prepared {
    stores: Arc<TenantStorageSet>,
    application_slot: Slot,
    custody_slot: Slot,
    application_weak: Weak<TenantStore>,
    custody_weak: Weak<TenantStore>,
    activate: watch::Sender<bool>,
}

struct Handoff {
    prepared: Mutex<Option<Prepared>>,
    decided: Notify,
}

/// This private ticket is not a store handle. A successful channel send does
/// not commit ownership: even a ticket dropped while buffered wakes its owner.
struct Ticket(Arc<Handoff>);

impl Ticket {
    fn claim(self) -> Result<Arc<TenantStorageSet>> {
        let mut pending = self.0.prepared.lock();
        pending
            .as_ref()
            .context("catalog initialization handoff already consumed")?
            .stores
            .check_access()?;
        let Prepared {
            stores,
            mut application_slot,
            mut custody_slot,
            application_weak,
            custody_weak,
            activate,
        } = pending.take().expect("checked prepared catalog handoff");
        // No await, allocation or fallible operation from the first publication
        // through returned-handle ownership. Both gates remain held throughout.
        *custody_slot = custody_weak;
        *application_slot = application_weak;
        activate.send_replace(true);
        drop(application_slot);
        drop(custody_slot);
        Ok(stores)
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        self.0.decided.notify_one();
    }
}

impl TenantStorageSet {
    /// Install a genuinely new application/custody pair. Existing catalogs,
    /// cached owners and orphan physical rows are rejected before key calls or
    /// writes. Failed or cancelled installation can leave authenticated disk
    /// metadata; retry must not silently adopt it as a new installation.
    ///
    /// The node retains preparation/cleanup tasks. After cancelling this future,
    /// call `NodeStore::drain_initializers` before releasing the node. Once this
    /// future returns Ready, its returned handles have ordinary runtime ownership;
    /// dropping a returned result does not undo publication or stop shared stores.
    pub async fn initialize_catalogs(
        node: Arc<NodeStore>,
        tenant: String,
        application_provider: Arc<dyn KeyProvider>,
        custody_provider: Arc<dyn KeyProvider>,
        application_access: StorageAccess,
    ) -> Result<Arc<Self>> {
        let receive = begin(Input {
            node,
            tenant,
            application_provider,
            custody_provider,
            application_access,
        })
        .await?;
        // There is deliberately no yield from receiving the private ticket to
        // claiming and returning the public pair. Cancellation before receiving
        // (including an already buffered ticket) remains unpublished cleanup.
        receive
            .await
            .context("catalog initializer stopped")??
            .claim()
    }
}

impl NodeStore {
    /// Join registered catalog initializers, including cleanup after a cancelled
    /// result receiver. This does not shut down committed/shared tenant stores.
    /// Stop admitting new initialization calls before using this as a final node
    /// drain. Cancellation of this drain retains every unfinished task handle.
    pub async fn drain_initializers(&self) -> Result<()> {
        let mut tasks = self.initializers.lock().await;
        let mut failure = None;
        while let Some(task) = tasks.last_mut() {
            let result = task.await;
            tasks.pop();
            if let Err(error) = result {
                failure.get_or_insert_with(|| anyhow::Error::new(error));
            }
        }
        match failure {
            Some(error) => Err(error.context("catalog initializer task failed")),
            None => Ok(()),
        }
    }
}

async fn begin(input: Input) -> Result<oneshot::Receiver<Result<Ticket>>> {
    validate_application_tenant(&input.tenant)?;
    input.application_access.validate_tenant(&input.tenant)?;
    input.application_access.check()?;
    let (send, receive) = oneshot::channel();
    let node = input.node.clone();
    let mut tasks = node.initializers.lock().await;
    // Reap only actual terminal tasks, so repeated installation does not retain
    // a lifetime history of JoinHandles. Unfinished owners stay registered.
    while let Some(index) = tasks.iter().position(tokio::task::JoinHandle::is_finished) {
        let result = (&mut tasks[index]).await;
        drop(tasks.swap_remove(index));
        result.context("prior catalog initializer task failed")?;
    }
    tasks.push(tokio::spawn(async move {
        match prepare(input, &send).await {
            Err(error) => {
                let _ = send.send(Err(error));
            }
            Ok(prepared) => deliver(prepared, send).await,
        }
    }));
    Ok(receive)
}

async fn deliver(prepared: Prepared, send: oneshot::Sender<Result<Ticket>>) {
    let handoff = Arc::new(Handoff {
        prepared: Mutex::new(Some(prepared)),
        decided: Notify::new(),
    });
    // Drop a rejected/buffered result through Ticket::drop as well.
    let _ = send.send(Ok(Ticket(handoff.clone())));
    handoff.decided.notified().await;
    let abandoned = handoff.prepared.lock().take();
    if let Some(prepared) = abandoned {
        prepared.stores.application.shutdown().await;
        prepared.stores.custody.store.shutdown().await;
        // Open gates remain owned until both new workers are joined.
        drop(prepared);
    }
}

async fn prepare(input: Input, receiver: &oneshot::Sender<Result<Ticket>>) -> Result<Prepared> {
    let Input {
        node,
        tenant,
        application_provider,
        custody_provider,
        application_access,
    } = input;
    let custody_name = CustodyStore::catalog_name(&tenant);
    let (custody_gate, application_gate) = {
        let mut registry = node.tenants.lock().await;
        let custody = registry.entry(custody_name.clone()).or_default().clone();
        let application = registry.entry(tenant.clone()).or_default().clone();
        (custody, application)
    };
    // Match existing composite opens: custody first, application second. Never
    // hold the node registry across per-domain waits or provider calls.
    let custody_slot = custody_gate.lock_owned().await;
    let application_slot = application_gate.lock_owned().await;
    ensure!(
        custody_slot.upgrade().is_none() && application_slot.upgrade().is_none(),
        "new catalog installation conflicts with a live storage owner"
    );
    require_pristine(&node, [&tenant, &custody_name])?;
    ensure!(
        !receiver.is_closed(),
        "catalog initialization receiver closed"
    );
    let custody_access = StorageAccess::custody(&tenant);
    let application_catalog =
        TenantStore::generate_catalog(&tenant, &application_provider, &application_access).await?;
    ensure!(
        !receiver.is_closed(),
        "catalog initialization receiver closed"
    );
    let custody_catalog =
        TenantStore::generate_catalog(&custody_name, &custody_provider, &custody_access).await?;
    ensure!(
        !receiver.is_closed(),
        "catalog initialization receiver closed"
    );
    application_access.check()?;
    let application = TenantStore::unpublished(
        node.clone(),
        tenant,
        application_provider,
        application_access,
        Arc::new(SystemLeaseClock),
        application_catalog,
    );
    let custody = TenantStore::unpublished(
        node,
        custody_name,
        custody_provider,
        custody_access,
        Arc::new(SystemLeaseClock),
        custody_catalog,
    );
    let prepared = async {
        let app = application.clone();
        let control = custody.clone();
        tokio::task::spawn_blocking(move || save_new_catalogs(&app, &control))
            .await
            .context("catalog publication worker failed")??;
        application.refresh_lease().await?;
        custody.refresh_lease().await?;
        ensure!(
            !receiver.is_closed(),
            "catalog initialization receiver closed"
        );
        let app = application.clone();
        let control = custody.clone();
        let stores = tokio::task::spawn_blocking(move || TenantStorageSet::install(app, control))
            .await
            .context("catalog binding worker failed")??;
        let (activate, ready) = watch::channel(false);
        TenantStore::prepare_renewal(&application, ready.clone()).await;
        TenantStore::prepare_renewal(&custody, ready).await;
        stores.check_access()?;
        Ok::<_, anyhow::Error>((stores, activate))
    }
    .await;
    match prepared {
        Ok((stores, activate)) => Ok(Prepared {
            stores,
            application_slot,
            custody_slot,
            application_weak: Arc::downgrade(&application),
            custody_weak: Arc::downgrade(&custody),
            activate,
        }),
        Err(error) => {
            application.shutdown().await;
            custody.shutdown().await;
            Err(error)
        }
    }
}

fn require_pristine(node: &NodeStore, tenants: [&str; 2]) -> Result<()> {
    let tx = node.db.begin_read()?;
    let catalogs = tx.open_table(CATALOG)?;
    let records = tx.open_table(RECORDS)?;
    for tenant in tenants {
        let hash = tenant_hash(tenant);
        ensure!(
            catalogs.get(hash.as_slice())?.is_none(),
            "catalog already initialized"
        );
        if let Some(row) = records.range(hash.as_slice()..)?.next() {
            let (key, _) = row?;
            ensure!(
                !key.value().starts_with(&hash),
                "new catalog has orphan physical rows"
            );
        }
    }
    Ok(())
}

fn save_new_catalogs(application: &TenantStore, custody: &TenantStore) -> Result<()> {
    application.access.check()?;
    custody.access.check()?;
    let application_catalog = application.catalog.read();
    let custody_catalog = custody.catalog.read();
    application_catalog.validate(&application.tenant)?;
    custody_catalog.validate(&custody.tenant)?;
    let bytes = [
        serde_json::to_vec(&*application_catalog)?,
        serde_json::to_vec(&*custody_catalog)?,
    ];
    let mut tx = application.node.db.begin_write()?;
    tx.set_durability(Durability::Immediate)?;
    tx.set_two_phase_commit(true);
    {
        let mut catalogs = tx.open_table(CATALOG)?;
        let records = tx.open_table(RECORDS)?;
        // Recheck under the actual publication transaction. No unknown record
        // or partial catalog can be overwritten by this fresh-only operation.
        for (tenant, bytes) in [
            (&application.tenant, &bytes[0]),
            (&custody.tenant, &bytes[1]),
        ] {
            let hash = tenant_hash(tenant);
            ensure!(
                catalogs.get(hash.as_slice())?.is_none(),
                "catalog already initialized"
            );
            if let Some(row) = records.range(hash.as_slice()..)?.next() {
                let (key, _) = row?;
                ensure!(
                    !key.value().starts_with(&hash),
                    "new catalog has orphan physical rows"
                );
            }
            catalogs.insert(hash.as_slice(), bytes.as_slice())?;
        }
    }
    application.access.check()?;
    custody.access.check()?;
    tx.commit()
        .context("catalog pair initialization outcome may be unknown")?;
    application.access.check()?;
    custody.access.check()
}

#[cfg(test)]
mod tests;
