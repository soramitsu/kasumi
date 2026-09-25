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
    outcome: Mutex<Option<Result<Prepared>>>,
    decided: Notify,
}

/// This private ticket is not a store handle. A successful channel send does
/// not commit ownership: even a ticket dropped while buffered wakes its owner.
struct Ticket(Arc<Handoff>);

impl Ticket {
    fn claim(self) -> Result<Arc<TenantStorageSet>> {
        let mut pending = self.0.outcome.lock();
        match pending
            .as_ref()
            .context("catalog initialization handoff already consumed")?
        {
            Ok(candidate) => candidate.stores.check_access()?,
            Err(_) => {
                let Some(Err(error)) = pending.take() else {
                    unreachable!("checked private catalog error ticket")
                };
                return Err(error);
            }
        }
        let Some(Ok(Prepared {
            stores,
            mut application_slot,
            mut custody_slot,
            application_weak,
            custody_weak,
            activate,
        })) = pending.take()
        else {
            unreachable!("checked prepared catalog handoff")
        };
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
            .context("catalog initializer stopped")?
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
        while let Some(task) = tasks.handles.last_mut() {
            let result = task.await;
            tasks.handles.pop();
            if let Err(error) = result
                .context("catalog initializer task join failed")
                .and_then(|outcome| outcome)
            {
                tasks.failure.get_or_insert(error);
            }
        }
        tasks.take_failure()
    }
}

async fn begin(input: Input) -> Result<oneshot::Receiver<Ticket>> {
    validate_application_tenant(&input.tenant)?;
    input.application_access.validate_tenant(&input.tenant)?;
    input.application_access.check()?;
    let (send, receive) = oneshot::channel();
    let node = input.node.clone();
    let mut tasks = node.initializers.lock().await;
    ensure!(!node.db.is_stopped(), "node catalog admission is closed");
    // Reap only actual terminal tasks, so repeated installation does not retain
    // a lifetime history of JoinHandles. Unfinished owners stay registered.
    tasks.reap_finished().await?;
    tasks.handles.push(tokio::spawn(async move {
        // A buffered preparation error is not observed until the recipient
        // claims its ticket. Abandonment returns it to the node's task registry.
        let outcome = prepare(input, &send).await;
        deliver(outcome, send).await
    }));
    Ok(receive)
}

async fn deliver(outcome: Result<Prepared>, send: oneshot::Sender<Ticket>) -> Result<()> {
    let handoff = Arc::new(Handoff {
        outcome: Mutex::new(Some(outcome)),
        decided: Notify::new(),
    });
    // Drop a rejected/buffered result through Ticket::drop as well.
    let _ = send.send(Ticket(handoff.clone()));
    handoff.decided.notified().await;
    let abandoned = handoff.outcome.lock().take();
    match abandoned {
        Some(Ok(prepared)) => {
            let outcome = prepared.stores.shutdown().await;
            // Open gates remain owned until both new workers are joined.
            drop(prepared);
            outcome?;
        }
        Some(Err(error)) => return Err(error),
        None => {}
    }
    Ok(())
}

async fn prepare(input: Input, receiver: &oneshot::Sender<Ticket>) -> Result<Prepared> {
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
            let mut report = DrainReport::default();
            for store in [&application, &custody] {
                if let Err(failure) = store.shutdown().await {
                    report.merge(&failure);
                }
            }
            Err(match report.complete() {
                Ok(()) => error,
                Err(failure) => error.context(failure),
            })
        }
    }
}

fn require_pristine(node: &NodeStore, tenants: [&str; 2]) -> Result<()> {
    #[cfg(any(test, feature = "test-utils"))]
    if node.db.has_fixture_direct_database() {
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
        return Ok(());
    }
    node.with_registered_read(|reader| {
        for tenant in tenants {
            let hash = tenant_hash(tenant);
            ensure!(!reader.catalog_exists(hash)?, "catalog already initialized");
            ensure!(
                !reader.record_prefix_exists(&hash)?,
                "new catalog has orphan physical rows"
            );
        }
        Ok(())
    })
}

fn save_new_catalogs(application: &Arc<TenantStore>, custody: &Arc<TenantStore>) -> Result<()> {
    application.access.check()?;
    custody.access.check()?;
    let application_catalog = application.catalog.read();
    let custody_catalog = custody.catalog.read();
    application_catalog.validate(&application.tenant)?;
    custody_catalog.validate(&custody.tenant)?;
    #[cfg(any(test, feature = "test-utils"))]
    if application.node.db.has_fixture_direct_database() {
        let bytes = [
            serde_json::to_vec(&*application_catalog)?,
            serde_json::to_vec(&*custody_catalog)?,
        ];
        let tx = application.node.db.begin_write()?;
        {
            let mut catalogs = tx.open_table(CATALOG)?;
            let records = tx.open_table(RECORDS)?;
            // Synthetic direct-database fixtures keep the original transaction.
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
        return custody.access.check();
    }

    let provider = application.node.persistent_disk().memory().clone();
    let plan = crate::storage_opening::write_plan::AdmittedCatalogPairPut::prepare(
        &application.tenant,
        &application_catalog,
        &custody.tenant,
        &custody_catalog,
        provider.clone(),
    )?;
    drop(application_catalog);
    drop(custody_catalog);
    application.access.check()?;
    custody.access.check()?;
    let writer = application.node.db.queue_registered_catalog_pair_put(
        plan,
        application.clone(),
        custody.clone(),
    )?;
    let _ = writer.run();
    let (committed, rejection) = {
        let report = writer.report();
        (
            report.committed_and_disposed(),
            report.clean_freshness_rejection(),
        )
    };
    if !committed && rejection.is_none() {
        return Err(NodeCatalogWriteFailure { writer }.into());
    }
    let id = writer.id();
    let disposition = writer.retire();
    if disposition != StorageCensusDisposition::Retired {
        return Err(NodeCatalogWriteRetirement {
            provider,
            id,
            disposition,
        }
        .into());
    }
    if let Some(message) = rejection {
        anyhow::bail!(message);
    }
    application.access.check()?;
    custody.access.check()
}

#[cfg(test)]
mod tests;
