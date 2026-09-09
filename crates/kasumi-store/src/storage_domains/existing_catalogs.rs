//! Existing catalog opens own new handles provisionally and borrow live handles.
//! No existing-state acquisition generates a key or installs missing metadata.
use super::*;
use tokio::sync::{Notify, OwnedMutexGuard, oneshot};

type Slot = OwnedMutexGuard<Weak<TenantStore>>;
type Application = (Arc<dyn KeyProvider>, StorageAccess);
pub(super) enum Opened {
    Custody(Arc<CustodyStore>),
    Pair(Arc<TenantStorageSet>),
}
impl Opened {
    fn check(&self) -> Result<()> {
        match self {
            Self::Custody(value) => value.store.check_access(),
            Self::Pair(value) => value.check_access(),
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Ownership {
    New,
    Borrowed,
}
struct Held {
    store: Arc<TenantStore>,
    ownership: Ownership,
}
impl Held {
    async fn prepare(&self, ready: watch::Receiver<bool>) -> Result<()> {
        if self.ownership == Ownership::New {
            self.store.refresh_lease().await?;
            TenantStore::prepare_renewal(&self.store, ready).await;
        }
        self.store.check_access()
    }
    async fn close_unpublished(&self) {
        if self.ownership == Ownership::New {
            self.store.shutdown().await;
        }
    }
}
struct Prepared {
    value: Opened,
    custody: Held,
    application: Option<Held>,
    custody_slot: Slot,
    application_slot: Option<Slot>,
    custody_weak: Weak<TenantStore>,
    application_weak: Option<Weak<TenantStore>>,
    activate: watch::Sender<bool>,
}
struct Handoff {
    prepared: Mutex<Option<Prepared>>,
    decided: Notify,
}
struct Ticket(Arc<Handoff>);
impl Drop for Ticket {
    fn drop(&mut self) {
        self.0.decided.notify_one();
    }
}
impl Ticket {
    fn claim(self) -> Result<Opened> {
        let mut pending = self.0.prepared.lock();
        let candidate = pending
            .as_ref()
            .context("existing catalog ticket consumed")?;
        let binding = validate(
            &candidate.custody.store,
            candidate.application.as_ref().map(|held| &held.store),
            match &candidate.value {
                Opened::Custody(value) => value.binding.tenant(),
                Opened::Pair(value) => value.custody.binding.tenant(),
            },
        )?;
        let expected = match &candidate.value {
            Opened::Custody(value) => &value.binding,
            Opened::Pair(value) => &value.custody.binding,
        };
        ensure!(
            &binding == expected,
            "existing binding changed before handoff"
        );
        candidate.value.check()?;
        let mut prepared = pending
            .take()
            .expect("checked private existing catalog ticket");
        // Borrowed slots are never changed. Weak handles and dormant workers were
        // prepared before delivery; no await/allocation/failure follows publication.
        if prepared.custody.ownership == Ownership::New {
            *prepared.custody_slot = prepared.custody_weak;
        }
        if let (Some(application), Some(slot), Some(weak)) = (
            &prepared.application,
            &mut prepared.application_slot,
            prepared.application_weak,
        ) {
            if application.ownership == Ownership::New {
                **slot = weak;
            }
        }
        prepared.activate.send_replace(true);
        Ok(prepared.value)
    }
}

pub(super) async fn open(
    node: Arc<NodeStore>,
    tenant: String,
    custody_provider: Arc<dyn KeyProvider>,
    application: Option<Application>,
) -> Result<Opened> {
    validate_application_tenant(&tenant)?;
    if let Some((_, access)) = &application {
        access.validate_tenant(&tenant)?;
    }
    let (send, receive) = oneshot::channel();
    let mut tasks = node.initializers.lock().await;
    tasks.reap_finished().await?;
    let owner = node.clone();
    tasks.handles.push(tokio::spawn(async move {
        match prepare(owner, tenant, custody_provider, application, &send).await {
            Err(error) => {
                let _ = send.send(Err(error));
            }
            Ok(prepared) => deliver(prepared, send).await,
        }
    }));
    drop(tasks);
    receive
        .await
        .context("existing catalog owner stopped")??
        .claim()
}

async fn deliver(prepared: Prepared, send: oneshot::Sender<Result<Ticket>>) {
    let handoff = Arc::new(Handoff {
        prepared: Mutex::new(Some(prepared)),
        decided: Notify::new(),
    });
    let _ = send.send(Ok(Ticket(handoff.clone())));
    handoff.decided.notified().await;
    let abandoned = handoff.prepared.lock().take();
    if let Some(prepared) = abandoned {
        if let Some(application) = &prepared.application {
            application.close_unpublished().await;
        }
        prepared.custody.close_unpublished().await;
        // Every relevant open gate remains held until only our new workers drain.
        drop(prepared);
    }
}

async fn select(
    node: Arc<NodeStore>,
    tenant: String,
    provider: Arc<dyn KeyProvider>,
    access: StorageAccess,
    slot: &Slot,
) -> Result<Held> {
    access.validate_tenant(&tenant)?;
    let catalog = node
        .catalog(&tenant)?
        .context("existing tenant catalog absent")?;
    ensure!(
        &catalog.purpose == access.purpose(),
        "existing catalog storage purpose differs"
    );
    if let Some(existing) = slot.upgrade() {
        ensure!(
            existing.access.purpose() == access.purpose(),
            "cached storage purpose differs"
        );
        if existing.shutdown_requested.load(Ordering::Acquire) {
            // Observe completed prior shutdown; never initiate shutdown of an old
            // handle on behalf of this new opener. The mutex waits for an already
            // running shutdown to finish its registered workers.
            ensure!(
                existing.background.lock().await.handles.is_empty(),
                "prior cached owner has not drained"
            );
        } else {
            match (existing.access.serving_gate(), access.serving_gate()) {
                (Some(old), Some(new)) => ensure!(
                    Arc::ptr_eq(old, new),
                    "live store belongs to another serving capability"
                ),
                (None, None) => {}
                _ => anyhow::bail!("live store serving capability differs"),
            }
            match (existing.access.lifecycle_gate(), access.lifecycle_gate()) {
                (Some(old), Some(new)) => ensure!(
                    Arc::ptr_eq(old, new),
                    "live store belongs to another lifecycle capability"
                ),
                (None, None) => {}
                _ => anyhow::bail!("live store lifecycle capability differs"),
            }
            ensure!(
                *existing.catalog.read() == catalog,
                "cached catalog differs from existing storage"
            );
            existing.check_access()?;
            return Ok(Held {
                store: existing,
                ownership: Ownership::Borrowed,
            });
        }
    }
    Ok(Held {
        store: TenantStore::unpublished(
            node,
            tenant,
            provider,
            access,
            Arc::new(SystemLeaseClock),
            catalog,
        ),
        ownership: Ownership::New,
    })
}

async fn prepare(
    node: Arc<NodeStore>,
    tenant: String,
    custody_provider: Arc<dyn KeyProvider>,
    application_input: Option<Application>,
    receiver: &oneshot::Sender<Result<Ticket>>,
) -> Result<Prepared> {
    let custody_name = CustodyStore::catalog_name(&tenant);
    let (custody_gate, application_gate) = {
        let mut registry = node.tenants.lock().await;
        let custody = registry.entry(custody_name.clone()).or_default().clone();
        let application = application_input
            .as_ref()
            .map(|_| registry.entry(tenant.clone()).or_default().clone());
        (custody, application)
    };
    let custody_slot = custody_gate.lock_owned().await;
    let application_slot = match application_gate {
        Some(gate) => Some(gate.lock_owned().await),
        None => None,
    };
    ensure!(!receiver.is_closed(), "existing catalog receiver closed");
    let custody = select(
        node.clone(),
        custody_name,
        custody_provider,
        StorageAccess::custody(&tenant),
        &custody_slot,
    )
    .await?;
    let mut application = None;
    let (activate, ready) = watch::channel(false);
    let result = async {
        custody.prepare(ready.clone()).await?;
        // Authenticate the installed relationship before constructing application
        // keys. Both raw catalog records and the binding come from one read root.
        let binding = validate(&custody.store, None, &tenant)?;
        ensure!(!receiver.is_closed(), "existing catalog receiver closed");
        let value = match application_input {
            None => Opened::Custody(Arc::new(CustodyStore {
                store: custody.store.clone(),
                binding,
            })),
            Some((provider, access)) => {
                ensure!(
                    &binding.application_purpose == access.purpose(),
                    "serving authority differs from authenticated binding"
                );
                let held = select(
                    node,
                    tenant.clone(),
                    provider,
                    access,
                    application_slot.as_ref().expect("pair application gate"),
                )
                .await?;
                application = Some(held);
                let held = application.as_ref().expect("selected application");
                held.prepare(ready).await?;
                let binding = validate(&custody.store, Some(&held.store), &tenant)?;
                Opened::Pair(Arc::new(TenantStorageSet {
                    application: held.store.clone(),
                    custody: Arc::new(CustodyStore {
                        store: custody.store.clone(),
                        binding,
                    }),
                }))
            }
        };
        ensure!(!receiver.is_closed(), "existing catalog receiver closed");
        value.check()?;
        Ok::<_, anyhow::Error>(value)
    }
    .await;
    match result {
        Ok(value) => {
            let custody_weak = Arc::downgrade(&custody.store);
            let application_weak = application.as_ref().map(|held| Arc::downgrade(&held.store));
            Ok(Prepared {
                value,
                custody,
                application,
                custody_slot,
                application_slot,
                custody_weak,
                application_weak,
                activate,
            })
        }
        Err(error) => {
            if let Some(application) = &application {
                application.close_unpublished().await;
            }
            custody.close_unpublished().await;
            Err(error)
        }
    }
}

fn validate(
    custody: &Arc<TenantStore>,
    application: Option<&Arc<TenantStore>>,
    tenant: &str,
) -> Result<StorageBinding> {
    // Match all installed domain mutations: application first, custody second.
    let _application_mutation = application.map(|store| store.mutations.lock());
    let _custody_mutation = custody.mutations.lock();
    let view = custody.read_view()?;
    let app_catalog = view
        .catalog(tenant)?
        .context("existing application catalog absent")?;
    let custody_catalog = view
        .catalog(&CustodyStore::catalog_name(tenant))?
        .context("existing custody catalog absent")?;
    ensure!(
        *custody.catalog.read() == custody_catalog,
        "custody cache differs from installed catalog"
    );
    let binding = derive_binding(&app_catalog, &custody_catalog)?;
    let bytes = view
        .get(BINDING_NS, BINDING_KEY, MAX_KEY_CATALOG_BYTES)?
        .context("existing storage domain binding absent")?;
    ensure!(
        serde_json::from_slice::<StorageBinding>(&bytes)? == binding,
        "existing storage domain binding differs"
    );
    if let Some(application) = application {
        ensure!(
            *application.catalog.read() == app_catalog,
            "application cache differs from installed catalog"
        );
        application.check_access()?;
        let application_state = application.state.read();
        let custody_state = custody.state.read();
        application.require_access(&application_state)?;
        custody.require_access(&custody_state)?;
        validate_distinct_keys(&application_state, &custody_state)?;
    }
    custody.check_access()?;
    Ok(binding)
}

#[cfg(test)]
mod tests;
