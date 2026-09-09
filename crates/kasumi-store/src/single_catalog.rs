//! Explicit singleton installation and strict reopening. Application/custody
//! domains use their private paired owners, never this production entry point.
use super::*;
use tokio::sync::{Notify, OwnedMutexGuard, oneshot};

type Slot = OwnedMutexGuard<Weak<TenantStore>>;

#[derive(Clone, Copy)]
enum Mode {
    Initialize,
    Existing,
}

struct Input {
    node: Arc<NodeStore>,
    tenant: String,
    provider: Arc<dyn KeyProvider>,
    access: StorageAccess,
    clock: Arc<dyn LeaseClock>,
    renew: bool,
    mode: Mode,
}

impl TenantStore {
    /// Install an absent singleton catalog under explicit local installation
    /// ownership. Existing catalogs, live owners and orphan rows are errors.
    /// Cancellation may leave an incomplete installation on disk; it never
    /// authorizes retry to adopt that catalog. Retain the node and drain its
    /// initializers before releasing physical installation ownership.
    pub async fn initialize_catalog(
        node: Arc<NodeStore>,
        tenant: String,
        provider: Arc<dyn KeyProvider>,
        access: StorageAccess,
    ) -> Result<Arc<Self>> {
        require_singleton(&access)?;
        open(Input {
            node,
            tenant,
            provider,
            access,
            clock: Arc::new(SystemLeaseClock),
            renew: true,
            mode: Mode::Initialize,
        })
        .await
    }

    /// Open only an installed singleton. This never generates keys or repairs
    /// absent metadata. A matching cached owner is borrowed without refreshing
    /// its original provider, clock or capability. The caller retains the node
    /// through acknowledged handoff or completed initializer drain.
    pub async fn open_existing(
        node: Arc<NodeStore>,
        tenant: String,
        provider: Arc<dyn KeyProvider>,
        access: StorageAccess,
    ) -> Result<Arc<Self>> {
        require_singleton(&access)?;
        open(Input {
            node,
            tenant,
            provider,
            access,
            clock: Arc::new(SystemLeaseClock),
            renew: true,
            mode: Mode::Existing,
        })
        .await
    }
}

fn require_singleton(access: &StorageAccess) -> Result<()> {
    ensure!(
        matches!(
            access.purpose(),
            StoragePurpose::SecurityAudit
                | StoragePurpose::LiveSignerTrust { .. }
                | StoragePurpose::TargetJournal { .. }
        ),
        "application and custody catalogs require their paired storage owner"
    );
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Ownership {
    New,
    Borrowed,
}

struct Prepared {
    store: Arc<TenantStore>,
    slot: Slot,
    weak: Weak<TenantStore>,
    ownership: Ownership,
    activate: watch::Sender<bool>,
}

struct Handoff {
    outcome: Mutex<Option<Result<Prepared>>>,
    decided: Notify,
}
struct Ticket(Arc<Handoff>);
impl Drop for Ticket {
    fn drop(&mut self) {
        self.0.decided.notify_one();
    }
}
impl Ticket {
    fn claim(self) -> Result<Arc<TenantStore>> {
        let mut pending = self.0.outcome.lock();
        let prepared = match pending.as_ref().context("singleton ticket consumed")? {
            Ok(prepared) => prepared,
            Err(_) => {
                let Some(Err(error)) = pending.take() else {
                    unreachable!("checked error ticket")
                };
                return Err(error);
            }
        };
        let current = prepared
            .store
            .node
            .catalog(prepared.store.tenant())?
            .context("singleton catalog disappeared before handoff")?;
        ensure!(
            *prepared.store.catalog.read() == current,
            "singleton catalog changed before handoff"
        );
        prepared.store.check_access()?;
        let Some(Ok(mut prepared)) = pending.take() else {
            unreachable!("checked owner ticket")
        };
        // No await, allocation or fallible work after publication. Borrowed
        // owners keep their existing weak slot and all original worker state.
        if prepared.ownership == Ownership::New {
            *prepared.slot = prepared.weak;
            prepared.activate.send_replace(true);
        }
        Ok(prepared.store)
    }
}

async fn open(input: Input) -> Result<Arc<TenantStore>> {
    begin(input)
        .await?
        .await
        .context("singleton initializer stopped")?
        .claim()
}

async fn begin(input: Input) -> Result<oneshot::Receiver<Ticket>> {
    input.access.validate_tenant(&input.tenant)?;
    ensure!(
        !input.tenant.is_empty() && input.tenant.len() <= 1024,
        "invalid tenant identifier"
    );
    let (send, receive) = oneshot::channel();
    let node = input.node.clone();
    let mut tasks = node.initializers.lock().await;
    tasks.reap_finished().await?;
    tasks.handles.push(tokio::spawn(async move {
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
    let _ = send.send(Ticket(handoff.clone()));
    handoff.decided.notified().await;
    let abandoned = handoff.outcome.lock().take();
    match abandoned {
        Some(Ok(prepared)) if prepared.ownership == Ownership::New => {
            prepared.store.shutdown().await;
            // Retain the exact open gate until this new owner's workers join.
            drop(prepared);
        }
        Some(Err(error)) => return Err(error),
        _ => {}
    }
    Ok(())
}

async fn prepare(input: Input, receiver: &oneshot::Sender<Ticket>) -> Result<Prepared> {
    let Input {
        node,
        tenant,
        provider,
        access,
        clock,
        renew,
        mode,
    } = input;
    let gate = node
        .tenants
        .lock()
        .await
        .entry(tenant.clone())
        .or_default()
        .clone();
    let slot = gate.lock_owned().await;
    ensure!(!receiver.is_closed(), "singleton receiver closed");
    access.check()?;
    let catalog = match mode {
        Mode::Initialize => {
            ensure!(
                slot.upgrade().is_none(),
                "catalog initialization conflicts with a live owner"
            );
            require_pristine(&node, &tenant)?;
            TenantStore::generate_catalog(&tenant, &provider, &access).await?
        }
        Mode::Existing => {
            let catalog = node
                .catalog(&tenant)?
                .context("existing singleton catalog absent")?;
            ensure!(
                &catalog.purpose == access.purpose(),
                "existing catalog purpose differs"
            );
            if let Some(existing) = slot.upgrade() {
                ensure!(
                    existing.access.purpose() == access.purpose(),
                    "cached storage purpose differs"
                );
                if existing.shutdown_requested.load(Ordering::Acquire) {
                    // Observe an existing drain; this opener never initiates or
                    // takes over shutdown of somebody else's cached owner.
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
                    let (activate, _) = watch::channel(false);
                    return Ok(Prepared {
                        weak: Arc::downgrade(&existing),
                        store: existing,
                        slot,
                        ownership: Ownership::Borrowed,
                        activate,
                    });
                }
            }
            catalog
        }
    };
    ensure!(!receiver.is_closed(), "singleton receiver closed");
    let store = TenantStore::unpublished(node, tenant, provider, access, clock, catalog);
    let result = async {
        if matches!(mode, Mode::Initialize) {
            let owner = store.clone();
            tokio::task::spawn_blocking(move || save_new_catalog(&owner))
                .await
                .context("singleton catalog publication worker failed")??;
        }
        ensure!(!receiver.is_closed(), "singleton receiver closed");
        store.refresh_lease().await?;
        let (activate, ready) = watch::channel(false);
        if renew {
            TenantStore::prepare_renewal(&store, ready).await;
        }
        ensure!(!receiver.is_closed(), "singleton receiver closed");
        store.check_access()?;
        Ok::<_, anyhow::Error>(activate)
    }
    .await;
    match result {
        Ok(activate) => Ok(Prepared {
            weak: Arc::downgrade(&store),
            store,
            slot,
            ownership: Ownership::New,
            activate,
        }),
        Err(error) => {
            store.shutdown().await;
            Err(error)
        }
    }
}

fn require_pristine(node: &NodeStore, tenant: &str) -> Result<()> {
    let tx = node.db.begin_read()?;
    let hash = tenant_hash(tenant);
    ensure!(
        tx.open_table(CATALOG)?.get(hash.as_slice())?.is_none(),
        "catalog already initialized"
    );
    if let Some(row) = tx.open_table(RECORDS)?.range(hash.as_slice()..)?.next() {
        ensure!(
            !row?.0.value().starts_with(&hash),
            "new catalog has orphan physical rows"
        );
    }
    Ok(())
}

fn save_new_catalog(store: &TenantStore) -> Result<()> {
    store.access.check()?;
    let catalog = store.catalog.read();
    catalog.validate(store.tenant())?;
    let bytes = serde_json::to_vec(&*catalog)?;
    let hash = tenant_hash(store.tenant());
    let mut tx = store.node.db.begin_write()?;
    tx.set_durability(Durability::Immediate)?;
    tx.set_two_phase_commit(true);
    {
        let mut catalogs = tx.open_table(CATALOG)?;
        ensure!(
            catalogs.get(hash.as_slice())?.is_none(),
            "catalog already initialized"
        );
        if let Some(row) = tx.open_table(RECORDS)?.range(hash.as_slice()..)?.next() {
            ensure!(
                !row?.0.value().starts_with(&hash),
                "new catalog has orphan physical rows"
            );
        }
        catalogs.insert(hash.as_slice(), bytes.as_slice())?;
    }
    store.access.check()?;
    tx.commit()
        .context("singleton catalog initialization outcome may be unknown")?;
    store.access.check()
}

#[cfg(any(test, feature = "test-utils"))]
#[path = "single_catalog/fixtures.rs"]
mod fixtures;
#[cfg(test)]
#[path = "single_catalog/tests.rs"]
mod tests;
