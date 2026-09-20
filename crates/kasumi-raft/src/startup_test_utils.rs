//! Fixture-only control over an actual local group's initialization boundary.
//! No runtime configuration enables this gate; the trusted fixture installs it
//! directly on the already admitted snapshot owner before constructing a group.
use crate::SnapshotBufferOwner;
use anyhow::{Result, ensure};
use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicBool, Ordering},
};

pub struct LocalStartupGate {
    pub(crate) entered: tokio::sync::Notify,
    pub(crate) release: tokio::sync::Semaphore,
    // Keep the erased observer boundary: embedding a concrete Raft here would
    // make SnapshotBufferOwner's associated SnapshotData Send proof recursive.
    pub(crate) raft: Mutex<Option<Arc<dyn std::any::Any + Send + Sync>>>,
    pub(crate) ownership: Mutex<Option<Weak<AtomicBool>>>,
    pub(crate) router: Mutex<Option<Weak<dyn Send + Sync>>>,
    error: Mutex<Option<anyhow::Error>>,
}
impl LocalStartupGate {
    pub fn install(owner: &SnapshotBufferOwner, error: anyhow::Error) -> Result<Arc<Self>> {
        let mut installed = owner.local_startup_gate.lock().unwrap();
        ensure!(
            installed.is_none(),
            "local startup fixture gate already installed"
        );
        let gate = Arc::new(Self {
            entered: Default::default(),
            release: tokio::sync::Semaphore::new(0),
            raft: Default::default(),
            ownership: Default::default(),
            router: Default::default(),
            error: Mutex::new(Some(error)),
        });
        *installed = Some(gate.clone());
        Ok(gate)
    }
    pub async fn entered(&self) {
        self.entered.notified().await;
    }
    pub fn release(&self) {
        self.release.add_permits(1);
    }
    pub fn claim_is_live(&self) -> bool {
        self.ownership
            .lock()
            .unwrap()
            .as_ref()
            .and_then(Weak::upgrade)
            .is_some_and(|claim| claim.load(Ordering::Acquire))
    }
    pub fn router_is_alive(&self) -> bool {
        self.router
            .lock()
            .unwrap()
            .as_ref()
            .and_then(Weak::upgrade)
            .is_some()
    }
    pub fn raft(&self) -> Option<crate::Raft> {
        self.raft
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|raft| raft.downcast_ref::<crate::Raft>())
            .cloned()
    }
    pub(crate) async fn pause(&self, group: &crate::RaftGroup) -> Result<()> {
        *self.raft.lock().unwrap() = Some(Arc::new(group.raft.clone()));
        *self.ownership.lock().unwrap() = Some(Arc::downgrade(&group.ownership));
        let router: Arc<dyn Send + Sync> = group.local_route.as_ref().unwrap().0.clone();
        *self.router.lock().unwrap() = Some(Arc::downgrade(&router));
        self.entered.notify_one();
        self.release.acquire().await.unwrap().forget();
        Err(self
            .error
            .lock()
            .unwrap()
            .take()
            .expect("fixture gate is used once"))
    }
}
