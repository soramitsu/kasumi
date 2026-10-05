//! Exact node retirement in the original benchmark startup resource owner.
//!
//! A returned facade never owns the sole resource inventory. The same initial
//! startup cell retains this closed control, every original shutdown result,
//! and each original NodeRetirement. This is not a DTO/router/output-disposal
//! certificate and does not make the startup terminal retirement-ready.
use super::*;
use kasumi_store::{NodeRetirement, StorageCensusDisposition};
use kasumi_types::drain::{DrainCompletion, DrainFailure};
use std::{
    any::Any,
    future::Future,
    mem::ManuallyDrop,
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    task::{Context as TaskContext, Poll},
};

type OriginalPanic = Box<dyn Any + Send>;

#[derive(Default)]
pub(super) enum Body<E> {
    #[default]
    NotEntered,
    Entered,
    Returned(std::result::Result<(), E>),
    Panicked(OriginalPanic),
}
#[derive(Default)]
pub(super) enum Disposal {
    #[default]
    NotEntered,
    Entered,
    Returned,
    Panicked(OriginalPanic),
}
impl Disposal {
    fn returned(&self) -> bool {
        matches!(self, Self::Returned)
    }
    fn fmt_report(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotEntered => write!(f, "not entered"),
            Self::Entered => write!(f, "entered without return"),
            Self::Returned => write!(f, "returned"),
            Self::Panicked(original) => fmt_panic(original, f),
        }
    }
    fn observe(&mut self, work: impl FnOnce()) -> bool {
        if !matches!(self, Self::NotEntered) {
            return self.returned();
        }
        *self = Self::Entered;
        match catch_unwind(AssertUnwindSafe(work)) {
            Ok(()) => *self = Self::Returned,
            Err(original) => *self = Self::Panicked(original),
        }
        self.returned()
    }
}
pub(super) struct Operation<E> {
    pub(super) body: Body<E>,
    pub(super) future_disposal: Disposal,
}
impl<E> Default for Operation<E> {
    fn default() -> Self {
        Self {
            body: Body::NotEntered,
            future_disposal: Disposal::NotEntered,
        }
    }
}
fn fmt_panic(original: &OriginalPanic, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "original panic retained")?;
    if let Some(message) = original.downcast_ref::<String>() {
        write!(f, ": {message}")?;
    } else if let Some(message) = original.downcast_ref::<&'static str>() {
        write!(f, ": {message}")?;
    }
    Ok(())
}
impl Operation<DrainFailure> {
    fn fmt_report(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.body {
            Body::NotEntered => write!(f, "not entered")?,
            Body::Entered => write!(f, "entered without return")?,
            Body::Returned(Ok(())) => write!(f, "returned")?,
            Body::Returned(Err(original)) => std::fmt::Display::fmt(original, f)?,
            Body::Panicked(original) => fmt_panic(original, f)?,
        }
        write!(f, ", actual future disposal ")?;
        self.future_disposal.fmt_report(f)
    }
    fn settled(&self) -> bool {
        self.future_disposal.returned()
            && match &self.body {
                Body::Returned(Ok(())) => true,
                Body::Returned(Err(original)) => original.completion() == DrainCompletion::Complete,
                _ => false,
            }
    }
    fn clean(&self) -> bool {
        self.future_disposal.returned() && matches!(self.body, Body::Returned(Ok(())))
    }
}

/// Actual pinned producer disposal is independent of the returned body result.
/// The synchronous constructor captures F even if the wrapper is never polled.
/// Pending cancellation records Entered plus disposal; it never means no child.
struct Observed<'a, F, E> {
    operation: &'a mut Operation<E>,
    work: ManuallyDrop<F>,
    disposed: bool,
}
impl<'a, F, E> Observed<'a, F, E> {
    fn new(operation: &'a mut Operation<E>, work: F) -> Self {
        debug_assert!(matches!(operation.body, Body::NotEntered));
        Self {
            operation,
            work: ManuallyDrop::new(work),
            disposed: false,
        }
    }
    fn dispose_work(&mut self) {
        if self.disposed {
            return;
        }
        self.disposed = true;
        self.operation.future_disposal = Disposal::Entered;
        // F stays at its pinned address; the same original is destroyed once.
        match catch_unwind(AssertUnwindSafe(|| unsafe {
            ManuallyDrop::drop(&mut self.work)
        })) {
            Ok(()) => self.operation.future_disposal = Disposal::Returned,
            Err(original) => self.operation.future_disposal = Disposal::Panicked(original),
        }
    }
}
impl<F, E> Future for Observed<'_, F, E>
where
    F: Future<Output = std::result::Result<(), E>>,
{
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<()> {
        // Neither F nor its ManuallyDrop storage is ever moved after pinning.
        let this = unsafe { self.get_unchecked_mut() };
        assert!(!this.disposed, "original shutdown future already disposed");
        this.operation.body = Body::Entered;
        let result = catch_unwind(AssertUnwindSafe(|| unsafe {
            Pin::new_unchecked(&mut *this.work).poll(cx)
        }));
        match result {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(original)) => {
                this.operation.body = Body::Returned(original);
                this.dispose_work();
                Poll::Ready(())
            }
            Err(original) => {
                this.operation.body = Body::Panicked(original);
                this.dispose_work();
                Poll::Ready(())
            }
        }
    }
}
impl<F, E> Drop for Observed<'_, F, E> {
    fn drop(&mut self) {
        self.dispose_work();
    }
}

/// This private slot prevents an implicit last alias destruction from becoming
/// a native receipt. Explicit disposal records its original panic separately.
pub(super) struct Alias<T> {
    value: Option<T>,
    pub(super) disposal: Disposal,
}
impl<T> Alias<T> {
    pub(super) fn new(value: T) -> Self {
        Self {
            value: Some(value),
            disposal: Disposal::NotEntered,
        }
    }
    pub(super) fn get(&self) -> &T {
        self.value.as_ref().expect("same live benchmark alias")
    }
    pub(super) fn dispose(&mut self) -> bool {
        if self.value.is_none() {
            return self.disposal.returned();
        }
        let original = self.value.take().expect("same original benchmark alias");
        self.disposal.observe(|| drop(original))
    }
}
impl<T> Drop for Alias<T> {
    fn drop(&mut self) {
        if let Some(original) = self.value.take() {
            // No fallback native proof or destructive work during facade Drop.
            std::mem::forget(original);
        }
    }
}

pub(super) struct Replica {
    pub(super) database: Alias<Arc<Database>>,
    pub(super) shutdown: Operation<DrainFailure>,
    pub(super) unregister: Disposal,
}
impl Replica {
    pub(super) fn new(database: Arc<Database>) -> Self {
        Self {
            database: Alias::new(database),
            shutdown: Operation::default(),
            unregister: Disposal::NotEntered,
        }
    }
}
pub(super) struct Audit {
    pub(super) audit: Alias<Arc<SecurityAudit>>,
    pub(super) shutdown: Operation<DrainFailure>,
}
impl Audit {
    pub(super) fn new(audit: Arc<SecurityAudit>) -> Self {
        Self {
            audit: Alias::new(audit),
            shutdown: Operation::default(),
        }
    }
}
pub(super) struct Node {
    original: Option<NodeStore>,
    pub(super) id: Option<kasumi_store::StorageOwnerId>,
    pub(super) shutdown: Operation<DrainFailure>,
    pub(super) retirement: Option<NodeRetirement>,
    pub(super) retirement_attempt: Disposal,
}
impl Node {
    pub(super) fn new(original: NodeStore) -> Self {
        Self {
            id: original.registered_opening_id(),
            original: Some(original),
            shutdown: Operation::default(),
            retirement: None,
            retirement_attempt: Disposal::NotEntered,
        }
    }
    pub(super) fn get(&self) -> &NodeStore {
        self.original.as_ref().expect("same live original node")
    }
    fn retire(&mut self) {
        if self.retirement.is_some()
            || !self.shutdown.settled()
            || !matches!(self.retirement_attempt, Disposal::NotEntered)
        {
            return;
        }
        self.retirement_attempt = Disposal::Entered;
        let original = self.original.take().expect("same original ready node");
        match catch_unwind(AssertUnwindSafe(|| original.retire())) {
            Ok(receipt) => {
                // The exact receipt is resident before any other destruction.
                self.retirement = Some(receipt);
                self.retirement_attempt = Disposal::Returned;
            }
            Err(original) => self.retirement_attempt = Disposal::Panicked(original),
        }
    }
    fn retry(&mut self) {
        let Some(original) = self.retirement.as_mut() else {
            return;
        };
        if original.disposition() != StorageCensusDisposition::Retained
            || !self.retirement_attempt.returned()
        {
            return;
        }
        // A panic ends this exact attempt without replacing the original receipt.
        self.retirement_attempt = Disposal::Entered;
        match catch_unwind(AssertUnwindSafe(|| original.retry())) {
            Ok(_) => self.retirement_attempt = Disposal::Returned,
            Err(original) => self.retirement_attempt = Disposal::Panicked(original),
        }
    }
    fn retired(&self) -> bool {
        self.retirement_attempt.returned()
            && self
                .retirement
                .as_ref()
                .is_some_and(NodeRetirement::is_retired)
    }
}
impl Drop for Node {
    fn drop(&mut self) {
        if let Some(original) = self.original.take() {
            std::mem::forget(original);
        }
    }
}

pub(super) enum ClosePhase {
    NotEntered,
    Entered,
    Returned,
}
pub(super) struct Resources {
    pub(super) tenants: Vec<Tenant>,
    pub(super) nodes: Vec<Node>,
    pub(super) router: Arc<InProcessRouter>,
    pub(super) provider: Arc<LocalKeyProvider>,
    pub(super) audits: Vec<Audit>,
    pub(super) stores: Vec<Alias<Arc<TenantStore>>>,
    pub(super) domains: Vec<Alias<Arc<kasumi_store::TenantStorageSet>>>,
    pub(super) security_providers: Vec<Arc<LocalKeyProvider>>,
    pub(super) custody_provider: Arc<LocalKeyProvider>,
    pub(super) close_phase: ClosePhase,
    pub(super) bootstrap_capture: Disposal,
    pub(super) close_bootstraps: Option<Option<Vec<ReplicatedBootstrap>>>,
}
impl Resources {
    pub(super) fn fmt_report(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (tenant, value) in self.tenants.iter().enumerate() {
            for (replica, value) in value.replicas.iter().enumerate() {
                write!(f, "; database {tenant}/{replica}: ")?;
                value.shutdown.fmt_report(f)?;
                write!(f, ", route release ")?;
                value.unregister.fmt_report(f)?;
                write!(f, ", alias destruction ")?;
                value.database.disposal.fmt_report(f)?;
            }
        }
        for (index, value) in self.audits.iter().enumerate() {
            write!(f, "; audit {index}: ")?;
            value.shutdown.fmt_report(f)?;
            write!(f, ", alias destruction ")?;
            value.audit.disposal.fmt_report(f)?;
        }
        for (index, value) in self.domains.iter().enumerate() {
            write!(f, "; domain alias {index}: ")?;
            value.disposal.fmt_report(f)?;
        }
        for (index, value) in self.stores.iter().enumerate() {
            write!(f, "; store alias {index}: ")?;
            value.disposal.fmt_report(f)?;
        }
        for (index, value) in self.nodes.iter().enumerate() {
            write!(f, "; node {index} {:?}: ", value.id)?;
            value.shutdown.fmt_report(f)?;
            write!(f, ", retirement attempt ")?;
            value.retirement_attempt.fmt_report(f)?;
            if let Some(original) = &value.retirement {
                write!(
                    f,
                    ", exact receipt {:?} {:?}",
                    original.id(),
                    original.disposition()
                )?;
            }
        }
        Ok(())
    }
    // The actual Tokio mutex lends this Send inventory exclusively; retained
    // original panic payloads require no fabricated Sync implementation.
    pub(super) async fn leader(&mut self, tenant: usize) -> Result<Arc<Database>> {
        let start = Instant::now();
        loop {
            for replica in &self.tenants[tenant].replicas {
                let database = replica.database.get();
                let metrics = database.raft_group().raft().metrics();
                let metrics = metrics.borrow();
                if metrics.current_leader == Some(metrics.id) {
                    return Ok(database.clone());
                }
            }
            ensure!(
                start.elapsed() < Duration::from_secs(10),
                "no serving leader for tenant {tenant}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    fn retry_retirements(&mut self) -> bool {
        if !matches!(self.close_phase, ClosePhase::Returned) {
            return false;
        }
        for node in &mut self.nodes {
            node.retry();
        }
        self.all_retired()
    }
    fn all_retired(&self) -> bool {
        !self.nodes.is_empty() && self.nodes.iter().all(Node::retired)
    }
    fn clean(&self) -> bool {
        matches!(self.close_phase, ClosePhase::Returned)
            && self.bootstrap_capture.returned()
            && self.tenants.iter().all(|tenant| {
                tenant.replicas.iter().all(|replica| {
                    replica.shutdown.clean()
                        && (tenant.bootstrap.is_none() || replica.unregister.returned())
                        && replica.database.disposal.returned()
                })
            })
            && self
                .audits
                .iter()
                .all(|audit| audit.shutdown.clean() && audit.audit.disposal.returned())
            && self.stores.iter().all(|store| store.disposal.returned())
            && self
                .domains
                .iter()
                .all(|domains| domains.disposal.returned())
            && self.nodes.iter().all(|node| node.shutdown.clean())
            && self.all_retired()
    }
    async fn close(&mut self) {
        if !matches!(self.close_phase, ClosePhase::NotEntered) {
            return;
        }
        self.close_phase = ClosePhase::Entered;
        self.bootstrap_capture = Disposal::Entered;
        match catch_unwind(AssertUnwindSafe(|| {
            self.tenants
                .iter()
                .map(|tenant| tenant.bootstrap.clone())
                .collect::<Option<Vec<_>>>()
        })) {
            Ok(original) => {
                self.close_bootstraps = Some(original);
                self.bootstrap_capture = Disposal::Returned;
            }
            Err(original) => {
                self.bootstrap_capture = Disposal::Panicked(original);
                return;
            }
        }
        for (tenant_index, tenant) in self.tenants.iter_mut().enumerate() {
            for replica in &mut tenant.replicas {
                Observed::new(&mut replica.shutdown, replica.database.get().shutdown()).await;
                if !replica.shutdown.settled() {
                    return;
                }
                if let Some(bootstrap) = &tenant.bootstrap {
                    let database = replica.database.get();
                    if !replica.unregister.observe(|| {
                        self.router.unregister(
                            &format!("{}/{}", context(tenant_index).tenant, bootstrap.incarnation),
                            database.raft_group().raft().metrics().borrow().id,
                        );
                    }) {
                        return;
                    }
                }
                // The local producer never registered a route. Its actual
                // unregister observation stays NotEntered; no Returned witness
                // is manufactured for that statically absent operation.
            }
        }
        // Every actual owned Database alias is released individually after its
        // shutdown witness. An external alias can still retain the exact node.
        for tenant in &mut self.tenants {
            for replica in &mut tenant.replicas {
                if !replica.database.dispose() {
                    return;
                }
            }
        }
        for audit in &mut self.audits {
            Observed::new(&mut audit.shutdown, audit.audit.get().shutdown()).await;
            if !audit.shutdown.settled() {
                return;
            }
        }
        for audit in &mut self.audits {
            if !audit.audit.dispose() {
                return;
            }
        }
        // Database/audit shutdown settled those actual owners. Releasing these
        // fixture aliases is not itself a native disposal witness.
        for domains in &mut self.domains {
            if !domains.dispose() {
                return;
            }
        }
        for store in &mut self.stores {
            if !store.dispose() {
                return;
            }
        }
        for node in &mut self.nodes {
            Observed::new(
                &mut node.shutdown,
                node.original.as_ref().unwrap().shutdown(),
            )
            .await;
            if !node.shutdown.settled() {
                return;
            }
            node.retire();
            if !node.retirement_attempt.returned() {
                return;
            }
        }
        self.close_phase = ClosePhase::Returned;
    }
}

/// The actual outer Arc is private. Every alias takes Arc::into_inner so its
/// control is gone before a positively disposed payload could release credit.
/// The current partial output frontier preserves the extracted payload/credit.
pub(super) struct ResourcesOwner {
    inner: Option<Arc<ResourcesState>>,
}
pub(super) struct ResourcesState {
    value: tokio::sync::Mutex<Resources>,
    // Last, after the actual mutex payload/array/control destruction.
    _same_charge: SharedBudgetCharge,
}
impl ResourcesOwner {
    pub(super) fn new(resources: Resources, charge: SharedBudgetCharge) -> Self {
        Self {
            inner: Some(Arc::new(ResourcesState {
                value: tokio::sync::Mutex::new(resources),
                _same_charge: charge,
            })),
        }
    }
    fn state(&self) -> &ResourcesState {
        self.inner.as_deref().expect("same closed resource owner")
    }
    pub(super) async fn lock(&self) -> tokio::sync::MutexGuard<'_, Resources> {
        self.state().value.lock().await
    }
    pub(super) fn with_report<R>(&self, inspect: impl FnOnce(Option<&Resources>) -> R) -> R {
        match self.state().value.try_lock() {
            Ok(value) => inspect(Some(&value)),
            Err(_) => inspect(None),
        }
    }
    #[cfg(test)]
    fn retry_retirements(&self) -> bool {
        let Ok(mut value) = self.state().value.try_lock() else {
            return false;
        };
        value.retry_retirements()
    }
    pub(super) async fn close(&self) -> BenchmarkResult<Option<Vec<ReplicatedBootstrap>>> {
        let mut value = self.lock().await;
        value.close().await;
        // A repeated close call can retry ONLY each exact Retained receipt.
        // It never repeats shutdown, alias destruction, or a prior panic.
        value.retry_retirements();
        if value.clean() {
            Ok(value
                .close_bootstraps
                .take()
                .expect("same staged bootstraps"))
        } else {
            Err(BenchmarkFailure::Close(self.clone()))
        }
    }
}
impl Clone for ResourcesOwner {
    fn clone(&self) -> Self {
        Self {
            inner: Some(
                self.inner
                    .as_ref()
                    .expect("same live resource owner")
                    .clone(),
            ),
        }
    }
}
impl Drop for ResourcesOwner {
    fn drop(&mut self) {
        if let Some(original) =
            Arc::into_inner(self.inner.take().expect("same live resource owner"))
        {
            // Full DTO/router/output disposal is intentionally not established.
            // The final control is gone; preserve its actual payload/arrays and
            // SAME charge instead of refunding an unproved output inventory.
            // During normal operation the startup census owns a live alias, so
            // caller facade loss remains inspectable through its exact ID.
            std::mem::forget(original);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn retained_resources(owner: &benchmark_startup::BenchmarkStartup) -> ResourcesOwner {
        owner.with_report(|value| {
            value
                .expect("same resident benchmark terminal")
                .resources
                .clone()
        })
    }
    fn receipt(
        resources: &ResourcesOwner,
    ) -> (
        kasumi_store::StorageOwnerId,
        StorageCensusDisposition,
        usize,
    ) {
        resources.with_report(|value| {
            let value = value.expect("same resident resource inventory");
            let node = &value.nodes[0];
            let receipt = node
                .retirement
                .as_ref()
                .expect("actual node retirement result");
            assert_eq!(node.id, Some(receipt.id()));
            (
                receipt.id(),
                receipt.disposition(),
                receipt as *const _ as usize,
            )
        })
    }

    #[tokio::test]
    async fn benchmark_actual_retired_node_receipt_survives_facade_loss_and_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let physical = BenchmarkStorage::open(directory.path(), 1).unwrap();
        let databases = Databases::open(&physical, 1, 1, 4, false, None, true)
            .await
            .unwrap();
        let id = databases._startup.as_ref().unwrap().id();
        let startup = physical.admissions[0]
            .memory()
            .prepaid_startup::<benchmark_startup::BenchmarkTerminal>(id)
            .unwrap();
        let original_node = databases
            .resources
            .with_report(|value| value.unwrap().nodes[0].id.unwrap());
        assert!(databases.close().await.unwrap().is_none());
        let resources = retained_resources(&startup);
        let (node_id, disposition, address) = receipt(&resources);
        assert_eq!(node_id, original_node);
        assert_eq!(disposition, StorageCensusDisposition::Retired);
        let settled = physical.admissions[0].snapshot();
        drop(resources);
        drop(startup);
        // The successful output and caller aliases are gone; the SAME original
        // startup census still lends the actual original positive receipt.
        let recovered = physical.admissions[0]
            .memory()
            .prepaid_startup::<benchmark_startup::BenchmarkTerminal>(id)
            .unwrap();
        let resources = retained_resources(&recovered);
        assert_eq!(receipt(&resources), (node_id, disposition, address));
        assert!(resources.retry_retirements());
        assert_eq!(
            physical.admissions[0].snapshot().reserved_bytes,
            settled.reserved_bytes
        );
        assert_eq!(
            physical.admissions[0].snapshot().live_reservations,
            settled.live_reservations
        );
        // Native retirement does not certify the separate output/DTO frontier.
        assert!(!recovered.retire_empty().await);
        let reopened = Databases::open(&physical, 1, 1, 4, false, None, false)
            .await
            .unwrap();
        assert_eq!(reopened.tenant_count, 1);
        assert!(reopened.close().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn benchmark_escaped_leader_keeps_same_receipt_retained_until_actual_alias_release() {
        let directory = tempfile::tempdir().unwrap();
        let physical = BenchmarkStorage::open(directory.path(), 1).unwrap();
        let databases = Databases::open(&physical, 1, 1, 4, false, None, true)
            .await
            .unwrap();
        let startup_id = databases._startup.as_ref().unwrap().id();
        let escaped = databases.leader(0).await.unwrap();
        let original_node = databases
            .resources
            .with_report(|value| value.unwrap().nodes[0].id.unwrap());
        let failed = match databases.close().await {
            Err(BenchmarkFailure::Close(owner)) => owner,
            Err(other) => panic!("whole original close custody must remain typed: {other:?}"),
            Ok(_) => panic!("an escaped actual Database must retain its original node facade"),
        };
        let (node_id, disposition, address) = receipt(&failed);
        assert_eq!(node_id, original_node);
        assert_eq!(disposition, StorageCensusDisposition::Retained);
        let retained = physical.admissions[0].snapshot();
        assert!(!failed.retry_retirements());
        assert_eq!(receipt(&failed), (node_id, disposition, address));
        assert_eq!(
            physical.admissions[0].snapshot().reserved_bytes,
            retained.reserved_bytes
        );
        assert_eq!(
            physical.admissions[0].snapshot().live_reservations,
            retained.live_reservations
        );
        drop(failed);
        let recovered = physical.admissions[0]
            .memory()
            .prepaid_startup::<benchmark_startup::BenchmarkTerminal>(startup_id)
            .unwrap();
        let resources = retained_resources(&recovered);
        assert_eq!(receipt(&resources), (node_id, disposition, address));
        drop(escaped);
        let before_retry = physical.admissions[0].snapshot();
        assert!(resources.retry_retirements());
        let (retired_id, retired_disposition, retired_address) = receipt(&resources);
        assert_eq!(retired_id, node_id);
        assert_eq!(retired_address, address);
        assert_eq!(retired_disposition, StorageCensusDisposition::Retired);
        // Retry consumes the same actual census receipt; it does not open a
        // replacement node or acquire a replacement startup/native grant.
        let after_retry = physical.admissions[0].snapshot();
        assert!(after_retry.reserved_bytes < before_retry.reserved_bytes);
        assert!(after_retry.live_reservations < before_retry.live_reservations);
        assert!(!recovered.retire_empty().await);
    }
}
