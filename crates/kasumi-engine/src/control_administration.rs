//! An owned current Control quorum observation for administrative adapters.
//! Its constructor reads the actual database. Serialized roots, membership lists
//! and historical receipts cannot construct this authorization.
use super::*;

pub struct ControlAdministrativeFence {
    database: Arc<Database>,
    context: RequestContext,
    installation: LifecycleInstallation,
    partition: ControlAuthorityPartition,
    policy_epoch: u64,
    term: u64,
    node_id: u64,
    membership: Arc<kasumi_raft::StoredMembership<u64, kasumi_raft::BasicNode>>,
    cancellation: QueryCancellation,
    closed: AtomicBool,
    _work: WorkRegistration,
    _slot: tokio::sync::OwnedSemaphorePermit,
    _reservation: Reservation,
}
impl ControlAdministrativeFence {
    pub fn context(&self) -> &RequestContext {
        &self.context
    }
    pub fn installation(&self) -> &LifecycleInstallation {
        &self.installation
    }
    pub fn partition(&self) -> &ControlAuthorityPartition {
        &self.partition
    }
    pub fn local_node_id(&self) -> u64 {
        self.node_id
    }
    /// Actual committed Control members, including learners. These IDs do not
    /// attest physical verifier identities; the installed issuer registry must
    /// separately bind every receiver before a remote trust operation.
    pub fn members(&self) -> impl Iterator<Item = u64> + '_ {
        self.membership.membership().nodes().map(|(id, _)| *id)
    }
    pub fn voters(&self) -> impl Iterator<Item = u64> + '_ {
        self.membership.membership().voter_ids()
    }
    pub fn check(&self) -> Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(changed(
                "original Control administrative observation is closed",
            ));
        }
        let result = self.check_current();
        if result.is_err() {
            self.closed.store(true, Ordering::SeqCst);
        } else if self.closed.load(Ordering::SeqCst) {
            return Err(changed(
                "original Control administrative observation is closed",
            ));
        }
        result
    }
    fn check_current(&self) -> Result<()> {
        self.cancellation.check()?;
        self.context.authorization.check_live()?;
        self.database.access()?;
        self.database
            .engine
            .authorize(&self.context, None, Action::Admin)?;
        let state = self.database.engine.generation()?;
        self.context
            .authorization
            .require_control(&state.state.incarnation)?;
        let control = state
            .state
            .lifecycle_control
            .as_ref()
            .ok_or_else(|| changed("current Control installation absent"))?;
        if state.state.tenant != crate::control::CONTROL_TENANT
            || state.state.incarnation != self.installation.root.control_incarnation.to_string()
            || state.state.policy_epoch != self.policy_epoch
            || control.retired
            || control.pending_change.is_some()
            || control.installation != self.installation
        {
            return Err(changed(
                "current Control administrative installation changed",
            ));
        }
        drop(state);
        let metrics = self.database.group.raft().metrics().borrow().clone();
        if metrics.id != self.node_id
            || metrics.current_leader != Some(self.node_id)
            || metrics.current_term != self.term
            || metrics.membership_config != self.membership
        {
            return Err(changed("current Control administrative quorum changed"));
        }
        self.cancellation.check()?;
        self.context.authorization.check_live()
    }
    /// A response or remote dispatch must cross a fresh current-quorum barrier
    /// while retaining this invocation's original credential and observation.
    pub async fn release(&self) -> Result<()> {
        let mut attempt = ReleaseAttempt {
            closed: &self.closed,
            completed: false,
        };
        self.check()?;
        if self.database.lifecycle_barrier(&self.context).await? != self.term {
            return Err(changed(
                "Control term changed before administrative release",
            ));
        }
        self.check()?;
        attempt.completed = true;
        Ok(())
    }
}
struct ReleaseAttempt<'a> {
    closed: &'a AtomicBool,
    completed: bool,
}
impl Drop for ReleaseAttempt<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.closed.store(true, Ordering::SeqCst);
        }
    }
}
fn changed(message: &str) -> Error {
    Error::new(ErrorCode::Unavailable, message)
}
impl Database {
    /// Authorize against the actual live Control group and an exact installed
    /// issuer partition. This grants no issuer or local verifier mutation by
    /// itself: a remote adapter must also verify its current physical admission.
    pub async fn authorize_control_administration(
        self: &Arc<Self>,
        context: RequestContext,
        partition: ControlAuthorityPartition,
    ) -> Result<Arc<ControlAdministrativeFence>> {
        context.authorization.check_live()?;
        if context.authorization.expires_at_ms().is_none() {
            return Err(Error::new(
                ErrorCode::Unauthorized,
                "Control administration requires a finite verified credential",
            ));
        }
        partition.validate()?;
        let cancellation = QueryCancellation::default();
        let work = self.work.begin(cancellation.clone())?;
        let slot = self.query_slots.clone().try_acquire_owned().map_err(|_| {
            Error::new(
                ErrorCode::ResourceExhausted,
                "Control administrative concurrency limit",
            )
        })?;
        let term = self.lifecycle_barrier(&context).await?;
        let metrics = self.group.raft().metrics().borrow().clone();
        let state = self.engine.generation()?;
        let control = state
            .state
            .lifecycle_control
            .as_ref()
            .ok_or_else(|| changed("current Control installation absent"))?;
        if control.installation.partitions.get(&partition.key()) != Some(&partition) {
            return Err(Error::new(
                ErrorCode::Forbidden,
                "issuer partition differs from current Control installation",
            ));
        }
        // Only bounded installation metadata is copied. The tenant generation
        // and document roots are released before this owned observation escapes.
        let membership_bytes = metrics
            .membership_config
            .membership()
            .nodes()
            .try_fold(4096_u64, |total, (_, node)| {
                u64::try_from(node.addr.len())
                    .ok()
                    .and_then(|bytes| bytes.checked_add(256))
                    .and_then(|bytes| total.checked_add(bytes))
            })
            .ok_or_else(|| changed("Control membership metadata accounting overflow"))?;
        let bytes = u64::try_from(control.installation.partitions.len())
            .ok()
            .and_then(|count| count.checked_mul(1024))
            .and_then(|bytes| bytes.checked_add(membership_bytes))
            .ok_or_else(|| changed("Control administrative metadata accounting overflow"))?;
        let mut reservation = self.admission().reserve(bytes, None)?;
        let installation = control.installation.clone();
        let policy_epoch = state.state.policy_epoch;
        drop(state);
        if metrics.current_term != term
            || metrics.current_leader != Some(metrics.id)
            || metrics
                .membership_config
                .membership()
                .get_joint_config()
                .len()
                != 1
        {
            return Err(changed("stable current Control quorum required"));
        }
        reservation.retain_workspace();
        let fence = Arc::new(ControlAdministrativeFence {
            database: self.clone(),
            context,
            installation,
            partition,
            policy_epoch,
            term,
            node_id: metrics.id,
            membership: metrics.membership_config,
            cancellation,
            closed: AtomicBool::new(false),
            _work: work,
            _slot: slot,
            _reservation: reservation,
        });
        fence.release().await?;
        Ok(fence)
    }
}
