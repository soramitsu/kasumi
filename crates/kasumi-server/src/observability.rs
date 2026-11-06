//! Protected, bounded observations on the private administrative TLS listener.
//! These are local samples, not a distributed snapshot or authorization lease.
use crate::{administration::Administration, auth::Authenticator};
use axum::{
    Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use kasumi_engine::{
    EncodedResponseFence,
    admission::{AdmissionSnapshot, NodeAdmission, Reservation},
};
use kasumi_store::TenantStore;
use kasumi_types::{Action, AuditRetentionBudget, Error, ErrorCode, RecoveryPhase};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    fmt::Write,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
};
use uuid::Uuid;

const MAX_RESPONSE_BYTES: usize = 1 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub(crate) enum Lifecycle {
    Starting,
    Serving,
    Draining,
    Closed,
}

#[derive(Default, Clone, Copy, Serialize)]
pub(crate) struct RequestCounts {
    pub inflight: u64,
    pub returned_ok: u64,
    pub returned_denied: u64,
    pub returned_error: u64,
    pub cancelled: u64,
}

pub(crate) const BACKUP_OPERATIONS: [&str; 5] = ["create", "verify", "status", "abort", "cleanup"];
pub(crate) struct Telemetry {
    lifecycle: AtomicU8,
    backup: Mutex<[RequestCounts; 5]>,
    #[cfg(test)]
    pub release_gate: tokio::sync::Mutex<Option<crate::rpc::AuditReleaseGate>>,
}
impl Telemetry {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            lifecycle: AtomicU8::new(Lifecycle::Starting as u8),
            backup: Mutex::new([RequestCounts::default(); 5]),
            #[cfg(test)]
            release_gate: tokio::sync::Mutex::new(None),
        })
    }
    pub(crate) fn lifecycle(&self) -> Lifecycle {
        match self.lifecycle.load(Ordering::Acquire) {
            0 => Lifecycle::Starting,
            1 => Lifecycle::Serving,
            2 => Lifecycle::Draining,
            _ => Lifecycle::Closed,
        }
    }
    pub(crate) fn set_lifecycle(&self, state: Lifecycle) {
        let previous = self.lifecycle.swap(state as u8, Ordering::AcqRel);
        if previous != state as u8 {
            tracing::info!(event = "node_lifecycle", state = ?state, "node serving state changed");
        }
    }
    pub(crate) async fn backup_request<T>(
        self: &Arc<Self>,
        operation: usize,
        future: impl std::future::Future<Output = Result<T, tonic::Status>>,
    ) -> Result<T, tonic::Status> {
        let mut guard = RequestGuard {
            telemetry: self.clone(),
            operation,
            completed: false,
        };
        {
            let mut counters = self.backup.lock().unwrap_or_else(|p| p.into_inner());
            counters[operation].inflight += 1;
        }
        let result = future.await;
        {
            let mut counters = self.backup.lock().unwrap_or_else(|p| p.into_inner());
            let counts = &mut counters[operation];
            counts.inflight -= 1;
            let value = match &result {
                Ok(_) => &mut counts.returned_ok,
                Err(error)
                    if matches!(
                        error.code(),
                        tonic::Code::Unauthenticated | tonic::Code::PermissionDenied
                    ) =>
                {
                    &mut counts.returned_denied
                }
                Err(_) => &mut counts.returned_error,
            };
            *value = value.saturating_add(1);
            guard.completed = true;
        }
        result
    }
}
struct RequestGuard {
    telemetry: Arc<Telemetry>,
    operation: usize,
    completed: bool,
}
impl Drop for RequestGuard {
    fn drop(&mut self) {
        if !self.completed {
            let mut counters = self
                .telemetry
                .backup
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let counts = &mut counters[self.operation];
            counts.inflight -= 1;
            counts.cancelled = counts.cancelled.saturating_add(1);
        }
    }
}

#[derive(Clone, Copy, Serialize)]
pub(crate) struct RetentionObservation {
    pub next_sequence: u64,
    pub pruned_before: u64,
    pub hot_bytes: u64,
    pub archive_bytes: u64,
    pub archive_segments: u64,
    pub draining: bool,
    pub archive_backlog_bytes: u64,
    pub hot_budget_bytes: u64,
    pub archive_budget_bytes: u64,
}
/// Bytes above the drain target only when archive maintenance is due.
pub(crate) fn archive_backlog_bytes(
    hot_bytes: u64,
    budget: &AuditRetentionBudget,
    draining: bool,
    eligible: bool,
) -> u64 {
    if eligible && (draining || hot_bytes >= budget.starts_at()) {
        hot_bytes.saturating_sub(budget.drains_to())
    } else {
        0
    }
}
#[derive(Clone, Copy, Serialize)]
pub(crate) struct CapacityObservation {
    pub documents: u64,
    pub logical_bytes: u64,
    pub logical_budget_bytes: u64,
    pub snapshot_disk_budget_bytes: u64,
    pub permanent_staged_bytes: u64,
    pub reserved_staged_terminal_bytes: u64,
    pub permanent_staged_budget_bytes: u64,
    pub schema_activation_bytes: u64,
    pub schema_activation_budget_bytes: u64,
    pub retirement_bytes: u64,
    pub retirement_budget_bytes: u64,
}
/// One node database's retained `.kvseg`/`.kvdir` files and persisted
/// compaction cycle, as its node worker last published them. The worker
/// copies the status after each of its maintenance steps; reading this never
/// waits on the database. File figures are the last census completed in this
/// process lifetime and stay, aging, while a cycle has invalidated it.
#[derive(Clone, Serialize)]
pub(crate) struct StorageObservation {
    /// The census is current: no cycle has invalidated it since.
    pub measured: bool,
    pub segment_files: Option<u64>,
    pub segment_bytes: Option<u64>,
    pub arena_files: Option<u64>,
    pub arena_bytes: Option<u64>,
    /// Seconds since the worker first published those file figures.
    pub census_age_seconds: Option<f64>,
    /// Seconds since the worker last published this status.
    pub status_age_seconds: f64,
    pub garbage_files: u64,
    pub compaction_phase: &'static str,
    pub compaction_cycle: u64,
    pub compaction_requested: bool,
    pub compaction_baseline_bytes: u64,
    pub compaction_baseline_files: u64,
    pub compaction_trigger_bytes: u64,
    pub compaction_trigger_files: u64,
    pub snapshot_retained_files: u64,
    pub snapshot_retained_bytes: u64,
    pub reclaimed_files_total: u64,
    pub reclaimed_bytes_total: u64,
    pub relocated_bytes_total: u64,
    /// Of the evacuation this process last selected for: old segments with
    /// live values, those kept in place, and their estimated garbage.
    pub evacuation_surveyed_segments: u64,
    pub evacuation_kept_segments: u64,
    pub evacuation_kept_garbage_bytes: u64,
    /// Evacuations that kept every old segment, unsurveyed.
    pub evacuation_survey_fallbacks_total: u64,
    pub reclaim_invalidations_total: u64,
    pub capacity_deferrals_total: u64,
    pub rejected_deferrals_total: u64,
    /// `capacity` or `rejected` while the last maintenance step deferred.
    pub last_deferral: Option<&'static str>,
}
impl StorageObservation {
    pub(crate) fn published(
        published: &kasumi_store::PublishedStorageStatus,
        now: std::time::Instant,
    ) -> Self {
        let status = &published.status;
        let census = published.census;
        Self {
            measured: status.measured,
            segment_files: census.map(|census| census.segment_files),
            segment_bytes: census.map(|census| census.segment_bytes),
            arena_files: census.map(|census| census.arena_files),
            arena_bytes: census.map(|census| census.arena_bytes),
            census_age_seconds: census.map(|census| {
                now.saturating_duration_since(census.measured_at)
                    .as_secs_f64()
            }),
            status_age_seconds: now
                .saturating_duration_since(published.published_at)
                .as_secs_f64(),
            garbage_files: status.garbage_files,
            compaction_phase: status.phase.as_str(),
            compaction_cycle: status.cycle,
            compaction_requested: status.requested,
            compaction_baseline_bytes: status.baseline_bytes,
            compaction_baseline_files: status.baseline_files,
            compaction_trigger_bytes: status.trigger_bytes,
            compaction_trigger_files: status.trigger_files,
            snapshot_retained_files: status.snapshot_retained_files,
            snapshot_retained_bytes: status.snapshot_retained_bytes,
            reclaimed_files_total: status.reclaimed_files_total,
            reclaimed_bytes_total: status.reclaimed_bytes_total,
            relocated_bytes_total: status.relocated_bytes_total,
            evacuation_surveyed_segments: status.evacuation_surveyed_segments,
            evacuation_kept_segments: status.evacuation_kept_segments,
            evacuation_kept_garbage_bytes: status.evacuation_kept_garbage_bytes,
            evacuation_survey_fallbacks_total: status.evacuation_survey_fallbacks_total,
            reclaim_invalidations_total: status.reclaim_invalidations_total,
            capacity_deferrals_total: status.capacity_deferrals_total,
            rejected_deferrals_total: status.rejected_deferrals_total,
            last_deferral: status.last_deferral.map(|deferral| match deferral {
                kasumi_store::MaintenanceDeferral::Capacity => "capacity",
                kasumi_store::MaintenanceDeferral::Rejected(_) => "rejected",
            }),
        }
    }
}
/// One configured local group. Figures from its store are the latest this
/// process observed while the store was available: `figures_age_seconds` is
/// zero when this sample observed them and grows while the store is closed.
/// `None` (JSON null, Prometheus NaN) means never observed in this process.
#[derive(Serialize)]
pub(crate) struct GroupObservation {
    pub tenant: String,
    pub store_available: bool,
    pub routed: bool,
    /// The newest completed readiness probe and its age.
    pub quorum: Option<bool>,
    pub probe_age_seconds: Option<f64>,
    pub authority_required: bool,
    pub authority_remaining_seconds: Option<f64>,
    pub figures_age_seconds: Option<f64>,
    pub retention: Option<RetentionObservation>,
    pub audit_maintenance: Option<kasumi_engine::AuditMaintenanceStatus>,
    pub capacity: Option<CapacityObservation>,
    /// Whether this group's records live in a node database of its own (a
    /// standalone generation's), reported in `storage` under this group.
    /// The node's shared database is reported once, at the top level.
    pub storage_dedicated: Option<bool>,
    pub storage: Option<StorageObservation>,
}
/// The effective memory admission limit and the use it compares requests
/// with: an operation of `n` bytes is admitted only while
/// `resident + reserved + n` stays below `high_water_bytes` (and the sample
/// is usable and unpressured). Use is unknown while the sample is unusable.
#[derive(Clone, Copy, Serialize)]
pub(crate) struct MemoryAdmissionObservation {
    pub high_water_bytes: u64,
    pub used_bytes: Option<u64>,
    pub headroom_bytes: Option<i64>,
}
impl MemoryAdmissionObservation {
    fn of(admission: &AdmissionSnapshot) -> Self {
        let used = admission.sample_usable.then(|| {
            admission
                .resident_bytes
                .saturating_add(admission.reserved_bytes)
        });
        Self {
            high_water_bytes: admission.high_water_bytes,
            used_bytes: used,
            headroom_bytes: used.map(|used| {
                saturating_i64(i128::from(admission.high_water_bytes) - i128::from(used))
            }),
        }
    }
}
fn saturating_i64(value: i128) -> i64 {
    i64::try_from(value).unwrap_or(if value < 0 { i64::MIN } else { i64::MAX })
}
pub(crate) struct LocalObservation {
    pub admission: AdmissionSnapshot,
    pub persistent_disk: kasumi_store::NodeDiskSnapshot,
    pub scratch_disk: kasumi_store::ScratchDiskSnapshot,
    pub coverage: crate::readiness::Status,
    pub coverage_token: Option<crate::readiness::Token>,
    pub groups: Vec<GroupObservation>,
    pub stores: Vec<Arc<TenantStore>>,
    pub standalone_recovery_pending: Option<bool>,
    /// The node's shared database.
    pub storage: Option<StorageObservation>,
}

/// Figures last observed from one group's available store.
#[derive(Clone)]
pub(crate) struct CachedGroup {
    pub incarnation: String,
    pub observed_at: tokio::time::Instant,
    pub retention: RetentionObservation,
    pub capacity: CapacityObservation,
    pub audit_maintenance: Option<kasumi_engine::AuditMaintenanceStatus>,
    pub storage_dedicated: bool,
    pub storage: Option<kasumi_store::PublishedStorageStatus>,
}

/// Bytes one protected observation may hold at once: its figures, the
/// encoded body below `MAX_RESPONSE_BYTES` and transport buffers. This is
/// the charge each request previously reserved from the shared pool.
pub(crate) const OBSERVATION_SLOT_BYTES: u64 =
    4 * kasumi_types::MAX_SECURITY_AUDIT_PAGE_BYTES as u64;
/// How long a request waits for the dedicated slot when the shared pool
/// also refuses it.
const OBSERVATION_SLOT_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// Observation state owned by the administration manager for its lifetime.
///
/// Admission: one observation slot is reserved from node admission when
/// the manager is built and retained as resident, so scrapes do not compete
/// with requests for operation slots or bytes. Pressure that refuses every
/// new reservation (the RSS high-water, an exhausted operation or byte
/// budget) cannot refuse a scrape that holds this slot. A second concurrent
/// observation first tries the shared pool as before and otherwise waits
/// briefly for the slot. One slot bounds the permanent charge to
/// `OBSERVATION_SLOT_BYTES`; each observation's memory is bounded by the
/// response limit, so it needs no per-request quote beyond it.
pub(crate) struct ObservationState {
    slot: Arc<tokio::sync::Semaphore>,
    _slot_charge: Reservation,
    // At most one entry per rostered group (128), a few hundred bytes each;
    // the retained slot's charge leaves room for it beside one observation.
    figures: Mutex<BTreeMap<String, CachedGroup>>,
    // 0 unknown, 1 not pending, 2 pending.
    recovery_pending: AtomicU8,
}
pub(crate) enum ObservationWorkspace {
    Dedicated(#[allow(dead_code, reason = "held until release")] tokio::sync::OwnedSemaphorePermit),
    Shared(#[allow(dead_code, reason = "held until release")] Reservation),
}
impl ObservationState {
    pub(crate) fn new(admission: &Arc<NodeAdmission>) -> kasumi_types::Result<Self> {
        let mut reservation = admission.reserve(OBSERVATION_SLOT_BYTES, None)?;
        reservation.retain(OBSERVATION_SLOT_BYTES);
        Ok(Self {
            slot: Arc::new(tokio::sync::Semaphore::new(1)),
            _slot_charge: reservation,
            figures: Mutex::new(BTreeMap::new()),
            recovery_pending: AtomicU8::new(0),
        })
    }
    pub(crate) fn set_recovery_pending(&self, pending: Option<bool>) {
        self.recovery_pending.store(
            match pending {
                None => 0,
                Some(false) => 1,
                Some(true) => 2,
            },
            Ordering::Release,
        );
    }
    pub(crate) fn recovery_pending(&self) -> Option<bool> {
        match self.recovery_pending.load(Ordering::Acquire) {
            1 => Some(false),
            2 => Some(true),
            _ => None,
        }
    }
    /// The dedicated slot if free, else the shared pool, else the slot once
    /// it frees within `OBSERVATION_SLOT_WAIT`.
    pub(crate) async fn workspace(
        &self,
        admission: &Arc<NodeAdmission>,
    ) -> Option<ObservationWorkspace> {
        if let Ok(permit) = self.slot.clone().try_acquire_owned() {
            return Some(ObservationWorkspace::Dedicated(permit));
        }
        if let Ok(reservation) = admission.reserve(OBSERVATION_SLOT_BYTES, None) {
            return Some(ObservationWorkspace::Shared(reservation));
        }
        tokio::time::timeout(OBSERVATION_SLOT_WAIT, self.slot.clone().acquire_owned())
            .await
            .ok()?
            .ok()
            .map(ObservationWorkspace::Dedicated)
    }
    /// Remember an available group's figures, or fill an unavailable one's
    /// from what was last observed for the same incarnation, with its age.
    pub(crate) fn reconcile(
        &self,
        observation: &mut GroupObservation,
        incarnation: &str,
        dedicated_storage: Option<kasumi_store::PublishedStorageStatus>,
        now: tokio::time::Instant,
        clock: std::time::Instant,
    ) {
        let mut figures = self.figures.lock().unwrap_or_else(|p| p.into_inner());
        if observation.store_available
            && let (Some(retention), Some(capacity)) = (observation.retention, observation.capacity)
        {
            figures.insert(
                observation.tenant.clone(),
                CachedGroup {
                    incarnation: incarnation.to_owned(),
                    observed_at: now,
                    retention,
                    capacity,
                    audit_maintenance: observation.audit_maintenance.clone(),
                    storage_dedicated: observation.storage_dedicated.unwrap_or(false),
                    storage: dedicated_storage,
                },
            );
            observation.figures_age_seconds = Some(0.0);
            return;
        }
        let Some(cached) = figures
            .get(&observation.tenant)
            .filter(|cached| cached.incarnation == incarnation)
        else {
            return;
        };
        observation.figures_age_seconds = Some(
            now.saturating_duration_since(cached.observed_at)
                .as_secs_f64(),
        );
        observation.retention = Some(cached.retention);
        observation.capacity = Some(cached.capacity);
        observation.audit_maintenance = cached.audit_maintenance.clone();
        observation.storage_dedicated = observation
            .storage_dedicated
            .or(Some(cached.storage_dedicated));
        if observation.storage.is_none()
            && cached.storage_dedicated
            && let Some(storage) = &cached.storage
        {
            observation.storage = Some(StorageObservation::published(storage, clock));
        }
    }
    /// Forget groups the roster no longer lists.
    pub(crate) fn retain_roster(&self, roster: &[(String, String)]) {
        self.figures
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|tenant, _| roster.iter().any(|(listed, _)| listed == tenant));
    }
}

#[derive(Serialize)]
struct ServiceAuditObservation {
    retention: RetentionObservation,
    persistence_failed: bool,
    maintenance_failures: u64,
}
#[derive(Serialize)]
struct Observation {
    lifecycle: Lifecycle,
    ready: bool,
    admission: AdmissionSnapshot,
    memory_admission: MemoryAdmissionObservation,
    persistent_disk: kasumi_store::NodeDiskSnapshot,
    scratch_disk: kasumi_store::ScratchDiskSnapshot,
    readiness_coverage: crate::readiness::Status,
    /// The node's shared database; groups with their own report theirs.
    storage: Option<StorageObservation>,
    groups: Vec<GroupObservation>,
    service_audit: ServiceAuditObservation,
    standalone_recovery_pending: Option<bool>,
    credential_expires_at_ms: Option<u64>,
    backup_requests: std::collections::BTreeMap<&'static str, RequestCounts>,
    #[serde(skip)]
    standalone: bool,
}

/// One durable Control operation, deliberately excluding request and dispatch inputs.
#[derive(Serialize)]
struct RecoveryStatusObservation {
    operation_id: Uuid,
    phase: RecoveryPhase,
    updated_revision: u64,
    phase_pending: bool,
    terminal: bool,
}

#[derive(Clone)]
struct Service {
    auth: Arc<Authenticator>,
    management: Arc<Administration>,
    telemetry: Arc<Telemetry>,
}
pub(crate) fn router(
    auth: Arc<Authenticator>,
    management: Arc<Administration>,
    telemetry: Arc<Telemetry>,
) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/metrics", get(metrics))
        .route("/recovery/{operation_id}", get(recovery_status))
        .route("/maintenance/compaction", post(compaction))
        .with_state(Service {
            auth,
            management,
            telemetry,
        })
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Endpoint {
    Health,
    Ready,
    Metrics,
}
async fn health(State(service): State<Service>, request: axum::extract::Request) -> Response {
    service.response(request, Endpoint::Health).await
}
async fn ready(State(service): State<Service>, request: axum::extract::Request) -> Response {
    service.response(request, Endpoint::Ready).await
}
async fn metrics(State(service): State<Service>, request: axum::extract::Request) -> Response {
    service.response(request, Endpoint::Metrics).await
}
async fn recovery_status(
    State(service): State<Service>,
    request: axum::extract::Request,
) -> Response {
    match service.observe_recovery(request).await {
        Ok(response) => response,
        Err(failure) => failure.response(true),
    }
}
async fn compaction(State(service): State<Service>, request: axum::extract::Request) -> Response {
    match service.request_compaction(request).await {
        Ok(response) => response,
        Err(failure) => failure.response(false),
    }
}

/// Coarse class of a withheld result, named only to authenticated callers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Reason {
    /// No observation workspace could be reserved.
    Admission = 1,
    /// Control authorization, its quorum barrier or response fence.
    ControlQuorum,
    /// The durable service audit store refused the request's record.
    AuditUnavailable,
    /// An observed store closed before the result was released.
    StoreClosed,
    /// Readiness coverage changed or expired before release.
    CoverageStale,
    /// Persistent-disk admission stopped being ready before release.
    DiskUnready,
    /// The node left the serving state the result described.
    Lifecycle,
    Forbidden,
    InvalidRequest,
    NotFound,
    ResponseLimit,
    Unclassified,
}
impl Reason {
    const ALL: [Self; 12] = [
        Self::Admission,
        Self::ControlQuorum,
        Self::AuditUnavailable,
        Self::StoreClosed,
        Self::CoverageStale,
        Self::DiskUnready,
        Self::Lifecycle,
        Self::Forbidden,
        Self::InvalidRequest,
        Self::NotFound,
        Self::ResponseLimit,
        Self::Unclassified,
    ];
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Admission => "admission",
            Self::ControlQuorum => "control_quorum",
            Self::AuditUnavailable => "audit_unavailable",
            Self::StoreClosed => "store_closed",
            Self::CoverageStale => "coverage_stale",
            Self::DiskUnready => "disk_unready",
            Self::Lifecycle => "lifecycle",
            Self::Forbidden => "forbidden",
            Self::InvalidRequest => "invalid_request",
            Self::NotFound => "not_found",
            Self::ResponseLimit => "response_limit",
            Self::Unclassified => "unclassified",
        }
    }
    fn from_code(code: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|reason| *reason as u8 == code)
    }
}

/// A protected request that returned no result.
#[derive(Debug)]
pub(crate) enum Failure {
    /// Unauthenticated, or a 401 other than expiry: the generic body.
    Generic(ErrorCode),
    /// The verified bearer credential's own expiry passed.
    Expired,
    /// An authenticated caller is told the coarse class.
    Classified(ErrorCode, Reason),
}
impl Failure {
    /// Classify an error raised after authentication. A 401 stays generic
    /// unless it is the credential's own expiry.
    fn after_authentication(error: Error, reason: Reason) -> Self {
        match error.code {
            _ if kasumi_types::credential_expired(&error) => Self::Expired,
            ErrorCode::Unauthorized => Self::Generic(ErrorCode::Unauthorized),
            ErrorCode::Forbidden => Self::Classified(ErrorCode::Forbidden, Reason::Forbidden),
            ErrorCode::AuditUnavailable => {
                Self::Classified(ErrorCode::AuditUnavailable, Reason::AuditUnavailable)
            }
            code => Self::Classified(code, reason),
        }
    }
    fn status(&self, recovery_status: bool) -> StatusCode {
        let code = match self {
            Self::Generic(code) | Self::Classified(code, _) => *code,
            Self::Expired => ErrorCode::Unauthorized,
        };
        match code {
            ErrorCode::Unauthorized => StatusCode::UNAUTHORIZED,
            ErrorCode::Forbidden => StatusCode::FORBIDDEN,
            ErrorCode::InvalidArgument if recovery_status => StatusCode::BAD_REQUEST,
            ErrorCode::NotFound if recovery_status => StatusCode::NOT_FOUND,
            _ => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
    pub(crate) fn response(self, recovery_status: bool) -> Response {
        let status = self.status(recovery_status);
        let mut response = match self {
            Self::Generic(_) => (status, GENERIC_BODY).into_response(),
            Self::Expired => {
                let mut response = (
                    status,
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    "{\"error\":\"credential_expired\",\"detail\":\"the access token expired\"}\n",
                )
                    .into_response();
                response.headers_mut().insert(
                    axum::http::header::WWW_AUTHENTICATE,
                    axum::http::HeaderValue::from_static(
                        "Bearer error=\"invalid_token\", error_description=\"the access token expired\"",
                    ),
                );
                response
            }
            Self::Classified(_, reason) => (
                status,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                format!(
                    "{{\"error\":\"protected node observation unavailable\",\"reason\":\"{}\"}}\n",
                    reason.as_str()
                ),
            )
                .into_response(),
        };
        response.headers_mut().insert(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-store"),
        );
        response
    }
}
const GENERIC_BODY: &str = "protected node observation unavailable\n";

fn error(code: ErrorCode) -> Error {
    Error::new(code, "protected node observation unavailable")
}
fn bearer(headers: &HeaderMap) -> &str {
    let mut values = headers.get_all(axum::http::header::AUTHORIZATION).iter();
    let first = values.next().and_then(|v| v.to_str().ok()).unwrap_or("");
    if values.next().is_some() { "" } else { first }
}
/// Release checks record which check withheld the result.
struct Withheld<'a>(&'a AtomicU8);
impl Withheld<'_> {
    fn fail(&self, reason: Reason) -> Error {
        self.0.store(reason as u8, Ordering::Release);
        error(ErrorCode::Unavailable)
    }
}
struct Fence<'a> {
    control: kasumi_engine::ResponseFence<'a>,
    audit: Arc<kasumi_engine::SecurityAudit>,
    stores: Vec<Arc<TenantStore>>,
    telemetry: Arc<Telemetry>,
    lifecycle: Lifecycle,
    disk_was_ready: bool,
    management: Arc<Administration>,
    coverage_epoch: crate::readiness::Epoch,
    coverage_token: Option<crate::readiness::Token>,
    /// A metrics sample is a point observation: readiness inputs it reports
    /// as gauges do not withhold it at release.
    readiness_fenced: bool,
    withheld: Withheld<'a>,
    _workspace: ObservationWorkspace,
}
/// The exact status route needs no all-group readiness sample. Retain the
/// original Control response and audit-store owners through final encoding.
struct RecoveryFence<'a> {
    control: kasumi_engine::ResponseFence<'a>,
    audit: Arc<kasumi_engine::SecurityAudit>,
    telemetry: Arc<Telemetry>,
    withheld: Withheld<'a>,
    _workspace: ObservationWorkspace,
}
impl EncodedResponseFence for RecoveryFence<'_> {
    fn check(&self) -> kasumi_types::Result<()> {
        if self.telemetry.lifecycle() != Lifecycle::Serving {
            return Err(self.withheld.fail(Reason::Lifecycle));
        }
        self.audit
            .store()
            .check_access()
            .map_err(|_| self.withheld.fail(Reason::AuditUnavailable))?;
        self.control.check()
    }
}
impl EncodedResponseFence for Fence<'_> {
    fn check(&self) -> kasumi_types::Result<()> {
        if self.telemetry.lifecycle() != self.lifecycle {
            return Err(self.withheld.fail(Reason::Lifecycle));
        }
        if self.readiness_fenced
            && self.disk_was_ready
            && !persistent_ready(&self.audit.store().persistent_disk().snapshot())
        {
            return Err(self.withheld.fail(Reason::DiskUnready));
        }
        self.audit
            .store()
            .check_access()
            .map_err(|_| self.withheld.fail(Reason::AuditUnavailable))?;
        for store in &self.stores {
            store
                .check_access()
                .map_err(|_| self.withheld.fail(Reason::StoreClosed))?;
        }
        self.control.check()?;
        if !self.readiness_fenced {
            return Ok(());
        }
        let epoch = self
            .management
            .readiness_epoch()
            .map_err(|_| self.withheld.fail(Reason::ControlQuorum))?;
        if epoch != self.coverage_epoch
            || self.coverage_token.is_some_and(|token| {
                !self
                    .management
                    .readiness
                    .check(token, epoch, tokio::time::Instant::now())
            })
        {
            return Err(self.withheld.fail(Reason::CoverageStale));
        }
        Ok(())
    }
}
fn persistent_ready(disk: &kasumi_store::NodeDiskSnapshot) -> bool {
    disk.phase == kasumi_store::NodeDiskPhase::Open
        && disk.filesystem_admission_ready
        && disk
            .filesystem_min_free_bytes
            .checked_add(disk.filesystem_pending_bytes)
            .zip(disk.filesystem_available_bytes)
            .is_some_and(|(required, available)| available >= required)
}

/// Response of `POST /maintenance/compaction`: every node database this
/// runtime owns and whether it accepted the request.
#[derive(Serialize)]
struct CompactionResponse {
    accepted: usize,
    refused: usize,
    databases: Vec<CompactionRequestOutcome>,
}
#[derive(Serialize)]
pub(crate) struct CompactionRequestOutcome {
    /// `node` for the shared node database, else the tenant whose
    /// standalone generation owns the database.
    pub database: String,
    pub accepted: bool,
}

impl Service {
    async fn response(&self, request: axum::extract::Request, endpoint: Endpoint) -> Response {
        match self.observe(request, endpoint).await {
            Ok(response) => response,
            Err(failure) => failure.response(false),
        }
    }
    /// Keep the same mTLS, bearer, Control identity and quorum authorization
    /// boundary for aggregate observations, exact recovery observations and
    /// the compaction request.
    async fn authorized_control(
        &self,
        request: axum::extract::Request,
    ) -> Result<(kasumi_types::RequestContext, Arc<kasumi_engine::Database>), Failure> {
        let certificate = request
            .extensions()
            .get::<crate::tls::AuthenticatedTlsPeer>()
            .and_then(crate::tls::AuthenticatedTlsPeer::certificate_pin);
        let bearer = bearer(request.headers()).to_owned();
        drop(request);
        let Some(certificate) = certificate else {
            self.auth.anonymous_denial().await;
            return Err(Failure::Generic(ErrorCode::Unauthorized));
        };
        // A certificate-bound bearer must come from its own certificate.
        let context = self
            .auth
            .authenticate_presented(&bearer, Some(certificate))
            .await
            .map_err(|error| {
                if kasumi_types::credential_expired(&error) {
                    Failure::Expired
                } else if error.code == ErrorCode::AuditUnavailable {
                    // Only a verified credential reaches its success record.
                    Failure::Classified(ErrorCode::AuditUnavailable, Reason::AuditUnavailable)
                } else {
                    Failure::Generic(error.code)
                }
            })?;
        self.auth
            .audit_result(
                &context,
                if context.tenant == crate::runtime::CONTROL_TENANT {
                    Ok(())
                } else {
                    Err(error(ErrorCode::Forbidden))
                },
            )
            .await
            .map_err(|error| Failure::after_authentication(error, Reason::Forbidden))?;
        let database = self
            .auth
            .audit_result(
                &context,
                self.management.authorized_database(&context).await,
            )
            .await
            .map_err(|error| Failure::after_authentication(error, Reason::ControlQuorum))?;
        Ok((context, database))
    }
    /// Classify a failed release by the check that recorded its reason.
    fn released(withheld: &AtomicU8, error: Error) -> Failure {
        let reason = Reason::from_code(withheld.load(Ordering::Acquire));
        Failure::after_authentication(error, reason.unwrap_or(Reason::ControlQuorum))
    }
    async fn observe_recovery(&self, request: axum::extract::Request) -> Result<Response, Failure> {
        let path = request.uri().path().to_owned();
        let (context, database) = self.authorized_control(request).await?;
        // URI validation happens only after the protected authorization boundary.
        // The fixed-length UUID prevents unbounded parsing or path-derived output.
        let operation = path
            .as_str()
            .strip_prefix("/recovery/")
            .filter(|value| value.len() == 36)
            .and_then(|value| Uuid::parse_str(value).ok())
            .filter(|value| !value.is_nil())
            .ok_or(Failure::Classified(
                ErrorCode::InvalidArgument,
                Reason::InvalidRequest,
            ))?;
        let control = self
            .auth
            .audit_result(&context, database.response_fence(&context))
            .await
            .map_err(|error| Failure::after_authentication(error, Reason::ControlQuorum))?;
        let workspace = self
            .management
            .observation()
            .workspace(self.management.admission())
            .await
            .ok_or(Failure::Classified(
                ErrorCode::ResourceExhausted,
                Reason::Admission,
            ))?;
        if self.telemetry.lifecycle() != Lifecycle::Serving {
            return Err(Failure::Classified(
                ErrorCode::Unavailable,
                Reason::Lifecycle,
            ));
        }
        // This call performs the point-addressed current-quorum read, audit, and
        // first release check; it owns its bounded record reservation until return.
        let proof = self
            .auth
            .audit_result(
                &context,
                database.recovery_status(context.clone(), operation).await,
            )
            .await
            .map_err(|error| {
                let reason = if error.code == ErrorCode::NotFound {
                    Reason::NotFound
                } else {
                    Reason::ControlQuorum
                };
                Failure::after_authentication(error, reason)
            })?;
        let record = proof.record();
        let status = RecoveryStatusObservation {
            operation_id: operation,
            phase: record.phase,
            updated_revision: record.updated_revision,
            phase_pending: record.pending_phase.is_some(),
            terminal: record.phase.terminal(),
        };
        let body = serde_json::to_string(&status)
            .map_err(|_| Failure::Classified(ErrorCode::Unavailable, Reason::Unclassified))?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(Failure::Classified(
                ErrorCode::ResourceExhausted,
                Reason::ResponseLimit,
            ));
        }
        let response = (
            StatusCode::OK,
            [
                (axum::http::header::CONTENT_TYPE, "application/json"),
                (axum::http::header::CACHE_CONTROL, "no-store"),
            ],
            body,
        )
            .into_response();
        #[cfg(test)]
        let gate = self.telemetry.release_gate.lock().await.take();
        #[cfg(test)]
        if let Some(gate) = gate {
            gate.entered.notify_one();
            gate.release.notified().await;
        }
        // Recheck the original recovery proof after encoding or a held response.
        self.auth
            .audit_result(&context, proof.release().await)
            .await
            .map_err(|error| Failure::after_authentication(error, Reason::ControlQuorum))?;
        self.auth
            .audit_result(
                &context,
                database.engine().authorize(&context, None, Action::Admin),
            )
            .await
            .map_err(|error| Failure::after_authentication(error, Reason::ControlQuorum))?;
        let withheld = AtomicU8::new(0);
        crate::api::release_response(
            &self.auth,
            &context,
            RecoveryFence {
                control,
                audit: self.management.security_audit().clone(),
                telemetry: self.telemetry.clone(),
                withheld: Withheld(&withheld),
                _workspace: workspace,
            },
            response,
            false,
        )
        .await
        .map_err(|error| Self::released(&withheld, error))
    }
    async fn observe(
        &self,
        request: axum::extract::Request,
        endpoint: Endpoint,
    ) -> Result<Response, Failure> {
        let (context, database) = self.authorized_control(request).await?;
        let control = self
            .auth
            .audit_result(&context, database.response_fence(&context))
            .await
            .map_err(|error| Failure::after_authentication(error, Reason::ControlQuorum))?;
        let workspace = self
            .management
            .observation()
            .workspace(self.management.admission())
            .await
            .ok_or(Failure::Classified(
                ErrorCode::ResourceExhausted,
                Reason::Admission,
            ))?;
        let lifecycle = self.telemetry.lifecycle();
        let observed = self
            .management
            .local_observation()
            .await
            .map_err(|_| Failure::Classified(ErrorCode::Unavailable, Reason::ControlQuorum))?;
        let audit = self.management.security_audit().clone();
        let service_audit = audit.status().map_err(|_| {
            Failure::Classified(ErrorCode::AuditUnavailable, Reason::AuditUnavailable)
        })?;
        let standalone = self.management.config.mode == crate::runtime::DeploymentMode::Standalone;
        let ready = lifecycle == Lifecycle::Serving
            && observed.coverage.ready()
            && observed.coverage_token.is_some()
            && persistent_ready(&observed.persistent_disk)
            && observed.admission.sample_usable
            && !observed.admission.pressured
            && !service_audit.persistence_failed
            && (!standalone || observed.standalone_recovery_pending == Some(false));
        let coverage_epoch = observed.coverage.membership_epoch;
        let observation = Observation {
            lifecycle,
            ready,
            memory_admission: MemoryAdmissionObservation::of(&observed.admission),
            admission: observed.admission,
            persistent_disk: observed.persistent_disk,
            scratch_disk: observed.scratch_disk,
            readiness_coverage: observed.coverage,
            storage: observed.storage,
            groups: observed.groups,
            service_audit: ServiceAuditObservation {
                retention: RetentionObservation {
                    next_sequence: service_audit.position.next_sequence,
                    pruned_before: service_audit.position.pruned_before,
                    hot_bytes: service_audit.position.hot_bytes,
                    archive_bytes: service_audit.archived_bytes,
                    archive_segments: service_audit.archive_segments,
                    draining: service_audit.draining,
                    archive_backlog_bytes: archive_backlog_bytes(
                        service_audit.position.hot_bytes,
                        &service_audit.budget,
                        service_audit.draining,
                        true,
                    ),
                    hot_budget_bytes: service_audit.budget.hot_bytes,
                    archive_budget_bytes: service_audit.budget.archive_bytes,
                },
                persistence_failed: service_audit.persistence_failed,
                maintenance_failures: service_audit.maintenance_failures,
            },
            standalone_recovery_pending: observed.standalone_recovery_pending,
            credential_expires_at_ms: context.authorization.expires_at_ms(),
            backup_requests: BACKUP_OPERATIONS
                .into_iter()
                .zip(
                    *self
                        .telemetry
                        .backup
                        .lock()
                        .unwrap_or_else(|p| p.into_inner()),
                )
                .collect(),
            standalone,
        };
        let body = match endpoint {
            Endpoint::Metrics => observation.prometheus(),
            _ => serde_json::to_string(&observation)
                .map_err(|_| Failure::Classified(ErrorCode::Unavailable, Reason::Unclassified))?,
        };
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(Failure::Classified(
                ErrorCode::ResourceExhausted,
                Reason::ResponseLimit,
            ));
        }
        let code = match endpoint {
            Endpoint::Ready if !ready => StatusCode::SERVICE_UNAVAILABLE,
            Endpoint::Health if lifecycle != Lifecycle::Serving => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::OK,
        };
        let response = (
            code,
            [
                (
                    axum::http::header::CONTENT_TYPE,
                    if matches!(endpoint, Endpoint::Metrics) {
                        "text/plain; version=0.0.4; charset=utf-8"
                    } else {
                        "application/json"
                    },
                ),
                (axum::http::header::CACHE_CONTROL, "no-store"),
            ],
            body,
        )
            .into_response();
        #[cfg(test)]
        let gate = self.telemetry.release_gate.lock().await.take();
        #[cfg(test)]
        if let Some(gate) = gate {
            gate.entered.notify_one();
            gate.release.notified().await;
        }
        self.auth
            .audit_result(
                &context,
                database.engine().authorize(&context, None, Action::Admin),
            )
            .await
            .map_err(|error| Failure::after_authentication(error, Reason::ControlQuorum))?;
        let withheld = AtomicU8::new(0);
        crate::api::release_response(
            &self.auth,
            &context,
            Fence {
                control,
                audit,
                stores: observed.stores,
                telemetry: self.telemetry.clone(),
                lifecycle,
                disk_was_ready: ready,
                management: self.management.clone(),
                coverage_epoch,
                coverage_token: observed.coverage_token,
                readiness_fenced: endpoint != Endpoint::Metrics,
                withheld: Withheld(&withheld),
                _workspace: workspace,
            },
            response,
            false,
        )
        .await
        .map_err(|error| Self::released(&withheld, error))
    }
    /// Ask every node database this runtime owns to begin a compaction cycle
    /// at its next maintenance step. This also clears a deferral's backoff.
    async fn request_compaction(
        &self,
        request: axum::extract::Request,
    ) -> Result<Response, Failure> {
        let (context, database) = self.authorized_control(request).await?;
        if self.telemetry.lifecycle() != Lifecycle::Serving {
            return Err(Failure::Classified(
                ErrorCode::Unavailable,
                Reason::Lifecycle,
            ));
        }
        self.auth
            .audit_result(
                &context,
                database.engine().authorize(&context, None, Action::Admin),
            )
            .await
            .map_err(|error| Failure::after_authentication(error, Reason::ControlQuorum))?;
        let databases = self
            .management
            .request_storage_compaction(&context)
            .await
            .map_err(|error| Failure::after_authentication(error, Reason::AuditUnavailable))?;
        let accepted = databases.iter().filter(|outcome| outcome.accepted).count();
        let body = serde_json::to_string(&CompactionResponse {
            accepted,
            refused: databases.len() - accepted,
            databases,
        })
        .map_err(|_| Failure::Classified(ErrorCode::Unavailable, Reason::Unclassified))?;
        Ok((
            StatusCode::OK,
            [
                (axum::http::header::CONTENT_TYPE, "application/json"),
                (axum::http::header::CACHE_CONTROL, "no-store"),
            ],
            body,
        )
            .into_response())
    }
}
/// A Prometheus sample value; unknown values are exported as `NaN` so every
/// family keeps its series instead of disappearing.
#[derive(Clone, Copy)]
enum Value {
    Unsigned(u64),
    Signed(i64),
    Float(f64),
    Unknown,
}
impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsigned(value) => write!(f, "{value}"),
            Self::Signed(value) => write!(f, "{value}"),
            Self::Float(value) => write!(f, "{value}"),
            Self::Unknown => f.write_str("NaN"),
        }
    }
}
impl From<u64> for Value {
    fn from(value: u64) -> Self {
        Self::Unsigned(value)
    }
}
impl From<usize> for Value {
    fn from(value: usize) -> Self {
        Self::Unsigned(value as u64)
    }
}
impl From<u32> for Value {
    fn from(value: u32) -> Self {
        Self::Unsigned(value.into())
    }
}
impl From<i64> for Value {
    fn from(value: i64) -> Self {
        Self::Signed(value)
    }
}
impl From<f64> for Value {
    fn from(value: f64) -> Self {
        Self::Float(value)
    }
}
impl From<bool> for Value {
    fn from(value: bool) -> Self {
        Self::Unsigned(value.into())
    }
}
impl<T: Into<Value>> From<Option<T>> for Value {
    fn from(value: Option<T>) -> Self {
        value.map_or(Self::Unknown, Into::into)
    }
}

/// Storage families shared by the node's database and each group that has
/// one of its own: (suffix, kind, value).
type StorageFamily = (&'static str, &'static str, fn(&StorageObservation) -> Value);
const STORAGE_FAMILIES: [StorageFamily; 22] = [
    ("measured", "gauge", |s| s.measured.into()),
    ("segment_files", "gauge", |s| s.segment_files.into()),
    ("segment_bytes", "gauge", |s| s.segment_bytes.into()),
    ("arena_files", "gauge", |s| s.arena_files.into()),
    ("arena_bytes", "gauge", |s| s.arena_bytes.into()),
    ("census_age_seconds", "gauge", |s| {
        s.census_age_seconds.into()
    }),
    ("status_age_seconds", "gauge", |s| {
        s.status_age_seconds.into()
    }),
    ("garbage_files", "gauge", |s| s.garbage_files.into()),
    ("compaction_cycle", "gauge", |s| s.compaction_cycle.into()),
    ("compaction_requested", "gauge", |s| {
        s.compaction_requested.into()
    }),
    ("compaction_baseline_bytes", "gauge", |s| {
        s.compaction_baseline_bytes.into()
    }),
    ("compaction_trigger_bytes", "gauge", |s| {
        s.compaction_trigger_bytes.into()
    }),
    ("snapshot_retained_bytes", "gauge", |s| {
        s.snapshot_retained_bytes.into()
    }),
    ("evacuation_surveyed_segments", "gauge", |s| {
        s.evacuation_surveyed_segments.into()
    }),
    ("evacuation_kept_segments", "gauge", |s| {
        s.evacuation_kept_segments.into()
    }),
    ("evacuation_kept_garbage_bytes", "gauge", |s| {
        s.evacuation_kept_garbage_bytes.into()
    }),
    ("reclaimed_files_total", "counter", |s| {
        s.reclaimed_files_total.into()
    }),
    ("reclaimed_bytes_total", "counter", |s| {
        s.reclaimed_bytes_total.into()
    }),
    ("relocated_bytes_total", "counter", |s| {
        s.relocated_bytes_total.into()
    }),
    ("evacuation_survey_fallbacks_total", "counter", |s| {
        s.evacuation_survey_fallbacks_total.into()
    }),
    ("reclaim_invalidations_total", "counter", |s| {
        s.reclaim_invalidations_total.into()
    }),
    ("snapshot_retained_files", "gauge", |s| {
        s.snapshot_retained_files.into()
    }),
];
const COMPACTION_PHASES: [&str; 4] = ["idle", "evacuating", "reclaiming", "packing"];
const DEFERRAL_CLASSES: [&str; 2] = ["capacity", "rejected"];

/// Write every storage family for each (labels, storage) entry, grouped by
/// family as the exposition format requires.
fn storage_families(
    out: &mut String,
    prefix: &str,
    entries: &[(String, Option<&StorageObservation>)],
) {
    let separator = |labels: &String| if labels.is_empty() { "" } else { "," };
    for (suffix, kind, value) in STORAGE_FAMILIES {
        writeln!(out, "# TYPE {prefix}{suffix} {kind}").unwrap();
        for (labels, storage) in entries {
            let sample = storage.map_or(Value::Unknown, value);
            if labels.is_empty() {
                writeln!(out, "{prefix}{suffix} {sample}").unwrap();
            } else {
                writeln!(out, "{prefix}{suffix}{{{labels}}} {sample}").unwrap();
            }
        }
    }
    writeln!(out, "# TYPE {prefix}compaction_phase gauge").unwrap();
    for (labels, storage) in entries {
        for phase in COMPACTION_PHASES {
            let sample = storage.map_or(Value::Unknown, |s| (s.compaction_phase == phase).into());
            writeln!(
                out,
                "{prefix}compaction_phase{{{labels}{}phase=\"{phase}\"}} {sample}",
                separator(labels)
            )
            .unwrap();
        }
    }
    writeln!(out, "# TYPE {prefix}deferred gauge").unwrap();
    for (labels, storage) in entries {
        for class in DEFERRAL_CLASSES {
            let sample =
                storage.map_or(Value::Unknown, |s| (s.last_deferral == Some(class)).into());
            writeln!(
                out,
                "{prefix}deferred{{{labels}{}class=\"{class}\"}} {sample}",
                separator(labels)
            )
            .unwrap();
        }
    }
    writeln!(out, "# TYPE {prefix}maintenance_deferrals_total counter").unwrap();
    for (labels, storage) in entries {
        for class in DEFERRAL_CLASSES {
            let sample = storage.map_or(Value::Unknown, |s| {
                if class == "capacity" {
                    s.capacity_deferrals_total.into()
                } else {
                    s.rejected_deferrals_total.into()
                }
            });
            writeln!(
                out,
                "{prefix}maintenance_deferrals_total{{{labels}{}class=\"{class}\"}} {sample}",
                separator(labels)
            )
            .unwrap();
        }
    }
}

/// Per-group families: (name, kind, value). Every configured group has a
/// sample of each in every response; unknown values are `NaN`.
type GroupFamily = (&'static str, &'static str, fn(&GroupObservation) -> Value);
const GROUP_FAMILIES: [GroupFamily; 31] = [
    ("store_available", "gauge", |g| g.store_available.into()),
    ("routed", "gauge", |g| g.routed.into()),
    ("authority_required", "gauge", |g| {
        g.authority_required.into()
    }),
    ("quorum", "gauge", |g| g.quorum.into()),
    ("probe_age_seconds", "gauge", |g| g.probe_age_seconds.into()),
    ("figures_age_seconds", "gauge", |g| {
        g.figures_age_seconds.into()
    }),
    ("storage_dedicated", "gauge", |g| g.storage_dedicated.into()),
    ("audit_hot_bytes", "gauge", |g| {
        g.retention.map(|r| r.hot_bytes).into()
    }),
    ("audit_archive_bytes", "gauge", |g| {
        g.retention.map(|r| r.archive_bytes).into()
    }),
    ("audit_archive_segments", "gauge", |g| {
        g.retention.map(|r| r.archive_segments).into()
    }),
    ("audit_hot_budget_bytes", "gauge", |g| {
        g.retention.map(|r| r.hot_budget_bytes).into()
    }),
    ("audit_archive_budget_bytes", "gauge", |g| {
        g.retention.map(|r| r.archive_budget_bytes).into()
    }),
    ("audit_next_sequence", "gauge", |g| {
        g.retention.map(|r| r.next_sequence).into()
    }),
    ("audit_pruned_before", "gauge", |g| {
        g.retention.map(|r| r.pruned_before).into()
    }),
    ("audit_draining", "gauge", |g| {
        g.retention.map(|r| r.draining).into()
    }),
    ("audit_archive_backlog_bytes", "gauge", |g| {
        g.retention.map(|r| r.archive_backlog_bytes).into()
    }),
    ("audit_hot_bytes_above_drain_target", "gauge", |g| {
        g.retention
            .map(|r| r.hot_bytes.saturating_sub(r.hot_budget_bytes / 2))
            .into()
    }),
    ("audit_maintenance_failures_total", "counter", |g| {
        g.audit_maintenance.as_ref().map(|m| m.failures).into()
    }),
    (
        "audit_maintenance_committed_segments_total",
        "counter",
        |g| {
            g.audit_maintenance
                .as_ref()
                .map(|m| m.committed_segments)
                .into()
        },
    ),
    ("documents", "gauge", |g| {
        g.capacity.map(|c| c.documents).into()
    }),
    ("logical_bytes", "gauge", |g| {
        g.capacity.map(|c| c.logical_bytes).into()
    }),
    ("logical_budget_bytes", "gauge", |g| {
        g.capacity.map(|c| c.logical_budget_bytes).into()
    }),
    ("snapshot_disk_budget_bytes", "gauge", |g| {
        g.capacity.map(|c| c.snapshot_disk_budget_bytes).into()
    }),
    ("permanent_staged_bytes", "gauge", |g| {
        g.capacity.map(|c| c.permanent_staged_bytes).into()
    }),
    ("reserved_staged_terminal_bytes", "gauge", |g| {
        g.capacity.map(|c| c.reserved_staged_terminal_bytes).into()
    }),
    ("permanent_staged_budget_bytes", "gauge", |g| {
        g.capacity.map(|c| c.permanent_staged_budget_bytes).into()
    }),
    ("schema_activation_bytes", "gauge", |g| {
        g.capacity.map(|c| c.schema_activation_bytes).into()
    }),
    ("schema_activation_budget_bytes", "gauge", |g| {
        g.capacity.map(|c| c.schema_activation_budget_bytes).into()
    }),
    ("retirement_bytes", "gauge", |g| {
        g.capacity.map(|c| c.retirement_bytes).into()
    }),
    ("retirement_budget_bytes", "gauge", |g| {
        g.capacity.map(|c| c.retirement_budget_bytes).into()
    }),
    // Present only on replicated nodes, for every group.
    ("authority_remaining_seconds", "gauge", |g| {
        g.authority_remaining_seconds.into()
    }),
];

impl Observation {
    fn prometheus(&self) -> String {
        let mut out = String::new();
        macro_rules! gauge {
            ($name:literal, $value:expr) => {
                writeln!(
                    out,
                    "# TYPE kasumi_{} gauge\nkasumi_{} {}",
                    $name,
                    $name,
                    Value::from($value)
                )
                .unwrap();
            };
        }
        gauge!("ready", self.ready);
        writeln!(out, "# TYPE kasumi_lifecycle gauge").unwrap();
        for (label, state) in [
            ("starting", Lifecycle::Starting),
            ("serving", Lifecycle::Serving),
            ("draining", Lifecycle::Draining),
            ("closed", Lifecycle::Closed),
        ] {
            writeln!(
                out,
                "kasumi_lifecycle{{state=\"{label}\"}} {}",
                u8::from(self.lifecycle == state)
            )
            .unwrap();
        }
        let coverage = &self.readiness_coverage;
        gauge!("readiness_coverage_complete", coverage.complete);
        gauge!("readiness_coverage_fresh", coverage.fresh);
        gauge!("readiness_groups_expected", coverage.expected_groups);
        gauge!("readiness_groups_examined", coverage.examined_groups);
        gauge!("readiness_groups_healthy", coverage.healthy_groups);
        gauge!("local_group_detail_limit", coverage.detail_limit);
        gauge!("local_group_details", self.groups.len());
        gauge!(
            "readiness_oldest_probe_age_seconds",
            coverage.oldest_probe_age_seconds
        );
        let disk = &self.persistent_disk;
        gauge!("admission_sample_usable", self.admission.sample_usable);
        gauge!("persistent_disk_admission_ready", persistent_ready(disk));
        gauge!("persistent_disk_max_bytes", disk.max_bytes);
        gauge!(
            "persistent_disk_maintenance_reserve_bytes",
            disk.maintenance_reserve_bytes
        );
        gauge!("persistent_disk_charged_bytes", disk.charged_bytes);
        gauge!("persistent_disk_pending_bytes", disk.pending_bytes);
        gauge!("persistent_disk_files", disk.persistent_files);
        gauge!("persistent_disk_open_files", disk.open_files);
        gauge!(
            "persistent_disk_filesystem_pending_bytes",
            disk.filesystem_pending_bytes
        );
        gauge!(
            "persistent_disk_filesystem_min_free_bytes",
            disk.filesystem_min_free_bytes
        );
        gauge!(
            "persistent_disk_filesystem_available_bytes",
            disk.filesystem_available_bytes
        );
        gauge!(
            "persistent_disk_headroom_bytes",
            disk.filesystem_headroom_bytes
        );
        gauge!(
            "persistent_disk_filesystem_total_bytes",
            disk.filesystem_total_bytes
        );
        gauge!(
            "persistent_disk_filesystem_used_bytes",
            disk.filesystem_used_bytes
        );
        gauge!("persistent_disk_filesystem_device", disk.filesystem_device);
        persistent_filesystems(&mut out, disk);
        writeln!(
            out,
            "# TYPE kasumi_persistent_disk_capacity_refusals_total counter"
        )
        .unwrap();
        for count in &disk.capacity_refusals {
            writeln!(
                out,
                "kasumi_persistent_disk_capacity_refusals_total{{check=\"{}\"}} {}",
                count.check.as_str(),
                count.refusals
            )
            .unwrap();
        }
        let scratch = &self.scratch_disk;
        gauge!("scratch_disk_max_bytes", scratch.max_bytes);
        gauge!("scratch_disk_min_free_bytes", scratch.min_free_bytes);
        gauge!(
            "scratch_disk_native_cache_bytes",
            scratch.native_cache_bytes
        );
        gauge!("scratch_disk_charged_bytes", scratch.charged_bytes);
        gauge!("scratch_disk_live_files", scratch.live_files);
        gauge!(
            "scratch_disk_filesystem_pending_bytes",
            scratch.filesystem_pending_bytes
        );
        gauge!(
            "scratch_disk_filesystem_min_free_bytes",
            scratch.filesystem_min_free_bytes
        );
        gauge!(
            "scratch_disk_filesystem_available_bytes",
            scratch.filesystem_available_bytes
        );
        gauge!(
            "scratch_disk_headroom_bytes",
            scratch.filesystem_headroom_bytes
        );
        gauge!(
            "scratch_disk_filesystem_total_bytes",
            scratch.filesystem_total_bytes
        );
        gauge!(
            "scratch_disk_filesystem_used_bytes",
            scratch.filesystem_used_bytes
        );
        writeln!(
            out,
            "# TYPE kasumi_scratch_disk_capacity_refusals_total counter"
        )
        .unwrap();
        for count in &scratch.capacity_refusals {
            writeln!(
                out,
                "kasumi_scratch_disk_capacity_refusals_total{{check=\"{}\"}} {}",
                count.check.as_str(),
                count.refusals
            )
            .unwrap();
        }
        gauge!("admission_reserved_bytes", self.admission.reserved_bytes);
        gauge!(
            "admission_inflight_operations",
            self.admission.inflight_operations
        );
        gauge!(
            "admission_high_water_bytes",
            self.memory_admission.high_water_bytes
        );
        gauge!("admission_low_water_bytes", self.admission.low_water_bytes);
        gauge!(
            "admission_memory_used_bytes",
            self.memory_admission.used_bytes
        );
        gauge!(
            "admission_memory_headroom_bytes",
            self.memory_admission.headroom_bytes
        );
        let usable = self.admission.sample_usable;
        gauge!(
            "process_resident_memory_bytes",
            usable.then_some(self.admission.resident_bytes)
        );
        gauge!(
            "admission_pressured",
            usable.then_some(self.admission.pressured)
        );
        gauge!(
            "scrape_credential_expires_timestamp_seconds",
            self.credential_expires_at_ms
                .map(|expiry| expiry as f64 / 1000.0)
        );
        if self.standalone {
            gauge!(
                "standalone_recovery_pending",
                self.standalone_recovery_pending
            );
        }
        let audit = &self.service_audit.retention;
        gauge!("service_audit_hot_bytes", audit.hot_bytes);
        gauge!("service_audit_hot_budget_bytes", audit.hot_budget_bytes);
        gauge!(
            "service_audit_archive_budget_bytes",
            audit.archive_budget_bytes
        );
        gauge!("service_audit_archive_bytes", audit.archive_bytes);
        gauge!("service_audit_archive_segments", audit.archive_segments);
        gauge!("service_audit_next_sequence", audit.next_sequence);
        gauge!("service_audit_pruned_before", audit.pruned_before);
        gauge!("service_audit_draining", audit.draining);
        gauge!(
            "service_audit_archive_backlog_bytes",
            audit.archive_backlog_bytes
        );
        gauge!(
            "service_audit_hot_bytes_above_drain_target",
            audit.hot_bytes.saturating_sub(audit.hot_budget_bytes / 2)
        );
        gauge!(
            "service_audit_persistence_failed",
            self.service_audit.persistence_failed
        );
        writeln!(out, "# TYPE kasumi_service_audit_maintenance_failures_total counter\nkasumi_service_audit_maintenance_failures_total {}", self.service_audit.maintenance_failures).unwrap();
        // The node's shared database, once, without a tenant label.
        storage_families(
            &mut out,
            "kasumi_storage_",
            &[(String::new(), self.storage.as_ref())],
        );
        let tenants: Vec<String> = self
            .groups
            .iter()
            .map(|group| format!("tenant=\"{}\"", label(&group.tenant)))
            .collect();
        let replicated = self.groups.iter().any(|group| group.authority_required);
        for (name, kind, value) in GROUP_FAMILIES {
            if name == "authority_remaining_seconds" && !replicated {
                continue;
            }
            writeln!(out, "# TYPE kasumi_local_group_{name} {kind}").unwrap();
            for (group, tenant) in self.groups.iter().zip(&tenants) {
                writeln!(
                    out,
                    "kasumi_local_group_{name}{{{tenant}}} {}",
                    value(group)
                )
                .unwrap();
            }
        }
        // Groups served from their own database report it under their label.
        let dedicated: Vec<(String, Option<&StorageObservation>)> = self
            .groups
            .iter()
            .zip(&tenants)
            .filter(|(group, _)| group.storage_dedicated == Some(true))
            .map(|(group, tenant)| (tenant.clone(), group.storage.as_ref()))
            .collect();
        if !dedicated.is_empty() {
            storage_families(&mut out, "kasumi_local_group_storage_", &dedicated);
        }
        writeln!(out, "# TYPE kasumi_backup_requests_inflight gauge").unwrap();
        for (operation, counts) in &self.backup_requests {
            writeln!(
                out,
                "kasumi_backup_requests_inflight{{operation=\"{operation}\"}} {}",
                counts.inflight
            )
            .unwrap();
        }
        writeln!(out, "# TYPE kasumi_backup_requests_total counter").unwrap();
        for (operation, counts) in &self.backup_requests {
            for (outcome, count) in [
                ("returned_ok", counts.returned_ok),
                ("returned_denied", counts.returned_denied),
                ("returned_error", counts.returned_error),
                ("cancelled", counts.cancelled),
            ] {
                writeln!(out, "kasumi_backup_requests_total{{operation=\"{operation}\",outcome=\"{outcome}\"}} {count}").unwrap();
            }
        }
        out
    }
}
/// One filesystem holding persistent roots, as its floor check sees it.
struct FilesystemFloor {
    device: u64,
    available: Option<u64>,
    pending: u64,
    owner_pending: u64,
    min_free: u64,
    headroom: Option<i64>,
    admission_ready: bool,
}
/// Every filesystem of the persistent owner. A single filesystem is listed
/// from the scalar fields, which then describe it, so every node exports
/// one series per filesystem whatever its layout.
fn floors(disk: &kasumi_store::NodeDiskSnapshot) -> Vec<FilesystemFloor> {
    if disk.filesystems.is_empty() {
        return vec![FilesystemFloor {
            device: disk.filesystem_device,
            available: disk.filesystem_available_bytes,
            pending: disk.filesystem_pending_bytes,
            owner_pending: disk.pending_bytes,
            min_free: disk.filesystem_min_free_bytes,
            headroom: disk.filesystem_headroom_bytes,
            admission_ready: disk.filesystem_admission_ready,
        }];
    }
    disk.filesystems
        .iter()
        .map(|filesystem| FilesystemFloor {
            device: filesystem.device,
            available: filesystem.available_bytes,
            pending: filesystem.pending_bytes,
            owner_pending: filesystem.owner_pending_bytes,
            min_free: filesystem.min_free_bytes,
            headroom: filesystem.headroom_bytes,
            admission_ready: filesystem.admission_ready,
        })
        .collect()
}
/// Per-filesystem floor families, labelled by device number. Headroom is
/// exactly the margin a reservation in one of that filesystem's roots is
/// compared with: available less pending less min-free.
fn persistent_filesystems(out: &mut String, disk: &kasumi_store::NodeDiskSnapshot) {
    let floors = floors(disk);
    type Floor = (&'static str, fn(&FilesystemFloor) -> Value);
    const FAMILIES: [Floor; 6] = [
        ("available_bytes", |f| f.available.into()),
        ("pending_bytes", |f| f.pending.into()),
        ("owner_pending_bytes", |f| f.owner_pending.into()),
        ("min_free_bytes", |f| f.min_free.into()),
        ("headroom_bytes", |f| f.headroom.into()),
        ("admission_ready", |f| f.admission_ready.into()),
    ];
    for (name, value) in FAMILIES {
        writeln!(out, "# TYPE kasumi_persistent_filesystem_{name} gauge").unwrap();
        for floor in &floors {
            writeln!(
                out,
                "kasumi_persistent_filesystem_{name}{{filesystem=\"{}\"}} {}",
                floor.device,
                value(floor)
            )
            .unwrap();
        }
    }
}
fn label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_backlog_follows_start_drain_and_eligibility_boundaries() {
        let budget = AuditRetentionBudget::default();
        let start = budget.starts_at();
        let target = budget.drains_to();
        assert_eq!(archive_backlog_bytes(start - 1, &budget, false, true), 0);
        assert_eq!(
            archive_backlog_bytes(start, &budget, false, true),
            start - target
        );
        assert_eq!(
            archive_backlog_bytes(start - 1, &budget, true, true),
            start - 1 - target
        );
        assert_eq!(archive_backlog_bytes(target, &budget, true, true), 0);
        assert_eq!(archive_backlog_bytes(start, &budget, false, false), 0);
    }

    #[tokio::test]
    async fn cancelled_backup_request_releases_inflight_without_claiming_an_abort() {
        let telemetry = Telemetry::new();
        let another_installation = Telemetry::new();
        let counter = telemetry.clone();
        let (entered, waiting) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            counter
                .backup_request(0, async {
                    let _ = entered.send(());
                    std::future::pending::<Result<(), tonic::Status>>().await
                })
                .await
        });
        waiting.await.unwrap();
        assert_eq!(telemetry.backup.lock().unwrap()[0].inflight, 1);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        let counts = telemetry.backup.lock().unwrap()[0];
        assert_eq!(counts.inflight, 0);
        assert_eq!(counts.cancelled, 1);
        assert_eq!(
            counts.returned_ok + counts.returned_denied + counts.returned_error,
            0
        );
        assert_eq!(another_installation.backup.lock().unwrap()[0].cancelled, 0);
        assert_eq!(label("a\\b\"c\nd"), "a\\\\b\\\"c\\nd");
    }

    fn disk(available: Option<u64>) -> kasumi_store::NodeDiskSnapshot {
        kasumi_store::NodeDiskSnapshot {
            phase: kasumi_store::NodeDiskPhase::Open,
            charged_bytes: 10 << 20,
            pending_bytes: 1 << 20,
            persistent_files: 12,
            open_files: 3,
            persistent_directories: 2,
            open_directories: 1,
            open_directory_cursors: 0,
            open_census_streams: 0,
            retained_file_attempts: 0,
            uncertain_file_close: None,
            census_close_errno: None,
            observed_directory_bytes: 4096,
            max_bytes: 1 << 30,
            maintenance_reserve_bytes: 64 << 20,
            filesystem_pending_bytes: 2 << 20,
            filesystem_min_free_bytes: 256 << 20,
            filesystem_available_bytes: available,
            filesystem_headroom_bytes: available
                .map(|available| available as i64 - (2 << 20) - (256 << 20)),
            filesystem_total_bytes: available.map(|_| 1 << 40),
            filesystem_used_bytes: available.map(|_| 1 << 39),
            filesystem_device: 2049,
            filesystem_admission_ready: true,
            filesystems: Vec::new(),
            capacity_refusals: kasumi_store::CapacityCheck::PERSISTENT
                .map(|check| kasumi_store::CapacityRefusalCount { check, refusals: 0 }),
            last_capacity_refusal: None,
        }
    }
    fn scratch(available: Option<u64>) -> kasumi_store::ScratchDiskSnapshot {
        kasumi_store::ScratchDiskSnapshot {
            max_bytes: 1 << 30,
            min_free_bytes: 0,
            native_cache_bytes: 8 << 20,
            charged_bytes: 0,
            live_files: 0,
            filesystem_pending_bytes: 2 << 20,
            filesystem_min_free_bytes: 256 << 20,
            filesystem_available_bytes: available,
            filesystem_headroom_bytes: available
                .map(|available| available as i64 - (2 << 20) - (256 << 20)),
            filesystem_total_bytes: available.map(|_| 1 << 40),
            filesystem_used_bytes: available.map(|_| 1 << 39),
            filesystem_admission_ready: true,
            capacity_refusals: kasumi_store::CapacityCheck::SCRATCH
                .map(|check| kasumi_store::CapacityRefusalCount { check, refusals: 0 }),
            last_capacity_refusal: None,
        }
    }
    fn storage(phase: kasumi_store::StorageCompactionPhase, measured: bool) -> StorageObservation {
        let now = std::time::Instant::now();
        let published = kasumi_store::PublishedStorageStatus {
            status: kasumi_store::StorageMaintenanceStatus {
                phase,
                measured,
                segment_files: 4,
                segment_bytes: 4 << 20,
                ..Default::default()
            },
            published_at: now,
            census: Some(kasumi_store::PublishedCensus {
                segment_files: 4,
                segment_bytes: 4 << 20,
                arena_files: 1,
                arena_bytes: 1 << 20,
                measured_at: now,
            }),
        };
        StorageObservation::published(&published, now + std::time::Duration::from_secs(3))
    }
    fn group(tenant: &str, figures: bool, available: bool) -> GroupObservation {
        GroupObservation {
            tenant: tenant.into(),
            store_available: available,
            routed: available,
            quorum: figures.then_some(true),
            probe_age_seconds: figures.then_some(0.5),
            authority_required: false,
            authority_remaining_seconds: None,
            figures_age_seconds: figures.then_some(if available { 0.0 } else { 9.0 }),
            retention: figures.then_some(RetentionObservation {
                next_sequence: 7,
                pruned_before: 1,
                hot_bytes: 100,
                archive_bytes: 0,
                archive_segments: 0,
                draining: false,
                archive_backlog_bytes: 0,
                hot_budget_bytes: 1000,
                archive_budget_bytes: 1000,
            }),
            audit_maintenance: figures.then_some(kasumi_engine::AuditMaintenanceStatus {
                failures: 0,
                committed_segments: 2,
            }),
            capacity: figures.then_some(CapacityObservation {
                documents: 3,
                logical_bytes: 300,
                logical_budget_bytes: 1 << 20,
                snapshot_disk_budget_bytes: 1 << 20,
                permanent_staged_bytes: 0,
                reserved_staged_terminal_bytes: 0,
                permanent_staged_budget_bytes: 1 << 20,
                schema_activation_bytes: 0,
                schema_activation_budget_bytes: 1 << 20,
                retirement_bytes: 0,
                retirement_budget_bytes: 1 << 20,
            }),
            storage_dedicated: figures.then_some(false),
            storage: None,
        }
    }
    /// One observation in a given phase: compaction phase and census,
    /// whether tenant-a's store is open, whether it was ever observed, and
    /// whether the memory and filesystem samples are usable.
    fn observation(
        phase: kasumi_store::StorageCompactionPhase,
        measured: bool,
        tenant_open: bool,
        tenant_observed: bool,
        samples: bool,
    ) -> Observation {
        let admission = AdmissionSnapshot {
            resident_bytes: 100 << 20,
            high_water_bytes: 1 << 30,
            low_water_bytes: 900 << 20,
            reserved_bytes: 50 << 20,
            bookkeeping_bytes: 1 << 20,
            resident_reserved_bytes: 4 << 20,
            resident_reserved_bytes_by_origin: Default::default(),
            live_reservations: 9,
            inflight_operations: if samples { 1 } else { 64 },
            pressured: !samples,
            sample_usable: samples,
        };
        let available = samples.then_some(8 << 30);
        Observation {
            lifecycle: Lifecycle::Serving,
            ready: samples,
            memory_admission: MemoryAdmissionObservation::of(&admission),
            admission,
            persistent_disk: disk(available),
            scratch_disk: scratch(available),
            readiness_coverage: crate::readiness::Status {
                membership_epoch: crate::readiness::Epoch {
                    topology_version: 1,
                    installed_routes: 1,
                    actual_membership: 0,
                },
                expected_groups: samples.then_some(2),
                examined_groups: 2,
                healthy_groups: 2,
                complete: samples,
                fresh: samples,
                oldest_probe_age_seconds: samples.then_some(0.1),
                detail_limit: crate::readiness::DETAIL_LIMIT,
            },
            storage: (samples || measured).then(|| storage(phase, measured)),
            groups: vec![
                group(crate::runtime::CONTROL_TENANT, true, true),
                group("tenant-a", tenant_observed, tenant_open),
            ],
            service_audit: ServiceAuditObservation {
                retention: RetentionObservation {
                    next_sequence: 1,
                    pruned_before: 0,
                    hot_bytes: 0,
                    archive_bytes: 0,
                    archive_segments: 0,
                    draining: false,
                    archive_backlog_bytes: 0,
                    hot_budget_bytes: 1,
                    archive_budget_bytes: 1,
                },
                persistence_failed: false,
                maintenance_failures: 0,
            },
            standalone_recovery_pending: samples.then_some(false),
            credential_expires_at_ms: Some(1_000),
            backup_requests: BACKUP_OPERATIONS
                .into_iter()
                .map(|operation| (operation, RequestCounts::default()))
                .collect(),
            standalone: true,
        }
    }
    fn series(text: &str) -> std::collections::BTreeSet<String> {
        text.lines()
            .filter(|line| !line.starts_with('#'))
            .map(|line| line.rsplit_once(' ').unwrap().0.to_owned())
            .collect()
    }

    #[test]
    fn every_family_is_present_for_every_group_in_every_phase() {
        use kasumi_store::StorageCompactionPhase::*;
        let baseline = observation(Idle, true, true, true, true).prometheus();
        let expected = series(&baseline);
        for (phase, measured, open, observed, samples) in [
            (Evacuating, false, true, true, true),
            (Reclaiming, false, true, true, true),
            (Packing, true, true, true, true),
            // A closed store keeps its last figures with their age.
            (Idle, true, false, true, true),
            // A group never observed in this process reports NaN.
            (Idle, true, false, false, true),
            // Pressured memory and failed filesystem samples.
            (Evacuating, false, true, true, false),
        ] {
            let text = observation(phase, measured, open, observed, samples).prometheus();
            assert_eq!(
                series(&text),
                expected,
                "phase={phase:?} measured={measured} open={open} observed={observed} samples={samples}"
            );
        }
        // The shared database is reported once, never under tenant labels.
        assert!(baseline.contains("kasumi_storage_segment_bytes 4194304\n"));
        assert!(!baseline.contains("kasumi_local_group_storage_compaction_cycle"));
        assert!(baseline.contains("kasumi_local_group_storage_dedicated{tenant=\"tenant-a\"} 0\n"));
        let closed = observation(Idle, true, false, true, true).prometheus();
        assert!(closed.contains("kasumi_local_group_store_available{tenant=\"tenant-a\"} 0\n"));
        assert!(closed.contains("kasumi_local_group_figures_age_seconds{tenant=\"tenant-a\"} 9\n"));
        assert!(closed.contains("kasumi_local_group_documents{tenant=\"tenant-a\"} 3\n"));
        let unknown = observation(Idle, true, false, false, true).prometheus();
        assert!(unknown.contains("kasumi_local_group_documents{tenant=\"tenant-a\"} NaN\n"));
        let evacuating = observation(Evacuating, false, true, true, true).prometheus();
        assert!(evacuating.contains("kasumi_storage_measured 0\n"));
        assert!(evacuating.contains("kasumi_storage_segment_files 4\n"));
        assert!(evacuating.contains("kasumi_storage_census_age_seconds 3\n"));
        assert!(evacuating.contains("kasumi_storage_compaction_phase{phase=\"evacuating\"} 1\n"));
        let pressured = observation(Evacuating, false, true, true, false).prometheus();
        assert!(pressured.contains("kasumi_persistent_disk_headroom_bytes NaN\n"));
        assert!(pressured.contains("kasumi_admission_memory_used_bytes NaN\n"));
        // Headroom is the floor margin of the same sample, also per filesystem.
        assert!(baseline.contains(&format!(
            "kasumi_persistent_disk_headroom_bytes {}\n",
            (8i64 << 30) - (2 << 20) - (256 << 20)
        )));
        assert!(baseline.contains(&format!(
            "kasumi_persistent_filesystem_headroom_bytes{{filesystem=\"2049\"}} {}\n",
            (8i64 << 30) - (2 << 20) - (256 << 20)
        )));
        assert!(baseline.contains("kasumi_persistent_disk_filesystem_device 2049\n"));
        assert!(baseline.contains(&format!(
            "kasumi_admission_memory_used_bytes {}\n",
            150u64 << 20
        )));
        assert!(baseline.contains(&format!(
            "kasumi_admission_memory_headroom_bytes {}\n",
            (1i64 << 30) - (150 << 20)
        )));
        // Each family is one contiguous group introduced by its TYPE line.
        let mut seen = std::collections::BTreeSet::new();
        let mut current = String::new();
        for line in baseline.lines() {
            if let Some(family) = line.strip_prefix("# TYPE ") {
                current = family.split(' ').next().unwrap().to_owned();
                assert!(seen.insert(current.clone()), "{current} repeated");
                continue;
            }
            let name = line.split(['{', ' ']).next().unwrap();
            assert_eq!(name, current, "a sample outside its family group");
        }
    }

    #[test]
    fn each_filesystem_exports_its_own_floor_margin() {
        use kasumi_store::StorageCompactionPhase::Idle;
        let filesystem =
            |device, available: u64, pending, min_free| kasumi_store::NodeDiskFilesystemSnapshot {
                device,
                roots: vec![format!("root-{device}")],
                pending_bytes: pending,
                owner_pending_bytes: pending / 2,
                min_free_bytes: min_free,
                available_bytes: Some(available),
                headroom_bytes: Some(available as i64 - pending as i64 - min_free as i64),
                total_bytes: Some(1 << 40),
                used_bytes: Some(1 << 39),
                admission_ready: true,
            };
        let mut two = observation(Idle, true, true, true, true);
        two.persistent_disk.filesystems = vec![
            filesystem(11, 10 << 30, 1 << 30, 256 << 20),
            filesystem(12, 2 << 30, 1 << 30, 256 << 20),
        ];
        // The scalar fields describe the tightest filesystem.
        let tightest = two.persistent_disk.filesystems[1].clone();
        two.persistent_disk.filesystem_device = tightest.device;
        two.persistent_disk.filesystem_available_bytes = tightest.available_bytes;
        two.persistent_disk.filesystem_pending_bytes = tightest.pending_bytes;
        two.persistent_disk.filesystem_headroom_bytes = tightest.headroom_bytes;
        let text = two.prometheus();
        for (device, available) in [(11, 10i64 << 30), (12, 2i64 << 30)] {
            let headroom = available - (1 << 30) - (256 << 20);
            assert!(
                text.contains(&format!(
                    "kasumi_persistent_filesystem_headroom_bytes{{filesystem=\"{device}\"}} {headroom}\n"
                )),
                "{text}"
            );
            assert!(text.contains(&format!(
                "kasumi_persistent_filesystem_owner_pending_bytes{{filesystem=\"{device}\"}} {}\n",
                (1u64 << 30) / 2
            )));
        }
        assert!(text.contains(&format!(
            "kasumi_persistent_disk_headroom_bytes {}\n",
            (2i64 << 30) - (1 << 30) - (256 << 20)
        )));
        assert!(text.contains("kasumi_persistent_disk_filesystem_device 12\n"));
    }

    #[tokio::test]
    async fn failures_name_their_reason_only_after_authentication() {
        async fn parts(failure: Failure) -> (StatusCode, Option<String>, String) {
            let response = failure.response(false);
            assert_eq!(response.headers()["cache-control"], "no-store");
            let challenge = response
                .headers()
                .get(axum::http::header::WWW_AUTHENTICATE)
                .map(|value| value.to_str().unwrap().to_owned());
            let status = response.status();
            let body = axum::body::to_bytes(response.into_body(), 1 << 16)
                .await
                .unwrap();
            (status, challenge, String::from_utf8(body.to_vec()).unwrap())
        }
        let (status, challenge, body) = parts(Failure::Generic(ErrorCode::Unauthorized)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(challenge, None);
        assert_eq!(body, GENERIC_BODY);
        let expired = Error::new(ErrorCode::Unauthorized, "authenticated credential expired");
        assert!(matches!(
            Failure::after_authentication(expired, Reason::ControlQuorum),
            Failure::Expired
        ));
        let (status, challenge, body) = parts(Failure::Expired).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            challenge.as_deref(),
            Some("Bearer error=\"invalid_token\", error_description=\"the access token expired\"")
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body).unwrap()["error"],
            "credential_expired"
        );
        // Any other 401, such as a revoked family, stays generic.
        let revoked = Error::new(ErrorCode::Unauthorized, "credential family revoked");
        let (status, challenge, body) = parts(Failure::after_authentication(
            revoked,
            Reason::ControlQuorum,
        ))
        .await;
        assert_eq!((status, challenge), (StatusCode::UNAUTHORIZED, None));
        assert_eq!(body, GENERIC_BODY);
        for (error, reason, status) in [
            (
                Error::new(ErrorCode::Unavailable, "quorum"),
                "control_quorum",
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                Error::new(ErrorCode::Forbidden, "policy"),
                "forbidden",
                StatusCode::FORBIDDEN,
            ),
            (
                Error::new(ErrorCode::AuditUnavailable, "audit"),
                "audit_unavailable",
                StatusCode::SERVICE_UNAVAILABLE,
            ),
        ] {
            let (actual, challenge, body) =
                parts(Failure::after_authentication(error, Reason::ControlQuorum)).await;
            assert_eq!((actual, challenge), (status, None));
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&body).unwrap()["reason"],
                reason
            );
        }
        let (status, _, body) = parts(Failure::Classified(
            ErrorCode::ResourceExhausted,
            Reason::Admission,
        ))
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body).unwrap()["reason"],
            "admission"
        );
        for reason in Reason::ALL {
            assert_eq!(Reason::from_code(reason as u8), Some(reason));
        }
        assert_eq!(Reason::from_code(0), None);
    }
}
