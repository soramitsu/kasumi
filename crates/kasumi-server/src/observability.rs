//! Protected, bounded observations on the private administrative TLS listener.
//! These are local samples, not a distributed snapshot or authorization lease.
use crate::{administration::Administration, auth::Authenticator};
use axum::{
    Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use kasumi_engine::{EncodedResponseFence, admission::AdmissionSnapshot};
use kasumi_store::TenantStore;
use kasumi_types::{Action, Error, ErrorCode};
use serde::Serialize;
use std::{
    fmt::Write,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
};

pub(crate) const MAX_GROUPS: usize = 128;
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

#[derive(Serialize)]
pub(crate) struct RetentionObservation {
    pub next_sequence: u64,
    pub pruned_before: u64,
    pub hot_bytes: u64,
    pub archive_bytes: u64,
    pub archive_segments: u64,
    pub draining: bool,
    pub hot_budget_bytes: u64,
    pub archive_budget_bytes: u64,
}
#[derive(Serialize)]
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
#[derive(Serialize)]
pub(crate) struct GroupObservation {
    pub tenant: String,
    pub store_available: bool,
    pub routed: bool,
    pub quorum: Option<bool>,
    pub authority_required: bool,
    pub authority_remaining_seconds: Option<f64>,
    pub retention: Option<RetentionObservation>,
    pub capacity: Option<CapacityObservation>,
}
impl GroupObservation {
    fn ready(&self) -> bool {
        self.routed
            && self.store_available
            && self.quorum == Some(true)
            && (!self.authority_required || self.authority_remaining_seconds.is_some())
    }
}
pub(crate) struct LocalObservation {
    pub admission: AdmissionSnapshot,
    pub scratch_disk: kasumi_store::ScratchDiskSnapshot,
    pub expected_groups: usize,
    pub groups: Vec<GroupObservation>,
    pub stores: Vec<Arc<TenantStore>>,
    pub standalone_recovery_pending: Option<bool>,
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
    scratch_disk: kasumi_store::ScratchDiskSnapshot,
    expected_groups: usize,
    unexamined_groups: usize,
    groups: Vec<GroupObservation>,
    service_audit: ServiceAuditObservation,
    standalone_recovery_pending: Option<bool>,
    credential_expires_at_ms: Option<u64>,
    backup_requests: std::collections::BTreeMap<&'static str, RequestCounts>,
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
        .with_state(Service {
            auth,
            management,
            telemetry,
        })
}
#[derive(Clone, Copy)]
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

fn error(code: ErrorCode) -> Error {
    Error::new(code, "protected node observation unavailable")
}
fn storage_error(_: anyhow::Error) -> Error {
    error(ErrorCode::Unavailable)
}
fn bearer(headers: &HeaderMap) -> &str {
    let mut values = headers.get_all(axum::http::header::AUTHORIZATION).iter();
    let first = values.next().and_then(|v| v.to_str().ok()).unwrap_or("");
    if values.next().is_some() { "" } else { first }
}
struct Fence<'a> {
    control: kasumi_engine::ResponseFence<'a>,
    audit: Arc<kasumi_engine::SecurityAudit>,
    stores: Vec<Arc<TenantStore>>,
    telemetry: Arc<Telemetry>,
    lifecycle: Lifecycle,
    _workspace: kasumi_engine::admission::Reservation,
}
impl EncodedResponseFence for Fence<'_> {
    fn check(&self) -> kasumi_types::Result<()> {
        if self.telemetry.lifecycle() != self.lifecycle {
            return Err(error(ErrorCode::Unavailable));
        }
        self.audit.store().check_access().map_err(storage_error)?;
        for store in &self.stores {
            store.check_access().map_err(storage_error)?;
        }
        self.control.check()
    }
}
impl Service {
    async fn response(&self, request: axum::extract::Request, endpoint: Endpoint) -> Response {
        match self.observe(request, endpoint).await {
            Ok(response) => response,
            Err(error) => {
                let status = match error.code {
                    ErrorCode::Unauthorized => StatusCode::UNAUTHORIZED,
                    ErrorCode::Forbidden => StatusCode::FORBIDDEN,
                    _ => StatusCode::SERVICE_UNAVAILABLE,
                };
                let mut response =
                    (status, "protected node observation unavailable\n").into_response();
                response.headers_mut().insert(
                    axum::http::header::CACHE_CONTROL,
                    "no-store".parse().unwrap(),
                );
                response
            }
        }
    }
    async fn observe(
        &self,
        request: axum::extract::Request,
        endpoint: Endpoint,
    ) -> kasumi_types::Result<Response> {
        if !request
            .extensions()
            .get::<crate::tls::AuthenticatedTlsPeer>()
            .is_some_and(|peer| peer.certificate_pin().is_some())
        {
            self.auth.anonymous_denial().await;
            return Err(error(ErrorCode::Unauthorized));
        }
        let context = self.auth.authenticate(bearer(request.headers())).await?;
        self.auth
            .audit_result(
                &context,
                if context.tenant == crate::runtime::CONTROL_TENANT {
                    Ok(())
                } else {
                    Err(error(ErrorCode::Forbidden))
                },
            )
            .await?;
        let database = self
            .auth
            .audit_result(
                &context,
                self.management.authorized_database(&context).await,
            )
            .await?;
        let control = self
            .auth
            .audit_result(&context, database.response_fence(&context))
            .await?;
        let workspace = self
            .auth
            .audit_result(&context, self.management.security_audit_workspace())
            .await?;
        let lifecycle = self.telemetry.lifecycle();
        let observed = self
            .auth
            .audit_result(
                &context,
                self.management
                    .local_observation()
                    .await
                    .map_err(storage_error),
            )
            .await?;
        let audit = self.management.security_audit().clone();
        let service_audit = self
            .auth
            .audit_result(&context, audit.status().map_err(storage_error))
            .await?;
        let unexamined_groups = observed
            .expected_groups
            .saturating_sub(observed.groups.len());
        let ready = lifecycle == Lifecycle::Serving
            && unexamined_groups == 0
            && observed.groups.iter().all(GroupObservation::ready)
            && observed.admission.sample_usable
            && !observed.admission.pressured
            && !service_audit.persistence_failed
            && observed.standalone_recovery_pending != Some(true);
        let observation = Observation {
            lifecycle,
            ready,
            admission: observed.admission,
            scratch_disk: observed.scratch_disk,
            expected_groups: observed.expected_groups,
            unexamined_groups,
            groups: observed.groups,
            service_audit: ServiceAuditObservation {
                retention: RetentionObservation {
                    next_sequence: service_audit.position.next_sequence,
                    pruned_before: service_audit.position.pruned_before,
                    hot_bytes: service_audit.position.hot_bytes,
                    archive_bytes: service_audit.archived_bytes,
                    archive_segments: service_audit.archive_segments,
                    draining: service_audit.draining,
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
        };
        let body = match endpoint {
            Endpoint::Metrics => observation.prometheus(),
            _ => serde_json::to_string(&observation).map_err(|_| error(ErrorCode::Unavailable))?,
        };
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(error(ErrorCode::ResourceExhausted));
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
            .await?;
        crate::api::release_response(
            &self.auth,
            &context,
            Fence {
                control,
                audit,
                stores: observed.stores,
                telemetry: self.telemetry.clone(),
                lifecycle,
                _workspace: workspace,
            },
            response,
            false,
        )
        .await
    }
}

impl Observation {
    fn prometheus(&self) -> String {
        let mut out = String::new();
        macro_rules! gauge {
            ($name:literal, $value:expr) => {
                writeln!(
                    out,
                    "# TYPE kasumi_{} gauge\nkasumi_{} {}",
                    $name, $name, $value
                )
                .unwrap();
            };
        }
        gauge!("ready", u8::from(self.ready));
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
        gauge!("local_groups_expected", self.expected_groups);
        gauge!("local_groups_unexamined", self.unexamined_groups);
        gauge!(
            "admission_sample_usable",
            u8::from(self.admission.sample_usable)
        );
        gauge!("scratch_disk_max_bytes", self.scratch_disk.max_bytes);
        gauge!(
            "scratch_disk_min_free_bytes",
            self.scratch_disk.min_free_bytes
        );
        gauge!(
            "scratch_disk_charged_bytes",
            self.scratch_disk.charged_bytes
        );
        gauge!("scratch_disk_live_files", self.scratch_disk.live_files);
        gauge!(
            "scratch_disk_filesystem_pending_bytes",
            self.scratch_disk.filesystem_pending_bytes
        );
        if let Some(available) = self.scratch_disk.filesystem_available_bytes {
            gauge!("scratch_disk_filesystem_available_bytes", available);
        }
        gauge!("admission_reserved_bytes", self.admission.reserved_bytes);
        gauge!(
            "admission_inflight_operations",
            self.admission.inflight_operations
        );
        gauge!(
            "admission_high_water_bytes",
            self.admission.high_water_bytes
        );
        gauge!("admission_low_water_bytes", self.admission.low_water_bytes);
        if self.admission.sample_usable {
            gauge!(
                "process_resident_memory_bytes",
                self.admission.resident_bytes
            );
            gauge!("admission_pressured", u8::from(self.admission.pressured));
        }
        if let Some(expiry) = self.credential_expires_at_ms {
            gauge!(
                "scrape_credential_expires_timestamp_seconds",
                expiry as f64 / 1000.0
            );
        }
        if let Some(pending) = self.standalone_recovery_pending {
            gauge!("standalone_recovery_pending", u8::from(pending));
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
        gauge!("service_audit_draining", u8::from(audit.draining));
        gauge!(
            "service_audit_hot_bytes_above_drain_target",
            audit.hot_bytes.saturating_sub(audit.hot_budget_bytes / 2)
        );
        gauge!(
            "service_audit_persistence_failed",
            u8::from(self.service_audit.persistence_failed)
        );
        writeln!(out, "# TYPE kasumi_service_audit_maintenance_failures_total counter\nkasumi_service_audit_maintenance_failures_total {}", self.service_audit.maintenance_failures).unwrap();
        for group in &self.groups {
            let tenant = label(&group.tenant);
            macro_rules! group_gauge {
                ($name:literal, $value:expr) => {
                    writeln!(
                        out,
                        "kasumi_local_group_{}{{tenant=\"{}\"}} {}",
                        $name, tenant, $value
                    )
                    .unwrap();
                };
            }
            group_gauge!("store_available", u8::from(group.store_available));
            group_gauge!("routed", u8::from(group.routed));
            group_gauge!("authority_required", u8::from(group.authority_required));
            if let Some(quorum) = group.quorum {
                group_gauge!("quorum", u8::from(quorum));
            }
            if let Some(remaining) = group.authority_remaining_seconds {
                group_gauge!("authority_remaining_seconds", remaining);
            }
            if let Some(retention) = &group.retention {
                group_gauge!("audit_hot_bytes", retention.hot_bytes);
                group_gauge!("audit_archive_bytes", retention.archive_bytes);
                group_gauge!("audit_archive_segments", retention.archive_segments);
                group_gauge!("audit_hot_budget_bytes", retention.hot_budget_bytes);
                group_gauge!("audit_archive_budget_bytes", retention.archive_budget_bytes);
                group_gauge!("audit_next_sequence", retention.next_sequence);
                group_gauge!("audit_pruned_before", retention.pruned_before);
                group_gauge!("audit_draining", u8::from(retention.draining));
                group_gauge!(
                    "audit_hot_bytes_above_drain_target",
                    retention
                        .hot_bytes
                        .saturating_sub(retention.hot_budget_bytes / 2)
                );
            }
            if let Some(capacity) = &group.capacity {
                group_gauge!("documents", capacity.documents);
                group_gauge!("logical_bytes", capacity.logical_bytes);
                group_gauge!("logical_budget_bytes", capacity.logical_budget_bytes);
                group_gauge!(
                    "snapshot_disk_budget_bytes",
                    capacity.snapshot_disk_budget_bytes
                );
                group_gauge!("permanent_staged_bytes", capacity.permanent_staged_bytes);
                group_gauge!(
                    "reserved_staged_terminal_bytes",
                    capacity.reserved_staged_terminal_bytes
                );
                group_gauge!(
                    "permanent_staged_budget_bytes",
                    capacity.permanent_staged_budget_bytes
                );
                group_gauge!("schema_activation_bytes", capacity.schema_activation_bytes);
                group_gauge!(
                    "schema_activation_budget_bytes",
                    capacity.schema_activation_budget_bytes
                );
                group_gauge!("retirement_bytes", capacity.retirement_bytes);
                group_gauge!("retirement_budget_bytes", capacity.retirement_budget_bytes);
            }
        }
        writeln!(out, "# TYPE kasumi_backup_requests_total counter\n# TYPE kasumi_backup_requests_inflight gauge").unwrap();
        for (operation, counts) in &self.backup_requests {
            writeln!(
                out,
                "kasumi_backup_requests_inflight{{operation=\"{operation}\"}} {}",
                counts.inflight
            )
            .unwrap();
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
fn label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
