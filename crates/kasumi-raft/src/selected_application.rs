//! Selection proof from one supplied paired native view. This binds existing
//! canonical metadata; it neither rehashes bootstrap/snapshot body chunks nor
//! grants authorization, document-pool provenance or a serving source.
use crate::control::{AppliedCursor, AppliedPosition};
use crate::storage::{SnapshotCoverage, SnapshotKind, SnapshotManifest};
use crate::{AppliedEntryContext, BasicNode, RaftLimits, SnapshotRestoreContext};
use allocation::RetainedMetadata;
use anyhow::{Context, Result, ensure};
use kasumi_store::{
    ApplicationBootstrapManifest, PreparedTenantPointWorkspace, PreparedTenantSourcePointLoan,
    PreparedTenantSourcePointReads, SnapshotImage, TenantStorageReadView,
};
use openraft::{LogId, SnapshotMeta, StoredMembership};
use serde::{Serialize, de::DeserializeOwned};
use std::ops::Deref;

enum SelectedBytes<'a> {
    Borrowed(&'a [u8]),
    Owned(kasumi_store::PlaintextValue),
}
impl Deref for SelectedBytes<'_> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Self::Borrowed(bytes) => bytes,
            Self::Owned(bytes) => bytes.as_bytes(),
        }
    }
}

mod allocation;
mod plan;
pub use plan::{
    PreparedOrdinarySourceEnvelope, PreparedSelectionPlan, PreparedSourceCapacityEnvelope,
};

const META: &str = "raft.meta";
const CONTROL_BYTES: usize = 2 << 20;
const VALIDATION_WORKSPACE: u64 = 16 << 10;

enum SelectedReads<'view, 'points> {
    View {
        view: &'view TenantStorageReadView,
        points: Option<&'points mut PreparedTenantPointWorkspace>,
    },
    Prepared(&'points mut kasumi_store::PreparedTenantPointReads),
    Source(&'points mut PreparedTenantSourcePointReads),
    SourceLoan(&'points mut PreparedTenantSourcePointLoan<'view>),
}

/// Borrowed identity checks for the actual selected read. The protected variant
/// exposes neither its native transaction nor ordinary begin/fork operations.
pub struct SelectionReadIdentity<'a>(ReadIdentity<'a>);
enum ReadIdentity<'a> {
    View(&'a TenantStorageReadView),
    Prepared(&'a kasumi_store::PreparedTenantPointReads),
    Source(&'a PreparedTenantSourcePointReads),
    SourceLoan(&'a PreparedTenantSourcePointLoan<'a>),
}
impl SelectionReadIdentity<'_> {
    pub fn require_memory(
        &self,
        expected: &std::sync::Arc<dyn kasumi_store::NodeDiskMemoryAdmission>,
    ) -> Result<()> {
        match self.0 {
            ReadIdentity::View(view) => view.require_memory(expected),
            ReadIdentity::Prepared(reads) => reads.require_memory(expected),
            ReadIdentity::Source(source) => source.require_memory(expected),
            ReadIdentity::SourceLoan(source) => source.require_memory(expected),
        }
    }
    fn require_domains(
        &self,
        application: &std::sync::Arc<kasumi_store::TenantStore>,
        custody: &std::sync::Arc<kasumi_store::TenantStore>,
    ) -> Result<()> {
        match self.0 {
            ReadIdentity::View(view) => view.require_domains(application, custody),
            ReadIdentity::Prepared(reads) => reads.require_domains(application, custody),
            ReadIdentity::Source(source) => source.require_domains(application, custody),
            ReadIdentity::SourceLoan(source) => source.require_domains(application, custody),
        }
    }
}
impl SelectedReads<'_, '_> {
    fn identity(&self) -> SelectionReadIdentity<'_> {
        SelectionReadIdentity(match self {
            Self::View { view, .. } => ReadIdentity::View(view),
            Self::Prepared(reads) => ReadIdentity::Prepared(reads),
            Self::Source(source) => ReadIdentity::Source(source),
            Self::SourceLoan(source) => ReadIdentity::SourceLoan(source),
        })
    }
}

type Decode<T> = fn(&[u8], &mut dyn FnMut(&T) -> Result<()>) -> Result<T>;
fn decode_control<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    before: &mut dyn FnMut(&T) -> Result<()>,
) -> Result<T> {
    crate::control::decode_canonical_admitted(bytes, before)
}
fn decode_snapshot<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    before: &mut dyn FnMut(&T) -> Result<()>,
) -> Result<T> {
    crate::storage::decode_snapshot_record_admitted(bytes, before)
}
fn decode_bootstrap(
    bytes: &[u8],
    _: &mut dyn FnMut(&ApplicationBootstrapManifest) -> Result<()>,
) -> Result<ApplicationBootstrapManifest> {
    // Existing 256-byte bound and four scalar/string fields; fixed allowance
    // covers this unchanged canonical decoder, including its tiny re-encode.
    ApplicationBootstrapManifest::decode(bytes)
}

/// Trusted owned admission, not a success-only callback. Implementations must
/// own their real grant, preserve any preexisting input/control baseline, and
/// validate BOTH actual persistent/scratch domain providers against that grant.
/// Calls quote this proof's additional workspace; provider metadata is separate.
/// No default, unlimited or no-op provider is supplied. Quotes cover the pinned
/// concrete serde containers, buffers and bounded diagnostic text; optional
/// diagnostic backtraces and enclosing caller error boxes are separate custody.
pub trait SelectionWorkspace: Send + Sync + 'static {
    fn require_memory(&self, read: &SelectionReadIdentity<'_>) -> Result<()>;
    /// Grow the same grant before allocation. Refusal leaves its charge intact.
    fn ensure_peak(&mut self, bytes: u64) -> Result<()>;
    /// Called only after read/decode/validation scratch has been destroyed.
    /// Keep at least these bytes plus the implementation's original baseline;
    /// return unused capacity without allocating another per-record grant.
    /// Refusal must preserve the previous charge.
    fn retain(&mut self, bytes: u64) -> Result<()>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplicationSelectionMode {
    Serving,
    Reconstructing,
}

/// These are validation expectations from the real producer, not an authority
/// to serve an older reconstructed Generation. Bootstrap callers must retain
/// their separately authenticated body image; this function reads its manifest.
#[derive(Clone, Copy)]
pub enum ApplicationBoundaryRef<'a> {
    Bootstrap(&'a SnapshotImage),
    Entry(&'a AppliedEntryContext),
    Snapshot(&'a SnapshotRestoreContext),
}

/// Complete read-only canonical applied identity, with no owned extraction.
pub enum SelectedAppliedRef<'a> {
    Entry {
        log_id: LogId<u64>,
        previous: Option<LogId<u64>>,
        membership: &'a StoredMembership<u64, BasicNode>,
        command_sha256: &'a str,
    },
    Snapshot {
        meta: &'a SnapshotMeta<u64, BasicNode>,
        backend_sha256: &'a str,
        snapshot_sha256: &'a str,
    },
}

pub struct SelectedSnapshotRef<'a> {
    pub meta: &'a SnapshotMeta<u64, BasicNode>,
    pub backend_sha256: &'a str,
    pub snapshot_sha256: &'a str,
    pub manifest_id: &'a str,
    pub bytes: u64,
    pub chunks: u64,
}

/// Payload precedes its immutable retained grant. No Clone, raw inner extraction
/// or mutable canonical metadata is exposed. This does not own/close the view:
/// its caller must retain the exact parent and acknowledge explicit close.
pub struct SelectedApplicationPosition<W: SelectionWorkspace> {
    bootstrap: Option<ApplicationBootstrapManifest>,
    applied: Option<AppliedCursor>,
    coverage: Option<SnapshotCoverage>,
    manifest: Option<SnapshotManifest>,
    reconstructed: bool,
    plan: Option<PreparedSelectionPlan>,
    live: u64,
    workspace: W,
}
impl<W: SelectionWorkspace> SelectedApplicationPosition<W> {
    pub fn bootstrap(&self) -> &ApplicationBootstrapManifest {
        self.bootstrap.as_ref().expect("validated bootstrap")
    }
    pub fn applied(&self) -> Option<SelectedAppliedRef<'_>> {
        self.applied.as_ref().map(|cursor| match cursor {
            AppliedCursor::Entry(position) => SelectedAppliedRef::Entry {
                log_id: position.log_id,
                previous: position.previous,
                membership: &position.membership,
                command_sha256: &position.command_sha256,
            },
            AppliedCursor::Snapshot {
                meta,
                backend_sha256,
                snapshot_sha256,
            } => SelectedAppliedRef::Snapshot {
                meta,
                backend_sha256,
                snapshot_sha256,
            },
        })
    }
    pub fn snapshot(&self) -> Option<SelectedSnapshotRef<'_>> {
        self.coverage.as_ref().map(|coverage| {
            let manifest = self.manifest.as_ref().expect("validated coverage manifest");
            SelectedSnapshotRef {
                meta: &coverage.meta,
                backend_sha256: &coverage.backend_sha256,
                snapshot_sha256: &coverage.snapshot_sha256,
                manifest_id: &manifest.id,
                bytes: manifest.bytes,
                chunks: manifest.chunks,
            }
        })
    }
    /// Non-exact newer/equal-snapshot coverage accepted only in Reconstructing.
    /// This is not a report of which branch the publisher executed.
    pub fn is_covered_reconstruction(&self) -> bool {
        self.reconstructed
    }
    pub fn retained_workspace_bytes(&self) -> u64 {
        self.live
    }

    fn into_failure(self, original: anyhow::Error) -> SelectionFailure<W> {
        let Self {
            bootstrap,
            applied,
            coverage,
            manifest,
            workspace,
            ..
        } = self;
        // A failed selection exposes no metadata. Retire its partial payload
        // while the unchanged peak grant still funds both it and the original
        // owned error; reporting admission refusal needs no new allocation.
        drop((bootstrap, applied, coverage, manifest));
        SelectionFailure {
            original,
            _workspace: workspace,
        }
    }

    fn reserve(&mut self, extra: u64) -> Result<()> {
        self.workspace.ensure_peak(
            self.live
                .checked_add(extra)
                .context("selection workspace overflow")?,
        )
    }
    fn read<T: DeserializeOwned + Serialize + RetainedMetadata>(
        &mut self,
        reads: &mut SelectedReads<'_, '_>,
        application: bool,
        namespace: &str,
        key: &[u8],
        limit: usize,
        decode: Decode<T>,
    ) -> Result<Option<T>> {
        let planned = self
            .plan
            .as_ref()
            .map(|plan| plan.record(application, namespace, key))
            .transpose()?;
        let limit = planned.as_ref().map_or(limit, |record| record.limit());
        let bytes: Option<SelectedBytes<'_>> = match reads {
            SelectedReads::Prepared(reads) => if application {
                reads.application_get(namespace, key, limit)?
            } else {
                reads.custody_get(namespace, key, limit)?
            }
            .map(SelectedBytes::Borrowed),
            SelectedReads::Source(source) => {
                // The actual source owns a finite shape before capture. A
                // larger format ceiling does not require a format-sized buffer;
                // an actual row exceeding this owned ceiling is still refused.
                let limit = limit.min(source.value_capacity());
                if application {
                    source.application_get(namespace, key, limit)?
                } else {
                    source.custody_get(namespace, key, limit)?
                }
                .map(SelectedBytes::Borrowed)
            }
            SelectedReads::SourceLoan(source) => {
                let limit = limit.min(source.value_capacity());
                if application {
                    source.application_get(namespace, key, limit)?
                } else {
                    source.custody_get(namespace, key, limit)?
                }
                .map(SelectedBytes::Borrowed)
            }
            SelectedReads::View { view, points } => match points.as_deref_mut() {
                Some(points) => if application {
                    points.application_get(view, namespace, key, limit)?
                } else {
                    points.custody_get(view, namespace, key, limit)?
                }
                .map(SelectedBytes::Borrowed),
                None => {
                    let plaintext = if application {
                        view.application_get_workspace_bytes(namespace.len(), key.len(), limit)?
                    } else {
                        view.custody_get_workspace_bytes(namespace.len(), key.len(), limit)?
                    };
                    self.reserve(plaintext)?;
                    if application {
                        view.application_get(namespace, key, limit)?
                    } else {
                        view.custody_get(namespace, key, limit)?
                    }
                    .map(SelectedBytes::Owned)
                }
            },
        };
        if let Some(planned) = &planned {
            planned.verify(bytes.as_deref())?;
        }
        let Some(bytes) = bytes else { return Ok(None) };
        // The preflight visitor allocates nothing itself. Serde's bounded escape
        // scratch is covered before it parses any input, including malformed JSON.
        self.reserve(allocation::preflight_bytes(bytes.len())?)?;
        let quote = allocation::decode_quote(&bytes)?;
        self.reserve(quote.peak)?;
        let value = decode(&bytes, &mut |value: &T| {
            let encoded = allocation::canonical_bytes(value)?;
            if planned.is_some() {
                ensure!(
                    encoded == bytes.len() as u64,
                    "prospective metadata is not canonical"
                );
            }
            self.reserve(
                quote
                    .retained
                    .checked_add(allocation::encode_workspace(bytes.len(), encoded)?)
                    .context("selection canonical workspace overflow")?,
            )
        })?;
        let retained = value.retained_bytes()?;
        ensure!(
            retained <= quote.retained,
            "decoded metadata exceeds admitted shape quote"
        );
        let next = self
            .live
            .checked_add(retained)
            .context("selection retained workspace overflow")?;
        drop(bytes);
        self.live = next;
        Ok(Some(value))
    }
}

/// Opaque failure preserves its exact original error before the actual peak
/// workspace grant. Unexposed partial metadata is retired under that grant
/// before handoff. Borrowed classification cannot extract an error from an
/// anyhow context and detach it from its allocation custody.
pub struct SelectionFailure<W: SelectionWorkspace> {
    original: anyhow::Error,
    _workspace: W,
}
impl<W: SelectionWorkspace> SelectionFailure<W> {
    pub fn original_error(&self) -> &anyhow::Error {
        &self.original
    }
}
impl<W: SelectionWorkspace> std::fmt::Debug for SelectionFailure<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelectionFailure")
            .field("original", &self.original)
            .finish_non_exhaustive()
    }
}
impl<W: SelectionWorkspace> std::fmt::Display for SelectionFailure<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.original.fmt(f)
    }
}
impl<W: SelectionWorkspace> std::error::Error for SelectionFailure<W> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.original.as_ref())
    }
}

/// Read only the supplied selected native view. No current-store reopen occurs.
/// The caller supplies the actual configured snapshot limit and owns explicit
/// view cleanup on every result. Store/admission errors remain original objects.
pub fn selected_application_at<W: SelectionWorkspace>(
    view: &TenantStorageReadView,
    expected: ApplicationBoundaryRef<'_>,
    mode: ApplicationSelectionMode,
    limits: &RaftLimits,
    workspace: W,
) -> std::result::Result<SelectedApplicationPosition<W>, SelectionFailure<W>> {
    selected_application_at_inner(
        SelectedReads::View { view, points: None },
        expected,
        mode,
        limits,
        workspace,
        None,
    )
}

/// Capture under a producer-built quote. Exact domains and record identities
/// are checked before typed decoding; authorization still runs on every read.
pub fn selected_application_at_planned<W: SelectionWorkspace>(
    view: &TenantStorageReadView,
    expected: ApplicationBoundaryRef<'_>,
    mode: ApplicationSelectionMode,
    limits: &RaftLimits,
    workspace: W,
    plan: &PreparedSelectionPlan,
) -> std::result::Result<SelectedApplicationPosition<W>, SelectionFailure<W>> {
    selected_application_at_inner(
        SelectedReads::View { view, points: None },
        expected,
        mode,
        limits,
        workspace,
        Some(plan.clone()),
    )
}
/// Reuse the producer's actual prepublication backing against this exact
/// selected root. No reader, fork, output or decrypt grant is acquired here.
/// All record authentication and canonical proof validation remain shared.
pub fn selected_application_at_prepared<W: SelectionWorkspace>(
    view: &TenantStorageReadView,
    expected: ApplicationBoundaryRef<'_>,
    mode: ApplicationSelectionMode,
    limits: &RaftLimits,
    workspace: W,
    plan: &PreparedSelectionPlan,
    points: &mut PreparedTenantPointWorkspace,
) -> std::result::Result<SelectedApplicationPosition<W>, SelectionFailure<W>> {
    selected_application_at_inner(
        SelectedReads::View {
            view,
            points: Some(points),
        },
        expected,
        mode,
        limits,
        workspace,
        Some(plan.clone()),
    )
}
/// Validate the same canonical proof through a captured protected source. Its
/// registered native owner and preowned encrypted backing remain in the caller;
/// this path cannot reopen, fork, grow or extract that source's ordinary view.
pub fn selected_application_at_source<W: SelectionWorkspace>(
    source: &mut PreparedTenantSourcePointReads,
    expected: ApplicationBoundaryRef<'_>,
    mode: ApplicationSelectionMode,
    limits: &RaftLimits,
    workspace: W,
    plan: Option<&PreparedSelectionPlan>,
) -> std::result::Result<SelectedApplicationPosition<W>, SelectionFailure<W>> {
    selected_application_at_inner(
        SelectedReads::Source(source),
        expected,
        mode,
        limits,
        workspace,
        plan.cloned(),
    )
}
/// Canonical validation with a serialized borrow of the cohort's actual point
/// backing. The immutable source and backing remain separately owned.
pub fn selected_application_at_source_loan<W: SelectionWorkspace>(
    source: &mut PreparedTenantSourcePointLoan<'_>,
    expected: ApplicationBoundaryRef<'_>,
    mode: ApplicationSelectionMode,
    limits: &RaftLimits,
    workspace: W,
    plan: Option<&PreparedSelectionPlan>,
) -> std::result::Result<SelectedApplicationPosition<W>, SelectionFailure<W>> {
    selected_application_at_inner(
        SelectedReads::SourceLoan(source),
        expected,
        mode,
        limits,
        workspace,
        plan.cloned(),
    )
}
fn selected_application_at_inner<W: SelectionWorkspace>(
    mut reads: SelectedReads<'_, '_>,
    expected: ApplicationBoundaryRef<'_>,
    mode: ApplicationSelectionMode,
    limits: &RaftLimits,
    workspace: W,
    plan: Option<PreparedSelectionPlan>,
) -> std::result::Result<SelectedApplicationPosition<W>, SelectionFailure<W>> {
    let mut owner = SelectedApplicationPosition {
        bootstrap: None,
        applied: None,
        coverage: None,
        manifest: None,
        reconstructed: false,
        plan,
        live: 0,
        workspace,
    };
    let result = (|| -> Result<()> {
        owner.workspace.require_memory(&reads.identity())?;
        if let Some(plan) = &owner.plan {
            plan.require_read(&reads.identity())?;
        }
        owner.bootstrap = owner.read(
            &mut reads,
            true,
            "engine.bootstrap",
            b"manifest",
            kasumi_store::APPLICATION_BOOTSTRAP_MANIFEST_BYTES,
            decode_bootstrap,
        )?;
        ensure!(owner.bootstrap.is_some(), "bootstrap manifest absent");
        let bootstrap_baseline = owner.live;
        let bootstrap_digest: String = owner
            .read(
                &mut reads,
                false,
                META,
                b"application_bootstrap_sha256",
                256,
                decode_control,
            )?
            .context("application bootstrap commitment absent")?;
        ensure!(
            bootstrap_digest == owner.bootstrap().digest,
            "application bootstrap/control identity differs"
        );
        drop(bootstrap_digest);
        owner.live = bootstrap_baseline;
        owner.applied = owner.read(
            &mut reads,
            false,
            META,
            b"applied",
            CONTROL_BYTES,
            decode_control,
        )?;
        if matches!(owner.applied.as_ref(), Some(AppliedCursor::Snapshot { .. }))
            || matches!(expected, ApplicationBoundaryRef::Snapshot(_))
        {
            owner.coverage = owner.read(
                &mut reads,
                false,
                META,
                b"snapshot_coverage",
                CONTROL_BYTES,
                decode_snapshot,
            )?;
            owner.manifest = owner.read(
                &mut reads,
                true,
                "raft.snapshot",
                b"current",
                CONTROL_BYTES,
                decode_snapshot,
            )?;
        }
        owner.reserve(VALIDATION_WORKSPACE)?;
        validate(&owner, expected, mode, limits)?;
        owner.reconstructed = match expected {
            ApplicationBoundaryRef::Bootstrap(_) => owner.applied.is_some(),
            ApplicationBoundaryRef::Entry(expected) => !matches!(owner.applied.as_ref(),
                Some(AppliedCursor::Entry(position)) if entry_matches(position, expected)),
            ApplicationBoundaryRef::Snapshot(expected) => !matches!(owner.applied.as_ref(),
                Some(AppliedCursor::Snapshot { meta, backend_sha256, .. })
                    if meta == &expected.meta && backend_sha256 == &expected.backend_sha256),
        };
        Ok(())
    })();
    if let Err(original) = result {
        return Err(owner.into_failure(original));
    }
    // Owned point output and decode/re-encoding/validation temporaries have
    // died. Prepared plaintext remains in its separate point grant until the
    // caller retires that backing. This metadata grant retains only the DTO
    // quote in live; the temporary digest credit ended with its String.
    owner.plan = None;
    match owner.workspace.retain(owner.live) {
        Ok(()) => Ok(owner),
        Err(original) => Err(owner.into_failure(original)),
    }
}

fn entry_matches(position: &AppliedPosition, expected: &AppliedEntryContext) -> bool {
    position.log_id == expected.log_id
        && position.previous == expected.previous
        && position.membership == expected.membership
        && position.command_sha256 == expected.command_sha256
}

fn validate<W: SelectionWorkspace>(
    owner: &SelectedApplicationPosition<W>,
    expected: ApplicationBoundaryRef<'_>,
    mode: ApplicationSelectionMode,
    limits: &RaftLimits,
) -> Result<()> {
    if let Some(AppliedCursor::Entry(position)) = &owner.applied {
        kasumi_types::validate_sha256(&position.command_sha256)?;
    }
    if let Some(coverage) = &owner.coverage {
        let manifest = owner
            .manifest
            .as_ref()
            .context("snapshot manifest absent")?;
        crate::storage::validate_snapshot_manifest(manifest, limits.max_snapshot_bytes)?;
        crate::storage::validate_snapshot_coverage_record(coverage)?;
        ensure!(
            coverage.kind == SnapshotKind::Application
                && coverage.manifest_id == manifest.id
                && coverage.snapshot_sha256 == manifest.sha256,
            "snapshot/control coverage mismatch"
        );
    } else {
        ensure!(
            owner.manifest.is_none(),
            "snapshot lacks independently readable control coverage"
        );
    }
    if let Some(AppliedCursor::Snapshot {
        meta,
        backend_sha256,
        snapshot_sha256,
    }) = &owner.applied
    {
        kasumi_types::validate_sha256(backend_sha256)?;
        kasumi_types::validate_sha256(snapshot_sha256)?;
        ensure!(
            crate::storage::current_snapshot_id(&meta.snapshot_id),
            "invalid snapshot applied identity"
        );
        let coverage = owner
            .coverage
            .as_ref()
            .context("snapshot cursor lacks selected coverage")?;
        let actual = meta.last_log_id;
        let selected = coverage.meta.last_log_id;
        let order = actual.map(|id| id.index).cmp(&selected.map(|id| id.index));
        ensure!(
            order == actual.cmp(&selected),
            "snapshot applied position ordering differs"
        );
        if order.is_eq() {
            ensure!(
                meta == &coverage.meta
                    && backend_sha256 == &coverage.backend_sha256
                    && snapshot_sha256 == &coverage.snapshot_sha256,
                "snapshot applied cursor differs from selected coverage"
            );
        } else {
            // Installation/Reopen may reconstruct an older application image
            // while preserving independently newer durable Snapshot custody.
            // Its complete identity is retained; it is not relabeled with the
            // selected older image's hashes or fabricated into an Entry.
            ensure!(
                mode == ApplicationSelectionMode::Reconstructing && order.is_gt(),
                "selected snapshot is not exact serving coverage"
            );
        }
    }
    match expected {
        ApplicationBoundaryRef::Bootstrap(image) => {
            ensure!(
                owner.bootstrap().digest == image.sha256()
                    && owner.bootstrap().bytes == image.len(),
                "selected bootstrap image differs"
            );
            ensure!(
                mode == ApplicationSelectionMode::Reconstructing || owner.applied.is_none(),
                "serving bootstrap has applied coverage"
            );
        }
        ApplicationBoundaryRef::Entry(expected) => {
            let cursor = owner.applied.as_ref().context("applied cursor absent")?;
            let actual = cursor.log_id().context("applied cursor has no position")?;
            if actual.index == expected.log_id.index {
                ensure!(
                    actual == expected.log_id,
                    "replayed source log identity differs"
                );
                if let AppliedCursor::Entry(position) = cursor {
                    ensure!(
                        entry_matches(position, expected),
                        "replayed source applied position differs"
                    );
                } else {
                    ensure!(
                        mode == ApplicationSelectionMode::Reconstructing,
                        "serving entry requires its complete entry cursor"
                    );
                }
            } else {
                ensure!(
                    mode == ApplicationSelectionMode::Reconstructing
                        && actual.index > expected.log_id.index,
                    "selected application is not covered by custody"
                );
            }
        }
        ApplicationBoundaryRef::Snapshot(expected) => {
            let coverage = owner
                .coverage
                .as_ref()
                .context("snapshot coverage absent")?;
            ensure!(
                coverage.meta == expected.meta
                    && coverage.backend_sha256 == expected.backend_sha256,
                "selected snapshot context differs"
            );
            let cursor = owner
                .applied
                .as_ref()
                .context("snapshot applied cursor absent")?;
            let actual = cursor.log_id();
            let target = expected.meta.last_log_id;
            ensure!(
                actual.map(|id| id.index).cmp(&target.map(|id| id.index)) == actual.cmp(&target),
                "snapshot applied position ordering differs"
            );
            ensure!(
                actual.map(|id| id.index) >= target.map(|id| id.index),
                "snapshot exceeds applied coverage"
            );
            if actual.map(|id| id.index) == target.map(|id| id.index) {
                ensure!(
                    actual == target,
                    "snapshot applied position identity differs"
                );
                if let AppliedCursor::Entry(position) = cursor {
                    ensure!(
                        mode == ApplicationSelectionMode::Reconstructing
                            && position.membership == expected.meta.last_membership,
                        "snapshot membership differs at the same applied position"
                    );
                }
            } else {
                ensure!(
                    mode == ApplicationSelectionMode::Reconstructing,
                    "serving snapshot has newer applied coverage"
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod fixture;
#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) mod allocation_tests;

#[cfg(test)]
#[path = "selected_application/plan_tests.rs"]
mod plan_tests;

#[cfg(test)]
#[path = "selected_application/receipt_tests.rs"]
mod receipt_tests;

#[cfg(test)]
#[path = "selected_application/handoff_tests.rs"]
mod handoff_tests;

#[cfg(test)]
#[path = "selected_application/planning_session_tests.rs"]
mod planning_session_tests;
