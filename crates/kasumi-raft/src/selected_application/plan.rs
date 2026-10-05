//! Producer-built immutable read/shape bounds. This is a quotation, not funding,
//! a native root reservation, an authorization proof, or a durable publication.
use super::*;
use kasumi_store::{TenantStorageSet, TenantStore, WriteOp};
use sha2::{Digest, Sha256};
use std::sync::Arc;

#[path = "ordinary_envelope.rs"]
mod ordinary_envelope;
pub use ordinary_envelope::PreparedOrdinarySourceEnvelope;
#[path = "constructor_envelope.rs"]
mod constructor_envelope;
pub use constructor_envelope::PreparedSourceCapacityEnvelope;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct RecordPlan {
    bytes: usize,
    digest: Option<[u8; 32]>,
}

// Only the actual custody producer selects this origin. It is distinct from
// whether a later selected source reconstructs an older Entry: exact-current
// replay has CoveredReplay origin while still yielding an exact source proof.
#[derive(Clone, Copy)]
enum AppliedOrigin {
    Advance,
    CoveredReplay,
    // Exact already durable records, used before initial Engine source install.
    CurrentRoot,
}

/// Exact prospective record identities with conservative allocation envelopes.
/// Cloning this fixed-size value allocates no buffer and acquires no capacity.
/// The producer owns all construction; consumers cannot supply arbitrary bounds.
#[derive(Clone)]
pub struct PreparedSelectionPlan {
    application: Arc<TenantStore>,
    custody: Arc<TenantStore>,
    records: [Option<RecordPlan>; 5],
    joint_effects: [u8; 32],
    origin: AppliedOrigin,
    planning_records: [bool; 5],
    point_phases: [(usize, usize, usize); 3],
    peak: u64,
    retained: u64,
}

impl PreparedSelectionPlan {
    /// The test-only primary publisher requires a new canonical Entry. This
    /// checks the actual producer branch, not the selected source's later
    /// reconstruction status, and grants no publication or storage authority.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn require_advancing_entry(&self) -> Result<()> {
        ensure!(
            matches!(self.origin, AppliedOrigin::Advance),
            "primary publication requires an advancing Entry"
        );
        Ok(())
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) const fn applied_cursor_read_spec() -> (&'static str, &'static [u8], usize) {
        (crate::control::META, b"applied", CONTROL_BYTES)
    }

    /// Conservative mandatory selected-read peak for this exact plan. The
    /// metadata quote already includes plaintext/decode/re-encoding. Native
    /// output overlaps plaintext decode, so add the maximum native record phase;
    /// records and table checks are sequential. This acquires no capacity.
    pub fn read_peak_bytes(&self, read: &kasumi_store::PairedReadMemoryQuote) -> Result<u64> {
        read.require_domains(&self.application, &self.custody)?;
        let mut native = 0;
        for (index, record) in self.records.iter().enumerate() {
            if let Some(record) = record {
                let (application, namespace, key, _) = RECORDS[index];
                let point = if application {
                    read.application_get(namespace.len(), key.len(), record.bytes)?
                } else {
                    read.custody_get(namespace.len(), key.len(), record.bytes)?
                };
                native = native.max(point.native_peak_bytes());
            }
        }
        Ok(read.begin_peak_bytes()?.max(
            read.retained_bytes()
                .checked_add(self.peak)
                .and_then(|bytes| bytes.checked_add(native))
                .context("complete selection read quote overflow")?,
        ))
    }
    /// Prior-row reads use one registered root across control validation and
    /// selection. Directory preflight records the actual allocation phases.
    /// This quotes buffers/custody, not PreparedApplied/write DTO allocations.
    pub fn planning_read_peak_bytes(
        &self,
        read: &kasumi_store::PairedReadMemoryQuote,
    ) -> Result<u64> {
        read.require_domains(&self.application, &self.custody)?;
        let mut scratch = 0;
        for (index, read_before_plan) in self.planning_records.iter().enumerate() {
            if *read_before_plan {
                let (application, namespace, key, maximum) = RECORDS[index];
                let point = if application {
                    read.application_get(
                        namespace.len(),
                        key.len(),
                        maximum.min(self.point_phases[2].2),
                    )?
                } else {
                    read.custody_get(
                        namespace.len(),
                        key.len(),
                        maximum.min(self.point_phases[2].2),
                    )?
                };
                scratch = scratch.max(point.peak_bytes()?);
            }
        }
        // Preflight, ordinary control records, optional covered-snapshot
        // records, then final prospective proof. Quote each actual replacement
        // while its previous admitted backing is still owned.
        let mut overlap = read.begin_peak_bytes()?;
        let mut previous = None;
        for bounds in self.point_phases.into_iter().chain([self.point_bounds()]) {
            let backing = read.prepared_point_backing_bytes(bounds.0, bounds.1, bounds.2)?;
            let phase = match previous {
                Some((old_bounds, old_backing)) if old_bounds != bounds => {
                    backing.checked_add(old_backing)
                }
                _ => Some(backing),
            }
            .and_then(|bytes| bytes.checked_add(read.retained_bytes()))
            .context("selection point replacement quote overflow")?;
            overlap = overlap.max(phase);
            previous = Some((bounds, backing));
        }
        Ok(overlap.max(
            read.begin_peak_bytes()?.max(
                read.retained_bytes()
                    .checked_add(scratch)
                    .context("selection planning quote overflow")?,
            ),
        ))
    }
    /// Plaintext, decode, canonical validation and retained DTO peak only.
    /// Native reader/snapshot ownership and enclosing shells are quoted separately.
    #[cfg(test)]
    pub(super) fn planning_phases(&self) -> [(usize, usize, usize); 3] {
        self.point_phases
    }
    pub fn peak_bytes(&self) -> u64 {
        self.peak
    }
    /// Upper bound for successful retained DTO backing, not an extra grant.
    pub fn retained_bytes(&self) -> u64 {
        self.retained
    }
    pub fn require_stores(&self, stores: &TenantStorageSet) -> Result<()> {
        ensure!(
            self.belongs_to(stores),
            "selection plan belongs to another storage pair"
        );
        Ok(())
    }
    pub(crate) fn belongs_to(&self, stores: &TenantStorageSet) -> bool {
        Arc::ptr_eq(&self.application, stores.application())
            && Arc::ptr_eq(&self.custody, stores.custody().store())
    }
    pub(crate) fn joint_effects_fingerprint(&self) -> [u8; 32] {
        self.joint_effects
    }
    pub(crate) fn publication_fingerprint(
        &self,
        producer: [u8; 32],
        context: [u8; 32],
    ) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"kasumi.publication.plan.v1");
        hash.update(producer);
        hash.update(context);
        hash.update(self.joint_effects);
        hash.update([match self.origin {
            AppliedOrigin::Advance => 0,
            AppliedOrigin::CoveredReplay => 1,
            AppliedOrigin::CurrentRoot => 2,
        }]);
        for record in &self.records {
            match record {
                None => hash.update([0]),
                Some(record) => {
                    hash.update([1]);
                    // These private lengths were bounded by the fixed format.
                    hash.update((record.bytes as u64).to_be_bytes());
                    match record.digest {
                        None => hash.update([0]),
                        Some(digest) => {
                            hash.update([1]);
                            hash.update(digest);
                        }
                    }
                }
            }
        }
        for planned in self.planning_records {
            hash.update([u8::from(planned)]);
        }
        for (namespace, key, value) in self.point_phases {
            hash.update((namespace as u64).to_be_bytes());
            hash.update((key as u64).to_be_bytes());
            hash.update((value as u64).to_be_bytes());
        }
        hash.update(self.peak.to_be_bytes());
        hash.update(self.retained.to_be_bytes());
        hash.finalize().into()
    }
    pub(super) fn require_read(&self, read: &SelectionReadIdentity<'_>) -> Result<()> {
        read.require_domains(&self.application, &self.custody)
    }
    pub(super) fn record(
        &self,
        application: bool,
        namespace: &str,
        key: &[u8],
    ) -> Result<RecordPlan> {
        let index =
            record_index(application, namespace, key).context("unplanned selection record")?;
        self.records[index].context("selection record was not quoted")
    }
    /// Quote the exact already durable root before initial source installation.
    /// One registered view owns both extent probes and authenticated row loans.
    /// The later selected capture must match every planned byte and absence.
    /// This is not a prospective snapshot publication or Entry write plan.
    pub fn for_current_root(
        stores: &TenantStorageSet,
    ) -> Result<(Self, kasumi_store::PreparedTenantPointWorkspace)> {
        let initial = initial_point_bounds();
        let mut reads = stores
            .read_view()?
            .prepare_point_reads(initial.0, initial.1, initial.2)?;
        let result = Self::for_current_root_at(stores, &mut reads);
        reads.finish_with_workspace(result)
    }

    fn for_current_root_at(
        stores: &TenantStorageSet,
        reads: &mut kasumi_store::PreparedTenantPointReads,
    ) -> Result<Self> {
        let initial = initial_point_bounds();
        let mut current = initial;
        for (application, namespace, key, maximum) in &RECORDS[..3] {
            let bound = if *application {
                reads.application_value_bound(namespace, key, *maximum)?
            } else {
                reads.custody_value_bound(namespace, key, *maximum)?
            };
            current.2 = current.2.max(bound.unwrap_or(0));
        }
        reads.ensure_capacity(current.0, current.1, current.2)?;
        let mut plan = Self {
            application: stores.application().clone(),
            custody: stores.custody().store().clone(),
            records: [None; 5],
            joint_effects: Sha256::digest(b"kasumi.current-root-selection.v1").into(),
            origin: AppliedOrigin::CurrentRoot,
            planning_records: [true, true, true, false, false],
            point_phases: [initial, current, current],
            peak: 0,
            retained: 0,
        };
        let bootstrap = reads.application_get(
            "engine.bootstrap",
            b"manifest",
            kasumi_store::APPLICATION_BOOTSTRAP_MANIFEST_BYTES.min(current.2),
        )?;
        ensure!(
            bootstrap.is_some(),
            "bootstrap manifest absent during initial selection preparation"
        );
        plan.add(0, bootstrap)?;
        let bootstrap_retained = plan.retained;
        let digest =
            reads.custody_get(META, b"application_bootstrap_sha256", 256.min(current.2))?;
        ensure!(
            digest.is_some(),
            "bootstrap commitment absent during initial selection preparation"
        );
        plan.add(1, digest)?;
        plan.retained = bootstrap_retained;
        let applied = reads.custody_get(META, b"applied", CONTROL_BYTES.min(current.2))?;
        // Canonical externally tagged Snapshot cursors have this exact
        // prefix. Noncanonical/malformed cursors remain rejected by the
        // unchanged admitted typed decoder during actual selection. No DTO
        // is decoded or allocated merely to decide the required row set.
        let snapshot = applied.is_some_and(|bytes| bytes.starts_with(br#"{"Snapshot":"#));
        plan.add(2, applied)?;
        if snapshot {
            plan.planning_records[3] = true;
            plan.planning_records[4] = true;
            for (application, namespace, key, maximum) in &RECORDS[3..] {
                let bound = if *application {
                    reads.application_value_bound(namespace, key, *maximum)?
                } else {
                    reads.custody_value_bound(namespace, key, *maximum)?
                };
                current.2 = current.2.max(bound.unwrap_or(0));
            }
            reads.ensure_capacity(current.0, current.1, current.2)?;
            plan.point_phases[2] = current;
            let coverage =
                reads.custody_get(META, b"snapshot_coverage", CONTROL_BYTES.min(current.2))?;
            plan.add(3, coverage)?;
            let manifest =
                reads.application_get("raft.snapshot", b"current", CONTROL_BYTES.min(current.2))?;
            plan.add(4, manifest)?;
        }
        plan.peak = plan.peak.max(
            plan.retained
                .checked_add(VALIDATION_WORKSPACE)
                .context("initial selection quote overflow")?,
        );
        Ok(plan)
    }

    #[cfg(test)]
    pub(crate) fn for_applied(
        stores: &TenantStorageSet,
        prepared: &crate::control::PreparedApplied,
        application: &[WriteOp],
    ) -> Result<Self> {
        Self::for_applied_prepared(stores, prepared, application).map(|(plan, _)| plan)
    }

    #[cfg(test)]
    pub(crate) fn for_applied_prepared(
        stores: &TenantStorageSet,
        prepared: &crate::control::PreparedApplied,
        application: &[WriteOp],
    ) -> Result<(Self, kasumi_store::PreparedTenantPointWorkspace)> {
        let planning_records = match prepared {
            crate::control::PreparedApplied::Advance(_) => [true, true, false, false, false],
            crate::control::PreparedApplied::CoveredReplay { snapshot } => {
                [true, true, true, *snapshot, *snapshot]
            }
        };
        let bounds = planning_bounds(&planning_records);
        let mut reads = stores
            .read_view()?
            .prepare_point_reads(bounds.0, bounds.1, bounds.2)?;
        let result = Self::for_applied_at(stores, prepared, application, &mut reads, [bounds; 3]);
        reads.finish_with_workspace(result)
    }

    pub(crate) fn for_applied_at(
        stores: &TenantStorageSet,
        prepared: &crate::control::PreparedApplied,
        application: &[WriteOp],
        reads: &mut kasumi_store::PreparedTenantPointReads,
        point_phases: [(usize, usize, usize); 3],
    ) -> Result<Self> {
        // These identities are immutable or producer-owned. An application
        // callback may not substitute a proof record behind this quotation.
        for write in application {
            let (namespace, key) = match write {
                WriteOp::Put { namespace, key, .. } | WriteOp::Delete { namespace, key } => {
                    (namespace, key)
                }
            };
            ensure!(
                record_index(true, namespace, key).is_none(),
                "application write overlaps selection identity"
            );
        }
        let planning_records = match prepared {
            crate::control::PreparedApplied::Advance(_) => [true, true, false, false, false],
            crate::control::PreparedApplied::CoveredReplay { snapshot } => {
                [true, true, true, *snapshot, *snapshot]
            }
        };
        let mut plan = Self {
            application: stores.application().clone(),
            custody: stores.custody().store().clone(),
            records: [None; 5],
            joint_effects: crate::apply_publication::receipt::joint_effects_fingerprint(
                application,
                prepared.custody_writes(),
            )?,
            origin: match prepared {
                crate::control::PreparedApplied::Advance(_) => AppliedOrigin::Advance,
                crate::control::PreparedApplied::CoveredReplay { .. } => {
                    AppliedOrigin::CoveredReplay
                }
            },
            planning_records,
            point_phases,
            peak: 0,
            retained: 0,
        };
        let bootstrap = reads.application_get(
            "engine.bootstrap",
            b"manifest",
            kasumi_store::APPLICATION_BOOTSTRAP_MANIFEST_BYTES.min(point_phases[2].2),
        )?;
        ensure!(
            bootstrap.is_some(),
            "bootstrap manifest absent during selection preparation"
        );
        plan.add(0, bootstrap)?;
        let bootstrap_retained = plan.retained;
        let digest = reads.custody_get(
            META,
            b"application_bootstrap_sha256",
            256.min(point_phases[2].2),
        )?;
        ensure!(
            digest.is_some(),
            "bootstrap commitment absent during selection preparation"
        );
        plan.add(1, digest)?;
        plan.retained = bootstrap_retained;
        match prepared {
            crate::control::PreparedApplied::Advance(writes) => {
                let bytes = writes
                    .iter()
                    .find_map(|write| match write {
                        WriteOp::Put {
                            namespace,
                            key,
                            value,
                        } if namespace == META && key == b"applied" => Some(value.as_slice()),
                        _ => None,
                    })
                    .context("prepared applied cursor absent")?;
                plan.add(2, Some(bytes))?;
            }
            crate::control::PreparedApplied::CoveredReplay { snapshot } => {
                plan.planning_records[2] = true;
                let applied =
                    reads.custody_get(META, b"applied", CONTROL_BYTES.min(point_phases[2].2))?;
                plan.add(2, applied)?;
                if *snapshot {
                    plan.planning_records[3] = true;
                    plan.planning_records[4] = true;
                    let coverage = reads.custody_get(
                        META,
                        b"snapshot_coverage",
                        CONTROL_BYTES.min(point_phases[2].2),
                    )?;
                    plan.add(3, coverage)?;
                    let manifest = reads.application_get(
                        "raft.snapshot",
                        b"current",
                        CONTROL_BYTES.min(point_phases[2].2),
                    )?;
                    plan.add(4, manifest)?;
                }
            }
        }
        plan.peak = plan.peak.max(
            plan.retained
                .checked_add(VALIDATION_WORKSPACE)
                .context("selection quote overflow")?,
        );
        let (namespace, key, value) = plan.point_bounds();
        reads.ensure_capacity(namespace, key, value)?;
        Ok(plan)
    }

    fn point_bounds(&self) -> (usize, usize, usize) {
        let mut bounds = self.point_phases[2];
        for (record, (_, namespace, key, _)) in self.records.iter().zip(RECORDS) {
            if let Some(record) = record {
                bounds.0 = bounds.0.max(namespace.len());
                bounds.1 = bounds.1.max(key.len());
                bounds.2 = bounds.2.max(record.bytes);
            }
        }
        bounds
    }

    /// Prepaid point backing retained through queued begin and metadata decode.
    /// The existing metadata envelope remains conservative for ordinary reads.
    pub fn prepared_read_peak_bytes(
        &self,
        read: &kasumi_store::PairedReadMemoryQuote,
    ) -> Result<u64> {
        read.require_domains(&self.application, &self.custody)?;
        let (namespace, key, value) = self.point_bounds();
        let backing = read.prepared_point_backing_bytes(namespace, key, value)?;
        read.begin_peak_bytes()?
            .checked_add(backing)
            .and_then(|bytes| bytes.checked_add(self.peak))
            .context("prepared selection read quote overflow")
    }

    fn add(&mut self, index: usize, bytes: Option<&[u8]>) -> Result<()> {
        let (application, namespace, key, maximum) = RECORDS[index];
        let len = bytes.map_or(0, <[u8]>::len);
        ensure!(
            len <= maximum,
            "prospective selection record exceeds format limit"
        );
        let tenant = if application {
            self.application.tenant()
        } else {
            self.custody.tenant()
        };
        let quote = bytes.map(allocation::canonical_wire_quote).transpose()?;
        let (extra, retained) = record_allocation(tenant.len(), namespace, key, len, quote)?;
        self.peak = self.peak.max(
            self.retained
                .checked_add(extra)
                .context("selection quote overflow")?,
        );
        self.retained = self
            .retained
            .checked_add(retained)
            .context("selection quote overflow")?;
        self.records[index] = Some(RecordPlan {
            bytes: len,
            digest: bytes.map(|bytes| Sha256::digest(bytes).into()),
        });
        Ok(())
    }
}
fn initial_point_bounds() -> (usize, usize, usize) {
    (
        "engine.bootstrap".len(),
        b"application_bootstrap_sha256".len(),
        0,
    )
}

impl RecordPlan {
    pub(super) fn limit(&self) -> usize {
        self.bytes
    }
    pub(super) fn verify(&self, bytes: Option<&[u8]>) -> Result<()> {
        ensure!(
            bytes.map(|bytes| <[u8; 32]>::from(Sha256::digest(bytes))) == self.digest
                && bytes.is_none_or(|bytes| bytes.len() == self.bytes),
            "selected record differs from prospective publication"
        );
        Ok(())
    }
}
#[cfg(test)]
fn planning_bounds(planning: &[bool; 5]) -> (usize, usize, usize) {
    let mut bounds = (0, 0, 0);
    for (planned, (_, namespace, key, value)) in planning.iter().zip(RECORDS) {
        if *planned {
            bounds.0 = bounds.0.max(namespace.len());
            bounds.1 = bounds.1.max(key.len());
            bounds.2 = bounds.2.max(value);
        }
    }
    bounds
}

const RECORDS: [(bool, &str, &[u8], usize); 5] = [
    (
        true,
        "engine.bootstrap",
        b"manifest",
        kasumi_store::APPLICATION_BOOTSTRAP_MANIFEST_BYTES,
    ),
    (false, META, b"application_bootstrap_sha256", 256),
    (false, META, b"applied", CONTROL_BYTES),
    (false, META, b"snapshot_coverage", CONTROL_BYTES),
    (true, "raft.snapshot", b"current", CONTROL_BYTES),
];
fn record_index(application: bool, namespace: &str, key: &[u8]) -> Option<usize> {
    RECORDS
        .iter()
        .position(|&(app, ns, k, _)| app == application && ns == namespace && k == key)
}

// Shared by exact producer plans and ordinary source shape quotations. A shape
// quote grants no record identity or allocation; the actual caller owns funding.
fn record_allocation(
    tenant_bytes: usize,
    namespace: &str,
    key: &[u8],
    len: usize,
    quote: Option<allocation::Quote>,
) -> Result<(u64, u64)> {
    let plaintext =
        kasumi_store::plaintext_get_workspace_bytes(tenant_bytes, namespace.len(), key.len(), len)?;
    let mut extra = plaintext;
    let mut retained = 0;
    if let Some(quote) = quote {
        retained = quote.retained;
        extra = extra
            .max(allocation::preflight_bytes(len)?)
            .max(quote.peak)
            .max(
                quote
                    .retained
                    .checked_add(allocation::encode_workspace(len, len as u64)?)
                    .context("selection quote overflow")?,
            );
    }
    Ok((extra, retained))
}
