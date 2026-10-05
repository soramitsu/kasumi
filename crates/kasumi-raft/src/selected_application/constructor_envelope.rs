//! Closed capacity coverage for actual constructor state and its complete
//! retained tail. This is quotation, not accepted predecessor/append authority.
use super::*;
use crate::storage::retained_logs::{HEADER_BYTES, HeaderFold};
use kasumi_store::{PreparedTenantPointReads, PreparedTenantPointWorkspace};

/// Ordinary shape maxima plus one exact producer-owned reconstruction seed.
/// A large allocation envelope alone never authorizes CoveredReplay. The actor
/// separately owns accepted predecessor, entry IDs and eventual flush custody.
#[derive(Clone)]
pub struct PreparedSourceCapacityEnvelope {
    ordinary: PreparedOrdinarySourceEnvelope,
    reconstruction: PreparedSelectionPlan,
    retained_header_bytes: usize,
    retained_body_bytes: usize,
    peak: u64,
    retained: u64,
    point_bounds: (usize, usize, usize),
}

impl PreparedSourceCapacityEnvelope {
    /// Prepare before any replay or actor mutation, using the actual bootstrap
    /// image and one registered root for current proof and every retained header.
    /// This includes the accepted, uncommitted suffix: later commitment need not
    /// append another entry. The existing full LogStore validation remains
    /// mandatory before Raft::new; this fold is shape coverage only. Construction
    /// must install the actor gate before allowing an intervening append.
    ///
    /// The caller's existing workspace is consumed and returned. Original
    /// failures retain that exact grant in SelectionFailure, and native/point
    /// retirement failures retain their canonical registered custody.
    pub fn for_constructor<W: SelectionWorkspace>(
        stores: &TenantStorageSet,
        bootstrap: &SnapshotImage,
        limits: &RaftLimits,
        workspace: W,
    ) -> std::result::Result<(Self, PreparedTenantPointWorkspace, W), SelectionFailure<W>> {
        let initial = initial_point_bounds();
        let reads = stores
            .read_view()
            .and_then(|view| view.prepare_point_reads(initial.0, initial.1, initial.2));
        let mut reads = match reads {
            Ok(reads) => reads,
            Err(original) => {
                return Err(SelectionFailure {
                    original,
                    _workspace: workspace,
                });
            }
        };
        let plan = match PreparedSelectionPlan::for_current_root_at(stores, &mut reads) {
            Ok(plan) => plan,
            Err(original) => {
                return Err(finish_failure(
                    reads,
                    SelectionFailure {
                        original,
                        _workspace: workspace,
                    },
                ));
            }
        };
        let mut selected = match selected_application_at_inner(
            SelectedReads::Prepared(&mut reads),
            ApplicationBoundaryRef::Bootstrap(bootstrap),
            ApplicationSelectionMode::Reconstructing,
            limits,
            workspace,
            Some(plan.clone()),
        ) {
            Ok(selected) => selected,
            Err(failure) => return Err(finish_failure(reads, failure)),
        };
        let result = (|| {
            let empty = StoredMembership::default();
            let membership = match selected.applied.as_ref() {
                None => &empty,
                Some(AppliedCursor::Entry(position)) => &position.membership,
                Some(AppliedCursor::Snapshot { meta, .. }) => &meta.last_membership,
            };
            let ordinary = PreparedOrdinarySourceEnvelope::for_membership(
                stores,
                selected.bootstrap(),
                membership,
            )?;
            let mut scan = ConstructorFold {
                selected: &mut selected,
                ordinary,
                headers: HeaderFold::default(),
                plaintext: 0,
                header_bytes: 0,
                body_bytes: 0,
            };
            reads.custody_visit_with_workspace(
                crate::control::HEADERS,
                HEADER_BYTES,
                &mut scan,
                |scan, bytes| {
                    scan.plaintext = bytes;
                    scan.selected.reserve(bytes)
                },
                |scan, bounds, key, bytes| scan.observe(bounds, key, bytes),
            )?;
            scan.headers.finish()?;
            let mut envelope = Self {
                ordinary: scan.ordinary,
                reconstruction: plan,
                retained_header_bytes: scan.header_bytes,
                retained_body_bytes: scan.body_bytes,
                peak: 0,
                retained: 0,
                point_bounds: (0, 0, 0),
            };
            envelope.grow_high_water();
            Ok(envelope)
        })();
        let envelope = match result {
            Ok(envelope) => envelope,
            Err(original) => return Err(finish_failure(reads, selected.into_failure(original))),
        };
        let SelectedApplicationPosition {
            bootstrap,
            applied,
            coverage,
            manifest,
            mut workspace,
            ..
        } = selected;
        // Every current DTO and header has retired under its original peak
        // before reducing the actual grant or transferring point backing.
        drop((bootstrap, applied, coverage, manifest));
        if let Err(original) = workspace.retain(0) {
            return Err(finish_failure(
                reads,
                SelectionFailure {
                    original,
                    _workspace: workspace,
                },
            ));
        }
        let bounds = envelope.point_bounds();
        if let Err(original) = reads.ensure_capacity(bounds.0, bounds.1, bounds.2) {
            return Err(finish_failure(
                reads,
                SelectionFailure {
                    original,
                    _workspace: workspace,
                },
            ));
        }
        match reads.finish_with_workspace(Ok(envelope)) {
            Ok((envelope, points)) => Ok((envelope, points, workspace)),
            Err(original) => Err(SelectionFailure {
                original,
                _workspace: workspace,
            }),
        }
    }

    pub fn require_stores(&self, stores: &TenantStorageSet) -> Result<()> {
        self.ordinary.require_stores(stores)
    }

    /// Advancing ordinary rows use their derived shape. Reconstruction must
    /// match the exact final record identities captured by this producer seed;
    /// unrelated same-sized snapshots/cursors are not interchangeable.
    pub fn require_plan(&self, plan: &PreparedSelectionPlan) -> Result<()> {
        ensure!(
            Arc::ptr_eq(&self.reconstruction.application, &plan.application)
                && Arc::ptr_eq(&self.reconstruction.custody, &plan.custody),
            "source capacity plan belongs to another storage pair"
        );
        if matches!(plan.origin, AppliedOrigin::Advance) {
            return self.ordinary.require_plan(plan);
        }
        ensure!(
            matches!(
                plan.origin,
                AppliedOrigin::CurrentRoot | AppliedOrigin::CoveredReplay
            ) && plan.records == self.reconstruction.records,
            "source reconstruction differs from producer seed"
        );
        ensure!(
            plan.peak <= self.peak_bytes() && plan.retained <= self.retained_bytes(),
            "source reconstruction exceeds funded shape"
        );
        Ok(())
    }

    /// Pure prospective ordinary shape growth. This does not adopt capacity,
    /// replace the exact reconstruction seed or accept an actor predecessor.
    pub fn with_membership(&self, membership: &StoredMembership<u64, BasicNode>) -> Result<Self> {
        let mut next = self.clone();
        next.ordinary = self.ordinary.with_membership(membership)?;
        next.grow_high_water();
        Ok(next)
    }

    /// Pure capacity growth for every actual incoming membership, including
    /// intermediate joint configurations followed by a smaller final shape.
    /// Assigned log identities and actor predecessor acceptance remain owned
    /// by the caller's producer certificate; this does not replace the exact
    /// replay seed or quote incoming log-lookup body/decode backing.
    pub fn with_entries(&self, entries: &[crate::Entry<crate::TypeConfig>]) -> Result<Self> {
        let mut next = self.clone();
        for entry in entries {
            if let openraft::EntryPayload::Membership(membership) = &entry.payload {
                next.ordinary = next.ordinary.with_membership_shape(membership)?;
            }
        }
        next.grow_high_water();
        Ok(next)
    }

    /// Prepare the exact next replay seed from an opaque actual producer plan.
    /// This remains quotation: only the actor's accepted predecessor/flush token
    /// may adopt it, after funding all old/new overlap. Capacity growth alone
    /// cannot manufacture a seed, and the current envelope remains unchanged.
    pub fn with_publication_plan(&self, plan: &PreparedSelectionPlan) -> Result<Self> {
        self.require_plan(plan)?;
        let mut next = self.clone();
        next.reconstruction = plan.clone();
        next.grow_high_water();
        Ok(next)
    }

    /// Header wire bytes are authenticated observations. Body bounds are exact
    /// root directory extents only; later lookup must authenticate/decode and
    /// verify the original header/body commitment before returning any LogId.
    pub fn retained_lookup_bounds(&self) -> (usize, usize) {
        (self.retained_header_bytes, self.retained_body_bytes)
    }

    pub fn peak_bytes(&self) -> u64 {
        self.peak
    }
    pub fn retained_bytes(&self) -> u64 {
        self.retained
    }
    pub fn point_bounds(&self) -> (usize, usize, usize) {
        self.point_bounds
    }
    fn grow_high_water(&mut self) {
        self.peak = self
            .peak
            .max(self.ordinary.peak_bytes())
            .max(self.reconstruction.peak);
        self.retained = self
            .retained
            .max(self.ordinary.retained_bytes())
            .max(self.reconstruction.retained);
        let ordinary = self.ordinary.point_bounds();
        let bounds = &mut self.point_bounds;
        bounds.0 = bounds.0.max(ordinary.0);
        bounds.1 = bounds.1.max(ordinary.1);
        bounds.2 = bounds.2.max(ordinary.2);
        for (record, (_, namespace, key, _)) in self.reconstruction.records.iter().zip(RECORDS) {
            if let Some(record) = record {
                bounds.0 = bounds.0.max(namespace.len());
                bounds.1 = bounds.1.max(key.len());
                bounds.2 = bounds.2.max(record.bytes);
            }
        }
    }
}

struct ConstructorFold<'a, W: SelectionWorkspace> {
    selected: &'a mut SelectedApplicationPosition<W>,
    ordinary: PreparedOrdinarySourceEnvelope,
    headers: HeaderFold,
    plaintext: u64,
    header_bytes: usize,
    body_bytes: usize,
}
impl<W: SelectionWorkspace> ConstructorFold<'_, W> {
    fn reserve(&mut self, extra: u64) -> Result<()> {
        self.selected.reserve(
            self.plaintext
                .checked_add(extra)
                .context("constructor header workspace overflow")?,
        )
    }
    fn observe(
        &mut self,
        bounds: &mut kasumi_store::PreparedTenantPointBounds<'_>,
        key: &[u8],
        bytes: &[u8],
    ) -> Result<()> {
        let index = u64::from_be_bytes(key.try_into().context("invalid raft index key")?);
        // The header owns the same membership containers as selected cursors,
        // plus a byte Vec for the opaque initialization certificate. That Vec
        // has one scalar token per byte, beneath the existing per-token bound.
        self.reserve(allocation::preflight_bytes(bytes.len())?)?;
        let quote = allocation::decode_quote(bytes)?;
        self.reserve(quote.peak)?;
        let header: crate::control::LogHeader =
            crate::control::decode_canonical_admitted(bytes, |header| {
                let encoded = allocation::canonical_bytes(header)?;
                self.reserve(
                    quote
                        .retained
                        .checked_add(allocation::encode_workspace(bytes.len(), encoded)?)
                        .context("constructor header canonical quote overflow")?,
                )
            })?;
        self.headers.observe_id(index, header.log_id)?;
        self.header_bytes = self.header_bytes.max(bytes.len());
        let body = if matches!(
            header.payload,
            crate::control::HeaderPayload::Custody { .. }
        ) {
            bounds.custody_value_bound(crate::storage::CUSTODY_LOG, key, HEADER_BYTES)?
        } else {
            bounds.application_value_bound("raft.log", key, HEADER_BYTES)?
        };
        // Metadata entries are reconstructed from their canonical header by the
        // existing reader; missing body records do not change that supported
        // path. Normal payloads still require their actual selected body extent.
        let body = if matches!(
            header.payload,
            crate::control::HeaderPayload::Blank | crate::control::HeaderPayload::Membership(_)
        ) {
            body.unwrap_or(0)
        } else {
            body.context("missing retained raft body during constructor preparation")?
        };
        self.body_bytes = self.body_bytes.max(body);

        if let crate::control::HeaderPayload::Membership(membership) = &header.payload {
            self.ordinary = self.ordinary.with_membership_shape(membership)?;
        }
        // Initialization signatures and command/body semantics remain with the
        // mandatory full LogStore validator. This exact authenticated fold
        // grants only membership shape coverage, never acceptance authority.
        Ok(())
    }
}

fn finish_failure<W: SelectionWorkspace>(
    reads: PreparedTenantPointReads,
    failure: SelectionFailure<W>,
) -> SelectionFailure<W> {
    let SelectionFailure {
        original,
        _workspace,
    } = failure;
    let original = reads
        .finish::<()>(Err(original))
        .expect_err("constructor failure remains failed");
    SelectionFailure {
        original,
        _workspace,
    }
}

#[cfg(test)]
#[path = "constructor_envelope_tests.rs"]
mod tests;
