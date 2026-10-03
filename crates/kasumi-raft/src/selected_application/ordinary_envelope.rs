//! Pure capacity coverage for ordinary bootstrap/current-root and advancing
//! Entry selection. This never admits, adopts, authenticates or publishes a root.
use super::*;
use openraft::{CommittedLeaderId, Membership};

/// A pair-bound quotation derived from actual bootstrap and membership DTOs.
/// Scalar positions reserve every supported u64 digit width. Membership node
/// addresses, joint sets and map keys retain their actual canonical shape.
/// The owner must fund any expanded quote, including overlap, before adoption.
#[derive(Clone)]
pub struct PreparedOrdinarySourceEnvelope {
    application: Arc<TenantStore>,
    custody: Arc<TenantStore>,
    bootstrap: [RecordPlan; 2],
    bootstrap_peak: u64,
    bootstrap_retained: u64,
    entry_bytes: usize,
    peak: u64,
    retained: u64,
}

// Borrowed views mirror the existing canonical DTO fields; the tests compare
// their serialization against the actual AppliedCursor/StoredMembership DTOs.
// No membership is cloned to quote it, and no synthetic DTO becomes authority.
#[derive(Serialize)]
struct MembershipShape<'a> {
    log_id: Option<LogId<u64>>,
    membership: &'a Membership<u64, BasicNode>,
}
#[derive(Serialize)]
struct EntryShape<'a> {
    log_id: LogId<u64>,
    previous: Option<LogId<u64>>,
    membership: MembershipShape<'a>,
    command_sha256: &'a str,
}
#[derive(Serialize)]
enum CursorShape<'a> {
    Entry(EntryShape<'a>),
}
const HASH_SHAPE: &str = "0000000000000000000000000000000000000000000000000000000000000000";

impl PreparedOrdinarySourceEnvelope {
    /// Quote actual immutable bootstrap metadata and one actual membership.
    /// A caller-supplied DTO supplies shape only; require_plan and the canonical
    /// selected-source validator still check the real publication and identity.
    pub fn for_membership(
        stores: &TenantStorageSet,
        bootstrap: &ApplicationBootstrapManifest,
        membership: &StoredMembership<u64, BasicNode>,
    ) -> Result<Self> {
        ensure!(
            bootstrap.format == 2
                && bootstrap.bytes > 0
                && bootstrap.chunks
                    == bootstrap
                        .bytes
                        .div_ceil(kasumi_store::APPLICATION_BOOTSTRAP_CHUNK_BYTES as u64),
            "invalid ordinary bootstrap shape"
        );
        kasumi_types::validate_sha256(&bootstrap.digest)?;
        let (manifest_bytes, manifest_quote, manifest_digest) =
            allocation::serialized_quote(bootstrap)?;
        let (commitment_bytes, commitment_quote, commitment_digest) =
            allocation::serialized_quote(&bootstrap.digest)?;
        ensure!(
            manifest_bytes <= RECORDS[0].3 && commitment_bytes <= RECORDS[1].3,
            "ordinary bootstrap shape exceeds format limit"
        );
        let (manifest_peak, manifest_retained) = record_allocation(
            stores.application().tenant().len(),
            RECORDS[0].1,
            RECORDS[0].2,
            manifest_bytes,
            Some(manifest_quote),
        )?;
        let (commitment_peak, _) = record_allocation(
            stores.custody().store().tenant().len(),
            RECORDS[1].1,
            RECORDS[1].2,
            commitment_bytes,
            Some(commitment_quote),
        )?;
        // The decoded commitment is verified then retired before the applied
        // cursor, exactly as in PreparedSelectionPlan::add's caller.
        let bootstrap_peak = manifest_peak.max(
            manifest_retained
                .checked_add(commitment_peak)
                .context("ordinary bootstrap quote overflow")?,
        );
        let seed = Self {
            application: stores.application().clone(),
            custody: stores.custody().store().clone(),
            bootstrap: [
                RecordPlan {
                    bytes: manifest_bytes,
                    digest: Some(manifest_digest),
                },
                RecordPlan {
                    bytes: commitment_bytes,
                    digest: Some(commitment_digest),
                },
            ],
            bootstrap_peak,
            bootstrap_retained: manifest_retained,
            entry_bytes: 0,
            peak: bootstrap_peak,
            retained: manifest_retained,
        };
        seed.with_membership(membership)
    }

    /// Expand a quotation from another actual producer membership. This does
    /// not replace an installed envelope or acquire its required capacity.
    pub fn with_membership(&self, membership: &StoredMembership<u64, BasicNode>) -> Result<Self> {
        self.with_membership_shape(membership.membership())
    }

    pub(super) fn with_membership_shape(
        &self,
        membership: &Membership<u64, BasicNode>,
    ) -> Result<Self> {
        let maximum = LogId::new(CommittedLeaderId::new(u64::MAX, u64::MAX), u64::MAX);
        let shape = CursorShape::Entry(EntryShape {
            log_id: maximum,
            previous: Some(maximum),
            membership: MembershipShape {
                log_id: Some(maximum),
                membership,
            },
            command_sha256: HASH_SHAPE,
        });
        let (bytes, quote, _) = allocation::serialized_quote(&shape)?;
        let (extra, retained) = record_allocation(
            self.custody.tenant().len(),
            RECORDS[2].1,
            RECORDS[2].2,
            bytes,
            Some(quote),
        )?;
        let retained = self
            .bootstrap_retained
            .checked_add(retained)
            .context("ordinary retained quote overflow")?;
        let peak = self
            .bootstrap_peak
            .max(
                self.bootstrap_retained
                    .checked_add(extra)
                    .context("ordinary selection quote overflow")?,
            )
            .max(
                retained
                    .checked_add(VALIDATION_WORKSPACE)
                    .context("ordinary validation quote overflow")?,
            );
        let mut expanded = self.clone();
        // A digit-width upper bound can cross the existing format ceiling by a
        // few bytes. Quote the full conservative metadata shape while capping
        // actual point backing at the unchanged writer/decoder format limit.
        expanded.entry_bytes = expanded.entry_bytes.max(bytes.min(CONTROL_BYTES));
        expanded.peak = expanded.peak.max(peak);
        expanded.retained = expanded.retained.max(retained);
        Ok(expanded)
    }

    /// Combine two already derived quotations for the same immutable pair and
    /// bootstrap. Funding the combined/overlapping owners remains the caller's job.
    pub fn merge(&self, other: &Self) -> Result<Self> {
        ensure!(
            Arc::ptr_eq(&self.application, &other.application)
                && Arc::ptr_eq(&self.custody, &other.custody)
                && self
                    .bootstrap
                    .iter()
                    .zip(other.bootstrap)
                    .all(|(a, b)| a.bytes == b.bytes && a.digest == b.digest),
            "ordinary source envelopes differ in pair or bootstrap"
        );
        let mut merged = self.clone();
        merged.entry_bytes = merged.entry_bytes.max(other.entry_bytes);
        merged.peak = merged.peak.max(other.peak);
        merged.retained = merged.retained.max(other.retained);
        Ok(merged)
    }
    pub fn require_stores(&self, stores: &TenantStorageSet) -> Result<()> {
        ensure!(
            Arc::ptr_eq(&self.application, stores.application())
                && Arc::ptr_eq(&self.custody, stores.custody().store()),
            "ordinary source envelope belongs to another storage pair"
        );
        Ok(())
    }
    /// Check the actual producer plan before accepting its ordinary handoff.
    /// Covered reconstruction and snapshot plans need a separately admitted
    /// path; similar wire length does not make their producer origin ordinary.
    pub fn require_plan(&self, plan: &PreparedSelectionPlan) -> Result<()> {
        ensure!(
            Arc::ptr_eq(&self.application, &plan.application)
                && Arc::ptr_eq(&self.custody, &plan.custody),
            "ordinary source plan belongs to another storage pair"
        );
        ensure!(
            matches!(
                plan.origin,
                AppliedOrigin::Advance | AppliedOrigin::CurrentRoot
            ) && plan.records[3..].iter().all(Option::is_none)
                && !plan.planning_records[3]
                && !plan.planning_records[4],
            "ordinary source envelope excludes covered or snapshot reconstruction"
        );
        for (planned, expected) in plan.records[..2].iter().zip(self.bootstrap) {
            ensure!(
                planned.is_some_and(
                    |record| record.bytes == expected.bytes && record.digest == expected.digest
                ),
                "ordinary source bootstrap identity differs"
            );
        }
        let bounds = self.point_bounds();
        // Prior planning buffers may include directory/key-ID extent slack or
        // unrelated control reads. Standing capture consumes only these exact
        // final authenticated rows; their planner custody is funded separately.
        let final_rows_fit =
            plan.records
                .iter()
                .zip(RECORDS)
                .all(|(record, (_, namespace, key, _))| {
                    record.is_none_or(|record| {
                        namespace.len() <= bounds.0
                            && key.len() <= bounds.1
                            && record.bytes <= bounds.2
                    })
                });
        ensure!(
            final_rows_fit && plan.peak <= self.peak && plan.retained <= self.retained,
            "ordinary source plan exceeds funded shape"
        );
        Ok(())
    }
    pub fn peak_bytes(&self) -> u64 {
        self.peak
    }
    pub fn retained_bytes(&self) -> u64 {
        self.retained
    }
    /// Plaintext bounds for the actual canonical prepared encrypted constructor.
    /// That constructor still derives encryption/key/provider overhead itself.
    pub fn point_bounds(&self) -> (usize, usize, usize) {
        (
            RECORDS[..3].iter().map(|row| row.1.len()).max().unwrap(),
            RECORDS[..3].iter().map(|row| row.2.len()).max().unwrap(),
            self.entry_bytes
                .max(self.bootstrap[0].bytes)
                .max(self.bootstrap[1].bytes),
        )
    }
}

#[cfg(test)]
#[path = "ordinary_envelope_tests.rs"]
mod tests;
