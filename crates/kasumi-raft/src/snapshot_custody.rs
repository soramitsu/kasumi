//! Portable closed retirement input carried by Raft snapshots. Publication
//! rebinds it to the receiver's custody catalog; it never copies another node's
//! key authority or grants current administrative access.
use crate::control::{
    self, AppliedCursor, LogHeader, META, RetainedSeed, RetiredBoundary, SEEDS, load,
};
use crate::{
    BasicNode, RaftCommand, RetiredSnapshotState, RetirementLogSeed, TypeConfig, command::sha256,
};
use anyhow::{Context, Result, ensure};
use kasumi_store::{TenantStorageSet, TenantStore, WriteOp};
use openraft::{Entry, EntryPayload, SnapshotMeta};
use serde::{Deserialize, Serialize};

const MAX_SNAPSHOT_CUSTODY_BYTES: usize = 2 << 20;
const PROJECTION: &[u8] = b"snapshot_retirement";

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SnapshotRetirement {
    state: RetiredSnapshotState,
    boundary: RetiredBoundary,
    header: LogHeader,
    seed: Vec<u8>,
    bootstrap_sha256: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Projection {
    meta: SnapshotMeta<u64, BasicNode>,
    snapshot_sha256: String,
    retirement: SnapshotRetirement,
}

impl SnapshotRetirement {
    fn validate(&self, meta: &SnapshotMeta<u64, BasicNode>) -> Result<()> {
        ensure!(
            self.seed.len() <= crate::MAX_RETIREMENT_SEED_BYTES,
            "snapshot retirement seed quota exceeded"
        );
        // Reject oversized metadata without allocating a second JSON copy of a
        // hostile snapshot. Actual publication allocates only after this bound.
        struct QuotaWriter(usize);
        impl std::io::Write for QuotaWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0 = self
                    .0
                    .checked_sub(bytes.len())
                    .ok_or_else(|| std::io::Error::other("snapshot custody quota exceeded"))?;
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        serde_json::to_writer(QuotaWriter(MAX_SNAPSHOT_CUSTODY_BYTES), self)?;
        self.state.validate(meta)?;
        kasumi_types::validate_sha256(&self.bootstrap_sha256)?;
        self.header.validate()?;
        let seed = RetirementLogSeed::decode(&self.seed)?;
        let entry: Entry<TypeConfig> = Entry {
            log_id: self.header.log_id,
            payload: EntryPayload::Normal(RaftCommand::retirement(
                seed.reconstructed_command()?,
                seed.clone(),
            )?),
        };
        self.header
            .check_entry(&entry, &crate::storage::encode_entry(&entry)?)?;
        let revision = seed
            .source()
            .revision_base
            .checked_add(self.header.log_id.index)
            .context("retirement revision overflow")?;
        seed.validate_receipt(revision, &self.boundary.receipt)?;
        ensure!(
            self.header.log_id == self.boundary.position.log_id
                && self.header.log_id.index
                    <= meta
                        .last_log_id
                        .context("retirement snapshot has no log coverage")?
                        .index
                && self.header.log_id <= meta.last_log_id.expect("checked snapshot position")
                && self.boundary.position.command_sha256 == seed.command_sha256()
                && self.boundary.seed_sha256 == sha256(&self.seed)
                && self.boundary.request == *seed.request()
                && self.state.request == self.boundary.request
                && self.state.receipt == self.boundary.receipt
                && self.state.revision_base == seed.source().revision_base,
            "snapshot retirement seed/applied boundary differs"
        );
        Ok(())
    }
    fn check_installation(&self, domains: &TenantStorageSet) -> Result<()> {
        let control = domains.custody().store();
        let source = &self.state.receipt;
        ensure!(
            domains.custody().binding().tenant() == source.tenant
                && load::<String>(control, META, b"group")?.as_deref()
                    == Some(format!("{}/{}", source.tenant, source.source_incarnation).as_str())
                && load::<String>(control, META, b"application_bootstrap_sha256")?.as_ref()
                    == Some(&self.bootstrap_sha256),
            "snapshot custody source/bootstrap differs from installed tenant"
        );
        Ok(())
    }
    fn local_seed(&self, domains: &TenantStorageSet) -> Result<RetainedSeed> {
        Ok(RetainedSeed {
            header: self.header.clone(),
            seed: self.seed.clone(),
            bootstrap_sha256: self.bootstrap_sha256.clone(),
            storage_binding_sha256: domains.custody().binding().digest()?,
        })
    }
}

pub(crate) fn capture(
    domains: &TenantStorageSet,
    meta: &SnapshotMeta<u64, BasicNode>,
    state: Option<RetiredSnapshotState>,
) -> Result<Option<SnapshotRetirement>> {
    let Some(state) = state else {
        return Ok(None);
    };
    let boundary = control::retired_boundary(domains.custody())?
        .context("retired snapshot lacks accepted custody boundary")?;
    let retained: RetainedSeed = load(
        domains.custody().store(),
        SEEDS,
        &boundary.position.log_id.index.to_be_bytes(),
    )?
    .context("retired snapshot lacks original seed")?;
    let retirement = SnapshotRetirement {
        state,
        boundary,
        header: retained.header,
        seed: retained.seed,
        bootstrap_sha256: retained.bootstrap_sha256,
    };
    retirement.validate(meta)?;
    retirement.check_installation(domains)?;
    Ok(Some(retirement))
}

pub(crate) fn check_backend(
    meta: &SnapshotMeta<u64, BasicNode>,
    retirement: Option<&SnapshotRetirement>,
    actual: Option<RetiredSnapshotState>,
) -> Result<()> {
    match (retirement, actual) {
        (None, None) => Ok(()),
        (Some(retirement), Some(actual)) => {
            retirement.validate(meta)?;
            ensure!(
                retirement.state == actual,
                "snapshot custody differs from validated application state"
            );
            Ok(())
        }
        _ => anyhow::bail!("snapshot retirement marker is missing or substituted"),
    }
}

/// Semantic closed metadata is stable across backend re-encoding. This compares
/// the complete validated capsule, not a digest of application serialization.
pub(crate) fn check_same_retirement(
    left: Option<&SnapshotRetirement>,
    right: Option<&SnapshotRetirement>,
) -> Result<()> {
    ensure!(
        left == right,
        "snapshot would substitute custody identity at the same applied position"
    );
    Ok(())
}

/// Returns only custody writes. The caller publishes them atomically with the
/// final application snapshot manifest, after complete backend validation.
pub(crate) fn installation_writes(
    domains: &TenantStorageSet,
    meta: &SnapshotMeta<u64, BasicNode>,
    retirement: Option<&SnapshotRetirement>,
    backend_sha256: &str,
    snapshot_sha256: &str,
) -> Result<Vec<WriteOp>> {
    kasumi_types::validate_sha256(backend_sha256)?;
    kasumi_types::validate_sha256(snapshot_sha256)?;
    let control = domains.custody().store();
    let mut writes = Vec::new();
    let existing_boundary = control::retired_boundary(domains.custody())?;
    match retirement {
        Some(retirement) => {
            retirement.validate(meta)?;
            retirement.check_installation(domains)?;
            if let Some(existing) = &existing_boundary {
                ensure!(
                    *existing == retirement.boundary,
                    "snapshot would replace permanent retirement binding"
                );
            }
            let local = retirement.local_seed(domains)?;
            if let Some(existing) = load::<RetainedSeed>(
                control,
                SEEDS,
                &retirement.header.log_id.index.to_be_bytes(),
            )? && existing != local
            {
                // A receiver may have an uncommitted conflicting candidate at
                // this index. Only a validated committed snapshot may replace it.
                let committed = control::committed_coverage(control)?;
                ensure!(
                    existing_boundary.is_none()
                        && committed.is_none_or(|id| id.index < retirement.header.log_id.index),
                    "snapshot would substitute committed retirement seed"
                );
            }
            writes.push(WriteOp::put(
                SEEDS,
                retirement.header.log_id.index.to_be_bytes(),
                serde_json::to_vec(&local)?,
            ));
            writes.push(WriteOp::put(
                META,
                b"retired_boundary",
                serde_json::to_vec(&retirement.boundary)?,
            ));
            writes.push(WriteOp::put(
                META,
                PROJECTION,
                serde_json::to_vec(&Projection {
                    meta: meta.clone(),
                    snapshot_sha256: snapshot_sha256.into(),
                    retirement: retirement.clone(),
                })?,
            ));
        }
        None => {
            // An older capture may precede a later durable retirement. It must
            // leave that boundary intact and can only cover the earlier prefix.
            if let Some(boundary) = &existing_boundary {
                ensure!(
                    meta.last_log_id
                        .is_none_or(|id| id.index < boundary.position.log_id.index),
                    "snapshot would reopen a retired source"
                );
            }
        }
    }
    let previous = load::<AppliedCursor>(control, META, b"applied")?;
    if let (Some(old), Some(new)) = (
        previous.as_ref().and_then(AppliedCursor::log_id),
        meta.last_log_id,
    ) {
        ensure!(
            old.index.cmp(&new.index) == old.cmp(&new),
            "snapshot applied position ordering differs"
        );
    }
    if previous.as_ref().is_none_or(|previous| {
        previous.log_id().map(|id| id.index) <= meta.last_log_id.map(|id| id.index)
    }) {
        if let Some(AppliedCursor::Snapshot { meta: old, .. }) = &previous
            && old.last_log_id == meta.last_log_id
        {
            // Backends can encode the same logical image differently (e.g.
            // randomized persistent map order after restore). Each image keeps
            // its own exact digest; custody identity at this position cannot vary.
            let existing = load::<Projection>(control, META, PROJECTION)?;
            ensure!(
                old.last_membership == meta.last_membership,
                "snapshot membership differs at the same applied position"
            );
            ensure!(
                existing.as_ref().is_none_or(|value| value.meta == *old),
                "previous custody projection position differs"
            );
            check_same_retirement(existing.as_ref().map(|value| &value.retirement), retirement)?;
        }
        writes.push(WriteOp::put(
            META,
            b"applied",
            serde_json::to_vec(&AppliedCursor::Snapshot {
                meta: meta.clone(),
                backend_sha256: backend_sha256.into(),
                snapshot_sha256: snapshot_sha256.into(),
            })?,
        ));
    }
    Ok(writes)
}

pub(crate) fn check_published(
    domains: &TenantStorageSet,
    meta: &SnapshotMeta<u64, BasicNode>,
    snapshot_sha256: &str,
    retirement: Option<&SnapshotRetirement>,
) -> Result<()> {
    if let Some(retirement) = retirement {
        retirement.validate(meta)?;
        retirement.check_installation(domains)?;
        let projection: Projection = load(domains.custody().store(), META, PROJECTION)?
            .context("snapshot custody projection absent")?;
        ensure!(
            projection.meta == *meta
                && projection.snapshot_sha256 == snapshot_sha256
                && projection.retirement == *retirement,
            "snapshot custody projection differs from published image"
        );
        let boundary = control::retired_boundary(domains.custody())?
            .context("snapshot retired boundary absent")?;
        ensure!(
            boundary == retirement.boundary,
            "snapshot retired boundary differs"
        );
    }
    Ok(())
}

/// Coverage for a replica that installed the seed through a snapshot rather
/// than receiving and then purging its original log header.
pub(crate) fn covers_seed(store: &TenantStore, record: &RetainedSeed) -> Result<bool> {
    let Some(projection) = load::<Projection>(store, META, PROJECTION)? else {
        return Ok(false);
    };
    projection.retirement.validate(&projection.meta)?;
    let coverage: crate::storage::SnapshotCoverage =
        load(store, META, b"snapshot_coverage")?.context("snapshot custody coverage absent")?;
    ensure!(
        coverage.meta == projection.meta && coverage.snapshot_sha256 == projection.snapshot_sha256,
        "retirement projection snapshot coverage differs"
    );
    kasumi_types::validate_sha256(&projection.snapshot_sha256)?;
    Ok(projection.retirement.header == record.header
        && projection.retirement.seed == record.seed
        && projection.retirement.bootstrap_sha256 == record.bootstrap_sha256)
}

/// Independently readable committed snapshot coverage, kept distinct from the
/// log store's committed cursor so a crash before Raft's log purge does not
/// fabricate physical log entries or change the log-store recovery contract.
pub(crate) fn committed_snapshot(store: &TenantStore) -> Result<Option<crate::LogId<u64>>> {
    let Some(coverage) =
        load::<crate::storage::SnapshotCoverage>(store, META, b"snapshot_coverage")?
    else {
        return Ok(None);
    };
    kasumi_types::validate_sha256(&coverage.snapshot_sha256)?;
    kasumi_types::validate_sha256(&coverage.backend_sha256)?;
    uuid::Uuid::parse_str(&coverage.manifest_id)?;
    Ok(coverage.meta.last_log_id)
}
