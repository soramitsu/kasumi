//! Independently encrypted consensus metadata. A durable local commit cursor is
//! recovery input, not fresh quorum or administrative release authority.
use crate::{BasicNode, LogId, RetirementLogSeed, TypeConfig, command::sha256};
use anyhow::{Context, Result, ensure};
use kasumi_store::{CustodyStore, TenantStorageSet, TenantStore, WriteOp};
use openraft::{Entry, EntryPayload, Membership, StoredMembership, Vote};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::sync::Arc;

pub(crate) const META: &str = "raft.meta";
pub(crate) const HEADERS: &str = "raft.headers";
pub(crate) const SEEDS: &str = "raft.retirement-seeds";

/// Actual adapter-assigned execution position. No request can select its term,
/// leader, predecessor or membership. The engine validates a seed against its
/// current generation before publishing the matching retirement effect.
#[derive(Debug, Clone)]
pub struct AppliedEntryContext {
    pub log_id: LogId<u64>,
    pub previous: Option<LogId<u64>>,
    pub membership: StoredMembership<u64, BasicNode>,
    pub command_sha256: String,
    pub retirement_seed: Option<RetirementLogSeed>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AppliedPosition {
    pub log_id: LogId<u64>,
    pub previous: Option<LogId<u64>>,
    pub membership: StoredMembership<u64, BasicNode>,
    pub command_sha256: String,
}
/// A snapshot is an applied state boundary, not an invented log command.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) enum AppliedCursor {
    Entry(AppliedPosition),
    Snapshot {
        meta: openraft::SnapshotMeta<u64, BasicNode>,
        backend_sha256: String,
        snapshot_sha256: String,
    },
}
impl AppliedCursor {
    pub(crate) fn log_id(&self) -> Option<LogId<u64>> {
        match self {
            Self::Entry(position) => Some(position.log_id),
            Self::Snapshot { meta, .. } => meta.last_log_id,
        }
    }
}
impl AppliedEntryContext {
    pub(crate) fn record(&self) -> AppliedPosition {
        AppliedPosition {
            log_id: self.log_id,
            previous: self.previous,
            membership: self.membership.clone(),
            command_sha256: self.command_sha256.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct LogHeader {
    pub log_id: LogId<u64>,
    pub entry_sha256: String,
    pub payload: HeaderPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) enum HeaderPayload {
    Blank,
    Membership(Membership<u64, BasicNode>),
    Application {
        command_sha256: String,
    },
    Retirement {
        command_sha256: String,
        seed_sha256: String,
    },
}

impl LogHeader {
    pub(crate) fn build(
        entry: &Entry<TypeConfig>,
        encoded: &[u8],
    ) -> Result<(Self, Option<Vec<u8>>)> {
        let (payload, seed) = match &entry.payload {
            EntryPayload::Blank => (HeaderPayload::Blank, None),
            EntryPayload::Membership(membership) => {
                (HeaderPayload::Membership(membership.clone()), None)
            }
            EntryPayload::Normal(command) => {
                let command_sha256 = sha256(command.bytes());
                match command.seed_bytes()? {
                    Some(bytes) => (
                        HeaderPayload::Retirement {
                            command_sha256,
                            seed_sha256: sha256(&bytes),
                        },
                        Some(bytes),
                    ),
                    None => (HeaderPayload::Application { command_sha256 }, None),
                }
            }
        };
        Ok((
            Self {
                log_id: entry.log_id,
                entry_sha256: sha256(encoded),
                payload,
            },
            seed,
        ))
    }
    pub(crate) fn validate(&self) -> Result<()> {
        kasumi_types::validate_sha256(&self.entry_sha256)?;
        match &self.payload {
            HeaderPayload::Application { command_sha256 } => {
                kasumi_types::validate_sha256(command_sha256)?;
            }
            HeaderPayload::Retirement {
                command_sha256,
                seed_sha256,
            } => {
                kasumi_types::validate_sha256(command_sha256)?;
                kasumi_types::validate_sha256(seed_sha256)?;
            }
            _ => {}
        }
        Ok(())
    }
    pub(crate) fn check_entry(&self, entry: &Entry<TypeConfig>, encoded: &[u8]) -> Result<()> {
        let (expected, _) = Self::build(entry, encoded)?;
        ensure!(
            serde_json::to_vec(&expected)? == serde_json::to_vec(self)?,
            "raft body/control header differs"
        );
        Ok(())
    }
}

pub(crate) fn load<T: DeserializeOwned>(
    store: &TenantStore,
    namespace: &str,
    key: &[u8],
) -> Result<Option<T>> {
    store
        .get(namespace, key)?
        .map(|bytes| serde_json::from_slice(&bytes).context("invalid raft control record"))
        .transpose()
}

pub(crate) fn committed_coverage(store: &TenantStore) -> Result<Option<LogId<u64>>> {
    let log = load::<Option<LogId<u64>>>(store, META, b"committed")?.flatten();
    let snapshot = crate::snapshot_custody::committed_snapshot(store)?;
    if let (Some(log), Some(snapshot)) = (log, snapshot) {
        ensure!(
            log.index.cmp(&snapshot.index) == log.cmp(&snapshot),
            "log and snapshot committed identities disagree"
        );
    }
    Ok(log.max(snapshot))
}

/// A checked, locally committed seed. This type deliberately cannot construct
/// VerifiedRetirementReceipt and does not establish current policy/lease/quorum.
pub struct CommittedRetirementSeed {
    log_id: LogId<u64>,
    committed: LogId<u64>,
    group: String,
    seed: RetirementLogSeed,
}
impl CommittedRetirementSeed {
    pub fn log_id(&self) -> LogId<u64> {
        self.log_id
    }
    pub fn committed(&self) -> LogId<u64> {
        self.committed
    }
    pub fn group(&self) -> &str {
        &self.group
    }
    pub fn seed(&self) -> &RetirementLogSeed {
        &self.seed
    }
}

/// Metadata-only recovery reader. It cannot read application log bodies or
/// initialize a serving state machine. Native source custody routing is separate.
pub struct ControlLog {
    custody: Arc<CustodyStore>,
    group: String,
}
impl ControlLog {
    pub fn open(custody: Arc<CustodyStore>, node_id: u64, group: String) -> Result<Self> {
        let store = custody.store();
        ensure!(
            load::<u64>(store, META, b"node_id")? == Some(node_id),
            "control node identity differs"
        );
        ensure!(
            load::<String>(store, META, b"group")?.as_ref() == Some(&group),
            "control group identity differs"
        );
        Ok(Self { custody, group })
    }
    pub fn read_vote(&self) -> Result<Option<Vote<u64>>> {
        load(self.custody.store(), META, b"vote")
    }
    pub fn committed(&self) -> Result<Option<LogId<u64>>> {
        committed_coverage(self.custody.store())
    }
    pub fn retirement_seed(&self, index: u64) -> Result<Option<CommittedRetirementSeed>> {
        let store = self.custody.store();
        let Some(committed) = self.committed()? else {
            return Ok(None);
        };
        if index > committed.index {
            return Ok(None);
        }
        let Some(record) = load::<RetainedSeed>(store, SEEDS, &index.to_be_bytes())? else {
            return Ok(None);
        };
        record.header.validate()?;
        ensure!(
            load::<String>(store, META, b"application_bootstrap_sha256")?.as_ref()
                == Some(&record.bootstrap_sha256)
                && record.storage_binding_sha256 == self.custody.binding().digest()?,
            "retirement seed bootstrap/encryption binding differs"
        );
        ensure!(
            record.header.log_id.index == index && record.header.log_id <= committed,
            "retirement seed commit position differs"
        );
        let HeaderPayload::Retirement {
            command_sha256,
            seed_sha256,
        } = &record.header.payload
        else {
            anyhow::bail!("nonretirement seed record");
        };
        ensure!(
            sha256(&record.seed) == *seed_sha256,
            "retirement seed ciphertext payload differs"
        );
        let seed = RetirementLogSeed::decode(&record.seed)?;
        ensure!(
            seed.command_sha256() == command_sha256
                && self.group == format!("{}/{}", seed.source().tenant, seed.source().incarnation)
                && seed.source().tenant == self.custody.binding().tenant(),
            "retirement seed installed source differs"
        );
        // A committed snapshot supersedes any old candidate log beneath its
        // floor. Only its exact accepted retirement capsule can retain a seed.
        if crate::snapshot_custody::committed_snapshot(store)?.is_some_and(|id| id.index >= index)
            && !crate::snapshot_custody::covers_seed(store, &record)?
        {
            return Ok(None);
        }
        // If retained in the active prefix, compare its exact immutable header.
        if crate::snapshot_custody::covers_seed(store, &record)? {
            // Snapshot coverage supersedes conflicting uncommitted physical logs
            // while Raft's separate purge operation is still pending.
        } else if let Some(active) = load::<LogHeader>(store, HEADERS, &index.to_be_bytes())? {
            ensure!(
                active == record.header,
                "retirement seed active header differs"
            );
        } else {
            let purged: LogId<u64> =
                load(store, META, b"purged")?.context("retirement seed lacks log coverage")?;
            ensure!(
                purged.index >= index,
                "retirement seed is outside covered prefix"
            );
        }
        store.check_access()?;
        Ok(Some(CommittedRetirementSeed {
            log_id: record.header.log_id,
            committed,
            group: self.group.clone(),
            seed,
        }))
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetainedSeed {
    pub header: LogHeader,
    pub seed: Vec<u8>,
    pub bootstrap_sha256: String,
    pub storage_binding_sha256: String,
}

pub(crate) fn applied_write(context: &AppliedEntryContext) -> Result<WriteOp> {
    Ok(WriteOp::put(
        META,
        b"applied",
        serde_json::to_vec(&AppliedCursor::Entry(context.record()))?,
    ))
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetiredBoundary {
    pub(crate) position: AppliedPosition,
    pub(crate) request: kasumi_types::RetireSourceRequest,
    pub(crate) receipt: kasumi_types::RetirementReceipt,
    pub(crate) seed_sha256: String,
}

pub(crate) fn retired_boundary(custody: &CustodyStore) -> Result<Option<RetiredBoundary>> {
    let store = custody.store();
    let value = load::<RetiredBoundary>(store, META, b"retired_boundary")?;
    if let Some(boundary) = &value {
        validate_retired_boundary(custody, boundary)?;
    }
    Ok(value)
}

fn validate_retired_boundary(custody: &CustodyStore, boundary: &RetiredBoundary) -> Result<()> {
    let store = custody.store();
    boundary.receipt.validate()?;
    ensure!(
        boundary.receipt.request_digest == boundary.request.reference()?.request_digest,
        "retired boundary request differs"
    );
    let source: RetainedSeed = load(store, SEEDS, &boundary.position.log_id.index.to_be_bytes())?
        .context("retired boundary seed absent")?;
    source.header.validate()?;
    let seed = RetirementLogSeed::decode(&source.seed)?;
    let committed = committed_coverage(store)?.context("retired boundary commit absent")?;
    ensure!(
        committed >= boundary.position.log_id && committed.index >= boundary.position.log_id.index,
        "retired boundary is outside committed prefix"
    );
    ensure!(
        matches!(&source.header.payload,
        HeaderPayload::Retirement { command_sha256, seed_sha256 }
        if command_sha256 == seed.command_sha256() && *seed_sha256 == sha256(&source.seed)),
        "retired boundary header differs"
    );
    ensure!(
        seed.source().tenant == custody.binding().tenant()
            && source.storage_binding_sha256 == custody.binding().digest()?
            && load::<String>(store, META, b"application_bootstrap_sha256")?.as_ref()
                == Some(&source.bootstrap_sha256)
            && load::<String>(store, META, b"group")?.as_deref()
                == Some(format!("{}/{}", seed.source().tenant, seed.source().incarnation).as_str()),
        "retired boundary installed source differs"
    );
    let revision = seed
        .source()
        .revision_base
        .checked_add(boundary.position.log_id.index)
        .context("retired source revision overflow")?;
    seed.validate_receipt(revision, &boundary.receipt)?;
    ensure!(
        source.header.log_id == boundary.position.log_id
            && seed.command_sha256() == boundary.position.command_sha256
            && sha256(&source.seed) == boundary.seed_sha256,
        "retired boundary applied position differs"
    );
    Ok(())
}

pub(crate) fn persist_applied(
    domains: &TenantStorageSet,
    context: &AppliedEntryContext,
    retirement: Option<kasumi_types::RetirementReceipt>,
) -> Result<()> {
    domains.check_access()?;
    let store = domains.custody().store();
    let boundary = retirement
        .map(|receipt| -> Result<RetiredBoundary> {
            let seed = context
                .retirement_seed
                .as_ref()
                .context("retirement outcome without a seed")?;
            let revision = seed
                .source()
                .revision_base
                .checked_add(context.log_id.index)
                .context("retired source revision overflow")?;
            seed.validate_receipt(revision, &receipt)?;
            Ok(RetiredBoundary {
                position: context.record(),
                request: seed.request().clone(),
                receipt,
                seed_sha256: sha256(&seed.encoded()?),
            })
        })
        .transpose()?;
    if let Some(boundary) = &boundary {
        validate_retired_boundary(domains.custody(), boundary)?;
    }
    let existing_boundary = if boundary.is_some() {
        retired_boundary(domains.custody())?
    } else {
        None
    };
    if let (Some(existing), Some(new)) = (&existing_boundary, &boundary) {
        ensure!(existing == new, "immutable retired boundary differs");
    }
    if let Some(previous) = load::<AppliedCursor>(store, META, b"applied")?
        && previous
            .log_id()
            .is_some_and(|id| id.index >= context.log_id.index)
    {
        if previous
            .log_id()
            .is_some_and(|id| id.index == context.log_id.index)
        {
            ensure!(
                previous.log_id() == Some(context.log_id),
                "replayed source log identity differs"
            );
            if let AppliedCursor::Entry(previous) = &previous {
                ensure!(
                    *previous == context.record(),
                    "replayed source applied position differs"
                );
            }
        }
        ensure!(
            boundary.is_none() || existing_boundary == boundary,
            "previously applied retirement lacks its atomic boundary"
        );
        return Ok(());
    }
    let mut writes = vec![applied_write(context)?];
    if let Some(boundary) = boundary {
        writes.push(WriteOp::put(
            META,
            b"retired_boundary",
            serde_json::to_vec(&boundary)?,
        ));
    }
    domains.write_batch(&[], &writes)
}

#[cfg(test)]
#[path = "control_tests.rs"]
pub(crate) mod tests;
