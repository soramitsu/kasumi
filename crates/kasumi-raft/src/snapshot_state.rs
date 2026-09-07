//! Trusted backend snapshot output. These records describe an immutable capture;
//! they are never current administrative release authority or a serving lease.
use crate::{BasicNode, LogId};
use anyhow::{Context, Result, ensure};
use kasumi_types::{RetireSourceRequest, RetirementReceipt, validate_name};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub struct BackendSnapshot {
    pub data: Vec<u8>,
    pub retirement: Option<RetiredSnapshotState>,
}
impl BackendSnapshot {
    pub fn application(data: Vec<u8>) -> Self {
        Self {
            data,
            retirement: None,
        }
    }
}

/// Closed metadata derived from the same validated generation as the image.
/// The Raft adapter additionally binds this to the committed retirement seed and
/// its actual applied position. A raw instance cannot create a verified proof.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RetiredSnapshotState {
    pub revision_base: u64,
    pub revision: u64,
    pub policy_epoch: u64,
    pub administrators: BTreeSet<String>,
    pub request: RetireSourceRequest,
    pub receipt: RetirementReceipt,
}
impl RetiredSnapshotState {
    pub(crate) fn validate(&self, meta: &openraft::SnapshotMeta<u64, BasicNode>) -> Result<()> {
        self.request.validate()?;
        self.receipt.validate()?;
        let LogId { index, .. } = meta
            .last_log_id
            .context("retired snapshot has no applied log")?;
        let ceiling = self
            .revision_base
            .checked_add(index)
            .context("snapshot revision overflow")?;
        ensure!(
            self.receipt.revision > self.revision_base
                && self.receipt.revision <= self.revision
                && self.revision <= ceiling
                && self.receipt.policy_epoch <= self.policy_epoch
                && self.administrators.len() <= 1024
                && self.receipt.tenant == self.request.checkpoint.tenant
                && self.receipt.source_incarnation == self.request.expected_source_incarnation
                && self.receipt.target_incarnation == self.request.target_incarnation
                && self.receipt.retirement_id == self.request.retirement_id
                && self.receipt.request_digest == self.request.reference()?.request_digest
                && self.receipt.checkpoint == self.request.checkpoint,
            "retired snapshot state binding differs"
        );
        for principal in &self.administrators {
            validate_name(principal)?;
        }
        Ok(())
    }
}
