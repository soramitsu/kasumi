//! Bounded encrypted custody snapshot records. Metadata carries only the policy
//! head and the digest of this immutable, point-addressed record set.
use crate::custody_state::CustodyAudit;
#[cfg(test)]
use crate::custody_state::CustodyState;
use crate::custody_tables::{AUDIT, COMMANDS, CustodyHead, HEAD, HEAD_BYTES, RECORD_BYTES};
use anyhow::{Context, Result, ensure};
use kasumi_store::{EncryptedTable, TenantStore};
use kasumi_types::{CustodyReceipt, validate_name};
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub(crate) struct Records {
    pub(crate) head: CustodyHead,
    commands: EncryptedTable,
    audit: EncryptedTable,
    sha256: String,
}

pub(crate) struct Builder {
    records: Records,
    commands: u64,
    audit: u64,
    history_bytes: u64,
}
impl Builder {
    pub(crate) fn new(
        scratch_disk: &Arc<kasumi_store::ScratchDisk>,
        head: CustodyHead,
    ) -> Result<Self> {
        head.validate()?;
        let disk = head
            .policy
            .limits
            .max_state_bytes
            .checked_mul(8)
            .and_then(|n| n.checked_add(64 << 20))
            .context("custody staging quota overflow")?;
        Ok(Self {
            records: Records {
                head,
                commands: EncryptedTable::new(scratch_disk, disk)?,
                audit: EncryptedTable::new(scratch_disk, disk)?,
                sha256: String::new(),
            },
            commands: 0,
            audit: 0,
            history_bytes: 0,
        })
    }
    pub(crate) fn command(&mut self, bytes: &[u8]) -> Result<()> {
        ensure!(
            bytes.len() <= RECORD_BYTES,
            "custody receipt record exceeds bound"
        );
        ensure!(
            self.commands < self.records.head.commands,
            "unexpected custody receipt"
        );
        let receipt: CustodyReceipt = serde_json::from_slice(bytes)?;
        receipt.validate()?;
        ensure!(
            serde_json::to_vec(&receipt)? == bytes,
            "noncanonical custody receipt"
        );
        let policy = &self.records.head.policy;
        ensure!(
            receipt.revision > policy.origin.revision
                && receipt.revision <= policy.revision
                && receipt.policy_epoch <= policy.policy_epoch,
            "custody receipt position differs"
        );
        self.history_bytes = self
            .history_bytes
            .checked_add(crate::custody_tables::command_bytes(&receipt)?)
            .and_then(|n| n.checked_add(u64::from(self.commands != 0)))
            .context("custody history byte overflow")?;
        ensure!(
            self.history_bytes <= self.records.head.history_bytes,
            "custody history exceeds head"
        );
        self.records
            .commands
            .insert(receipt.command_id.as_bytes(), bytes)?;
        self.commands = self
            .commands
            .checked_add(1)
            .context("custody command count overflow")?;
        Ok(())
    }
    pub(crate) fn audit(&mut self, key: &[u8], bytes: &[u8]) -> Result<()> {
        ensure!(
            bytes.len() <= RECORD_BYTES,
            "custody audit record exceeds bound"
        );
        ensure!(
            self.audit < self.records.head.audit,
            "unexpected custody audit"
        );
        let index = u64::from_be_bytes(key.try_into().context("invalid custody audit key")?);
        ensure!(
            index < self.records.head.audit,
            "custody audit sequence exceeds head"
        );
        let event: CustodyAudit = serde_json::from_slice(bytes)?;
        ensure!(
            serde_json::to_vec(&event)? == bytes,
            "noncanonical custody audit"
        );
        self.history_bytes = self
            .history_bytes
            .checked_add(bytes.len() as u64)
            .and_then(|n| n.checked_add(u64::from(self.audit != 0)))
            .context("custody history byte overflow")?;
        ensure!(
            self.history_bytes <= self.records.head.history_bytes,
            "custody history exceeds head"
        );
        self.records.audit.insert(key, bytes)?;
        self.audit = self
            .audit
            .checked_add(1)
            .context("custody audit count overflow")?;
        Ok(())
    }
    pub(crate) fn finish(mut self) -> Result<Arc<Records>> {
        let head = &self.records.head;
        ensure!(
            self.commands == head.commands
                && self.audit == head.audit
                && self.history_bytes == head.history_bytes,
            "custody terminal accounting differs"
        );
        let mut previous = head.policy.origin.revision;
        let mut originals = 0u64;
        for index in 0..head.audit {
            let bytes = self
                .records
                .audit
                .get(&index.to_be_bytes())?
                .context("custody audit sequence missing")?;
            let event: CustodyAudit = serde_json::from_slice(&bytes)?;
            validate_name(&event.principal)?;
            validate_name(&event.request_id)?;
            let bytes = self
                .records
                .commands
                .get(event.command_id.as_bytes())?
                .context("custody audit command absent")?;
            let receipt: CustodyReceipt = serde_json::from_slice(&bytes)?;
            ensure!(
                event.revision > previous
                    && event.revision <= head.policy.revision
                    && event.request_digest == receipt.request_digest
                    && event.policy_epoch <= head.policy.policy_epoch
                    && event.policy_epoch >= receipt.policy_epoch
                    && event.accepted == receipt.outcome.is_ok(),
                "custody audit linkage differs"
            );
            if event.replay {
                ensure!(
                    receipt.revision < event.revision,
                    "custody replay precedes original receipt"
                );
            } else {
                ensure!(
                    event.revision == receipt.revision
                        && event.principal == receipt.principal
                        && event.admitted_at_ms == receipt.admitted_at_ms
                        && event.policy_epoch == receipt.policy_epoch,
                    "custody original receipt differs"
                );
                originals = originals
                    .checked_add(1)
                    .context("custody original count overflow")?;
            }
            previous = event.revision;
        }
        ensure!(
            originals == head.commands,
            "custody original receipt missing"
        );
        let mut digest = Sha256::new();
        digest.update(b"kasumi.custody-records.v1");
        for (tag, table) in [(1u8, &self.records.commands), (2, &self.records.audit)] {
            table.visit(|key, value| {
                digest.update([tag]);
                digest.update((key.len() as u64).to_be_bytes());
                digest.update(key);
                digest.update((value.len() as u64).to_be_bytes());
                digest.update(value);
                Ok(())
            })?;
        }
        self.records.sha256 = hex::encode(digest.finalize());
        Ok(Arc::new(self.records))
    }
}
impl Records {
    pub(crate) fn capture(store: &Arc<TenantStore>) -> Result<Arc<Self>> {
        let view = store.read_view()?;
        let head = serde_json::from_slice(
            &view
                .get(crate::control::META, HEAD, HEAD_BYTES)?
                .context("custody point table head absent")?,
        )?;
        let mut builder = Builder::new(store.scratch_disk(), head)?;
        view.visit(COMMANDS, RECORD_BYTES, |key, bytes| {
            let receipt: CustodyReceipt = serde_json::from_slice(bytes)?;
            ensure!(
                key == receipt.command_id.as_bytes(),
                "custody receipt key differs"
            );
            builder.command(bytes)
        })?;
        view.visit(AUDIT, RECORD_BYTES, |key, bytes| builder.audit(key, bytes))?;
        builder.finish()
    }
    pub(crate) fn sha256(&self) -> &str {
        &self.sha256
    }
    pub(crate) fn namespaces(&self) -> [(&str, &EncryptedTable); 2] {
        [(COMMANDS, &self.commands), (AUDIT, &self.audit)]
    }
    pub(crate) fn visit(&self, mut visitor: impl FnMut(u8, &[u8]) -> Result<()>) -> Result<()> {
        self.commands.visit(|_, bytes| visitor(1, bytes))?;
        self.audit.visit(|_, bytes| visitor(2, bytes))
    }
    #[cfg(test)]
    pub(crate) fn from_state(state: &CustodyState) -> Result<Arc<Self>> {
        let mut builder = Builder::new(
            &kasumi_store::ScratchDisk::fixture(),
            CustodyHead::from_state(state)?,
        )?;
        for receipt in state.commands.values() {
            builder.command(&serde_json::to_vec(receipt)?)?;
        }
        for (index, event) in state.audit.iter().enumerate() {
            builder.audit(&(index as u64).to_be_bytes(), &serde_json::to_vec(event)?)?;
        }
        builder.finish()
    }
}
