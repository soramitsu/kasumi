//! Synchronous installed write completion never returns a native facade.
use super::*;

#[cfg(test)]
std::thread_local! {
    static WRITE_HANDOFF_RETRY_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

pub struct NodeScopedWriteFailure {
    writer: Option<RegisteredNodeWrite>,
}
impl NodeScopedWriteFailure {
    pub fn writer_id(&self) -> StorageOwnerId {
        self.writer.as_ref().unwrap().id()
    }
    pub fn report(&self) -> NodeWriteReport<'_> {
        self.writer.as_ref().unwrap().report()
    }
    pub fn retire(mut self) -> StorageCensusDisposition {
        self.writer.take().unwrap().retire()
    }
}
impl Drop for NodeScopedWriteFailure {
    fn drop(&mut self) {
        if let Some(writer) = self.writer.take() {
            let _ = writer.retire_clean_body_error();
        }
    }
}
impl std::fmt::Debug for NodeScopedWriteFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NodeScopedWriteFailure")
            .field("writer_id", &self.writer_id())
            .field("phase", &self.report().phase())
            .finish()
    }
}
impl std::fmt::Display for NodeScopedWriteFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let report = self.report();
        write!(formatter, "registered write {:?} failed", self.writer_id())?;
        if let kasumi_kv::TerminalObservation::Returned(Err(original)) = report.body() {
            write!(formatter, ": {original:#}")?;
        } else if let kasumi_kv::TerminalObservation::Returned(Err(original)) = report.post_commit()
        {
            write!(formatter, " after commit: {original:#}")?;
        } else if let kasumi_kv::TerminalObservation::Returned(Err(original)) = report.begin() {
            write!(formatter, " at begin: {original}")?;
        } else if let Some(terminal) = report.terminal()
            && let kasumi_kv::TerminalObservation::Returned(Err(original)) = terminal.terminal()
        {
            write!(formatter, " at terminal: {original:?}")?;
        }
        Ok(())
    }
}
impl std::error::Error for NodeScopedWriteFailure {}

pub struct NodeScopedWriteRetirement {
    provider: Arc<dyn NodeDiskMemoryAdmission>,
    id: StorageOwnerId,
    disposition: StorageCensusDisposition,
}
impl NodeScopedWriteRetirement {
    pub fn writer_id(&self) -> StorageOwnerId {
        self.id
    }
    pub fn disposition(&self) -> StorageCensusDisposition {
        self.disposition
    }
    pub fn retry_retirement(&self) -> StorageCensusDisposition {
        match self.provider.storage_census().drain_owner(self.id) {
            StorageCensusDisposition::Stale | StorageCensusDisposition::Retired => {
                StorageCensusDisposition::Retired
            }
            retained => retained,
        }
    }
    pub fn output_disposal(
        &self,
    ) -> Option<crate::storage_census::StorageWriteOutputObservation<'_>> {
        self.provider
            .storage_census()
            .write_output_observation(self.id)
    }
}
impl std::fmt::Debug for NodeScopedWriteRetirement {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NodeScopedWriteRetirement")
            .field("writer_id", &self.id)
            .field("disposition", &self.disposition)
            .finish()
    }
}
impl std::fmt::Display for NodeScopedWriteRetirement {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "registered write {:?} retirement {:?}",
            self.id, self.disposition
        )
    }
}
impl std::error::Error for NodeScopedWriteRetirement {}

impl NodeStore {
    pub(crate) fn with_registered_write<W, T>(
        &self,
        workspace: &mut W,
        body: impl FnOnce(&kasumi_kv::WriteTransaction, &mut W) -> Result<()>,
        post_commit: impl FnOnce(&mut W) -> Result<T>,
    ) -> Result<T> {
        let deadline = std::time::Instant::now() + NATIVE_WRITE_TIMEOUT;
        // The explicit synthetic branch is selected from the actual node type,
        // never from an installed refusal or a missing admission provider.
        #[cfg(any(test, feature = "test-utils"))]
        if self.body().db.has_fixture_direct_database() {
            let transaction = self.body().db.begin_write()?;
            body(&transaction, workspace)?;
            let committed = transaction.commit_holding_writer()?;
            let output = post_commit(workspace);
            drop(committed);
            return output;
        }
        let writer = self.body().db.queue_registered_write_until(deadline)?;
        let provider = writer.provider();
        let id = writer.id();
        let output = writer.run(workspace, body, post_commit);
        if !writer.report().committed_and_disposed() {
            provider.storage_census().dispose_write_output(id, output);
            return Err(NodeScopedWriteFailure {
                writer: Some(writer),
            }
            .into());
        }
        let progress = writer.retire_for_handoff();
        let census = provider.storage_census();
        let disposition = census.complete_owner_until(
            id,
            progress,
            deadline,
            crate::storage_census::StorageCompletionGoal::WriteOutputHandoff,
            || {
                #[cfg(test)]
                if let Some(hook) = WRITE_HANDOFF_RETRY_HOOK.with(|hook| hook.borrow_mut().take()) {
                    hook();
                }
            },
        );
        if census.retirement_is_terminal(id) || !census.hand_off_write_output(id) {
            census.dispose_write_output(id, output);
            census.release_disposed_write_output(id);
            return Err(NodeScopedWriteRetirement {
                provider,
                id,
                disposition,
            }
            .into());
        }
        Ok(output.expect("successful post-commit observation retains its synchronous output"))
    }
}

#[cfg(test)]
mod tests;
