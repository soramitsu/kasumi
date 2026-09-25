//! Exact census custody for a bounded installed-node read body.
use super::*;
use std::panic::AssertUnwindSafe;

/// The original native read and close observations remain in this exact child.
pub struct NodeScopedReadFailure {
    reader: RegisteredNodeRead,
    stage: &'static str,
    body_error: Option<anyhow::Error>,
}
impl NodeScopedReadFailure {
    pub(crate) fn from_view(reader: &RegisteredNodeRead, body_error: anyhow::Error) -> Self {
        Self {
            reader: reader.retain_report_facade(),
            stage: "view read",
            body_error: Some(body_error),
        }
    }

    pub fn reader(&self) -> &RegisteredNodeRead {
        &self.reader
    }
    pub fn into_reader(self) -> RegisteredNodeRead {
        self.reader
    }
    pub fn stage(&self) -> &'static str {
        self.stage
    }
    pub fn body_error(&self) -> Option<&anyhow::Error> {
        self.body_error.as_ref()
    }
}
impl std::fmt::Debug for NodeScopedReadFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeScopedReadFailure")
            .field("reader_id", &self.reader.id())
            .field("stage", &self.stage)
            .field("reader_phase", &self.reader.phase())
            .field("body_error", &self.body_error)
            .finish()
    }
}
impl std::fmt::Display for NodeScopedReadFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "registered read {:?} failed at {}",
            self.reader.id(),
            self.stage
        )
    }
}
impl std::error::Error for NodeScopedReadFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.body_error.as_ref().map(|error| error.as_ref() as _)
    }
}

/// A clean native close whose exact census cell still needs a retirement retry.
pub struct NodeScopedReadRetirement {
    provider: Arc<dyn NodeDiskMemoryAdmission>,
    id: StorageOwnerId,
    disposition: StorageCensusDisposition,
    body_error: Option<anyhow::Error>,
}
impl NodeScopedReadRetirement {
    pub fn id(&self) -> StorageOwnerId {
        self.id
    }
    pub fn disposition(&self) -> StorageCensusDisposition {
        self.disposition
    }
    pub fn retry_retirement(&self) -> StorageCensusDisposition {
        self.provider.storage_census().drain_owner(self.id)
    }
    pub fn body_error(&self) -> Option<&anyhow::Error> {
        self.body_error.as_ref()
    }
}
impl std::fmt::Debug for NodeScopedReadRetirement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeScopedReadRetirement")
            .field("id", &self.id)
            .field("disposition", &self.disposition)
            .field("body_error", &self.body_error)
            .finish()
    }
}
impl std::fmt::Display for NodeScopedReadRetirement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "registered read {:?} retirement {:?}",
            self.id, self.disposition
        )
    }
}
impl std::error::Error for NodeScopedReadRetirement {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.body_error.as_ref().map(|error| error.as_ref() as _)
    }
}

impl NodeStore {
    pub(crate) fn begin_registered_read(&self) -> Result<RegisteredNodeRead> {
        let reader = self.db.queue_registered_read()?;
        if reader.begin() != NodeReadPhase::Active {
            return Err(NodeScopedReadFailure {
                reader,
                stage: "begin",
                body_error: None,
            }
            .into());
        }
        Ok(reader)
    }

    pub(crate) fn with_registered_read<T>(
        &self,
        body: impl FnOnce(&RegisteredNodeRead) -> Result<T>,
    ) -> Result<T> {
        let reader = self.begin_registered_read()?;
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| body(&reader)));
        match result {
            Ok(result) => self.settle_registered_read(reader, result),
            Err(payload) => {
                // Transfer the original payload into the exact census child.
                // Re-unwinding it would consume that original and let a later
                // parent drive mistake the native close for clean success.
                reader.preserve_body_panic(payload);
                let _ = reader.finish();
                Err(NodeScopedReadFailure {
                    reader,
                    stage: "body panic",
                    body_error: None,
                }
                .into())
            }
        }
    }

    pub(crate) fn settle_registered_read<T>(
        &self,
        reader: RegisteredNodeRead,
        result: Result<T>,
    ) -> Result<T> {
        let phase = reader.finish();
        if phase != NodeReadPhase::Finished || reader.report().has_failures() {
            return Err(NodeScopedReadFailure {
                reader,
                stage: if phase == NodeReadPhase::Finished {
                    "body"
                } else {
                    "finish"
                },
                body_error: result.err(),
            }
            .into());
        }
        let id = reader.id();
        let disposition = reader.retire();
        if disposition != StorageCensusDisposition::Retired {
            return Err(NodeScopedReadRetirement {
                provider: self.persistent_disk().memory().clone(),
                id,
                disposition,
                body_error: result.err(),
            }
            .into());
        }
        result
    }
}
