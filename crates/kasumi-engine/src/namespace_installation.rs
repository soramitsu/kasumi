//! Verified rows copied to a durable stage before its namespace is selected.
use anyhow::Result;
use kasumi_store::{EncryptedTable, NamespaceStage};
use std::sync::Arc;

pub(crate) enum PreparedRows {
    Empty,
    Staged(Arc<EncryptedTable>),
}

impl PreparedRows {
    pub(crate) fn stage(&self, stage: &NamespaceStage) -> Result<()> {
        match self {
            Self::Empty => stage.seal_empty(),
            Self::Staged(table) => stage.write_table(table),
        }
    }
}
