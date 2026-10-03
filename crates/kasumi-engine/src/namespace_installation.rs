//! Verified replacement rows retained until their namespace publication commits.
use kasumi_store::{EncryptedTable, NamespaceReplacement};
use std::sync::Arc;

pub(crate) enum PreparedRows {
    Empty,
    Staged(Arc<EncryptedTable>),
}

impl PreparedRows {
    pub(crate) fn replacement<'a>(&'a self, namespace: &'a str) -> NamespaceReplacement<'a> {
        match self {
            Self::Empty => NamespaceReplacement::empty(namespace),
            Self::Staged(table) => NamespaceReplacement::from_table(namespace, table),
        }
    }
}
