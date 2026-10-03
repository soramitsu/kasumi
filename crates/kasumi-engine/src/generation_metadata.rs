//! Borrowed observations from one immutable, already selected generation.
//!
//! These accessors allocate nothing and expose no document map, index owner or
//! runtime-state extraction. They do not acquire a newer generation or replace
//! the caller's authorization, key-access, or local-versus-quorum read contract.
use crate::Generation;
use kasumi_types::{
    AuditRetentionState, CollectionDefinition, FullBackupCheckpoint, LifecycleInstallation, Limits,
    PendingRestore, Policy,
};

/// Schema and counters borrowed from the same selected generation.
#[derive(Clone, Copy)]
pub struct CollectionMetadata<'a> {
    pub definition: &'a CollectionDefinition,
    pub data_epoch: u64,
    pub live_documents: usize,
    pub archived_documents: usize,
    pub archived_document_bytes: usize,
}

/// The immutable installation identity, without Control intent/change history.
#[derive(Clone, Copy)]
pub struct LifecycleInstallationMetadata<'a> {
    pub installation: &'a LifecycleInstallation,
    pub installation_command_id: uuid::Uuid,
}

impl Generation {
    /// Header-only local Control observation from this exact selected generation.
    /// It does not decode a body, perform authorization, or establish a quorum.
    pub fn local_control_topology_version(&self) -> Option<u64> {
        (self.tenant() == crate::control::CONTROL_TENANT)
            .then(|| {
                self.state
                    .collections
                    .get("topology")
                    .and_then(|collection| collection.documents.get("current"))
                    .map(|document| document.version)
            })
            .flatten()
    }

    pub fn tenant(&self) -> &str {
        &self.state.tenant
    }
    pub fn incarnation(&self) -> &str {
        &self.state.incarnation
    }
    pub fn revision(&self) -> u64 {
        self.state.revision
    }
    pub fn revision_base(&self) -> u64 {
        self.state.revision_base
    }
    pub fn policy_epoch(&self) -> u64 {
        self.state.policy_epoch
    }
    pub fn schema_epoch(&self) -> u64 {
        self.state.schema_epoch
    }
    pub fn suspended(&self) -> bool {
        self.state.suspended
    }
    pub fn retired(&self) -> bool {
        self.state.retired
    }
    pub fn pending_restore(&self) -> &Option<PendingRestore> {
        &self.state.pending_restore
    }
    pub fn restored_from(&self) -> &Option<FullBackupCheckpoint> {
        &self.state.restored_from
    }
    pub fn document_count(&self) -> u64 {
        self.state.document_count
    }
    pub fn logical_bytes(&self) -> u64 {
        self.state.logical_bytes
    }
    pub fn policy(&self) -> &Policy {
        &self.state.policy
    }
    pub fn limits(&self) -> &Limits {
        &self.state.limits
    }
    pub fn permanent_staged_bytes(&self) -> u64 {
        self.state.permanent_staged_bytes
    }
    pub fn reserved_staged_terminal_bytes(&self) -> u64 {
        self.state.reserved_staged_terminal_bytes
    }
    pub fn schema_activation_bytes(&self) -> u64 {
        self.state.schema_activation_bytes
    }
    pub fn retirement_bytes(&self) -> u64 {
        self.state.retirement_bytes
    }
    pub fn audit_retention(&self) -> &AuditRetentionState {
        &self.state.audit_retention
    }

    pub fn collection_metadata(&self, name: &str) -> Option<CollectionMetadata<'_>> {
        self.state
            .collections
            .get(name)
            .map(|collection| CollectionMetadata {
                definition: &collection.definition,
                data_epoch: collection.data_epoch,
                live_documents: collection.documents.len(),
                archived_documents: collection.archived_documents.len(),
                archived_document_bytes: collection.archived_document_bytes,
            })
    }

    pub fn collection_metadata_iter(
        &self,
    ) -> impl ExactSizeIterator<Item = (&str, CollectionMetadata<'_>)> {
        self.state.collections.iter().map(|(name, collection)| {
            (
                name.as_str(),
                CollectionMetadata {
                    definition: &collection.definition,
                    data_epoch: collection.data_epoch,
                    live_documents: collection.documents.len(),
                    archived_documents: collection.archived_documents.len(),
                    archived_document_bytes: collection.archived_document_bytes,
                },
            )
        })
    }

    pub fn lifecycle_installation(&self) -> Option<LifecycleInstallationMetadata<'_>> {
        self.state
            .lifecycle_control
            .as_ref()
            .map(|control| LifecycleInstallationMetadata {
                installation: &control.installation,
                installation_command_id: control.installation_command_id,
            })
    }
}

#[cfg(test)]
#[path = "generation_metadata_tests.rs"]
mod tests;
