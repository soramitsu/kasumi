//! Atomic, permanently identified administrative schema/index activation.
use crate::{CollectionDefinition, ReadAssertion, Result, WriteReceipt, staged_digest};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_SCHEMA_CHANGESET_BYTES: usize = 8 << 20;
pub const MAX_SCHEMA_CHANGESET_COLLECTIONS: usize = 128;
pub const MAX_SCHEMA_READ_ASSERTIONS: usize = 512;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadSchema {
    pub collections: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaSnapshot {
    pub incarnation: String,
    pub revision: u64,
    pub policy_epoch: u64,
    pub schema_epoch: u64,
    pub collections: BTreeMap<String, Option<SchemaCollection>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaCollection {
    pub definition: CollectionDefinition,
    pub data_epoch: u64,
    pub archived_document_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaChangeSet {
    pub activation_id: String,
    pub expected_incarnation: String,
    pub expected_schema_epoch: u64,
    /// Immutable pre-transition dependencies, included in the permanent digest.
    /// Evaluate only when applying a fresh effect, never after its own schema
    /// transition or when recovering its historical result.
    pub read_set: Vec<ReadAssertion>,
    pub changes: Vec<SchemaChange>,
}

impl SchemaChangeSet {
    pub fn reference(&self) -> Result<SchemaActivationRef> {
        Ok(SchemaActivationRef {
            activation_id: self.activation_id.clone(),
            request_digest: staged_digest(self)?.0,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SchemaChange {
    Create {
        definition: CollectionDefinition,
    },
    Replace {
        definition: CollectionDefinition,
        expected_data_epoch: u64,
    },
}

impl SchemaChange {
    pub fn definition(&self) -> &CollectionDefinition {
        match self {
            Self::Create { definition } | Self::Replace { definition, .. } => definition,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaActivationRef {
    pub activation_id: String,
    pub request_digest: String,
}

/// Current admission for historical status. These assertions are separate from
/// the original immutable effect and remain live through response release.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadSchemaActivation {
    pub reference: SchemaActivationRef,
    pub read_set: Vec<ReadAssertion>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SchemaActivationStatus {
    pub request_digest: String,
    pub outcome: Result<WriteReceipt>,
}

/// Operational metadata, included in every full snapshot/backup. Never expires
/// or enters the user document/archive namespace.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredSchemaActivation {
    pub principal: String,
    pub activation_id: String,
    pub request_digest: String,
    pub collections: BTreeSet<String>,
    /// Retained dependency access is reauthorized even on historical recovery.
    pub read_collections: BTreeSet<String>,
    pub outcome: Result<WriteReceipt>,
}
