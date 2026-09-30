//! Routing and operator metadata belong to their own encrypted Raft group.
//! Tenant permissions remain authoritative in the tenant's Database.
use crate::Database;
use kasumi_types::*;
use serde_json::json;
use std::sync::Arc;

pub const CONTROL_TENANT: &str = "__kasumi_control";
const COLLECTION: &str = "topology";
const DOCUMENT: &str = "current";
pub use kasumi_types::control_topology::*;

/// Operators supply a server-authenticated control identity. No method rewrites
/// an end user's tenant context or grants data access through routing metadata.
pub struct ControlPlane {
    database: Arc<Database>,
}
impl ControlPlane {
    pub fn new(database: Arc<Database>) -> Result<Self> {
        if database.engine().generation()?.state.tenant != CONTROL_TENANT {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "control metadata needs its dedicated group",
            ));
        }
        Ok(Self { database })
    }
    pub fn database(&self) -> &Arc<Database> {
        &self.database
    }

    /// Create the reserved schema once, through consensus. Existing schemas are
    /// verified and never silently replaced by startup configuration.
    pub async fn initialize(&self, context: RequestContext) -> Result<()> {
        self.database
            .engine()
            .authorize(&context, None, Action::Admin)?;
        for definition in [Self::topology_definition(), Self::enrollment_definition()] {
            let existing = self
                .database
                .collections(&context)
                .await?
                .into_iter()
                .find(|collection| collection.name == definition.name);
            if let Some(existing) = existing {
                if existing != definition {
                    return Err(Error::new(
                        ErrorCode::Corruption,
                        "reserved Control schema differs from expected schema",
                    ));
                }
                continue;
            }
            if self
                .database
                .engine()
                .generation()?
                .state
                .lifecycle_control
                .is_some()
            {
                return Err(Error::new(
                    ErrorCode::Corruption,
                    "installed Control reserved schema is missing",
                ));
            }
            match self
                .database
                .administer(
                    context.clone(),
                    Operation::CreateCollection(definition.clone()),
                )
                .await
            {
                Ok(_) => {}
                Err(error) if error.code == ErrorCode::AlreadyExists => {
                    if !self
                        .database
                        .collections(&context)
                        .await?
                        .iter()
                        .any(|collection| collection == &definition)
                    {
                        return Err(Error::new(
                            ErrorCode::Corruption,
                            "reserved Control schema differs from expected schema",
                        ));
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
    pub(crate) fn topology_definition() -> CollectionDefinition {
        CollectionDefinition {
            retention_class: kasumi_types::CollectionRetentionClass::Operational,
            write_mode: kasumi_types::CollectionWriteMode::Mutable,
            name: COLLECTION.into(),
            schema: json!({
                "$schema":"https://json-schema.org/draft/2020-12/schema", "type":"object",
                "required":["nodes","tenants"], "additionalProperties":false,
                "properties":{"nodes":{"type":"object"},"tenants":{"type":"object"}}
            }),
            indexes: vec![],
            strict_read_audit: true,
        }
    }
    /// Reserved append-only approvals must exist before a closed lifecycle
    /// installation, which forbids later generic schema changes.
    pub fn enrollment_definition() -> CollectionDefinition {
        CollectionDefinition {
            retention_class: CollectionRetentionClass::Operational,
            write_mode: CollectionWriteMode::AppendOnly,
            name: "tenant_enrollments".into(),
            schema: json!({"type":"object"}),
            indexes: vec![],
            strict_read_audit: true,
        }
    }
    /// Inspect a replica's actual local state without implying a quorum read.
    /// Missing or substituted reserved state is corruption, never provisioning.
    pub fn applied_topology(state: &TenantState) -> Result<VersionedTopology> {
        let corrupt = |message| Error::new(ErrorCode::Corruption, message);
        if state.tenant != CONTROL_TENANT {
            return Err(corrupt("Control state has the wrong namespace"));
        }
        let collection = state
            .collections
            .get(COLLECTION)
            .ok_or_else(|| corrupt("installed Control topology schema is missing"))?;
        if collection.definition != Self::topology_definition() {
            return Err(corrupt("installed Control topology schema differs"));
        }
        if state.lifecycle_control.is_some()
            && state
                .collections
                .get("tenant_enrollments")
                .is_none_or(|collection| collection.definition != Self::enrollment_definition())
        {
            return Err(corrupt(
                "installed Control enrollment schema is missing or differs",
            ));
        }
        let document = collection
            .documents
            .get(DOCUMENT)
            .ok_or_else(|| corrupt("installed Control topology is missing"))?;
        let topology: ControlTopology = serde_json::from_value(document.body.clone())
            .map_err(|_| corrupt("installed Control topology is invalid"))?;
        topology.validate()?;
        Ok(VersionedTopology {
            version: document.version,
            topology,
        })
    }
    /// An established installation must retain its reserved schema. This read
    /// never interprets a missing schema as permission to initialize it.
    pub async fn require_initialized(&self, context: &RequestContext) -> Result<()> {
        self.database
            .engine()
            .authorize(context, None, Action::Admin)?;
        let collections = self.database.collections(context).await?;
        let existing = collections
            .iter()
            .find(|collection| collection.name == COLLECTION)
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::Corruption,
                    "installed Control topology schema is missing",
                )
            })?;
        if serde_json::to_value(existing)
            .map_err(|_| Error::new(ErrorCode::Corruption, "invalid installed Control schema"))?
            != serde_json::to_value(Self::topology_definition())
                .map_err(|_| Error::new(ErrorCode::Corruption, "invalid Control schema contract"))?
        {
            return Err(Error::new(
                ErrorCode::Corruption,
                "installed Control topology schema differs",
            ));
        }
        if self
            .database
            .engine()
            .generation()?
            .state
            .lifecycle_control
            .is_some()
            && collections
                .iter()
                .find(|collection| collection.name == "tenant_enrollments")
                != Some(&Self::enrollment_definition())
        {
            return Err(Error::new(
                ErrorCode::Corruption,
                "installed Control enrollment schema is missing or differs",
            ));
        }
        Ok(())
    }
    pub async fn topology(&self, context: &RequestContext) -> Result<Option<VersionedTopology>> {
        self.database
            .engine()
            .authorize(context, None, Action::Admin)?;
        let document = match self.database.get(context, COLLECTION, DOCUMENT).await {
            Ok(document) => document,
            Err(error) if error.code == ErrorCode::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let topology: ControlTopology = serde_json::from_value(document.body)
            .map_err(|_| Error::new(ErrorCode::Corruption, "invalid control topology"))?;
        topology
            .validate()
            .map_err(|_| Error::new(ErrorCode::Corruption, "invalid control placement"))?;
        Ok(Some(VersionedTopology {
            version: document.version,
            topology,
        }))
    }
    /// CAS the whole bounded topology so node approval and tenant routing become
    /// visible together. Raft membership changes remain explicit separate actions.
    pub async fn replace_topology(
        &self,
        context: RequestContext,
        topology: ControlTopology,
        expected: Precondition,
        idempotency_key: String,
    ) -> Result<WriteReceipt> {
        self.database
            .engine()
            .authorize(&context, None, Action::Admin)?;
        topology.validate()?;
        if matches!(expected, Precondition::Any) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "control updates require an explicit CAS precondition",
            ));
        }
        self.database
            .mutate(
                context,
                MutationBatch {
                    read_set: Vec::new(),
                    idempotency_key,
                    operations: vec![Mutation::Put {
                        collection: COLLECTION.into(),
                        id: DOCUMENT.into(),
                        body: serde_json::to_value(topology).map_err(|_| {
                            Error::new(
                                ErrorCode::InvalidArgument,
                                "control topology encoding failed",
                            )
                        })?,
                        expected,
                    }],
                },
            )
            .await
    }
}

#[cfg(test)]
#[path = "control_enrollment_genesis_tests.rs"]
mod enrollment_genesis_tests;
