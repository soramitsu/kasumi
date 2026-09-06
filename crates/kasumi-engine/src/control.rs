//! Routing and operator metadata belong to their own encrypted Raft group.
//! Tenant permissions remain authoritative in the tenant's Database.
use crate::Database;
use kasumi_types::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

pub const CONTROL_TENANT: &str = "__kasumi_control";
const COLLECTION: &str = "topology";
const DOCUMENT: &str = "current";
const MAX_NODES: usize = 1024;
const MAX_TENANTS: usize = 100_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlNode {
    pub endpoint: String,
    pub failure_domain: String,
    /// SHA-256 of an approved TLS leaf DER certificate; rotation may overlap two.
    pub certificate_pins: BTreeSet<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentMode {
    Local,
    Replicated,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantRoute {
    pub incarnation: String,
    pub mode: DeploymentMode,
    pub voters: BTreeSet<u64>,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlTopology {
    pub nodes: BTreeMap<u64, ControlNode>,
    pub tenants: BTreeMap<String, TenantRoute>,
}
#[derive(Clone, Debug)]
pub struct VersionedTopology {
    pub version: u64,
    pub topology: ControlTopology,
}

impl ControlTopology {
    pub fn validate(&self) -> Result<()> {
        let invalid = |message| Error::new(ErrorCode::InvalidArgument, message);
        if self.nodes.len() > MAX_NODES || self.tenants.len() > MAX_TENANTS {
            return Err(Error::new(
                ErrorCode::QuotaExceeded,
                "control topology limit exceeded",
            ));
        }
        let mut pins = BTreeSet::new();
        for (id, node) in &self.nodes {
            let url =
                url::Url::parse(&node.endpoint).map_err(|_| invalid("invalid node endpoint"))?;
            if *id == 0
                || url.scheme() != "https"
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || !matches!(url.path(), "" | "/")
                || url.query().is_some()
                || url.fragment().is_some()
                || node.certificate_pins.is_empty()
                || node.certificate_pins.len() > 2
            {
                return Err(invalid(
                    "node requires a TLS endpoint and approved certificate pins",
                ));
            }
            validate_name(&node.failure_domain)?;
            for pin in &node.certificate_pins {
                if pin.len() != 64
                    || !pin
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    || !pins.insert(pin)
                {
                    return Err(invalid("certificate pin must identify exactly one node"));
                }
            }
        }
        for (tenant, route) in &self.tenants {
            validate_name(tenant)?;
            if tenant.starts_with("__kasumi_") || uuid::Uuid::parse_str(&route.incarnation).is_err()
            {
                return Err(invalid("reserved tenant name or invalid incarnation"));
            }
            let required = if route.mode == DeploymentMode::Local {
                1
            } else {
                3
            };
            if route.voters.len() != required {
                return Err(invalid("deployment voter count is invalid"));
            }
            let mut domains = BTreeSet::new();
            for id in &route.voters {
                let node = self
                    .nodes
                    .get(id)
                    .ok_or_else(|| invalid("tenant placement references an unapproved node"))?;
                if !domains.insert(&node.failure_domain) {
                    return Err(invalid(
                        "tenant voters must occupy independent failure domains",
                    ));
                }
            }
        }
        Ok(())
    }
}

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
        let definition = CollectionDefinition {
            write_mode: kasumi_types::CollectionWriteMode::Mutable,
            name: COLLECTION.into(),
            schema: json!({
                "$schema":"https://json-schema.org/draft/2020-12/schema", "type":"object",
                "required":["nodes","tenants"], "additionalProperties":false,
                "properties":{"nodes":{"type":"object"},"tenants":{"type":"object"}}
            }),
            indexes: vec![],
            strict_read_audit: true,
        };
        let existing = self
            .database
            .collections(&context)
            .await?
            .into_iter()
            .find(|c| c.name == COLLECTION);
        if let Some(existing) = existing {
            if serde_json::to_value(existing).ok() != serde_json::to_value(&definition).ok() {
                return Err(Error::new(
                    ErrorCode::Corruption,
                    "control topology schema differs from expected schema",
                ));
            }
            return Ok(());
        }
        match self
            .database
            .administer(context, Operation::CreateCollection(definition))
            .await
        {
            Ok(_) => Ok(()),
            Err(error) if error.code == ErrorCode::AlreadyExists => Ok(()),
            Err(error) => Err(error),
        }
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
