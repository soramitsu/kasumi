//! Exact routing metadata shared by the dedicated Control service and native clients.
use crate::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

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
    #[serde(deserialize_with = "kasumi_types::deserialize_u64_map")]
    pub nodes: BTreeMap<u64, ControlNode>,
    pub tenants: BTreeMap<String, TenantRoute>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

