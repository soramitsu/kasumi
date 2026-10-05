//! Exact routing metadata shared by the dedicated Control service and native clients.
use crate::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[path = "control_topology_memory.rs"]
mod memory;
pub use memory::TopologyMemory;

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
    #[serde(deserialize_with = "crate::deserialize_u64_map")]
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
    /// Conservative heap peak of default `url::Url::parse`, including the
    /// returned URL until drop. This pure quote does not reserve memory.
    ///
    /// The bound is tied to the pinned Rust/URL/IDNA implementations and the
    /// documented backing-allocation policy in the private workspace module.
    /// It excludes this topology's DTO, validation sets and Error String. A
    /// semantic caller must admit all those owners before doing the work.
    pub fn endpoint_workspace_bytes(endpoint: &str) -> Result<u64> {
        workspace::quote(endpoint)
    }

    pub fn validate(&self) -> Result<()> {
        validate_parts(
            &self.nodes,
            self.tenants
                .iter()
                .map(|(tenant, route)| (tenant.as_str(), RouteRef::from(route))),
        )
    }

    /// Validate the whole topology with one existing route's candidate voters.
    /// An absent tenant leaves the topology unchanged, including its validation.
    pub fn validate_voter_override(&self, tenant: &str, voters: &BTreeSet<u64>) -> Result<()> {
        validate_parts(
            &self.nodes,
            self.tenants.iter().map(|(name, route)| {
                let mut route = RouteRef::from(route);
                if name == tenant {
                    route.voters = voters;
                }
                (name.as_str(), route)
            }),
        )
    }

    /// Validate an enrollment's borrowed node map and sole proposed route.
    pub fn validate_single_route(
        nodes: &BTreeMap<u64, ControlNode>,
        tenant: &str,
        route: &TenantRoute,
    ) -> Result<()> {
        validate_parts(nodes, std::iter::once((tenant, RouteRef::from(route))))
    }
}

struct RouteRef<'a> {
    incarnation: &'a str,
    mode: &'a DeploymentMode,
    voters: &'a BTreeSet<u64>,
}
impl<'a> From<&'a TenantRoute> for RouteRef<'a> {
    fn from(route: &'a TenantRoute) -> Self {
        Self {
            incarnation: &route.incarnation,
            mode: &route.mode,
            voters: &route.voters,
        }
    }
}

// Only concrete map/once iterators reach this private boundary. Their exact
// cardinality preserves the topology quotas without constructing an owned view.
fn validate_parts<'a>(
    nodes: &BTreeMap<u64, ControlNode>,
    tenants: impl ExactSizeIterator<Item = (&'a str, RouteRef<'a>)>,
) -> Result<()> {
    let invalid = |message| Error::new(ErrorCode::InvalidArgument, message);
    if nodes.len() > MAX_NODES || tenants.len() > MAX_TENANTS {
        return Err(Error::new(
            ErrorCode::QuotaExceeded,
            "control topology limit exceeded",
        ));
    }
    let mut pins = BTreeSet::new();
    for (id, node) in nodes {
        let url = url::Url::parse(&node.endpoint).map_err(|_| invalid("invalid node endpoint"))?;
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
    for (tenant, route) in tenants {
        validate_name(tenant)?;
        let incarnation = uuid::Uuid::parse_str(route.incarnation)
            .map_err(|_| invalid("invalid tenant incarnation"))?;
        if tenant.starts_with("__kasumi_")
            || incarnation.is_nil()
            || incarnation.to_string() != route.incarnation
        {
            return Err(invalid("reserved tenant name or invalid incarnation"));
        }
        let required = if *route.mode == DeploymentMode::Local {
            1
        } else {
            3
        };
        if route.voters.len() != required {
            return Err(invalid("deployment voter count is invalid"));
        }
        let mut domains = BTreeSet::new();
        for id in route.voters {
            let node = nodes
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

#[path = "control_topology_workspace.rs"]
mod workspace;

#[cfg(test)]
#[path = "control_topology_tests.rs"]
mod tests;
