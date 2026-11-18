//! Explicit offline enrollment input. Runtime never derives genesis from current
//! operational configuration or from a missing applied Control document.
use crate::runtime::{DeploymentMode, RuntimeConfig};
use anyhow::{Context, Result, ensure};
use kasumi_engine::control::{ControlTopology, DeploymentMode as RouteMode, TenantRoute};
use kasumi_engine::{
    ControlGenesis, ControlLifecycleGenesis, ReplicatedBootstrap, ReplicatedGenesis,
};
use std::collections::BTreeMap;

/// The data routes may name only the remote node set. Combining both sets
/// additionally validates global peer IDs, endpoints and TLS pin ownership.
pub(crate) fn dedicated_topology(
    config: &RuntimeConfig,
    remote: &ControlTopology,
) -> Result<ControlTopology> {
    ensure!(
        config.mode == DeploymentMode::Replicated
            && config.tenants.is_empty()
            && config.target_recovery.is_none(),
        "dedicated Control placement requires replicated mode and no local data or target"
    );
    remote.validate()?;
    ensure!(
        remote
            .tenants
            .values()
            .all(|route| route.mode == RouteMode::Replicated),
        "dedicated Control requires replicated data routes"
    );
    let mut nodes = config
        .replication
        .as_ref()
        .context("Control replication roster missing")?
        .control_nodes()?;
    let mut endpoints = nodes
        .values()
        .map(|node| node.endpoint.clone())
        .collect::<std::collections::BTreeSet<_>>();
    for (id, node) in &remote.nodes {
        let endpoint = url::Url::parse(&node.endpoint)?
            .origin()
            .ascii_serialization();
        ensure!(
            endpoints.insert(endpoint) && nodes.insert(*id, node.clone()).is_none(),
            "data placement reuses a Control or data endpoint or node ID"
        );
    }
    let topology = ControlTopology {
        nodes,
        tenants: remote.tenants.clone(),
    };
    topology.validate()?;
    Ok(topology)
}

pub(crate) fn bootstrap(config: &RuntimeConfig) -> Result<ReplicatedBootstrap> {
    ensure!(
        config.mode == DeploymentMode::Replicated,
        "Control genesis requires HA enrollment"
    );
    let replication = config
        .replication
        .as_ref()
        .context("Control genesis peers missing")?;
    let voters = replication.voters()?;
    let nodes = replication.control_nodes()?;
    let tenants = config
        .tenants
        .iter()
        .map(|tenant| {
            Ok((
                tenant.tenant.clone(),
                TenantRoute {
                    incarnation: tenant
                        .incarnation
                        .clone()
                        .context("Control genesis tenant incarnation missing")?,
                    mode: RouteMode::Replicated,
                    voters: voters.clone(),
                },
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let lifecycle = match &config.control.lifecycle {
        Some(installed) => ControlLifecycleGenesis::Installed {
            command_id: installed.command_id,
            installation: installed.installation.clone(),
        },
        None => ControlLifecycleGenesis::Disabled,
    };
    let mut bootstrap = config
        .bootstrap(
            &config.control.initial_policy,
            &config.control.initial_limits,
            config.control.incarnation.as_deref(),
        )?
        .context("Control genesis is missing")?;
    bootstrap.genesis = ReplicatedGenesis::Control(ControlGenesis {
        topology: match &config.control.remote_data {
            Some(remote) => dedicated_topology(config, remote)?,
            None => ControlTopology { nodes, tenants },
        },
        lifecycle,
    });
    bootstrap.validate()?;
    Ok(bootstrap)
}

#[cfg(test)]
#[path = "control_genesis_tests.rs"]
pub(crate) mod tests;
