//! Explicit offline enrollment input. Runtime never derives genesis from current
//! operational configuration or from a missing applied Control document.
use crate::runtime::{DeploymentMode, RuntimeConfig};
use anyhow::{Context, Result, ensure};
use kasumi_engine::control::{ControlTopology, DeploymentMode as RouteMode, TenantRoute};
use kasumi_engine::{
    ControlGenesis, ControlLifecycleGenesis, ReplicatedBootstrap, ReplicatedGenesis,
};
use std::collections::BTreeMap;

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
        topology: ControlTopology { nodes, tenants },
        lifecycle,
    });
    bootstrap.validate()?;
    Ok(bootstrap)
}

#[cfg(test)]
#[path = "control_genesis_tests.rs"]
pub(crate) mod tests;
