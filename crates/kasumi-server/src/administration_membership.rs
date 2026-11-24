//! Dedicated Data voters change their own Raft group. The Control quorum
//! publishes its tenant route after observing that final Data membership.
use super::*;

pub(super) async fn confirm_original_route(
    remote: &crate::remote_control::RemoteControl,
    database: &Database,
    tenant: &str,
    voters: &BTreeSet<u64>,
    peers: &[crate::runtime::ReplicaConfig],
) -> Result<()> {
    let group = database.raft_group();
    group.linearizable_barrier().await?;
    let before = group.metrics();
    let membership = &before.membership_config;
    let position = *membership.log_id();
    ensure!(
        before.current_leader == Some(before.id)
            && position.is_some()
            && before.last_applied >= position
            && membership.membership().get_joint_config().len() == 1,
        "Data leader requires a stable applied original membership"
    );
    let previous = membership.membership().voter_ids().collect::<BTreeSet<_>>();
    let incarnation = database.engine().generation()?.incarnation().to_owned();
    remote
        .released_routes(|topology| {
            let route = topology
                .tenants
                .get(tenant)
                .context("approved Data route absent")?;
            ensure!(
                route.voters == previous,
                "publish the previous Data membership before another change"
            );
            validate_voters(topology, voters)?;
            topology.validate_voter_override(tenant, voters)?;
            for peer in peers {
                crate::remote_control::approved_learner(
                    topology,
                    tenant,
                    &incarnation,
                    before.id,
                    peer,
                )?;
            }
            Ok(())
        })
        .await?;
    let after = group.metrics();
    ensure!(
        after.current_leader == Some(before.id)
            && after.current_term == before.current_term
            && after.membership_config == before.membership_config,
        "Data leadership or membership moved before proposal"
    );
    Ok(())
}

pub(crate) async fn publish_data_voters(
    database: &Arc<Database>,
    context: &RequestContext,
    tenant: &str,
    incarnation: Uuid,
    previous_voters: &BTreeSet<u64>,
    voters: &BTreeSet<u64>,
) -> Result<()> {
    require_control(context)?;
    let plane = ControlPlane::new(database.clone())?;
    let current = plane
        .topology(context)
        .await?
        .context("Control topology missing")?;
    let mut topology = current.topology;
    let route = topology.tenants.get(tenant).context("Data route missing")?;
    let incarnation_text = incarnation.to_string();
    ensure!(
        route.incarnation == incarnation_text
            && route.mode == kasumi_engine::control::DeploymentMode::Replicated
            && (&route.voters == previous_voters || &route.voters == voters),
        kasumi_types::Error::new(
            kasumi_types::ErrorCode::Conflict,
            "original Data route changed"
        )
    );
    validate_voters(&topology, previous_voters)?;
    validate_voters(&topology, voters)?;
    topology.validate_voter_override(tenant, voters)?;
    let membership = database
        .confirm_data_membership(context, tenant, incarnation, voters)
        .await?;
    if let Some(key) = publish_voters(
        &mut topology,
        tenant,
        voters.clone(),
        &hex::encode(membership),
    )? {
        plane
            .replace_topology(
                context.clone(),
                topology,
                Precondition::Version(current.version),
                key,
            )
            .await?;
    }
    let confirm = async {
        let confirmed = database
            .confirm_data_membership(context, tenant, incarnation, voters)
            .await?;
        let released = plane
            .topology(context)
            .await?
            .context("published Data route missing")?;
        ensure!(
            confirmed == membership
                && released
                    .topology
                    .tenants
                    .get(tenant)
                    .is_some_and(
                        |route| route.incarnation == incarnation_text && &route.voters == voters
                    ),
            "Data or Control membership moved during publication"
        );
        Ok::<(), anyhow::Error>(())
    };
    confirm.await.map_err(|error| {
        kasumi_types::Error::new(
            kasumi_types::ErrorCode::UnknownOutcome,
            "membership publication requires confirmation; retry the original request",
        )
        .with_physical_source(error)
        .into()
    })
}
