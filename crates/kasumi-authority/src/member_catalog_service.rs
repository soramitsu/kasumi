use super::*;
use kasumi_raft::member_catalog::{CatalogStart, MemberCatalogRequest};
use kasumi_types::{KeyCatalogDomain, staged_digest};

pub(super) struct CatalogObservation {
    position: MemberCatalogRequest,
    catalog: [u8; 32],
    _workspace: kasumi_store::DiskMemoryLease,
}

impl CatalogObservation {
    pub(super) fn check(&self, authority: &IndependentAuthority) -> Result<()> {
        self.position
            .check_position(&authority.group)
            .map_err(unavailable)?;
        authority
            .group
            .check_member_catalog_digest(&self.catalog)
            .map_err(unavailable)
    }
}

impl IndependentAuthority {
    pub(super) async fn read_member_catalog(
        self: &Arc<Self>,
        context: RequestContext,
        query: AuthorityCatalogRequest,
        permit: RequestPermit,
        signer: Arc<AuthoritySigner>,
    ) -> Result<(AuthorityMaintenanceResponse, AuthorityResponseFence)> {
        context.authorization.check_live()?;
        self.check_installed_configuration().map_err(unavailable)?;
        let installation = self.installation();
        if query.authority_id != installation.manifest.authority_id
            || query.partition != installation.partition
            || query.node_id != self.local_node_id
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "Authority catalog member differs from this installation",
            ));
        }
        // A follower's read must witness its leader's real quorum and catch up
        // locally before it consults the local policy or either physical catalog.
        let applied = self
            .group
            .observation_barrier()
            .await
            .map_err(unavailable)?
            .ok_or_else(|| unavailable("Authority member has no applied quorum position"))?;
        let epoch = self.backend.authorize_admin(&context)?;
        let metrics = self.group.metrics();
        let membership = (*metrics.membership_config.log_id())
            .ok_or_else(|| unavailable("Authority catalog has no installed membership"))?;
        let position = MemberCatalogRequest {
            nonce: query.nonce,
            leader: metrics
                .current_leader
                .ok_or_else(|| unavailable("Authority leader unavailable"))?,
            term: metrics.current_term,
            membership: Some(membership),
            applied,
            start: query.cursor.as_ref().map_or(CatalogStart::First, |cursor| {
                CatalogStart::After {
                    entry: cursor.after.clone(),
                }
            }),
            limit: query.limit,
        };
        let workspace = self
            .group
            .reserve_member_catalog_workspace()
            .map_err(unavailable)?;
        let mut physical = self
            .group
            .capture_member_catalog(&position, KeyCatalogDomain::IndependentAuthority, || {
                context.authorization.check_live()?;
                self.check_open()?;
                Ok(())
            })
            .map_err(unavailable)?;
        let inventory_sha256 = staged_digest(&(
            "kasumi.authority-member.catalog.v1",
            self.bootstrap_digest(),
            query.authority_id,
            query.partition,
            self.local_node_id,
            epoch,
            position.term,
            membership,
            physical.application_catalog,
            physical.custody_catalog,
            physical.catalog_sha256,
        ))?
        .0;
        if query
            .cursor
            .as_ref()
            .is_some_and(|cursor| cursor.inventory_sha256 != inventory_sha256)
        {
            return Err(Error::new(
                ErrorCode::CursorExpired,
                "Authority member catalog or membership changed",
            ));
        }
        let limit = usize::from(query.limit);
        let more = physical.entries.len() > limit;
        physical.entries.truncate(limit);
        let page = AuthorityCatalogPage {
            request_sha256: staged_digest(&query)?.0,
            term: position.term,
            membership_index: membership.index,
            applied_index: applied.index,
            application_catalog: physical.application_catalog,
            custody_catalog: physical.custody_catalog,
            next: more.then(|| AuthorityCatalogCursor {
                inventory_sha256: inventory_sha256.clone(),
                after: physical
                    .entries
                    .last()
                    .expect("positive catalog page limit")
                    .clone(),
            }),
            inventory_sha256,
            entries: physical.entries,
        };
        page.validate(&query).map_err(unavailable)?;
        let mut fence = self.fence(permit, signer, context, Some(epoch), None, position.term);
        fence.member_catalog = Some(CatalogObservation {
            position,
            catalog: physical.catalog_sha256,
            _workspace: workspace,
        });
        fence.check()?;
        Ok((AuthorityMaintenanceResponse::MemberCatalog { page }, fence))
    }
}
