use super::*;
use kasumi_types::{DATA_MEMBER_CATALOG_BYTES, DataMemberCatalogRead, DataMemberService};

impl Database {
    /// Confirm the Data group's final voter set through the installed Data
    /// leader and distinct physical voter identities before Control publishes it.
    pub async fn confirm_data_membership(
        &self,
        context: &RequestContext,
        tenant: &str,
        incarnation: uuid::Uuid,
        voters: &BTreeSet<u64>,
    ) -> Result<[u8; 32]> {
        let unavailable = |message| Error::new(ErrorCode::Unavailable, message);
        if self.store.tenant() != crate::control::CONTROL_TENANT
            || context.tenant != self.store.tenant()
            || voters.len() != 3
            || voters.contains(&0)
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "expected a hosted Control voter and three proposed Data voters",
            ));
        }
        self.engine.authorize(context, None, Action::Admin)?;
        let fence =
            ResponseFence::capture_workspace(ResponseDatabase::Borrowed(self), context, true)?;
        let _work = self.work.begin(fence.cancellation.clone())?;
        let _workspace = self.admission().reserve(
            6 * DATA_MEMBER_CATALOG_BYTES as u64,
            Some(fence.cancellation.clone()),
        )?;
        let reader = self
            .remote_data_catalog_reader
            .get()
            .ok_or_else(|| unavailable("Data voter readers are not enrolled"))?;
        let group = reader
            .groups()
            .get(tenant)
            .filter(|group| group.incarnation == incarnation && voters.is_subset(&group.members))
            .ok_or_else(|| {
                unavailable("Data voter set differs from the installed reader enrollment")
            })?;
        let confirm = async {
            self.barrier().await?;
            let mut observed = None;
            let mut last_failure = None;
            for &id in voters {
                fence.check()?;
                let verifier = reader
                    .verifier(id)
                    .filter(|verifier| verifier.node_id == id)
                    .ok_or_else(|| unavailable("Data voter verifier is missing"))?;
                let request = DataMemberCatalogRead {
                    tenant: tenant.into(),
                    incarnation,
                    verifier: verifier.clone(),
                    service: DataMemberService::Signer,
                    nonce: uuid::Uuid::new_v4(),
                    from_identity: None,
                    after: None,
                    limit: 1,
                };
                let page = match reader.read(voters, &request).await {
                    Ok(page) => page,
                    Err(error) => {
                        last_failure = Some(error);
                        continue;
                    }
                };
                page.validate(&request)?;
                if &page.membership.voters != voters
                    || !page.membership.members.is_subset(&group.members)
                {
                    return Err(Error::new(
                        ErrorCode::Conflict,
                        "Data has another committed membership",
                    ));
                }
                if let Some(first) = observed {
                    if first != page.membership {
                        return Err(Error::new(
                            ErrorCode::Conflict,
                            "Data membership moved during confirmation",
                        ));
                    }
                    self.barrier().await?;
                    fence.check()?;
                    self.engine.authorize(context, None, Action::Admin)?;
                    let mut digest = [0; 32];
                    hex::decode_to_slice(&page.membership.membership_sha256, &mut digest).map_err(
                        |_| unavailable("invalid confirmed Data membership fingerprint"),
                    )?;
                    return Ok(digest);
                }
                observed = Some(page.membership);
            }
            Err(
                unavailable("Data voter confirmations did not form a quorum").with_physical_source(
                    last_failure
                        .unwrap_or_else(|| anyhow::anyhow!("insufficient responding Data voters")),
                ),
            )
        };
        tokio::select! {
            biased;
            _ = cancelled(&fence.cancellation) => Err(cancelled_error()),
            result = tokio::time::timeout(std::time::Duration::from_secs(30), confirm) =>
                result.map_err(|_| unavailable("Data voter confirmation deadline elapsed"))?,
        }
    }
}
