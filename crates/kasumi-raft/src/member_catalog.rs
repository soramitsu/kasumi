//! Read-only reports from the installed application and custody catalogs of a
//! current member. The leader's request pins the membership and minimum applied
//! position. A report carries wrapping identifiers only.
use crate::{BasicNode, LogId, RaftGroup, RpcRequest, RpcResponse};
use anyhow::{Context, Result, ensure};
use kasumi_types::{
    KeyCatalogDomain, KeyIdentityRef, KeyReference, KeyRetentionEntry, staged_digest,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use uuid::Uuid;

/// A distributed page merges at most four entries and one lookahead per peer.
pub const MEMBER_CATALOG_LIMIT: u16 = 4;
/// Five maximum wrapping identities, including worst-case JSON escapes, plus framing.
pub const MEMBER_CATALOG_BYTES: usize = 320 << 10;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "start", rename_all = "snake_case", deny_unknown_fields)]
pub enum CatalogStart {
    First,
    After { entry: KeyRetentionEntry },
    Identity { identity: KeyIdentityRef },
}

impl CatalogStart {
    pub fn includes(&self, entry: &KeyRetentionEntry) -> bool {
        match self {
            Self::First => true,
            Self::After { entry: previous } => entry > previous,
            Self::Identity { identity } => {
                (&entry.key.provider, &entry.key.key_ref) >= (&identity.provider, &identity.key_ref)
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberCatalogRequest {
    pub nonce: Uuid,
    pub leader: u64,
    pub term: u64,
    pub membership: Option<LogId<u64>>,
    pub applied: LogId<u64>,
    pub start: CatalogStart,
    pub limit: u16,
}

impl MemberCatalogRequest {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.nonce.is_nil()
                && self.leader != 0
                && self.term > 0
                && self.applied.leader_id.term <= self.term
                && self
                    .membership
                    .is_none_or(|membership| membership.index <= self.applied.index)
                && (1..=MEMBER_CATALOG_LIMIT).contains(&self.limit),
            "invalid member catalog window"
        );
        match &self.start {
            CatalogStart::First => {}
            CatalogStart::After { entry } => entry.validate()?,
            CatalogStart::Identity { identity } => identity.validate()?,
        }
        Ok(())
    }

    fn at_position(&self, metrics: &crate::RaftMetrics<u64, BasicNode>) -> Result<bool> {
        let installed = metrics.membership_config.membership();
        ensure!(
            metrics.current_term == self.term
                && metrics.current_leader == Some(self.leader)
                && installed.voter_ids().any(|id| id == self.leader)
                && installed.get_node(&metrics.id).is_some()
                && metrics.membership_config.log_id() == &self.membership,
            "member catalog leadership or membership changed"
        );
        Ok(metrics.last_applied.is_some_and(|position| {
            position == self.applied
                || (position.index > self.applied.index && position >= self.applied)
        }))
    }

    pub fn check_position(&self, raft: &RaftGroup) -> Result<()> {
        raft.check_access()?;
        ensure!(
            self.at_position(&raft.metrics())?,
            "member has not applied the requested catalog position"
        );
        Ok(())
    }

    /// A follower may still be applying the entry that caused the leader's
    /// inventory. A membership or leadership change invalidates the request.
    pub async fn wait_position(&self, group: &RaftGroup) -> Result<()> {
        ensure!(!group.is_local(), "standalone group has no peer catalog");
        let mut metrics = group.raft().metrics();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                group.check_access()?;
                if self.at_position(&metrics.borrow_and_update())? {
                    return Ok(());
                }
                metrics.changed().await.context("catalog member stopped")?;
            }
        })
        .await
        .context("catalog member did not catch up")?
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberCatalogReport {
    pub request_sha256: String,
    pub node_id: u64,
    pub application_catalog: Uuid,
    pub custody_catalog: Uuid,
    pub bound_from_creation: bool,
    pub catalog_sha256: [u8; 32],
    pub entries: Vec<KeyRetentionEntry>,
}

impl MemberCatalogReport {
    pub fn validate(
        &self,
        request: &MemberCatalogRequest,
        node_id: u64,
        application: KeyCatalogDomain,
    ) -> Result<()> {
        ensure!(
            self.node_id == node_id
                && !self.application_catalog.is_nil()
                && !self.custody_catalog.is_nil()
                && self.custody_catalog != self.application_catalog
                && self.request_sha256 == staged_digest(request)?.0
                && self.entries.len() <= usize::from(request.limit) + 1
                && self.entries.windows(2).all(|pair| pair[0] < pair[1]),
            "catalog report differs from request"
        );
        for entry in &self.entries {
            entry.validate()?;
            ensure!(
                request.start.includes(entry)
                    && matches!(entry.reference,
                KeyReference::Catalog {node_id: node, catalog_id, domain} if node == node_id
                    && ((catalog_id == self.application_catalog && domain == application)
                        || (catalog_id == self.custody_catalog && domain == KeyCatalogDomain::RetirementCustody))),
                "catalog entry differs from installed member identity"
            );
        }
        Ok(())
    }
}

impl RaftGroup {
    pub async fn read_member_catalog(
        &self,
        node_id: u64,
        node: &BasicNode,
        request: &MemberCatalogRequest,
    ) -> Result<MemberCatalogReport> {
        request.validate()?;
        request.check_position(self)?;
        ensure!(
            self.node_id() == request.leader && node_id != request.leader,
            "catalog requires the current leader"
        );
        let transport = self
            .transport
            .as_ref()
            .context("replica transport unavailable")?;
        let send = transport.send(
            &self.group,
            self.id,
            node_id,
            node,
            RpcRequest::MemberCatalog(Box::new(request.clone())),
        );
        let response = tokio::time::timeout(Duration::from_secs(3), send).await??;
        request.check_position(self)?;
        match response {
            RpcResponse::MemberCatalog(Some(report)) => Ok(*report),
            _ => anyhow::bail!("member catalog unavailable"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kasumi_types::KeyVersionRef;

    #[test]
    fn report_binds_the_request_member_physical_catalogs_and_ordered_window() -> Result<()> {
        let applied = LogId::new(openraft::CommittedLeaderId::new(3, 1), 7);
        let request = MemberCatalogRequest {
            nonce: Uuid::new_v4(),
            leader: 1,
            term: 3,
            membership: Some(applied),
            applied,
            start: CatalogStart::First,
            limit: 1,
        };
        let app = Uuid::new_v4();
        let custody = Uuid::new_v4();
        let entry = |version, catalog_id, domain| KeyRetentionEntry {
            key: KeyVersionRef {
                provider: "kms".into(),
                key_ref: "retained".into(),
                version,
            },
            reference: KeyReference::Catalog {
                node_id: 2,
                catalog_id,
                domain,
            },
        };
        let first = entry(2, app, KeyCatalogDomain::Application);
        let next = entry(3, custody, KeyCatalogDomain::RetirementCustody);
        let report = MemberCatalogReport {
            node_id: 2,
            application_catalog: app,
            custody_catalog: custody,
            bound_from_creation: true,
            catalog_sha256: [11; 32],
            request_sha256: staged_digest(&request)?.0,
            entries: vec![first.clone(), next.clone()],
        };
        let application = KeyCatalogDomain::Application;
        report.validate(&request, 2, application)?;
        assert!(report.validate(&request, 3, application).is_err());
        assert!(
            report
                .validate(&request, 2, KeyCatalogDomain::NodeControl)
                .is_err()
        );
        let mut replay = request.clone();
        replay.nonce = Uuid::new_v4();
        assert!(report.validate(&replay, 2, application).is_err());
        let mut changed = report.clone();
        changed.application_catalog = Uuid::new_v4();
        assert!(changed.validate(&request, 2, application).is_err());
        changed = report.clone();
        changed.entries.reverse();
        assert!(changed.validate(&request, 2, application).is_err());
        let after_first = MemberCatalogRequest {
            start: CatalogStart::After { entry: first },
            ..request
        };
        changed = report;
        changed.request_sha256 = staged_digest(&after_first)?.0;
        assert!(changed.validate(&after_first, 2, application).is_err());
        changed.entries = vec![next];
        changed.validate(&after_first, 2, application)?;
        Ok(())
    }
}
