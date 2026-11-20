//! Read-only reports from the installed application and custody catalogs of a
//! current member. The leader's request pins the membership and minimum applied
//! position. A report carries wrapping identifiers only.
use crate::{BasicNode, LogId, RaftGroup, RpcRequest, RpcResponse};
use anyhow::{Context, Result, ensure};
use kasumi_types::{
    KeyCatalogDomain, KeyIdentityRef, KeyReference, KeyRetentionEntry, KeyVersionRef,
    MAX_KEY_PROVIDER_BYTES, MAX_KEY_REF_BYTES, staged_digest,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::time::Duration;
use uuid::Uuid;

/// A distributed page merges at most four entries and one lookahead per peer.
pub const MEMBER_CATALOG_LIMIT: u16 = kasumi_types::DATA_MEMBER_CATALOG_LIMIT;
/// Five maximum wrapping identities, including worst-case JSON escapes, plus framing.
pub const MEMBER_CATALOG_BYTES: usize = kasumi_types::DATA_MEMBER_CATALOG_BYTES;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CatalogPurpose {
    #[default]
    Group,
    ControlSigner,
    /// An enrolled read-only Control inventory principal delegates this one
    /// physical Data member read through its current authenticated Data leader.
    DataJournal {
        installation_id: Uuid,
        control: Uuid,
        expires_at_ms: u64,
    },
    /// The authenticated leader obtained this bounded physical read under a
    /// current Control-wide administrator grant. Recipients independently check
    /// this committed policy position and the credential deadline.
    ControlJournal {
        control: Uuid,
        policy_epoch: u64,
        principal_sha256: [u8; 32],
        expires_at_ms: u64,
    },
    /// A Data-group leader addresses the exact physical verifier on its voter.
    DataSigner {
        installation_id: Uuid,
    },
    ServiceAudit,
    DataServiceAudit {
        installation_id: Uuid,
    },
}

impl CatalogPurpose {
    pub fn data_installation(self) -> Option<Uuid> {
        match self {
            Self::DataSigner { installation_id }
            | Self::DataJournal {
                installation_id, ..
            }
            | Self::DataServiceAudit { installation_id } => Some(installation_id),
            _ => None,
        }
    }

    pub fn is_service_audit(self) -> bool {
        matches!(self, Self::ServiceAudit | Self::DataServiceAudit { .. })
    }

    fn is_group(&self) -> bool {
        *self == Self::Group
    }
}

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
    #[serde(default, skip_serializing_if = "CatalogPurpose::is_group")]
    pub purpose: CatalogPurpose,
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
        if let CatalogPurpose::ControlJournal {
            control,
            expires_at_ms,
            ..
        }
        | CatalogPurpose::DataJournal {
            control,
            expires_at_ms,
            ..
        } = self.purpose
        {
            ensure!(
                !control.is_nil() && expires_at_ms != 0,
                "invalid Control journal read"
            );
        }
        if let Some(installation_id) = self.purpose.data_installation() {
            ensure!(
                !installation_id.is_nil(),
                "missing physical Data verifier installation"
            );
        }
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
            request.purpose == CatalogPurpose::Group
                && self.node_id == node_id
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberSignerReport {
    pub request_sha256: String,
    pub verifier: kasumi_types::TrustVerifierIdentity,
    pub catalog: Uuid,
    pub catalog_sha256: [u8; 32],
    pub partitions_sha256: String,
    pub entries: Vec<KeyRetentionEntry>,
}

impl MemberSignerReport {
    pub fn validate(&self, request: &MemberCatalogRequest, node: u64) -> Result<()> {
        request.validate()?;
        self.verifier.validate()?;
        kasumi_types::validate_sha256(&self.partitions_sha256)?;
        ensure!(
            (request.purpose == CatalogPurpose::ControlSigner
                || request.purpose
                    == CatalogPurpose::DataSigner {
                        installation_id: self.verifier.installation_id
                    })
                && self.verifier.node_id == node
                && !self.catalog.is_nil()
                && self.request_sha256 == staged_digest(request)?.0
                && self.entries.len() <= usize::from(request.limit) + 1
                && self.entries.windows(2).all(|window| window[0] < window[1]),
            "signer catalog differs from the enrolled member or requested window"
        );
        for entry in &self.entries {
            entry.validate()?;
            ensure!(
                request.start.includes(entry)
                    && matches!(entry.reference, KeyReference::Catalog {node_id,catalog_id,domain:KeyCatalogDomain::LiveSignerTrust}
                        if node_id == node && catalog_id == self.catalog),
                "signer wrapping reference differs from this physical catalog"
            );
        }
        Ok(())
    }
}

/// One installed service audit writer's wrapping catalog and authenticated
/// archive chain, tied to the leader's original position and cursor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberAuditReport {
    pub request_sha256: String,
    pub node_id: u64,
    pub catalog: Uuid,
    pub stream: Uuid,
    pub catalog_sha256: [u8; 32],
    pub archives_sha256: [u8; 32],
    pub entries: Vec<KeyRetentionEntry>,
    pub unreadable_objects: Vec<Uuid>,
    pub truncated: bool,
}

/// The service that owns the installed writer keeps custody of archive reads
/// through cancellation and shutdown. Both service roles use its same projection.
#[async_trait::async_trait]
pub trait MemberAuditInventory: Send + Sync {
    async fn read_member_audit(
        &self,
        node: u64,
        request: MemberCatalogRequest,
    ) -> Result<MemberAuditReport>;
}

impl MemberAuditReport {
    pub fn validate(&self, request: &MemberCatalogRequest, node: u64) -> Result<()> {
        request.validate()?;
        ensure!(
            request.purpose.is_service_audit()
                && node != 0
                && self.node_id == node
                && !self.catalog.is_nil()
                && !self.stream.is_nil()
                && self.request_sha256 == staged_digest(request)?.0
                && self.entries.len() <= usize::from(request.limit) + 1
                && self.entries.windows(2).all(|pair| pair[0] < pair[1])
                && self.unreadable_objects.len() <= kasumi_types::MAX_MISSING_KEY_DEPENDENCIES
                && (!self.truncated
                    || self.unreadable_objects.len() == kasumi_types::MAX_MISSING_KEY_DEPENDENCIES)
                && self.unreadable_objects.iter().all(|id| !id.is_nil())
                && self
                    .unreadable_objects
                    .windows(2)
                    .all(|pair| pair[0] < pair[1]),
            "service audit report differs from the enrolled member or requested window"
        );
        for entry in &self.entries {
            entry.validate()?;
            ensure!(
                request.start.includes(entry)
                    && match entry.reference {
                        KeyReference::Catalog {
                            node_id,
                            catalog_id,
                            domain: KeyCatalogDomain::SecurityAudit,
                        } => node_id == node && catalog_id == self.catalog,
                        KeyReference::AuditArchive { stream_id, .. } => stream_id == self.stream,
                        _ => false,
                    },
                "service audit dependency belongs to another physical owner"
            );
        }
        Ok(())
    }
}

/// One physical journal and its verified historical backup dependencies.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberJournalReport {
    /// The receiving Control member proved that its original dedicated
    /// enrollment excludes a target. In that case catalog identifies the
    /// encrypted security store holding the enrollment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub excluded_by_enrollment: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writer_state_sha256: Option<String>,
    pub request_sha256: String,
    pub verifier: kasumi_types::TrustVerifierIdentity,
    pub catalog: Uuid,
    pub dependencies_sha256: [u8; 32],
    pub entries: Vec<KeyRetentionEntry>,
    pub unreadable_targets: Vec<Uuid>,
    pub truncated: bool,
}
impl MemberJournalReport {
    pub fn validate(&self, request: &MemberCatalogRequest, node: u64) -> Result<()> {
        request.validate()?;
        self.verifier.validate()?;
        if let Some(digest) = &self.writer_state_sha256 {
            kasumi_types::validate_sha256(digest)?;
        }
        if self.excluded_by_enrollment.is_some() {
            ensure!(
                matches!(request.purpose, CatalogPurpose::ControlJournal { .. })
                    && self.entries.is_empty()
                    && self.writer_state_sha256.is_none()
                    && self.unreadable_targets.is_empty()
                    && !self.truncated,
                "dedicated Control enrollment cannot report physical journal keys"
            );
        }
        if let CatalogPurpose::DataJournal {
            installation_id, ..
        } = request.purpose
        {
            ensure!(
                self.verifier.installation_id == installation_id,
                "target journal returned another physical Data verifier"
            );
        }

        ensure!(
            matches!(
                request.purpose,
                CatalogPurpose::ControlJournal { .. } | CatalogPurpose::DataJournal { .. }
            ) && self.verifier.node_id == node
                && self.request_sha256 == staged_digest(request)?.0
                && !self.catalog.is_nil()
                && self.entries.len() <= usize::from(request.limit) + 1
                && self.entries.windows(2).all(|w| w[0] < w[1])
                && self.unreadable_targets.len() <= kasumi_types::MAX_MISSING_KEY_DEPENDENCIES
                && (!self.truncated
                    || self.unreadable_targets.len() == kasumi_types::MAX_MISSING_KEY_DEPENDENCIES)
                && self.unreadable_targets.iter().all(|id| !id.is_nil())
                && self.unreadable_targets.windows(2).all(|w| w[0] < w[1]),
            "invalid member journal report"
        );
        for entry in &self.entries {
            entry.validate()?;
            ensure!(
                request.start.includes(entry)
                    && match entry.reference {
                        KeyReference::Catalog {
                            node_id,
                            catalog_id,
                            domain: KeyCatalogDomain::TargetJournal,
                        } => node_id == node && catalog_id == self.catalog,
                        KeyReference::TargetJournal { node_id, .. } => node_id == node,
                        KeyReference::CompletedBackup { .. } => true,
                        _ => false,
                    },
                "journal report contains another physical source or window"
            );
        }
        Ok(())
    }
}

impl RaftGroup {
    pub fn reserve_member_catalog_workspace(&self) -> Result<kasumi_store::DiskMemoryLease> {
        Ok(self
            .store
            .application()
            .plaintext_memory_owner()
            .clone()
            .reserve_document_decode((6 * MEMBER_CATALOG_BYTES) as u64)?)
    }

    pub fn check_member_catalog_digest(&self, expected: &[u8; 32]) -> Result<()> {
        let actual = self
            .store
            .visit_key_retention_catalogs(|_, _, _, _, _| Ok(()))?;
        ensure!(
            &actual == expected,
            "installed catalog changed before release"
        );
        Ok(())
    }

    /// Visit the application and custody catalogs that were supplied to this
    /// exact group at open. The caller owns admission and response release.
    pub fn capture_member_catalog(
        &self,
        request: &MemberCatalogRequest,
        application: KeyCatalogDomain,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<MemberCatalogReport> {
        ensure!(
            request.purpose == CatalogPurpose::Group,
            "group catalog purpose required"
        );
        request.validate()?;
        request.check_position(self)?;
        let purpose = self.store.application().storage_access().purpose();
        ensure!(
            matches!(
                application,
                KeyCatalogDomain::Application
                    | KeyCatalogDomain::NodeControl
                    | KeyCatalogDomain::IndependentAuthority
            ) && matches!(
                purpose,
                kasumi_store::StoragePurpose::IndependentAuthority { .. }
            ) == (application == KeyCatalogDomain::IndependentAuthority),
            "member catalog domain differs from installed storage"
        );
        check()?;
        let binding = self.store.custody().binding();
        let mut entries = BTreeSet::new();
        let catalog_sha256 = self.store.visit_key_retention_catalogs(
            |custody, catalog_id, provider, key_ref, version| {
                check()?;
                ensure!(
                    provider.len() <= MAX_KEY_PROVIDER_BYTES && key_ref.len() <= MAX_KEY_REF_BYTES,
                    "catalog identity exceeds member page bound"
                );
                let entry = KeyRetentionEntry {
                    key: KeyVersionRef {
                        provider: provider.into(),
                        key_ref: key_ref.into(),
                        version,
                    },
                    reference: KeyReference::Catalog {
                        node_id: self.id,
                        catalog_id,
                        domain: if custody {
                            KeyCatalogDomain::RetirementCustody
                        } else {
                            application
                        },
                    },
                };
                entry.validate()?;
                if request.start.includes(&entry) {
                    entries.insert(entry);
                    if entries.len() > usize::from(request.limit) + 1 {
                        entries.pop_last();
                    }
                }
                Ok(())
            },
        )?;
        let report = MemberCatalogReport {
            request_sha256: staged_digest(request)?.0,
            node_id: self.id,
            application_catalog: binding.application_catalog(),
            custody_catalog: binding.custody_catalog(),
            bound_from_creation: self.store.sessions_bound_from_creation()?,
            catalog_sha256,
            entries: entries.into_iter().collect(),
        };
        report.validate(request, self.id, application)?;
        request.check_position(self)?;
        check()?;
        Ok(report)
    }

    pub async fn read_member_catalog(
        &self,
        node_id: u64,
        node: &BasicNode,
        request: &MemberCatalogRequest,
    ) -> Result<MemberCatalogReport> {
        ensure!(
            request.purpose == CatalogPurpose::Group,
            "group catalog purpose required"
        );
        match self.request_member_catalog(node_id, node, request).await? {
            RpcResponse::MemberCatalog(Some(report)) => Ok(*report),
            _ => anyhow::bail!("member catalog unavailable"),
        }
    }

    pub async fn read_member_signer_catalog(
        &self,
        node_id: u64,
        node: &BasicNode,
        request: &MemberCatalogRequest,
    ) -> Result<MemberSignerReport> {
        ensure!(
            matches!(
                request.purpose,
                CatalogPurpose::ControlSigner | CatalogPurpose::DataSigner { .. }
            ),
            "member signer catalog purpose required"
        );
        match self.request_member_catalog(node_id, node, request).await? {
            RpcResponse::MemberSignerCatalog(report) => {
                report.validate(request, node_id)?;
                Ok(*report)
            }
            _ => anyhow::bail!("member signer catalog unavailable"),
        }
    }

    pub async fn read_member_journal_catalog(
        &self,
        node_id: u64,
        node: &BasicNode,
        request: &MemberCatalogRequest,
    ) -> Result<MemberJournalReport> {
        ensure!(
            matches!(
                request.purpose,
                CatalogPurpose::ControlJournal { .. } | CatalogPurpose::DataJournal { .. }
            ),
            "Control journal purpose required"
        );
        match self.request_member_catalog(node_id, node, request).await? {
            RpcResponse::MemberJournalCatalog(report) => {
                report.validate(request, node_id)?;
                Ok(*report)
            }
            _ => anyhow::bail!("physical target journal unavailable"),
        }
    }
    pub async fn read_member_audit_catalog(
        &self,
        node_id: u64,
        node: &BasicNode,
        request: &MemberCatalogRequest,
    ) -> Result<MemberAuditReport> {
        ensure!(
            request.purpose.is_service_audit(),
            "service audit purpose required"
        );
        match self.request_member_catalog(node_id, node, request).await? {
            RpcResponse::MemberAuditCatalog(report) => {
                report.validate(request, node_id)?;
                Ok(*report)
            }
            _ => anyhow::bail!("member service audit unavailable"),
        }
    }

    async fn request_member_catalog(
        &self,
        node_id: u64,
        node: &BasicNode,
        request: &MemberCatalogRequest,
    ) -> Result<RpcResponse> {
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
        // Service audit and target journal reads also authenticate retained objects at their destination.
        let timeout = if request.purpose.is_service_audit()
            || matches!(
                request.purpose,
                CatalogPurpose::ControlJournal { .. } | CatalogPurpose::DataJournal { .. }
            ) {
            30
        } else {
            3
        };
        let response = tokio::time::timeout(Duration::from_secs(timeout), send).await??;
        request.check_position(self)?;
        Ok(response)
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
            purpose: CatalogPurpose::Group,
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
        let journal_request = MemberCatalogRequest {
            purpose: CatalogPurpose::ControlJournal {
                control: Uuid::new_v4(),
                policy_epoch: 8,
                principal_sha256: [21; 32],
                expires_at_ms: 101,
            },
            ..request.clone()
        };
        let journal = MemberJournalReport {
            excluded_by_enrollment: None,
            writer_state_sha256: None,
            request_sha256: staged_digest(&journal_request)?.0,
            verifier: kasumi_types::TrustVerifierIdentity {
                node_id: 2,
                installation_id: Uuid::new_v4(),
            },
            catalog: app,
            dependencies_sha256: [44; 32],
            entries: vec![entry(1, app, KeyCatalogDomain::TargetJournal)],
            unreadable_targets: Vec::new(),
            truncated: false,
        };
        journal.validate(&journal_request, 2)?;
        // A retirement seeks the first version at or above one key identity.
        // Both authenticated member routes still bind and validate that window.
        for purpose in [
            journal_request.purpose,
            CatalogPurpose::DataJournal {
                installation_id: journal.verifier.installation_id,
                control: Uuid::new_v4(),
                expires_at_ms: 101,
            },
        ] {
            let mut seek = MemberCatalogRequest {
                purpose,
                start: CatalogStart::Identity {
                    identity: KeyIdentityRef {
                        provider: "kms".into(),
                        key_ref: "retained".into(),
                    },
                },
                ..journal_request.clone()
            };
            let mut result = journal.clone();
            result.request_sha256 = staged_digest(&seek)?.0;
            result.validate(&seek, 2)?;
            seek.start = CatalogStart::Identity {
                identity: KeyIdentityRef {
                    provider: "kms".into(),
                    key_ref: "zzz".into(),
                },
            };
            result.request_sha256 = staged_digest(&seek)?.0;
            assert!(
                result.validate(&seek, 2).is_err(),
                "earlier journal key crossed the retirement window"
            );
            result.entries.clear();
            result.validate(&seek, 2)?;
        }
        let mut excluded = journal.clone();
        excluded.excluded_by_enrollment = Some([6; 32]);
        assert!(excluded.validate(&journal_request, 2).is_err());
        excluded.entries.clear();
        excluded.validate(&journal_request, 2)?;
        assert!(journal.validate(&request, 2).is_err());
        assert!(journal.validate(&journal_request, 3).is_err());
        let mut wrong = journal.clone();
        wrong.entries[0].reference = KeyReference::LocalRecovery {
            operation_id: Uuid::new_v4(),
        };
        assert!(wrong.validate(&journal_request, 2).is_err());
        let mut wrong = journal;
        wrong.truncated = true;
        assert!(wrong.validate(&journal_request, 2).is_err());
        let signer_request = MemberCatalogRequest {
            purpose: CatalogPurpose::ControlSigner,
            ..request.clone()
        };
        let signer_id = Uuid::new_v4();
        let signer = MemberSignerReport {
            request_sha256: staged_digest(&signer_request)?.0,
            verifier: kasumi_types::TrustVerifierIdentity {
                installation_id: Uuid::new_v4(),
                node_id: 2,
            },
            catalog: signer_id,
            catalog_sha256: [1; 32],
            partitions_sha256: "a".repeat(64),
            entries: vec![entry(3, signer_id, KeyCatalogDomain::LiveSignerTrust)],
        };
        let audit_request = MemberCatalogRequest {
            purpose: CatalogPurpose::ServiceAudit,
            ..request.clone()
        };
        let stream = Uuid::new_v4();
        let mut audit = MemberAuditReport {
            request_sha256: staged_digest(&audit_request)?.0,
            node_id: 2,
            catalog: app,
            stream,
            catalog_sha256: [1; 32],
            archives_sha256: [2; 32],
            entries: vec![entry(2, app, KeyCatalogDomain::SecurityAudit)],
            unreadable_objects: vec![],
            truncated: false,
        };
        audit.validate(&audit_request, 2)?;
        assert!(audit.validate(&request, 2).is_err());
        assert!(audit.validate(&audit_request, 3).is_err());
        audit.entries[0].reference = KeyReference::AuditArchive {
            stream_id: stream,
            first_sequence: 11,
        };
        audit.validate(&audit_request, 2)?;
        audit.stream = Uuid::new_v4();
        assert!(audit.validate(&audit_request, 2).is_err());
        audit.stream = stream;
        audit.truncated = true;
        assert!(audit.validate(&audit_request, 2).is_err());
        signer.validate(&signer_request, 2)?;
        let mut data_request = MemberCatalogRequest {
            purpose: CatalogPurpose::DataSigner {
                installation_id: signer.verifier.installation_id,
            },
            ..signer_request.clone()
        };
        let mut data_report = MemberSignerReport {
            request_sha256: staged_digest(&data_request)?.0,
            ..signer.clone()
        };
        data_report.validate(&data_request, 2)?;
        assert!(data_report.validate(&signer_request, 2).is_err());
        data_report.verifier.installation_id = Uuid::new_v4();
        assert!(data_report.validate(&data_request, 2).is_err());
        data_request.purpose = CatalogPurpose::DataSigner {
            installation_id: Uuid::nil(),
        };
        assert!(data_request.validate().is_err());
        assert!(signer.validate(&request, 2).is_err());
        assert!(signer.validate(&signer_request, 3).is_err());
        assert!(report.validate(&signer_request, 2, application).is_err());
        let mut changed_signer = signer;
        changed_signer.entries = report.entries.clone();
        assert!(changed_signer.validate(&signer_request, 2).is_err());
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
