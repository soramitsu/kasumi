use super::*;
use kasumi_raft::member_catalog::{CatalogStart, MemberCatalogRequest};
use kasumi_store::{StoragePurpose, TenantStore};
use kasumi_types::{
    KeyCatalogDomain, KeyReference, KeyRetentionEntry, KeyVersionRef, staged_digest,
};
use std::sync::Weak;

pub(super) struct OperationalStores {
    audit: Weak<TenantStore>,
    signer: Weak<TenantStore>,
}

#[derive(Eq, PartialEq, serde::Serialize)]
struct OperationalObservation {
    ids: AuthorityOperationalCatalogs,
    digests: [[u8; 32]; 2],
}

pub(super) struct CatalogObservation {
    position: MemberCatalogRequest,
    catalog: [u8; 32],
    membership_sha256: String,
    operational: Option<OperationalObservation>,
    _workspace: kasumi_store::DiskMemoryLease,
}

impl CatalogObservation {
    pub(super) fn check(&self, authority: &IndependentAuthority) -> Result<()> {
        self.position
            .check_position(&authority.group)
            .map_err(unavailable)?;
        if authority.catalog_membership()?.1 != self.membership_sha256 {
            return Err(unavailable(
                "Authority operational membership changed before release",
            ));
        }
        authority
            .group
            .check_member_catalog_digest(&self.catalog)
            .map_err(unavailable)?;
        let current = authority
            .visit_operational_catalogs(|_, _, _, _, _| Ok(()))
            .map_err(unavailable)?;
        if current != self.operational {
            return Err(unavailable(
                "Authority operational key catalog changed before release",
            ));
        }
        Ok(())
    }
}

impl IndependentAuthority {
    fn catalog_membership(&self) -> Result<(Vec<u64>, String)> {
        let current = self
            .backend
            .operational_configuration()
            .map_err(unavailable)?;
        let raft = self.group.metrics();
        let membership = raft.membership_config.membership();
        if current.pending_operation.is_some()
            || !current
                .membership
                .members
                .keys()
                .copied()
                .eq(membership.nodes().map(|(id, _)| *id))
            || !current
                .membership
                .voters
                .iter()
                .copied()
                .eq(membership.voter_ids())
        {
            return Err(unavailable(
                "Authority operational and Raft membership are unsettled",
            ));
        }
        let digest = staged_digest(&current.membership)?.0;
        Ok((current.membership.members.keys().copied().collect(), digest))
    }
    /// The parent runtime retains shutdown ownership of both opened stores.
    pub fn install_operational_key_catalogs(
        &self,
        audit: &Arc<TenantStore>,
        signer: &Arc<TenantStore>,
    ) -> anyhow::Result<()> {
        let disk = self.group.storage_domains().application().persistent_disk();
        let verifier = &self
            .settings
            .installed_members
            .get(&self.local_node_id)
            .context("Authority member missing")?
            .verifier;
        ensure!(
            Arc::ptr_eq(audit.persistent_disk(), disk)
                && Arc::ptr_eq(signer.persistent_disk(), disk)
                && matches!(
                    audit.storage_access().purpose(),
                    StoragePurpose::SecurityAudit
                )
                && matches!(signer.storage_access().purpose(), StoragePurpose::LiveSignerTrust {verifier: original} if original == verifier),
            "operational key stores differ from this Authority disk or enrolled verifier"
        );
        audit.check_access()?;
        signer.check_access()?;
        let expected = OperationalStores {
            audit: Arc::downgrade(audit),
            signer: Arc::downgrade(signer),
        };
        let installed = self.operational_catalogs.get_or_init(|| OperationalStores {
            audit: expected.audit.clone(),
            signer: expected.signer.clone(),
        });
        ensure!(
            installed.audit.ptr_eq(&expected.audit) && installed.signer.ptr_eq(&expected.signer),
            "different operational key stores already installed"
        );
        Ok(())
    }

    fn visit_operational_catalogs(
        &self,
        mut visit: impl FnMut(KeyCatalogDomain, Uuid, &str, &str, u64) -> anyhow::Result<()>,
    ) -> anyhow::Result<Option<OperationalObservation>> {
        let Some(stores) = self.operational_catalogs.get() else {
            return Ok(None);
        };
        let mut read = |source: &Weak<TenantStore>, domain| -> anyhow::Result<_> {
            let store = source
                .upgrade()
                .context("installed Authority operational store unavailable")?;
            let mut catalog = None;
            let digest = store.visit_wrapping_identities(|id, provider, key_ref, version| {
                catalog = Some(id);
                visit(domain, id, provider, key_ref, version)
            })?;
            Ok((
                catalog.context("installed catalog lacks wrapping identities")?,
                digest,
            ))
        };
        let (security_audit, audit_digest) = read(&stores.audit, KeyCatalogDomain::SecurityAudit)?;
        let (live_signer_trust, signer_digest) =
            read(&stores.signer, KeyCatalogDomain::LiveSignerTrust)?;
        Ok(Some(OperationalObservation {
            ids: AuthorityOperationalCatalogs {
                security_audit,
                live_signer_trust,
            },
            digests: [audit_digest, signer_digest],
        }))
    }
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
        let epoch = self.backend.authorize_catalog(&context)?;
        let metrics = self.group.metrics();
        let membership = (*metrics.membership_config.log_id())
            .ok_or_else(|| unavailable("Authority catalog has no installed membership"))?;
        let (members, membership_sha256) = self.catalog_membership()?;
        let position = MemberCatalogRequest {
            purpose: kasumi_raft::member_catalog::CatalogPurpose::Group,
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
        let operational = self
            .visit_operational_catalogs(|domain, catalog_id, provider, key_ref, version| {
                context.authorization.check_live()?;
                self.check_open()?;
                ensure!(
                    provider.len() <= kasumi_types::MAX_KEY_PROVIDER_BYTES
                        && key_ref.len() <= kasumi_types::MAX_KEY_REF_BYTES,
                    "wrapping identifier exceeds the Authority page bound"
                );
                let entry = KeyRetentionEntry {
                    key: KeyVersionRef {
                        provider: provider.into(),
                        key_ref: key_ref.into(),
                        version,
                    },
                    reference: KeyReference::Catalog {
                        node_id: self.local_node_id,
                        catalog_id,
                        domain,
                    },
                };
                entry.validate()?;
                if position.start.includes(&entry)
                    && let Err(index) = physical.entries.binary_search(&entry)
                    && index <= usize::from(query.limit)
                {
                    physical.entries.insert(index, entry);
                    physical.entries.truncate(usize::from(query.limit) + 1);
                }
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
            &membership_sha256,
            physical.application_catalog,
            physical.custody_catalog,
            physical.catalog_sha256,
            &operational,
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
            members,
            membership_sha256: membership_sha256.clone(),
            application_catalog: physical.application_catalog,
            custody_catalog: physical.custody_catalog,
            operational_catalogs: operational.as_ref().map(|v| v.ids.clone()),
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
            membership_sha256,
            operational,
            _workspace: workspace,
        });
        fence.check()?;
        Ok((AuthorityMaintenanceResponse::MemberCatalog { page }, fence))
    }
}
