//! Physical member contribution to a distributed wrapping-key inventory.
use super::*;
use kasumi_raft::member_catalog::{
    CatalogStart, MEMBER_CATALOG_BYTES, MEMBER_CATALOG_LIMIT, MemberCatalogReport,
    MemberCatalogRequest,
};

fn unavailable(error: impl std::fmt::Display) -> Error {
    Error::new(ErrorCode::Unavailable, error.to_string())
}

impl Database {
    /// Called on the installed cluster listener after peer TLS, group enrollment,
    /// fingerprint and leader identity checks. No provider material leaves the store.
    pub async fn member_key_catalog(
        &self,
        request: MemberCatalogRequest,
    ) -> Result<AdmittedOutput<kasumi_raft::RpcResponse>> {
        request.validate().map_err(unavailable)?;
        self.access()?;
        let token = QueryCancellation::default();
        let _cancel = CancelOnDrop(token.clone());
        let registration = self.work.begin(token.clone())?;
        let charge = self
            .admission()
            .reserve((6 * MEMBER_CATALOG_BYTES) as u64, Some(token.clone()))?;
        tokio::select! {
            result = request.wait_position(&self.group) => result.map_err(unavailable)?,
            _ = cancelled(&token) => return Err(cancelled_error()),
        }
        let stores = self.stores.clone();
        let group = self.group.clone();
        let node_id = group.node_id();
        let control = self.store.tenant() == crate::control::CONTROL_TENANT;
        charge
            .retained_read(token, move |mut charge, token| {
                let _registration = registration;
                let domain = if control {
                    KeyCatalogDomain::NodeControl
                } else {
                    KeyCatalogDomain::Application
                };
                let binding = stores.custody().binding();
                let mut entries = BTreeSet::new();
                let catalog_sha256 = stores
                    .visit_key_retention_catalogs(
                        |custody, catalog_id, provider, key_ref, version| {
                            token.check()?;
                            anyhow::ensure!(
                                provider.len() <= MAX_KEY_PROVIDER_BYTES
                                    && key_ref.len() <= MAX_KEY_REF_BYTES,
                                "catalog identity exceeds member page bound"
                            );
                            let key = KeyVersionRef {
                                provider: provider.to_owned(),
                                key_ref: key_ref.to_owned(),
                                version,
                            };
                            let entry = KeyRetentionEntry {
                                key,
                                reference: KeyReference::Catalog {
                                    node_id,
                                    catalog_id,
                                    domain: if custody {
                                        KeyCatalogDomain::RetirementCustody
                                    } else {
                                        domain
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
                    )
                    .map_err(unavailable)?;
                let report = MemberCatalogReport {
                    request_sha256: staged_digest(&request)?.0,
                    node_id,
                    application_catalog: binding.application_catalog(),
                    custody_catalog: binding.custody_catalog(),
                    bound_from_creation: stores
                        .sessions_bound_from_creation()
                        .map_err(unavailable)?,
                    catalog_sha256,
                    entries: entries.into_iter().collect(),
                };
                report
                    .validate(&request, node_id, domain)
                    .map_err(unavailable)?;
                request.check_position(&group).map_err(unavailable)?;
                token.check()?;
                charge.retain_workspace();
                Ok(AdmittedOutput::new(
                    kasumi_raft::RpcResponse::MemberCatalog(Some(Box::new(report))),
                    Arc::new(charge),
                ))
            })
            .await
    }

    pub(super) async fn observe_member_catalogs(
        &self,
        metrics: &kasumi_raft::RaftMetrics<u64, kasumi_raft::BasicNode>,
        page: &ReadKeyRetentionRequest,
        probe: bool,
        cancellation: &QueryCancellation,
        entries: &mut BTreeSet<KeyRetentionEntry>,
        missing: (&mut BTreeSet<MissingKeyDependency>, &mut bool),
    ) -> Result<[u8; 32]> {
        let (missing, truncated) = missing;
        let mut digest = Sha256::new();
        let domain = if self.store.tenant() == crate::control::CONTROL_TENANT {
            KeyCatalogDomain::NodeControl
        } else {
            KeyCatalogDomain::Application
        };
        let local = self.group.node_id();
        let start = match page.cursor.as_ref() {
            Some(cursor) if probe => CatalogStart::Identity {
                identity: cursor.after.key.identity(),
            },
            Some(cursor) => CatalogStart::After {
                entry: cursor.after.clone(),
            },
            None => CatalogStart::First,
        };
        let members = metrics.membership_config.membership();
        if members.nodes().count() <= 1 {
            return Ok(digest.finalize().into());
        }
        // One peer request, response and decode buffer at a time. This workspace
        // is separate from the caller's reservation for the merged output.
        let _wire = self
            .admission()
            .reserve_resident((6 * MEMBER_CATALOG_BYTES) as u64)?;
        for (&node_id, node) in members.nodes() {
            if node_id == local {
                continue;
            }
            cancellation.check()?;
            let observed = async {
                let request = MemberCatalogRequest {
                    nonce: uuid::Uuid::new_v4(),
                    leader: local,
                    term: metrics.current_term,
                    membership: *metrics.membership_config.log_id(),
                    applied: metrics
                        .last_applied
                        .ok_or_else(|| unavailable("no applied catalog position"))?,
                    start: start.clone(),
                    limit: page.limit.min(MEMBER_CATALOG_LIMIT),
                };
                let report = self
                    .group
                    .read_member_catalog(node_id, node, &request)
                    .await
                    .map_err(unavailable)?;
                report
                    .validate(&request, node_id, domain)
                    .map_err(unavailable)?;
                Ok::<_, Error>(report)
            };
            let result = tokio::select! {
                result = observed => result,
                _ = cancelled(cancellation) => return Err(cancelled_error())
            };
            digest.update(node_id.to_be_bytes());
            match result {
                Ok(report) => {
                    digest.update([1, u8::from(report.bound_from_creation)]);
                    digest.update(report.application_catalog.as_bytes());
                    digest.update(report.custody_catalog.as_bytes());
                    digest.update(report.catalog_sha256);
                    if !report.bound_from_creation {
                        add_missing(
                            missing,
                            truncated,
                            MissingKeyDependency::SessionIndexUnavailable {},
                        );
                    }
                    for entry in report.entries {
                        consider_entry(page, entries, entry)?;
                    }
                }
                Err(error) => {
                    tracing::warn!(node_id, %error, "could not authenticate member key catalogs");
                    digest.update([0]);
                    add_missing(
                        missing,
                        truncated,
                        MissingKeyDependency::MemberUnreported { node_id },
                    );
                }
            }
        }
        Ok(digest.finalize().into())
    }
}
