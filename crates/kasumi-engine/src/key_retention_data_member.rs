//! Data-leader read of a physical service on one current voter or learner.
//! The administrative adapter separately checks the enrolled reader and its credential.
use super::*;
use kasumi_raft::member_catalog::{CatalogPurpose, CatalogStart, MemberCatalogRequest};
use kasumi_types::{
    DATA_MEMBER_CATALOG_BYTES, DataCatalogContents, DataCatalogMembership, DataMemberCatalogPage,
    DataMemberCatalogRead, DataMemberService,
};

fn unavailable(message: impl std::fmt::Display) -> Error {
    Error::new(ErrorCode::Unavailable, message.to_string())
}

impl Database {
    fn data_member_catalog_access(&self, read: &DataMemberCatalogRead) -> Result<()> {
        self.access()?;
        let access = self.store.storage_access();
        if !matches!(access.purpose(), kasumi_store::StoragePurpose::Serving { identity, .. }
            if identity.tenant == read.tenant && identity.incarnation == read.incarnation
                && identity.node.node_id == self.group.node_id())
        {
            return Err(unavailable(
                "requested Data group differs from installed serving storage",
            ));
        }
        access.check_serving().map_err(Error::from_physical_source)
    }

    /// The Data leader obtains the physical member's bounded projection at its
    /// own quorum position. The requested Data member never supplies an endpoint.
    pub async fn read_data_member_catalog(
        &self,
        read: &DataMemberCatalogRead,
    ) -> Result<AdmittedOutput<DataMemberCatalogPage>> {
        read.validate()?;
        self.data_member_catalog_access(read)?;
        let token = QueryCancellation::default();
        let _cancel = CancelOnDrop(token.clone());
        let _work = self.work.begin(token.clone())?;
        let mut reservation = self
            .admission()
            .reserve((6 * DATA_MEMBER_CATALOG_BYTES) as u64, Some(token.clone()))?;
        let capture = async {
            self.barrier().await?;
            let metrics = self.group.metrics();
            let membership = metrics.membership_config.membership();
            if self.group.is_local()
                || metrics.current_leader != Some(metrics.id)
                || membership.get_joint_config().len() != 1
                || membership
                    .nodes()
                    .take(kasumi_types::DATA_CATALOG_MAX_MEMBERS + 1)
                    .count()
                    > kasumi_types::DATA_CATALOG_MAX_MEMBERS
            {
                return Err(unavailable(
                    "Data group requires a leader with stable membership",
                ));
            }
            let id = read.verifier.node_id;
            let target = membership.get_node(&id).ok_or_else(|| {
                unavailable("requested Data member is outside current membership")
            })?;
            let request = MemberCatalogRequest {
                purpose: match read.service {
                    DataMemberService::Signer => CatalogPurpose::DataSigner {
                        installation_id: read.verifier.installation_id,
                    },
                    DataMemberService::SecurityAudit => CatalogPurpose::DataServiceAudit {
                        installation_id: read.verifier.installation_id,
                    },
                },
                nonce: read.nonce,
                leader: metrics.id,
                term: metrics.current_term,
                membership: *metrics.membership_config.log_id(),
                applied: metrics
                    .last_applied
                    .ok_or_else(|| unavailable("Data group lacks an applied position"))?,
                start: read
                    .after
                    .clone()
                    .map_or(CatalogStart::First, |entry| CatalogStart::After { entry }),
                limit: read.limit,
            };
            request.check_position(&self.group).map_err(unavailable)?;
            let position = DataCatalogMembership {
                leader: request.leader,
                term: request.term,
                membership_index: request
                    .membership
                    .ok_or_else(|| unavailable("Data membership position is absent"))?
                    .index,
                membership_sha256: staged_digest(&metrics.membership_config)?.0,
                members: membership.nodes().map(|(id, _)| *id).collect(),
                voters: membership.voter_ids().collect(),
            };
            let local;
            let remote;
            let reply = if id == metrics.id {
                local = self.member_key_catalog(request.clone()).await?;
                self.check_member_catalog_release(&local, &request).await?;
                &*local
            } else {
                remote = match read.service {
                    DataMemberService::Signer => {
                        kasumi_raft::RpcResponse::MemberSignerCatalog(Box::new(
                            self.group
                                .read_member_signer_catalog(id, target, &request)
                                .await
                                .map_err(unavailable)?,
                        ))
                    }
                    DataMemberService::SecurityAudit => {
                        kasumi_raft::RpcResponse::MemberAuditCatalog(Box::new(
                            self.group
                                .read_member_audit_catalog(id, target, &request)
                                .await
                                .map_err(unavailable)?,
                        ))
                    }
                };
                &remote
            };
            let (catalog, catalog_sha256, contents, entries) = match reply {
                kasumi_raft::RpcResponse::MemberSignerCatalog(report) => {
                    report.validate(&request, id).map_err(unavailable)?;
                    if report.verifier != read.verifier {
                        return Err(unavailable(
                            "physical Data signer differs from enrolled verifier",
                        ));
                    }
                    (
                        report.catalog,
                        report.catalog_sha256,
                        DataCatalogContents::Signer {
                            partitions_sha256: report.partitions_sha256.clone(),
                        },
                        report.entries.clone(),
                    )
                }
                kasumi_raft::RpcResponse::MemberAuditCatalog(report) => {
                    report.validate(&request, id).map_err(unavailable)?;
                    (
                        report.catalog,
                        report.catalog_sha256,
                        DataCatalogContents::SecurityAudit {
                            stream: report.stream,
                            archives_sha256: report.archives_sha256,
                            unreadable_objects: report.unreadable_objects.iter().copied().collect(),
                            truncated: report.truncated,
                        },
                        report.entries.clone(),
                    )
                }
                _ => return Err(unavailable("unexpected Data member catalog response")),
            };
            request.check_position(&self.group).map_err(unavailable)?;
            self.data_member_catalog_access(read)?;
            let page = DataMemberCatalogPage {
                request_sha256: read.digest()?,
                membership: position,
                applied_index: request.applied.index,
                verifier: read.verifier.clone(),
                catalog,
                catalog_sha256,
                contents,
                entries,
            };
            page.validate(read)?;
            Ok(page)
        };
        let page = tokio::select! {
            item = capture => item?,
            _ = cancelled(&token) => return Err(cancelled_error()),
        };
        reservation.retain_workspace();
        Ok(AdmittedOutput::new(page, Arc::new(reservation)))
    }

    /// Revisit the same member after encoding and discard the encoded reply
    /// if membership, dependencies or the selected ordered window changed.
    pub async fn check_data_member_catalog_release(
        &self,
        read: &DataMemberCatalogRead,
        first: &DataMemberCatalogPage,
        actor: &RequestContext,
    ) -> Result<()> {
        first.validate(read)?;
        actor.authorization.check_live()?;
        self.security_audit
            .record(SecurityEvent {
                kind: SecurityEventKind::KeyAdministration,
                principal: Some(actor.principal.clone()),
                tenant: Some(read.tenant.clone()),
                request_id: actor.request_id.clone(),
                outcome: SecurityOutcome::Succeeded,
            })
            .await
            .map_err(Error::from_physical_source)?;
        let next = self.read_data_member_catalog(read).await?;
        if next.membership != first.membership
            || next.applied_index < first.applied_index
            || next.verifier != first.verifier
            || next.catalog != first.catalog
            || next.catalog_sha256 != first.catalog_sha256
            || next.contents != first.contents
            || next.entries != first.entries
        {
            return Err(unavailable(
                "Data service catalog changed before response release",
            ));
        }
        self.data_member_catalog_access(read)
    }
}

/// Installed read-only Data services. The retained route map is the sole
/// authority for selecting a pinned listener and its physical installation.
pub trait RemoteDataCatalogReader: Send + Sync {
    fn groups(&self) -> &BTreeMap<String, kasumi_types::DataCatalogGroup>;
    fn verifier(&self, node: u64) -> Option<&TrustVerifierIdentity>;
    fn read<'a>(
        &'a self,
        voters: &'a BTreeSet<u64>,
        input: &'a DataMemberCatalogRead,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<DataMemberCatalogPage>> + Send + 'a>,
    >;
}

impl Database {
    pub fn install_remote_data_catalog_reader(
        &self,
        reader: Arc<dyn RemoteDataCatalogReader>,
    ) -> Result<()> {
        if self.store.tenant() != crate::control::CONTROL_TENANT {
            return Err(unavailable(
                "Data source reader requires a hosted Control database",
            ));
        }
        self.remote_data_catalog_reader
            .set(reader)
            .map_err(|_| unavailable("Data source reader is already installed"))
    }
}
