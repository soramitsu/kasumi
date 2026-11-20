//! Physical member contribution to a distributed wrapping-key inventory.
use super::*;
use kasumi_raft::member_catalog::{
    CatalogPurpose, CatalogStart, MEMBER_CATALOG_BYTES, MEMBER_CATALOG_LIMIT, MemberAuditReport,
    MemberCatalogRequest, MemberSignerReport,
};

#[derive(Clone, PartialEq, Eq, serde::Serialize)]
pub(super) enum ServiceIdentity {
    Signer(TrustVerifierIdentity, uuid::Uuid, [u8; 32]),
    Audit {
        catalog: uuid::Uuid,
        stream: uuid::Uuid,
        catalog_sha256: [u8; 32],
        archives_sha256: [u8; 32],
    },
}

impl ServiceIdentity {
    fn catalog(&self) -> uuid::Uuid {
        match self {
            Self::Signer(_, id, _) => *id,
            Self::Audit { catalog, .. } => *catalog,
        }
    }
}

#[derive(Default)]
pub(super) struct MemberInventories {
    pub(super) reported: std::collections::BTreeMap<u64, ServiceIdentity>,
    pub(super) catalogs: BTreeSet<uuid::Uuid>,
    pub(super) streams: BTreeSet<uuid::Uuid>,
    pub(super) entries: BTreeSet<KeyRetentionEntry>,
    pub(super) missing: BTreeSet<MissingKeyDependency>,
    pub(super) truncated: bool,
}

fn unavailable(error: impl std::fmt::Display) -> Error {
    Error::new(ErrorCode::Unavailable, error.to_string())
}

impl SignerCatalog {
    fn capture(
        &self,
        request: &MemberCatalogRequest,
        token: &QueryCancellation,
    ) -> Result<MemberSignerReport> {
        let store = self
            .store
            .upgrade()
            .ok_or_else(|| unavailable("installed signer store was closed"))?;
        let mut catalog = None;
        let mut entries = BTreeSet::new();
        let catalog_sha256 = store
            .visit_wrapping_identities(|id, provider, key_ref, version| {
                token.check()?;
                anyhow::ensure!(
                    provider.len() <= MAX_KEY_PROVIDER_BYTES && key_ref.len() <= MAX_KEY_REF_BYTES,
                    "signer wrapping identifier exceeds its bound"
                );
                catalog = Some(id);
                let entry = KeyRetentionEntry {
                    key: KeyVersionRef {
                        provider: provider.to_owned(),
                        key_ref: key_ref.to_owned(),
                        version,
                    },
                    reference: KeyReference::Catalog {
                        node_id: self.verifier.node_id,
                        catalog_id: id,
                        domain: KeyCatalogDomain::LiveSignerTrust,
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
            })
            .map_err(Error::from_physical_source)?;
        let report = MemberSignerReport {
            request_sha256: staged_digest(request)?.0,
            verifier: self.verifier.clone(),
            catalog: catalog.ok_or_else(|| {
                unavailable("installed signer catalog has no wrapping identities")
            })?,
            catalog_sha256,
            partitions_sha256: staged_digest(&self.partitions)?.0,
            entries: entries.into_iter().collect(),
        };
        report
            .validate(request, self.verifier.node_id)
            .map_err(unavailable)?;
        Ok(report)
    }
}

impl SecurityAudit {
    pub(crate) fn member_audit_report(
        &self,
        node: u64,
        request: &MemberCatalogRequest,
        token: &QueryCancellation,
    ) -> Result<MemberAuditReport> {
        let stream = self
            .status()
            .map_err(Error::from_physical_source)?
            .position
            .stream_id;
        let mut entries = BTreeSet::new();
        let mut select = |entry: KeyRetentionEntry| -> anyhow::Result<()> {
            token.check()?;
            entry.validate()?;
            if request.start.includes(&entry) {
                entries.insert(entry);
                if entries.len() > usize::from(request.limit) + 1 {
                    entries.pop_last();
                }
            }
            Ok(())
        };
        let mut catalog = None;
        let catalog_sha256 = self
            .store()
            .visit_wrapping_identities(|id, provider, key_ref, version| {
                anyhow::ensure!(
                    provider.len() <= MAX_KEY_PROVIDER_BYTES && key_ref.len() <= MAX_KEY_REF_BYTES,
                    "service audit wrapping identity exceeds its bound"
                );
                catalog = Some(id);
                select(KeyRetentionEntry {
                    key: KeyVersionRef {
                        provider: provider.into(),
                        key_ref: key_ref.into(),
                        version,
                    },
                    reference: KeyReference::Catalog {
                        node_id: node,
                        catalog_id: id,
                        domain: KeyCatalogDomain::SecurityAudit,
                    },
                })
            })
            .map_err(Error::from_physical_source)?;
        let mut unreadable_objects = BTreeSet::new();
        let mut truncated = false;
        let archives_sha256 = self
            .visit_retained_archive_keys(token, |item, authentic| {
                anyhow::ensure!(item.stream_id == stream, "member audit stream changed");
                select(KeyRetentionEntry {
                    key: KeyVersionRef::from(&item.key),
                    reference: KeyReference::AuditArchive {
                        stream_id: stream,
                        first_sequence: item.object.first_sequence,
                    },
                })?;
                if !authentic {
                    unreadable_objects.insert(item.object.object_id);
                    if unreadable_objects.len() > MAX_MISSING_KEY_DEPENDENCIES {
                        unreadable_objects.pop_last();
                        truncated = true;
                    }
                }
                Ok(())
            })
            .map_err(Error::from_physical_source)?;
        let report = MemberAuditReport {
            request_sha256: staged_digest(request)?.0,
            node_id: node,
            stream,
            catalog: catalog.ok_or_else(|| unavailable("no installed service audit catalog"))?,
            catalog_sha256,
            archives_sha256,
            entries: entries.into_iter().collect(),
            unreadable_objects: unreadable_objects.into_iter().collect(),
            truncated,
        };
        report.validate(request, node).map_err(unavailable)?;
        Ok(report)
    }
}

impl Database {
    /// Verify the physical projection again after response encoding. Archive
    /// reads run under the same retained blocking-worker admission as capture.
    pub async fn check_member_catalog_release(
        &self,
        report: &kasumi_raft::RpcResponse,
        request: &MemberCatalogRequest,
    ) -> Result<()> {
        if let kasumi_raft::RpcResponse::MemberAuditCatalog(original) = report {
            let next = self.member_key_catalog(request.clone()).await?;
            if !matches!(&*next, kasumi_raft::RpcResponse::MemberAuditCatalog(current) if current == original)
            {
                return Err(unavailable(
                    "member audit dependencies changed before release",
                ));
            }
        }
        if let kasumi_raft::RpcResponse::MemberSignerCatalog(report) = report {
            let store = self
                .signer_keys
                .get()
                .filter(|owner| owner.verifier == report.verifier)
                .and_then(|owner| owner.store.upgrade())
                .ok_or_else(|| unavailable("enrolled signer no longer available"))?;
            let digest = store
                .visit_wrapping_identities(|_, _, _, _| Ok(()))
                .map_err(Error::from_physical_source)?;
            if digest != report.catalog_sha256 {
                return Err(unavailable("member signer catalog changed before release"));
            }
        }
        Ok(())
    }

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
        let group = self.group.clone();
        let control = self.store.tenant() == crate::control::CONTROL_TENANT;
        let signer = self.signer_keys.get().filter(|_| control).cloned();
        let audit = self.security_audit.clone();
        charge
            .retained_read(token, move |mut charge, token| {
                let _registration = registration;
                let domain = if control {
                    KeyCatalogDomain::NodeControl
                } else {
                    KeyCatalogDomain::Application
                };
                let response = if request.purpose == CatalogPurpose::ControlSigner {
                    request.check_position(&group).map_err(unavailable)?;
                    let signer = signer
                        .ok_or_else(|| unavailable("Control signer catalog is unavailable"))?;
                    let report = signer.capture(&request, token)?;
                    request.check_position(&group).map_err(unavailable)?;
                    kasumi_raft::RpcResponse::MemberSignerCatalog(Box::new(report))
                } else if request.purpose == CatalogPurpose::ServiceAudit {
                    if !control {
                        return Err(unavailable(
                            "service audit inventory requires the enrolled Control group",
                        ));
                    }
                    request.check_position(&group).map_err(unavailable)?;
                    let report = audit.member_audit_report(group.node_id(), &request, token)?;
                    request.check_position(&group).map_err(unavailable)?;
                    kasumi_raft::RpcResponse::MemberAuditCatalog(Box::new(report))
                } else {
                    let report = group
                        .capture_member_catalog(&request, domain, || Ok(token.check()?))
                        .map_err(unavailable)?;
                    kasumi_raft::RpcResponse::MemberCatalog(Some(Box::new(report)))
                };
                token.check()?;
                charge.retain_workspace();
                Ok(AdmittedOutput::new(response, Arc::new(charge)))
            })
            .await
    }

    pub(super) async fn observe_service_members(
        &self,
        metrics: &kasumi_raft::RaftMetrics<u64, kasumi_raft::BasicNode>,
        page: &ReadKeyRetentionRequest,
        token: &QueryCancellation,
    ) -> Result<MemberInventories> {
        let members = metrics.membership_config.membership();
        let _wire = self
            .admission()
            .reserve_resident((6 * MEMBER_CATALOG_BYTES) as u64)?;
        let mut result = MemberInventories::default();
        let (purpose, partitions) = match page.scope {
            KeyRetentionScope::SecurityAudit {} => (CatalogPurpose::ServiceAudit, None),
            KeyRetentionScope::Signer {} => {
                let Some(signer) = self.signer_keys.get() else {
                    return Ok(result);
                };
                (
                    CatalogPurpose::ControlSigner,
                    Some(staged_digest(&signer.partitions)?.0),
                )
            }
            _ => return Err(unavailable("unsupported enrolled member inventory")),
        };
        let mut observed = std::collections::BTreeMap::new();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
        for recheck in [false, true] {
            for (&node_id, node) in members.nodes().filter(|(id, _)| **id != metrics.id) {
                token.check()?;
                if recheck && !observed.contains_key(&node_id) {
                    continue;
                }
                let request = MemberCatalogRequest {
                    purpose,
                    nonce: uuid::Uuid::new_v4(),
                    leader: metrics.id,
                    term: metrics.current_term,
                    membership: *metrics.membership_config.log_id(),
                    applied: metrics
                        .last_applied
                        .ok_or_else(|| unavailable("no applied Control signer position"))?,
                    start: page.cursor.as_ref().map_or(CatalogStart::First, |cursor| {
                        CatalogStart::After {
                            entry: cursor.after.clone(),
                        }
                    }),
                    limit: if recheck {
                        page.limit.min(MEMBER_CATALOG_LIMIT)
                    } else {
                        1
                    },
                };
                let read = async {
                    match purpose {
                        CatalogPurpose::ControlSigner => {
                            let report = self
                                .group
                                .read_member_signer_catalog(node_id, node, &request)
                                .await?;
                            anyhow::ensure!(
                                Some(&report.partitions_sha256) == partitions.as_ref(),
                                "issuer roster differs"
                            );
                            Ok((
                                ServiceIdentity::Signer(
                                    report.verifier,
                                    report.catalog,
                                    report.catalog_sha256,
                                ),
                                report.entries,
                                Vec::new(),
                                false,
                            ))
                        }
                        CatalogPurpose::ServiceAudit => {
                            let report = self
                                .group
                                .read_member_audit_catalog(node_id, node, &request)
                                .await?;
                            Ok((
                                ServiceIdentity::Audit {
                                    catalog: report.catalog,
                                    stream: report.stream,
                                    catalog_sha256: report.catalog_sha256,
                                    archives_sha256: report.archives_sha256,
                                },
                                report.entries,
                                report.unreadable_objects,
                                report.truncated,
                            ))
                        }
                        CatalogPurpose::Group => anyhow::bail!("unexpected group catalog"),
                    }
                };
                let report: anyhow::Result<_> = tokio::select! {
                    result = read => result,
                    _ = cancelled(token) => return Err(cancelled_error()),
                    _ = tokio::time::sleep_until(deadline) => return Ok(result),
                };
                let (identity, entries, unreadable, truncated) = match report {
                    Ok(report) => report,
                    Err(error) => {
                        tracing::warn!(node_id, %error, "Control member inventory unavailable");
                        continue;
                    }
                };
                if !recheck {
                    observed.insert(node_id, identity);
                    continue;
                }
                if observed.get(&node_id) != Some(&identity) {
                    continue;
                }
                if let ServiceIdentity::Audit { stream, .. } = &identity
                    && !result.streams.insert(*stream)
                {
                    return Err(unavailable(
                        "multiple Control members claim the same physical audit stream",
                    ));
                }
                if !result.catalogs.insert(identity.catalog()) {
                    return Err(unavailable(
                        "multiple Control members share a physical wrapping catalog",
                    ));
                }
                result.reported.insert(node_id, identity);
                result.truncated |= truncated;
                for id in unreadable {
                    add_missing(
                        &mut result.missing,
                        &mut result.truncated,
                        MissingKeyDependency::RecordUnreadable {
                            record_kind: KeyReferenceKind::AuditArchive,
                            id: id.to_string(),
                        },
                    );
                }
                for entry in entries {
                    consider_entry(page, &mut result.entries, entry)?;
                }
            }
        }
        Ok(result)
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
                    purpose: kasumi_raft::member_catalog::CatalogPurpose::Group,
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
