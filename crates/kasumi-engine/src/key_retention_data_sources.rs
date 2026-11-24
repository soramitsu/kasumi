//! The Control voter consults its enrolled Data groups twice at a fixed applied topology.
use super::*;
use kasumi_types::{
    DATA_MEMBER_CATALOG_BYTES, DATA_MEMBER_CATALOG_LIMIT, DataCatalogContents,
    DataMemberCatalogPage, DataMemberCatalogRead, DataMemberService,
};
use member::{MemberInventories, ServiceIdentity};

impl MemberInventories {
    fn absent(&mut self, id: u64) {
        add_missing(
            &mut self.missing,
            &mut self.truncated,
            MissingKeyDependency::MemberUnreported { node_id: id },
        );
    }

    fn add_data_page(
        &mut self,
        page: DataMemberCatalogPage,
        request: &ReadKeyRetentionRequest,
    ) -> Result<()> {
        let id = page.verifier.node_id;
        let identity = match page.contents {
            DataCatalogContents::TargetJournal {
                writer_state_sha256,
                unreadable_targets,
                truncated,
            } => {
                self.truncated |= truncated;
                for id in unreadable_targets {
                    add_missing(
                        &mut self.missing,
                        &mut self.truncated,
                        MissingKeyDependency::RecordUnreadable {
                            record_kind: KeyReferenceKind::TargetJournal,
                            id: id.to_string(),
                        },
                    );
                }
                ServiceIdentity::Journal(
                    page.verifier,
                    page.catalog,
                    page.catalog_sha256,
                    writer_state_sha256,
                )
            }
            DataCatalogContents::Signer { .. } => {
                ServiceIdentity::Signer(page.verifier, page.catalog, page.catalog_sha256)
            }
            DataCatalogContents::SecurityAudit {
                stream,
                archives_sha256,
                unreadable_objects,
                truncated,
            } => {
                self.truncated |= truncated;
                for object in unreadable_objects {
                    add_missing(
                        &mut self.missing,
                        &mut self.truncated,
                        MissingKeyDependency::RecordUnreadable {
                            record_kind: KeyReferenceKind::AuditArchive,
                            id: object.to_string(),
                        },
                    );
                }
                ServiceIdentity::Audit {
                    catalog: page.catalog,
                    stream,
                    catalog_sha256: page.catalog_sha256,
                    archives_sha256,
                }
            }
        };
        if let Some(existing) = self.reported.get(&id) {
            if existing != &identity {
                return Err(unavailable("Data groups disagree about a physical catalog"));
            }
            return Ok(());
        }
        if !self.catalogs.insert(page.catalog)
            || matches!(&identity,ServiceIdentity::Audit{stream,..} if !self.streams.insert(*stream))
        {
            return Err(unavailable(
                "distinct Data nodes reported the same physical catalog or stream",
            ));
        }
        self.reported.insert(id, identity);
        for entry in page.entries {
            consider_entry(request, &mut self.entries, entry)?;
        }
        Ok(())
    }
}
fn unavailable(message: &'static str) -> Error {
    Error::new(ErrorCode::Unavailable, message)
}

struct CatalogPass<'a> {
    reader: &'a dyn RemoteDataCatalogReader,
    roster: &'a crate::control::ControlTopology,
    request: &'a ReadKeyRetentionRequest,
    probe: bool,
    token: &'a QueryCancellation,
    service: DataMemberService,
    partitions: Option<String>,
}

impl CatalogPass<'_> {
    async fn observe(
        &self,
        mut output: Option<&mut MemberInventories>,
    ) -> Result<([u8; 32], [u8; 32])> {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
        let mut digest = Sha256::new();
        let mut window = Sha256::new();
        let mut physical = BTreeMap::new();
        for (tenant, route) in &self.roster.tenants {
            self.token.check()?;
            let Some(group) = self.reader.groups().get(tenant).filter(|group| {
                uuid::Uuid::parse_str(&route.incarnation) == Ok(group.incarnation)
                    && route.voters.is_subset(&group.members)
            }) else {
                digest
                    .update(staged_digest(&(tenant, &route.incarnation, &route.voters, false))?.0);
                if let Some(capture) = output.as_deref_mut() {
                    for &id in route.voters.iter().chain(
                        self.reader
                            .groups()
                            .get(tenant)
                            .into_iter()
                            .flat_map(|registered| &registered.members),
                    ) {
                        capture.absent(id);
                    }
                }
                continue;
            };
            let mut position = None;
            digest.update(staged_digest(&(tenant, group, &route.voters))?.0);
            for &id in &group.members {
                self.token.check()?;
                digest.update(id.to_be_bytes());
                let report = async {
                    let verifier = self
                        .reader
                        .verifier(id)
                        .ok_or_else(|| unavailable("missing Data verifier enrollment"))?;
                    let read = DataMemberCatalogRead {
                        tenant: tenant.clone(),
                        incarnation: group.incarnation,
                        verifier: verifier.clone(),
                        service: self.service,
                        nonce: uuid::Uuid::new_v4(),
                        from_identity: self.request.cursor.as_ref().filter(|_| self.probe).map(
                            |cursor| KeyIdentityRef {
                                provider: cursor.after.key.provider.clone(),
                                key_ref: cursor.after.key.key_ref.clone(),
                            },
                        ),
                        after: self
                            .request
                            .cursor
                            .as_ref()
                            .filter(|_| !self.probe)
                            .map(|cursor| cursor.after.clone()),
                        limit: self.request.limit.min(DATA_MEMBER_CATALOG_LIMIT),
                    };
                    let page = self
                        .reader
                        .read(&route.voters, &read)
                        .await
                        .map_err(Error::from_physical_source)?;
                    page.validate(&read)?;
                    if let DataCatalogContents::Signer { partitions_sha256 } = &page.contents
                        && self.partitions.as_ref() != Some(partitions_sha256)
                    {
                        return Err(unavailable(
                            "Data signer reports another Authority partition roster",
                        ));
                    }
                    Ok(page)
                };
                let report = tokio::select! {
                    biased;
                    _=cancelled(self.token)=>return Err(cancelled_error()),
                    _=tokio::time::sleep_until(deadline)=>Err(unavailable("Data catalog observation deadline elapsed")),
                    page=report=>page,
                };
                match report {
                    Err(error) => {
                        tracing::warn!(tenant,node_id=id,%error,"Data member inventory unavailable");
                        digest.update([0]);
                        if let Some(capture) = output.as_deref_mut() {
                            capture.absent(id);
                        }
                    }
                    Ok(page)
                        if page.membership.voters != route.voters
                            || page.membership.members != group.members
                            || !self.roster.nodes.contains_key(&id) =>
                    {
                        // The authenticated leader can identify an uncovered learner.
                        // No address or authority is taken from its response.
                        digest.update([2]);
                        digest.update(staged_digest(&page.membership)?.0);
                        if let Some(capture) = output.as_deref_mut() {
                            for &unreported in group.members.union(&page.membership.members) {
                                capture.absent(unreported);
                            }
                        }
                    }
                    Ok(page) => {
                        if let Some(observed) = &position
                            && observed != &page.membership
                        {
                            return Err(unavailable(
                                "Data membership changed while reading physical catalogs",
                            ));
                        }
                        position.get_or_insert_with(|| page.membership.clone());
                        let identity = staged_digest(&(
                            &page.verifier,
                            page.catalog,
                            page.catalog_sha256,
                            &page.contents,
                        ))?
                        .0;
                        let entries = staged_digest(&page.entries)?.0;
                        if let Some(first) =
                            physical.insert(id, (identity.clone(), entries.clone()))
                            && first != (identity.clone(), entries.clone())
                        {
                            return Err(unavailable(
                                "Data groups disagree about the same physical service",
                            ));
                        }
                        digest.update([1]);
                        digest.update(identity);
                        window.update(entries);
                        if let Some(capture) = output.as_deref_mut() {
                            capture.add_data_page(page, self.request)?;
                        }
                    }
                }
            }
            digest.update(staged_digest(&position)?.0);
        }
        // An older enrolled installation can still hold physical signer/audit
        // dependencies after a topology change. Only a current, independently
        // installed group is allowed to corroborate it.
        for (tenant, group) in self.reader.groups() {
            self.token.check()?;
            if !self.roster.tenants.contains_key(tenant) {
                digest.update(staged_digest(&(tenant, group, false))?.0);
                if let Some(capture) = output.as_deref_mut() {
                    for &id in &group.members {
                        capture.absent(id);
                    }
                }
            }
        }
        Ok((digest.finalize().into(), window.finalize().into()))
    }
}

impl Database {
    pub(super) async fn observe_remote_data_sources(
        &self,
        generation: &crate::Generation,
        request: &ReadKeyRetentionRequest,
        token: &QueryCancellation,
        probe: bool,
        result: &mut MemberInventories,
    ) -> Result<()> {
        let Some(reader) = self.remote_data_catalog_reader.get() else {
            return Ok(());
        };
        let document = generation
            .state
            .collections
            .get("topology")
            .and_then(|c| c.documents.get("current"))
            .ok_or_else(|| unavailable("Control topology for Data inventory is missing"))?;
        let document = generation
            .load_document_at("topology", "current", document)
            .map_err(document_load_error)?;
        let bytes =
            crate::service::control_topology_service::topology_workspace_bytes(&document.body)?;
        let _topology = self.admission().reserve_resident(bytes)?;
        let roster = crate::control::ControlPlane::applied_topology(
            &generation.state,
            generation.document_resolver(),
        )?;
        let budget = (8 * DATA_MEMBER_CATALOG_BYTES + roster.topology.nodes.len() * 1024) as u64;
        let retained = self.admission().reserve_resident(budget)?;
        let (service, partitions) = match request.scope {
            KeyRetentionScope::Signer {} => (
                DataMemberService::Signer,
                self.signer_keys
                    .get()
                    .map(|s| staged_digest(&s.partitions))
                    .transpose()?
                    .map(|d| d.0),
            ),
            KeyRetentionScope::SecurityAudit {} => (DataMemberService::SecurityAudit, None),
            KeyRetentionScope::TargetJournal {} if reader.target_journals() => {
                (DataMemberService::TargetJournal, None)
            }
            _ => return Err(unavailable("unsupported Data member catalog scope")),
        };
        let pass = CatalogPass {
            reader: reader.as_ref(),
            probe,
            roster: &roster.topology,
            request,
            token,
            service,
            partitions,
        };
        // Hold this contribution apart from the independently observed Control
        // catalogs until both Data passes agree. A moving or conflicting
        // Data source leaves its scope explicitly incomplete.
        let mut data = MemberInventories::default();
        let capture = async {
            let first = pass.observe(None).await?;
            let second = pass.observe(Some(&mut data)).await?;
            if first != second
                || !result.catalogs.is_disjoint(&data.catalogs)
                || !result.streams.is_disjoint(&data.streams)
                || data
                    .reported
                    .keys()
                    .any(|id| result.reported.contains_key(id) || *id == self.group.node_id())
            {
                return Err(unavailable(
                    "Data catalog coverage changed or overlaps Control",
                ));
            }
            Ok(second.0)
        }
        .await;
        token.check()?;
        match capture {
            Ok(stable) => {
                result.data_groups_digest = Some(stable);
                result.reported.append(&mut data.reported);
                result.catalogs.append(&mut data.catalogs);
                result.streams.append(&mut data.streams);
                result.truncated |= data.truncated;
                for item in data.missing {
                    add_missing(&mut result.missing, &mut result.truncated, item);
                }
                for entry in data.entries {
                    consider_entry(request, &mut result.entries, entry)?;
                }
            }
            Err(error) if error.code == ErrorCode::Unavailable => {
                tracing::warn!(%error,"could not establish a stable Data inventory");
                for group in reader.groups().values() {
                    for &id in &group.members {
                        result.absent(id);
                    }
                }
                for group in roster.topology.tenants.values() {
                    for &id in &group.voters {
                        result.absent(id);
                    }
                }
                result.data_groups_digest =
                    Some(Sha256::digest(b"kasumi.unconfirmed-data-inventories.v1").into());
            }
            Err(error) => return Err(error),
        }
        result.data_charge = Some(retained);
        Ok(())
    }
}
