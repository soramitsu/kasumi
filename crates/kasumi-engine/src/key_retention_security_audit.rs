//! Installed signer and service-audit wrapping keys observed at a Control read position.
use super::*;

/// The physical verifier store remains under its runtime's shutdown custody. All
/// hosted groups on a member share this immutable admission and issuer roster.
pub struct SignerCatalog {
    pub(super) store: std::sync::Weak<TenantStore>,
    pub(super) verifier: TrustVerifierIdentity,
    pub(super) partitions: BTreeSet<(uuid::Uuid, u16)>,
}

impl SignerCatalog {
    pub fn installed(
        store: &Arc<TenantStore>,
        verifier: &TrustVerifierIdentity,
        partitions: BTreeSet<(uuid::Uuid, u16)>,
    ) -> anyhow::Result<Arc<Self>> {
        verifier.validate()?;
        anyhow::ensure!(
            matches!(store.storage_access().purpose(),
                kasumi_store::StoragePurpose::LiveSignerTrust {verifier: owner} if owner == verifier)
                && store.tenant() == verifier.tenant()
                && partitions.iter().all(|(id, _)| !id.is_nil()),
            "signer catalog differs from the installed physical verifier"
        );
        store.check_access()?;
        Ok(Arc::new(Self {
            store: Arc::downgrade(store),
            verifier: verifier.clone(),
            partitions,
        }))
    }
}

impl Database {
    pub fn install_authority_signer_key_inventory(
        &self,
        inventory: std::sync::Weak<dyn AuthoritySignerKeyInventory>,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.store.tenant() == crate::control::CONTROL_TENANT
                && self.signer_keys.get().is_some(),
            "install the enrolled Control signer before attaching its issuer reader"
        );
        self.authority_signer_keys
            .set(inventory)
            .map_err(|_| anyhow::anyhow!("Authority signer inventory is already installed"))
    }
    pub fn install_local_recovery_key_inventory(
        &self,
        store: &Arc<TenantStore>,
        inventory: Arc<dyn LocalRecoveryKeyInventory>,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.store.tenant() == crate::control::CONTROL_TENANT
                && Arc::ptr_eq(self.security_audit.store(), store)
                && matches!(
                    store.storage_access().purpose(),
                    kasumi_store::StoragePurpose::SecurityAudit
                ),
            "local recovery inventory differs from the installed Control security store"
        );
        store.check_access()?;
        self.local_recovery_keys
            .set(inventory)
            .map_err(|_| anyhow::anyhow!("local recovery inventory is already installed"))
    }

    /// Attach the independently opened journal without taking custody of its workers.
    pub fn install_target_key_inventory(
        &self,
        journal: &Arc<crate::TargetJournal>,
    ) -> anyhow::Result<()> {
        let (installation, store) = journal.key_inventory_owner();
        anyhow::ensure!(
            self.store.tenant() == crate::control::CONTROL_TENANT
                && installation.node.node_id == self.group.node_id()
                && Arc::ptr_eq(self.store.persistent_disk(), store.persistent_disk()),
            "target journal differs from the installed Control member or disk owner"
        );
        store.check_access()?;
        let original = Arc::downgrade(journal);
        anyhow::ensure!(
            self.target_keys
                .get_or_init(|| original.clone())
                .ptr_eq(&original),
            "another target journal is already installed"
        );
        Ok(())
    }

    pub fn install_target_checkpoint_inventory(
        &self,
        journal: &Arc<crate::TargetJournal>,
        source: Arc<dyn TargetCheckpointInventory>,
    ) -> anyhow::Result<()> {
        self.install_target_key_inventory(journal)?;
        self.target_checkpoint_keys
            .set(source)
            .map_err(|_| anyhow::anyhow!("target checkpoint inventory already installed"))
    }

    /// Attach the catalog opened by this node's enrolled signer verifier. Its runtime
    /// retains shutdown custody. Replicated authority manifests supply the independent
    /// partition identities that still owe reports from their own installations.
    pub fn install_signer_key_inventory(
        &self,
        store: &Arc<TenantStore>,
        verifier: &TrustVerifierIdentity,
        partitions: BTreeSet<(uuid::Uuid, u16)>,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.store.tenant() == crate::control::CONTROL_TENANT,
            "Control signer owner required"
        );
        self.install_member_signer_key_inventory(&SignerCatalog::installed(
            store, verifier, partitions,
        )?)
    }

    /// The Data member's own current serving capability binds its physical
    /// verifier UUID. The same numeric node ID on another disk is insufficient.
    pub fn install_member_signer_key_inventory(
        &self,
        original: &Arc<SignerCatalog>,
    ) -> anyhow::Result<()> {
        let store = original
            .store
            .upgrade()
            .ok_or_else(|| anyhow::anyhow!("signer store was closed"))?;
        let member = match self.store.storage_access().purpose() {
            kasumi_store::StoragePurpose::NodeControl => {
                self.store.tenant() == crate::control::CONTROL_TENANT
            }
            kasumi_store::StoragePurpose::Serving { identity, .. } => {
                !self.group.is_local()
                    && identity.node.verifier == original.verifier
                    && identity.tenant == self.store.tenant()
            }
            _ => false,
        };
        anyhow::ensure!(
            member
                && original.verifier.node_id == self.group.node_id()
                && Arc::ptr_eq(self.store.persistent_disk(), store.persistent_disk()),
            "signer inventory differs from the installed member's storage or serving identity"
        );
        self.store.check_access()?;
        store.check_access()?;
        let installed = self.signer_keys.get_or_init(|| original.clone());
        anyhow::ensure!(
            installed.store.ptr_eq(&original.store)
                && installed.verifier == original.verifier
                && installed.partitions == original.partitions,
            "signer inventory already belongs to another installation"
        );
        Ok(())
    }
}

pub(in crate::service) struct InstalledInventories<'a> {
    pub(super) context: &'a RequestContext,
    pub(super) signer: Option<&'a SignerCatalog>,
    pub(super) issuers: Option<IssuerCoverage>,
    pub(super) member_inventories: Option<member::MemberInventories>,
    pub(super) journal: Option<&'a crate::TargetJournal>,
    pub(super) target_checkpoints: Option<&'a dyn TargetCheckpointInventory>,
    pub(super) local_recovery: Option<&'a dyn LocalRecoveryKeyInventory>,
}

#[derive(Default)]
pub(super) struct IssuerCoverage {
    entries: BTreeSet<KeyRetentionEntry>,
    digest: Sha256,
    missing: BTreeSet<MissingKeyDependency>,
    truncated: bool,
    catalogs: BTreeSet<uuid::Uuid>,
    streams: BTreeSet<uuid::Uuid>,
    owner_charges: Vec<Reservation>,
}

impl IssuerCoverage {
    pub(super) fn observe(
        &mut self,
        (authority_id, partition): (uuid::Uuid, u16),
        request: &ReadKeyRetentionRequest,
        report: anyhow::Result<AuthoritySignerKeys>,
        admission: &Arc<NodeAdmission>,
    ) -> Result<()> {
        self.digest.update(authority_id.as_bytes());
        self.digest.update(partition.to_be_bytes());
        match report {
            Ok(report) => {
                if report.entries.len() > usize::from(request.limit) + 1 {
                    return Err(Error::new(
                        ErrorCode::Unavailable,
                        "issuer inventory exceeded the requested window",
                    ));
                }
                let audit = matches!(request.scope, KeyRetentionScope::SecurityAudit {});
                if (audit && !(3..=64).contains(&report.audit_owners.len()))
                    || (!audit && !report.audit_owners.is_empty())
                {
                    return Err(Error::new(
                        ErrorCode::Unavailable,
                        "issuer physical audit roster differs from scope",
                    ));
                }
                if audit {
                    // Retain both ordered identity sets across partitions and the local comparison.
                    self.owner_charges.push(
                        admission
                            .reserve_resident(4096 + 1024 * report.audit_owners.len() as u64)?,
                    );
                    for (catalog, stream) in report.audit_owners {
                        if catalog.is_nil()
                            || stream.is_nil()
                            || !self.catalogs.insert(catalog)
                            || !self.streams.insert(stream)
                        {
                            return Err(Error::new(
                                ErrorCode::Unavailable,
                                "multiple issuer members claim the same physical audit",
                            ));
                        }
                    }
                }
                self.digest.update([1]);
                self.digest.update(report.inventory_sha256);
                for entry in report.entries {
                    consider_entry(request, &mut self.entries, entry)?;
                }
            }
            Err(error) => {
                tracing::warn!(%authority_id, %partition, %error, "issuer signer inventory unavailable");
                self.digest.update([0]);
                add_missing(
                    &mut self.missing,
                    &mut self.truncated,
                    MissingKeyDependency::AuthorityPartitionUnreported {
                        authority_id,
                        partition,
                    },
                );
            }
        }
        Ok(())
    }
}

impl SecurityAudit {
    pub(super) fn key_inventory_page(
        &self,
        generation: &crate::Generation,
        request: &ReadKeyRetentionRequest,
        metrics: &kasumi_raft::RaftMetrics<u64, kasumi_raft::BasicNode>,
        owners: InstalledInventories<'_>,
        token: &QueryCancellation,
    ) -> Result<KeyRetentionPage> {
        let InstalledInventories {
            context,
            signer,
            issuers,
            mut member_inventories,
            journal,
            target_checkpoints,
            local_recovery,
        } = owners;
        let state = &generation.state;
        let epoch = state.policy_epoch;
        let local = metrics.id;
        let member_set = &metrics.membership_config;
        let membership = *member_set.log_id();
        let membership_epoch = membership.map_or(0, |id| id.index);
        let mut entries = BTreeSet::new();
        let mut missing = BTreeSet::new();
        let mut truncated = false;
        let document = state
            .collections
            .get("topology")
            .and_then(|c| c.documents.get("current"))
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::Unavailable,
                    "installed service audit roster unavailable",
                )
            })?;
        let document = generation
            .load_document(document)
            .map_err(document_load_error)?;
        let size =
            crate::service::control_topology_service::topology_workspace_bytes(&document.body)?;
        let _topology = self.admission().reserve_resident(size)?;
        let roster =
            crate::control::ControlPlane::applied_topology(state, generation.document_resolver())?;
        let mut issuers = issuers;
        let issuer_digest = if let Some(issuers) = &mut issuers {
            entries = std::mem::take(&mut issuers.entries);
            missing = std::mem::take(&mut issuers.missing);
            truncated = issuers.truncated;
            Some(<[u8; 32]>::from(
                std::mem::take(&mut issuers.digest).finalize(),
            ))
        } else {
            None
        };
        if issuer_digest.is_none()
            && matches!(
                request.scope,
                KeyRetentionScope::SecurityAudit {} | KeyRetentionScope::Signer {}
            )
            && let Some(signer) = signer
        {
            for &(authority_id, partition) in &signer.partitions {
                add_missing(
                    &mut missing,
                    &mut truncated,
                    MissingKeyDependency::AuthorityPartitionUnreported {
                        authority_id,
                        partition,
                    },
                );
            }
        }
        let page_limit = if member_inventories.is_some() {
            request
                .limit
                .min(kasumi_raft::member_catalog::MEMBER_CATALOG_LIMIT)
        } else {
            request.limit
        };
        if let Some(peers) = &mut member_inventories {
            if issuers.as_ref().is_some_and(|issuer| {
                !issuer.streams.is_disjoint(&peers.streams)
                    || !issuer.catalogs.is_disjoint(&peers.catalogs)
            }) {
                return Err(Error::new(
                    ErrorCode::Unavailable,
                    "Control and Authority claim the same physical audit",
                ));
            }
            truncated |= peers.truncated;
            for dependency in std::mem::take(&mut peers.missing) {
                add_missing(&mut missing, &mut truncated, dependency);
            }
            if matches!(request.scope, KeyRetentionScope::SecurityAudit {})
                && peers.streams.contains(
                    &self
                        .status()
                        .map_err(Error::from_physical_source)?
                        .position
                        .stream_id,
                )
            {
                return Err(Error::new(
                    ErrorCode::Unavailable,
                    "local and remote service audit streams coincide",
                ));
            }
            for entry in std::mem::take(&mut peers.entries) {
                consider_entry(request, &mut entries, entry)?;
            }
        }
        for &node_id in roster
            .topology
            .nodes
            .keys()
            .chain(member_set.membership().nodes().map(|(id, _)| id))
        {
            if node_id != local
                && !member_inventories
                    .as_ref()
                    .is_some_and(|peers| peers.reported.contains_key(&node_id))
            {
                add_missing(
                    &mut missing,
                    &mut truncated,
                    MissingKeyDependency::MemberUnreported { node_id },
                );
            }
        }
        let service_audit = matches!(request.scope, KeyRetentionScope::SecurityAudit {});
        if service_audit
            && let Some(issuer) = &issuers
            && issuer.streams.contains(
                &self
                    .status()
                    .map_err(Error::from_physical_source)?
                    .position
                    .stream_id,
            )
        {
            return Err(Error::new(
                ErrorCode::Unavailable,
                "local and Authority audit streams coincide",
            ));
        }
        let journal = journal.filter(|journal| {
            let (installed, _) = journal.key_inventory_owner();
            matches!(request.scope, KeyRetentionScope::TargetJournal {})
                && state
                    .lifecycle_control
                    .as_ref()
                    .is_some_and(|control| control.installation.root == installed.root)
                && installed.root.control_incarnation.to_string() == state.incarnation
                && signer.is_some_and(|signer| signer.verifier == installed.node.verifier)
        });
        let (store, domain) = match request.scope {
            KeyRetentionScope::SecurityAudit {} => {
                (Some(self.store().clone()), KeyCatalogDomain::SecurityAudit)
            }
            KeyRetentionScope::Signer {} => (
                signer.and_then(|owner| owner.store.upgrade()),
                KeyCatalogDomain::LiveSignerTrust,
            ),
            KeyRetentionScope::TargetJournal {} => (None, KeyCatalogDomain::TargetJournal),
            // This scope visits its physical catalog and rows together at one native root.
            KeyRetentionScope::LocalRecovery {} => (None, KeyCatalogDomain::SecurityAudit),
            _ => {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "unsupported installed key inventory scope",
                ));
            }
        };
        let catalog_digest = if let Some(store) = store {
            Some(
                store
                    .visit_wrapping_identities(|catalog_id, provider, key_ref, version| {
                        token.check()?;
                        anyhow::ensure!(
                            !issuers
                                .as_ref()
                                .is_some_and(|issuer| issuer.catalogs.contains(&catalog_id)),
                            "local and Authority members share the same physical audit catalog"
                        );
                        if let Some(peers) = &member_inventories {
                            anyhow::ensure!(
                                !peers.catalogs.contains(&catalog_id),
                                "remote and local members share the same physical wrapping catalog"
                            );
                        }
                        anyhow::ensure!(
                            provider.len() <= MAX_KEY_PROVIDER_BYTES
                                && key_ref.len() <= MAX_KEY_REF_BYTES,
                            "wrapping identifier exceeds the key retention bound"
                        );
                        consider_entry(
                            request,
                            &mut entries,
                            KeyRetentionEntry {
                                key: KeyVersionRef {
                                    provider: provider.into(),
                                    key_ref: key_ref.into(),
                                    version,
                                },
                                reference: KeyReference::Catalog {
                                    node_id: local,
                                    catalog_id,
                                    domain,
                                },
                            },
                        )?;
                        Ok(())
                    })
                    .map_err(Error::from_physical_source)?,
            )
        } else if journal.is_some()
            || (matches!(request.scope, KeyRetentionScope::LocalRecovery {})
                && local_recovery.is_some())
        {
            None
        } else {
            add_missing(
                &mut missing,
                &mut truncated,
                MissingKeyDependency::MemberUnreported { node_id: local },
            );
            None
        };
        let archive_digest = if service_audit {
            Some(
                self.visit_retained_archive_keys(token, |reference, authentic| {
                    consider_entry(
                        request,
                        &mut entries,
                        KeyRetentionEntry {
                            key: KeyVersionRef::from(&reference.key),
                            reference: KeyReference::AuditArchive {
                                stream_id: reference.stream_id,
                                first_sequence: reference.object.first_sequence,
                            },
                        },
                    )?;
                    if !authentic {
                        add_missing(
                            &mut missing,
                            &mut truncated,
                            MissingKeyDependency::RecordUnreadable {
                                record_kind: KeyReferenceKind::AuditArchive,
                                id: reference.object.object_id.to_string(),
                            },
                        );
                    }
                    Ok(())
                })
                .map_err(|original| {
                    original
                        .downcast_ref::<Error>()
                        .cloned()
                        .unwrap_or_else(|| Error::from_physical_source(original))
                })?,
            )
        } else {
            None
        };
        let journal_digest = if let Some(journal) = journal {
            let rows = std::cell::RefCell::new(&mut entries);
            let mut external = Sha256::new();
            let read = LocalRecoveryKeyRead {
                context,
                request,
                security: self,
                token,
            };
            let digest = journal
                .visit_key_dependencies(
                    token,
                    |row| Ok(consider_entry(request, &mut rows.borrow_mut(), row)?),
                    |id, checkpoint| {
                        let graph = match target_checkpoints {
                            Some(inventory) => {
                                read.target_checkpoint(journal, inventory, id, checkpoint, |row| {
                                    Ok(consider_entry(request, &mut rows.borrow_mut(), row)?)
                                })?
                            }
                            None => None,
                        };
                        serde_json::to_writer(&mut external, &(id, graph))?;
                        if graph.is_some() {
                            return Ok(());
                        }
                        add_missing(
                            &mut missing,
                            &mut truncated,
                            MissingKeyDependency::RecordUnreadable {
                                record_kind: KeyReferenceKind::TargetJournal,
                                id: id.to_string(),
                            },
                        );
                        Ok(())
                    },
                )
                .map_err(|error| {
                    error
                        .downcast_ref::<Error>()
                        .cloned()
                        .unwrap_or_else(|| Error::from_physical_source(error))
                })?;
            external.update(digest);
            Some(<[u8; 32]>::from(external.finalize()))
        } else {
            None
        };
        let local_digest = if matches!(request.scope, KeyRetentionScope::LocalRecovery {})
            && let Some(owner) = local_recovery
        {
            Some(
                owner
                    .visit_keys(
                        self.store(),
                        local,
                        &LocalRecoveryKeyRead {
                            context,
                            request,
                            security: self,
                            token,
                        },
                        &mut |finding| {
                            token.check()?;
                            match finding {
                                LocalRecoveryKeyFinding::Entry(entry) => {
                                    consider_entry(request, &mut entries, entry)?
                                }
                                LocalRecoveryKeyFinding::Missing(dependency) => {
                                    dependency.validate()?;
                                    add_missing(&mut missing, &mut truncated, dependency);
                                }
                            }
                            Ok(())
                        },
                    )
                    .map_err(|error| {
                        error
                            .downcast_ref::<Error>()
                            .cloned()
                            .unwrap_or_else(|| Error::from_physical_source(error))
                    })?,
            )
        } else {
            None
        };
        let inventory_sha256 = staged_digest(&(
            "kasumi.installed-key-inventory.v1",
            &request.scope,
            signer.map(|owner| (&owner.verifier, &owner.partitions)),
            &state.incarnation,
            epoch,
            local,
            membership,
            &roster,
            catalog_digest,
            archive_digest,
            journal_digest.or(local_digest),
            issuer_digest,
            &missing,
            truncated,
        ))?
        .0;
        let inventory_sha256 = if let Some(peers) = member_inventories {
            if let Some(groups) = peers.data_groups_digest {
                staged_digest(&(
                    "kasumi.control-data-member-inventories.v1",
                    inventory_sha256,
                    peers.reported,
                    groups,
                ))?
                .0
            } else {
                staged_digest(&(
                    "kasumi.control-member-inventories.v1",
                    inventory_sha256,
                    peers.reported,
                ))?
                .0
            }
        } else {
            inventory_sha256
        };
        let revision = state.revision;
        InventoryWindow {
            entries,
            missing,
            truncated,
            inventory_sha256,
            revision,
            membership_epoch,
        }
        .page(request, page_limit, false)
    }
}
