//! Installed signer and service-audit wrapping keys observed at a Control read position.
use super::*;

pub(in crate::service) struct SignerCatalog {
    store: std::sync::Weak<TenantStore>,
    verifier: TrustVerifierIdentity,
    partitions: BTreeSet<(uuid::Uuid, u16)>,
}

impl Database {
    /// Attach the catalog opened by this node's enrolled signer verifier. Its runtime
    /// retains shutdown custody. Replicated authority manifests supply the independent
    /// partition identities that still owe reports from their own installations.
    pub fn install_signer_key_inventory(
        &self,
        store: &Arc<TenantStore>,
        verifier: &TrustVerifierIdentity,
        partitions: BTreeSet<(uuid::Uuid, u16)>,
    ) -> anyhow::Result<()> {
        verifier.validate()?;
        anyhow::ensure!(
            self.store.tenant() == crate::control::CONTROL_TENANT
                && verifier.node_id == self.group.node_id()
                && Arc::ptr_eq(self.store.persistent_disk(), store.persistent_disk())
                && matches!(store.storage_access().purpose(),
                    kasumi_store::StoragePurpose::LiveSignerTrust {verifier: owner} if owner == verifier)
                && store.tenant() == verifier.tenant()
                && partitions.iter().all(|(id, _)| !id.is_nil()),
            "signer inventory differs from the installed Control node or physical verifier"
        );
        store.check_access()?;
        let original = Arc::new(SignerCatalog {
            store: Arc::downgrade(store),
            verifier: verifier.clone(),
            partitions,
        });
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

impl SecurityAudit {
    pub(super) fn key_inventory_page(
        &self,
        generation: &crate::Generation,
        request: &ReadKeyRetentionRequest,
        metrics: &kasumi_raft::RaftMetrics<u64, kasumi_raft::BasicNode>,
        signer: Option<&SignerCatalog>,
        token: &QueryCancellation,
    ) -> Result<KeyRetentionPage> {
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
        if let Some(signer) = signer {
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
        for &node_id in roster
            .topology
            .nodes
            .keys()
            .chain(member_set.membership().nodes().map(|(id, _)| id))
        {
            if node_id != local {
                add_missing(
                    &mut missing,
                    &mut truncated,
                    MissingKeyDependency::MemberUnreported { node_id },
                );
            }
        }
        let service_audit = matches!(request.scope, KeyRetentionScope::SecurityAudit {});
        let (store, domain) = if service_audit {
            (Some(self.store().clone()), KeyCatalogDomain::SecurityAudit)
        } else {
            (
                signer.and_then(|owner| owner.store.upgrade()),
                KeyCatalogDomain::LiveSignerTrust,
            )
        };
        let catalog_digest = if let Some(store) = store {
            Some(
                store
                    .visit_wrapping_identities(|catalog_id, provider, key_ref, version| {
                        token.check()?;
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
            &missing,
            truncated,
        ))?
        .0;
        let revision = state.revision;
        InventoryWindow {
            entries,
            missing,
            truncated,
            inventory_sha256,
            revision,
            membership_epoch,
        }
        .page(request, request.limit, false)
    }
}
