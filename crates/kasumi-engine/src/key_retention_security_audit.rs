//! Security-audit wrapping keys reported by this installed node at a Control read position.
use super::*;

impl SecurityAudit {
    pub(super) fn key_inventory_page(
        &self,
        generation: &crate::Generation,
        request: &ReadKeyRetentionRequest,
        metrics: &kasumi_raft::RaftMetrics<u64, kasumi_raft::BasicNode>,
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
        if !roster.topology.nodes.contains_key(&local) {
            return Err(Error::new(
                ErrorCode::Unavailable,
                "local service audit node is outside installed topology",
            ));
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
        let catalog_digest = self
            .store()
            .visit_wrapping_identities(|catalog_id, provider, key_ref, version| {
                token.check()?;
                anyhow::ensure!(
                    provider.len() <= MAX_KEY_PROVIDER_BYTES && key_ref.len() <= MAX_KEY_REF_BYTES,
                    "service audit wrapping identifier exceeds limit"
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
                            domain: KeyCatalogDomain::SecurityAudit,
                        },
                    },
                )?;
                Ok(())
            })
            .map_err(Error::from_physical_source)?;
        let archive_digest = self
            .visit_retained_archive_keys(token, |reference, authentic| {
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
            })?;
        let inventory_sha256 = staged_digest(&(
            "kasumi.security-audit.key-inventory.v1",
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
