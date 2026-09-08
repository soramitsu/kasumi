//! Original archive identities remain authenticated even after replica changes
//! and restore. This check never mints storage or request authority.
use anyhow::{Result, ensure};
use kasumi_store::StoragePurpose;
use kasumi_types::{TenantState, validate_restore_lineage};

/// Call only after authenticating the enclosing snapshot/checkpoint and its
/// selected archive link. Live request/storage and final release fences remain
/// the caller's responsibility. A historical node's revocation cannot erase
/// retained evidence, while a different current installation cannot be aliased.
pub fn authorize_audit_source(
    state: &TenantState,
    snapshot_source: &StoragePurpose,
    archive_source: &StoragePurpose,
) -> Result<()> {
    validate_restore_lineage(
        &state.tenant,
        &state.incarnation,
        state.revision,
        state.restored_from.as_ref(),
        &state.restore_lineage,
    )?;
    let root_incarnation = application(snapshot_source, &state.tenant)?;
    let archive_incarnation = application(archive_source, &state.tenant)?;
    if snapshot_source.is_local_fixture() && archive_source.is_local_fixture() {
        return Ok(());
    }
    ensure!(
        root_incarnation == state.incarnation,
        "snapshot source purpose differs from state"
    );
    if archive_incarnation == state.incarnation {
        let matches = match (snapshot_source, archive_source) {
            (
                StoragePurpose::Standalone {
                    installation_id: a, ..
                },
                StoragePurpose::Standalone {
                    installation_id: b, ..
                },
            ) => a == b,
            (
                StoragePurpose::Serving {
                    manifest_digest: a,
                    recovery_checkpoint: p,
                    ..
                },
                StoragePurpose::Serving {
                    manifest_digest: b,
                    recovery_checkpoint: q,
                    ..
                },
            ) => {
                // The original node is authenticated in the archive and retained;
                // another replica of the same generation may preserve that range.
                a == b && p == q
            }
            _ => false,
        };
        ensure!(
            matches,
            "current audit source installation or generation differs"
        );
    } else {
        ensure!(
            state
                .restore_lineage
                .iter()
                .any(|link| link.checkpoint.source_incarnation == archive_incarnation),
            "audit source is absent from authenticated restore lineage"
        );
    }
    for purpose in [snapshot_source, archive_source] {
        if let StoragePurpose::Serving {
            identity,
            recovery_checkpoint,
            ..
        } = purpose
        {
            let original = state
                .restore_lineage
                .iter()
                .find(|link| link.target_incarnation == identity.incarnation.to_string())
                .map(|link| &link.checkpoint);
            ensure!(
                recovery_checkpoint.as_deref() == original,
                "audit source recovery checkpoint differs"
            );
        }
    }
    Ok(())
}

fn application(purpose: &StoragePurpose, tenant: &str) -> Result<String> {
    if purpose.is_local_fixture() {
        return Ok(String::new());
    }
    match purpose {
        StoragePurpose::Standalone {
            installation_id,
            tenant: original,
            incarnation,
        } => {
            ensure!(
                original == tenant && !installation_id.is_nil() && !incarnation.is_nil(),
                "invalid standalone audit source"
            );
            Ok(incarnation.to_string())
        }
        StoragePurpose::Serving {
            manifest_digest,
            identity,
            recovery_checkpoint,
        } => {
            kasumi_types::validate_sha256(manifest_digest)?;
            identity.validate()?;
            ensure!(identity.tenant == tenant, "audit source tenant differs");
            if let Some(checkpoint) = recovery_checkpoint {
                checkpoint.validate()?;
                ensure!(
                    checkpoint.tenant == tenant,
                    "audit source checkpoint tenant differs"
                );
            }
            Ok(identity.incarnation.to_string())
        }
        _ => anyhow::bail!("reserved storage purpose cannot be application audit history"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kasumi_types::*;
    use uuid::Uuid;

    fn state(incarnation: Uuid) -> TenantState {
        crate::TenantEngine::new(
            "tenant".into(),
            incarnation.to_string(),
            Policy {
                grants: vec![Grant {
                    principal: "owner".into(),
                    collection: None,
                    actions: [Action::Admin].into_iter().collect(),
                }],
                strict_read_audit: false,
            },
            Limits::default(),
        )
        .unwrap()
        .generation()
        .unwrap()
        .state
        .clone()
    }
    fn serving(incarnation: Uuid, node: u64) -> StoragePurpose {
        StoragePurpose::Serving {
            manifest_digest: "01".repeat(32),
            recovery_checkpoint: None,
            identity: kasumi_serving::ServingIdentity {
                tenant: "tenant".into(),
                incarnation,
                authority_epoch: 1,
                node: kasumi_serving::NodeIdentity {
                    node_id: node,
                    principal: format!("node-{node}"),
                    certificate_sha256: format!("{node:064x}"),
                },
            },
        }
    }
    #[test]
    fn replica_nodes_and_historical_epochs_share_history_without_aliasing_other_installations() {
        let incarnation = Uuid::new_v4();
        let state = state(incarnation);
        let root = serving(incarnation, 1);
        let mut archive = serving(incarnation, 2);
        authorize_audit_source(&state, &root, &archive).unwrap();
        if let StoragePurpose::Serving { identity, .. } = &mut archive {
            identity.authority_epoch = 2;
        }
        authorize_audit_source(&state, &root, &archive).unwrap();
        archive = serving(incarnation, 2);
        if let StoragePurpose::Serving {
            manifest_digest, ..
        } = &mut archive
        {
            *manifest_digest = "02".repeat(32);
        }
        assert!(authorize_audit_source(&state, &root, &archive).is_err());
        let root =
            kasumi_store::StorageAccess::standalone(Uuid::new_v4(), "tenant", incarnation).unwrap();
        let other =
            kasumi_store::StorageAccess::standalone(Uuid::new_v4(), "tenant", incarnation).unwrap();
        assert!(authorize_audit_source(&state, root.purpose(), other.purpose()).is_err());
        assert!(
            authorize_audit_source(&state, root.purpose(), &StoragePurpose::NodeControl).is_err()
        );
    }

    #[test]
    fn historical_incarnation_requires_complete_lineage_and_preserves_exact_source_checkpoint() {
        let original = Uuid::new_v4();
        let target = Uuid::new_v4();
        let mut state = state(target);
        let checkpoint = FullBackupCheckpoint {
            tenant: "tenant".into(),
            source_incarnation: original.to_string(),
            revision: 5,
            resident_sha256: "03".repeat(32),
            backup_id: Uuid::new_v4(),
            manifest_ciphertext_sha256: "04".repeat(32),
            key_lineage_digest: "05".repeat(32),
        };
        state.revision = 6;
        state.restored_from = Some(checkpoint.clone());
        state.restore_lineage.push(RestoreLineageLink {
            checkpoint: checkpoint.clone(),
            target_incarnation: target.to_string(),
        });
        let mut root = serving(target, 3);
        if let StoragePurpose::Serving {
            recovery_checkpoint,
            ..
        } = &mut root
        {
            *recovery_checkpoint = Some(Box::new(checkpoint.clone()));
        }
        let archive = serving(original, 1);
        authorize_audit_source(&state, &root, &archive).unwrap();
        assert!(authorize_audit_source(&state, &root, &serving(Uuid::new_v4(), 1)).is_err());
        let mut incorrect = archive;
        if let StoragePurpose::Serving {
            recovery_checkpoint,
            ..
        } = &mut incorrect
        {
            *recovery_checkpoint = Some(Box::new(checkpoint));
        }
        assert!(authorize_audit_source(&state, &root, &incorrect).is_err());
        state.restore_lineage.clear();
        assert!(authorize_audit_source(&state, &root, &incorrect).is_err());
    }
}
