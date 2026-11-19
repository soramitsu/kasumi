//! The snapshot gate serializes page-space staging with snapshot installation.
//! The bounded selection writes join the matching Raft snapshot publication.
use crate::{Generation, application_records};
use anyhow::{Result, ensure};
use kasumi_raft::SnapshotRestoreContext;
use kasumi_store::{
    NamespaceStage, SelectedGeneration, TenantStore, WriteOp,
    application_manifest::{ApplicationManifest, INITIAL_PAGE_SPACE, PAGE_FAMILY},
    ordered_pages::{self, Direction, TreeReader, TreeRoot},
};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, ops::Bound, sync::Arc};

const BINDINGS: [&str; 4] = [
    crate::mutation_receipt::CATALOG,
    crate::backup_binding::CATALOG,
    crate::staged_terminal::CATALOG,
    crate::target_resolution::CATALOG,
];

pub(crate) fn snapshot_identity(
    meta: &kasumi_raft::SnapshotMeta<u64, kasumi_raft::BasicNode>,
    backend_sha256: &str,
) -> Result<[u8; 32]> {
    let mut hash = Sha256::new();
    serde_json::to_writer(
        &mut hash,
        &("kasumi.application.snapshot.v1", meta, backend_sha256),
    )?;
    Ok(hash.finalize().into())
}

pub(crate) fn stage(
    store: &Arc<TenantStore>,
    generation: &Generation,
    context: &SnapshotRestoreContext,
    writes: &mut Vec<WriteOp>,
) -> Result<()> {
    let state = &generation.state;
    let checkpoint = context.checkpoint_sha256()?;
    let mut bindings = BTreeMap::new();
    for write in writes.iter() {
        if let WriteOp::Put {
            namespace,
            key,
            value,
        } = write
            && let Some(&catalog) = BINDINGS.iter().find(|&&catalog| catalog == namespace)
            && key == checkpoint.as_bytes()
        {
            ensure!(
                bindings.insert(catalog, value.as_slice()).is_none(),
                "duplicate checkpoint row binding"
            );
        }
    }
    ensure!(
        BINDINGS
            .iter()
            .all(|&catalog| bindings.contains_key(catalog)
                == (catalog != crate::backup_binding::CATALOG
                    || state.tenant == crate::control::CONTROL_TENANT)),
        "snapshot publication has incomplete permanent-row bindings"
    );
    NamespaceStage::reclaim_family(store, PAGE_FAMILY)?;
    let family = SelectedGeneration::adopt(store, PAGE_FAMILY, &INITIAL_PAGE_SPACE)?;
    let stage = NamespaceStage::begin_generation(store, PAGE_FAMILY)?;
    let records = ordered_pages::stage_tree(&stage, TreeRoot::new_tree().tree, |builder| {
        application_records::visit_all(
            generation,
            kasumi_store::application_manifest::DOCUMENT_HEADERS_LAYOUT,
            &bindings,
            store.plaintext_memory_owner(),
            |key, value| builder.push(key, value),
        )
    })?;
    let manifest = ApplicationManifest::new(
        &state.tenant,
        &state.incarnation,
        state.revision,
        state.revision_base,
        snapshot_identity(&context.meta, &context.backend_sha256)?,
        stage.namespace(),
        records,
        state.document_count,
        state.logical_bytes,
    );
    writes.extend(family.switch_writes(store, &[&stage])?);
    writes.push(manifest.write()?);
    Ok(())
}

fn record_digest(hash: &mut Sha256, key: &[u8], length: u64, value_sha256: [u8; 32]) {
    hash.update((key.len() as u64).to_be_bytes());
    hash.update(key);
    hash.update(length.to_be_bytes());
    hash.update(value_sha256);
}

/// Existing deployed snapshots have no manifest. When present, verify every
/// selected page and descriptor against the authenticated decoded snapshot.
/// The same pinned view supplies the selector, permanent bindings and pages.
pub(crate) fn verify(
    store: &Arc<TenantStore>,
    generation: &Generation,
    context: &SnapshotRestoreContext,
) -> Result<()> {
    let view = store.read_view()?;
    let outcome: Result<()> = (|| {
        let Some(manifest) = ApplicationManifest::load_at(&view)? else {
            return Ok(());
        };
        let state = &generation.state;
        ensure!(
            manifest.incarnation == state.incarnation
                && manifest.revision_base == state.revision_base
                && manifest.revision == state.revision
                && manifest.snapshot_sha256
                    == snapshot_identity(&context.meta, &context.backend_sha256)?
                && manifest.document_count == state.document_count
                && manifest.logical_bytes == state.logical_bytes,
            "selected application records belong to another snapshot"
        );
        let checkpoint = context.checkpoint_sha256()?;
        let mut owned = BTreeMap::new();
        for catalog in BINDINGS {
            if let Some(binding) = view.get(catalog, checkpoint.as_bytes(), 64 << 10)? {
                owned.insert(catalog, binding);
            }
        }
        let bindings = owned
            .iter()
            .map(|(&catalog, value)| (catalog, value.as_bytes()))
            .collect();
        let mut expected = Sha256::new();
        application_records::visit_all(
            generation,
            manifest.layout_epoch,
            &bindings,
            store.plaintext_memory_owner(),
            |key, value| {
                record_digest(
                    &mut expected,
                    key,
                    value.len() as u64,
                    Sha256::digest(value).into(),
                );
                Ok(())
            },
        )?;
        let reader = TreeReader::new(&view, &manifest.page_space, manifest.records, None)?;
        let mut selected = Sha256::new();
        reader.scan(Bound::Unbounded, Direction::Forward, &mut |key, value| {
            record_digest(
                &mut selected,
                key,
                value.len(),
                reader.value_sha256(&value)?,
            );
            Ok(true)
        })?;
        ensure!(
            expected.finalize() == selected.finalize(),
            "selected application records differ from snapshot"
        );
        Ok(())
    })();
    let close = view.close();
    match (outcome, close) {
        (Err(error), Err(close)) => Err(error.context(close)),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}
