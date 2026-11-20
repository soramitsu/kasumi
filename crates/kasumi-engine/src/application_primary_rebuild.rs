//! Reconcile a partial primary against one committed candidate at a time.
//! Every admitted mutation is applied to the private tree, including keys
//! outside the cursor. Only unchanged documents from the captured population
//! need the bounded scan. A deleted original key is simply absent when visited.
use super::*;
use kasumi_store::primary_manifest::{PrimaryCursor, PrimaryRebuild, PrimaryStatus};

pub(super) fn seed(
    owner: &PrimaryOwner,
    store: &Arc<TenantStore>,
    state: &TenantState,
    applied: Option<PrimaryApplied>,
) -> Result<Option<PrimaryPublication>> {
    let Some(captured) = applied.filter(|position| position.command_sha256.is_some()) else {
        return Ok(None);
    };
    let _cursor_workspace = store
        .plaintext_memory_owner()
        .clone()
        .reserve_installed(16 << 10)?;
    let through = state
        .collections
        .iter()
        .rev()
        .find_map(|(name, collection)| {
            let live = collection.documents.keys().next_back();
            let archived = collection.archived_documents.keys().next_back();
            live.max(archived).map(|id| PrimaryCursor {
                collection: name.clone(),
                after_document: Some(id.clone()),
            })
        })
        .context("large primary rebuild has no captured document")?;
    let family = SelectedGeneration::adopt(store, primary::FAMILY, &primary::INITIAL_SPACE)?;
    let stage = owner.begin_replacement(store, family.namespace(0))?;
    stage.seal_empty()?;
    let mut manifest = PrimaryManifest::new(
        &state.tenant,
        &state.incarnation,
        state.revision_base,
        state.revision,
        Some(captured.clone()),
        stage.namespace(),
        TreeRoot::new_tree(),
        state.document_count,
        state.logical_bytes,
    );
    manifest.status = PrimaryStatus::Rebuilding(PrimaryRebuild {
        captured,
        through,
        cursor: None,
    });
    let mut writes = family.switch_writes(store, &[&stage])?;
    writes.push(manifest.write()?);
    Ok(Some(PrimaryPublication::only(writes)))
}

/// Bound both document visits and empty collection hops. The terminal cursor
/// is the original last document even if a later mutation deleted it.
pub(super) fn advance(
    state: &TenantState,
    progress: &PrimaryRebuild,
    delta: usize,
    mut emit_missing: impl FnMut(&str, &str) -> Result<bool>,
) -> Result<PrimaryStatus> {
    if progress.cursor.as_ref() == Some(&progress.through) {
        return Ok(PrimaryStatus::Current);
    }
    let start = progress.cursor.as_ref().map_or(Bound::Unbounded, |c| {
        if c.after_document.is_some() {
            Bound::Included(c.collection.as_str())
        } else {
            Bound::Excluded(c.collection.as_str())
        }
    });
    // Each delta can introduce at most one new key before the captured
    // end. Spend one extra lookup for it, while copying at most one fixed
    // window of missing originals. Repeated inserts ahead of the scan
    // therefore cannot starve the captured population.
    let mut remaining = WINDOW_IDS + delta;
    let mut copies = WINDOW_IDS;
    let mut next = progress.clone();
    for (name, collection) in state.collections.range::<str, _>((start, Bound::Unbounded)) {
        if name > &progress.through.collection {
            break;
        }
        let after = progress
            .cursor
            .as_ref()
            .filter(|c| c.collection == *name)
            .and_then(|c| c.after_document.as_deref());
        for id in crate::index_source::resident_ids_after(collection, after) {
            if name == &progress.through.collection
                && Some(id) > progress.through.after_document.as_ref()
            {
                next.cursor = Some(progress.through.clone());
                return Ok(PrimaryStatus::Rebuilding(next));
            }
            copies -= usize::from(emit_missing(name, id)?);
            remaining -= 1;
            if remaining == 0 || copies == 0 {
                next.cursor = Some(PrimaryCursor {
                    collection: name.clone(),
                    after_document: Some(id.clone()),
                });
                return Ok(PrimaryStatus::Rebuilding(next));
            }
        }
        if name == &progress.through.collection {
            break;
        }
        remaining -= 1;
        if remaining == 0 {
            next.cursor = Some(PrimaryCursor {
                collection: name.clone(),
                after_document: None,
            });
            return Ok(PrimaryStatus::Rebuilding(next));
        }
    }
    next.cursor = Some(progress.through.clone());
    Ok(PrimaryStatus::Rebuilding(next))
}
