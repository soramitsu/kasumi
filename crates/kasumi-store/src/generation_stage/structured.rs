//! In-transaction rules of the ordinary structured directory row. They run
//! for every native write, paired publication included, so engine logic alone
//! cannot move the directory backward or select pages outside its family.
use super::*;
use crate::structured_manifest::{
    CURRENT, FAMILY, INITIAL_SPACE, MANIFESTS, MAX_MANIFEST_BYTES, StructuredManifest,
};

/// The structured directory row changes only forward. A put names the page
/// space selected after this batch. Without a selection switch in the same
/// batch it must succeed a current predecessor on the same tree with a larger
/// revision; with one it starts a replacement generation. Deletion is left to
/// whole-namespace removal.
pub(crate) fn validate_structured_manifest(
    tx: &kasumi_kv::WriteTransaction,
    store: &TenantStore,
    state: &KeyState,
    operations: &[WriteOp],
) -> Result<()> {
    let switched = operations.iter().find_map(|operation| match operation {
        WriteOp::Put {
            namespace,
            key,
            value,
        } if namespace == SELECTIONS && key.as_slice() == FAMILY.as_bytes() => Some(value),
        _ => None,
    });
    let mut seen = false;
    for operation in operations {
        let (namespace, key) = operation_target(operation);
        if namespace != MANIFESTS {
            continue;
        }
        ensure!(key.as_slice() == CURRENT, "unknown structured manifest row");
        ensure!(!seen, "duplicate structured manifest write");
        seen = true;
        let WriteOp::Put { value, .. } = operation else {
            continue;
        };
        let next = StructuredManifest::decode(value)?;
        ensure!(
            next.tenant == store.tenant,
            "structured manifest tenant differs"
        );
        let selected = match switched {
            Some(bytes) => Selection::decode(bytes)?.namespaces,
            None => read_selection(tx, store, state, FAMILY.as_bytes())?.map_or_else(
                || INITIAL_SPACE.iter().map(|space| (*space).into()).collect(),
                |selection| selection.namespaces,
            ),
        };
        ensure!(
            selected.len() == INITIAL_SPACE.len() && selected[0] == next.page_space,
            "structured manifest names an unselected page space"
        );
        if switched.is_some() {
            ensure!(
                next.is_current(),
                "a replacement structured generation must be current"
            );
            continue;
        }
        if let Some(previous) =
            read_record(tx, store, state, MANIFESTS, CURRENT, MAX_MANIFEST_BYTES)?
        {
            next.check_successor(&StructuredManifest::decode(&previous.value)?)?;
        }
    }
    // A selection written without its manifest (adoption of the initial
    // space) must keep naming the space a readable manifest uses. An
    // unreadable one is replaced by the next generation, never decoded here.
    if let (false, Some(bytes)) = (seen, switched)
        && let Some(previous) =
            read_record(tx, store, state, MANIFESTS, CURRENT, MAX_MANIFEST_BYTES)?
        && let Ok(previous) = StructuredManifest::decode(&previous.value)
    {
        let selected = Selection::decode(bytes)?.namespaces;
        ensure!(
            selected.len() == INITIAL_SPACE.len() && selected[0] == previous.page_space,
            "structured page-space selection leaves its manifest behind"
        );
    }
    Ok(())
}
