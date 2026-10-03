//! Closed test-only primary inputs from the actual accepted apply owner.
//! These prove semantic provenance only; candidate/index body funding and
//! production publication remain separate, unresolved corridors.
use super::*;
use crate::{admission::Reservation, application_sources::SourceRootsRef};
use anyhow::{Context as _, ensure};

pub(crate) struct AcceptedPrimary<'a> {
    pub(super) authority: PrimaryApplyGuard<'a>,
    pub(super) candidate: PrimaryCandidate<'a>,
}
impl<'a> AcceptedPrimary<'a> {
    pub(crate) fn split(self) -> (PrimaryApplyGuard<'a>, PrimaryCandidate<'a>) {
        (self.authority, self.candidate)
    }
}

// Constructors/fields are accessible only in the owning state module tree.
// In particular raw CollectionRecords/Generation/ChangedIds cannot construct
// this input from primary_tree's physical helpers.
pub(crate) struct PrimaryCandidate<'a> {
    pub(super) previous: &'a Arc<Generation>,
    pub(super) accepted: &'a Arc<Generation>,
    pub(super) changed: &'a ChangedIds,
    pub(super) roots: &'a SourceRootsRef,
    pub(super) scope: [u8; 32],
    pub(super) bootstrap: [u8; 32],
    pub(super) guard: &'a std::sync::MutexGuard<'a, ()>,
}
pub(crate) struct Replacement<'a> {
    collection: &'a str,
    id: &'a str,
    old: &'a Document,
    new: &'a Document,
    data_epoch: u64,
    revision: u64,
}
impl Replacement<'_> {
    pub(crate) fn collection(&self) -> &str {
        self.collection
    }
    pub(crate) fn id(&self) -> &str {
        self.id
    }
    pub(crate) fn old(&self) -> &Document {
        self.old
    }
    pub(crate) fn new_document(&self) -> &Document {
        self.new
    }
    pub(crate) fn data_epoch(&self) -> u64 {
        self.data_epoch
    }
    pub(crate) fn revision(&self) -> u64 {
        self.revision
    }
}
impl PrimaryCandidate<'_> {
    pub(crate) fn require_authority(
        &self,
        authority: &PrimaryApplyGuard<'_>,
    ) -> anyhow::Result<()> {
        ensure!(
            matches!(&authority._guard,PrimaryApplyLock::Borrowed(guard) if std::ptr::eq(*guard,self.guard))
                && authority.scope == self.scope
                && authority.bootstrap == self.bootstrap
                && std::ptr::eq(authority.roots, self.roots),
            "primary accepted apply guard differs"
        );
        Ok(())
    }
    pub(crate) fn accepted(&self) -> &Arc<Generation> {
        self.accepted
    }
    pub(crate) fn previous(&self) -> &Arc<Generation> {
        self.previous
    }
    pub(crate) fn roots(&self) -> &SourceRootsRef {
        self.roots
    }
    pub(crate) fn scope(&self) -> [u8; 32] {
        self.scope
    }
    pub(crate) fn bootstrap(&self) -> [u8; 32] {
        self.bootstrap
    }

    /// Independent complete diff, not a claim that PrimaryDelta's coarse
    /// changed-root checks prove ID completeness. The actual persistent map
    /// implementation may scan unshared inputs; no O(height) promise is made.
    pub(crate) fn replacement(&self) -> anyhow::Result<Replacement<'_>> {
        ensure!(
            self.changed.len() == 1,
            "primary replacement requires one changed collection"
        );
        let (name, ids) = self
            .changed
            .first_key_value()
            .context("primary changed collection absent")?;
        ensure!(
            ids.len() == 1,
            "primary replacement requires one changed ID"
        );
        let id = ids.first().context("primary changed ID absent")?;
        let old = &self.previous.state;
        let new = &self.accepted.state;
        ensure!(
            old.collections.len() == new.collections.len(),
            "primary collection membership changed"
        );
        for (other, before) in &old.collections {
            let after = new
                .collections
                .get(other)
                .context("primary collection removed")?;
            ensure!(
                before.definition == after.definition,
                "primary collection definition changed"
            );
            ensure!(
                before.archived_documents.ptr_eq(&after.archived_documents)
                    && before.archived_document_bytes == after.archived_document_bytes,
                "primary archive placement changed"
            );
            if other != name {
                ensure!(
                    before.documents.ptr_eq(&after.documents)
                        && before.data_epoch == after.data_epoch,
                    "primary untouched collection changed"
                );
            }
        }
        let before = old
            .collections
            .get(name)
            .context("primary prior collection absent")?;
        let after = new
            .collections
            .get(name)
            .context("primary next collection absent")?;
        ensure!(
            !before.archived_documents.contains_key(id)
                && !after.archived_documents.contains_key(id),
            "primary replacement overlaps archive"
        );
        let old_document = before
            .documents
            .get(id)
            .context("primary replacement is an insertion")?;
        let new_document = after
            .documents
            .get(id)
            .context("primary replacement is a deletion")?;
        ensure!(
            old_document.id == *id
                && new_document.id == *id
                && old_document.version <= before.data_epoch
                && new_document.version <= after.data_epoch
                && after.data_epoch <= new.revision,
            "primary replacement identity/version differs"
        );
        // imbl 7.0.1 Cursor uses Vec<(usize, &Branch)> and reserves node.level().
        // Valid B+ branches have >=2 children: at most usize::BITS frames each.
        // Both Vec allocations retire before this real grant, including panic.
        let frame_bytes = std::mem::size_of::<(usize, &())>()
            .checked_mul(usize::BITS as usize)
            .context("primary diff quote overflow")?;
        let cursor = frame_bytes
            .checked_next_power_of_two()
            .and_then(|bytes| bytes.checked_add(64))
            .context("primary diff quote overflow")?;
        let bytes = cursor
            .checked_mul(2)
            .context("primary diff quote overflow")? as u64;
        let _grant: Reservation = self
            .roots
            .primary_installation()
            .1
            .reserve_application_source(bytes)?;
        let mut diff = before.documents.diff(&after.documents);
        ensure!(
            matches!(diff.next(), Some(imbl::ordmap::DiffItem::Update { old: (a, value_a), new: (b, value_b) })
            if a == id && b == id && Arc::ptr_eq(value_a, old_document) && Arc::ptr_eq(value_b, new_document)),
            "primary replacement actual first difference differs"
        );
        ensure!(
            diff.next().is_none(),
            "primary replacement omitted another changed ID"
        );
        drop(diff);
        Ok(Replacement {
            collection: name,
            id,
            old: old_document,
            new: new_document,
            data_epoch: after.data_epoch,
            revision: new.revision,
        })
    }
}

#[path = "primary_projection_tests.rs"]
mod tests;
