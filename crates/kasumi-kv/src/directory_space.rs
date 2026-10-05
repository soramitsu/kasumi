//! A checked append bound for a complete sequence of private-root mutations.
//!
//! This requires the ordinary editor to leave at least two records on each
//! side of every split. Fix H=max(starting height,1). Initially at most one
//! logical page exists at level H-1, and each edit creates at most one more
//! lineage there (split or regained root, never both). All higher nodes were
//! born during this sequence with at least two children. Conceptually retain
//! removed-child tokens on surviving unary lineages; partition, never copy,
//! those tokens when a lineage splits. A node g levels above H-1 therefore
//! owns at least 2^g historical tokens even after deletion. At prefix i there
//! are at most 1+i tokens, bounding height by H+floor(log2(i+1)). This uses no
//! minimum live occupancy of the initial tree or of copied unary branches.
use super::*;

impl DirectoryRoot {
    pub(crate) fn transaction_page_bound(self, edits: usize) -> Result<u64, CoreError> {
        self.validate()?;
        if edits > crate::segment::MAX_BATCH_OPERATIONS {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "directory transaction exceeds operation bound",
            )));
        }
        let mut height = usize::from(self.height.max(1));
        let mut remaining = edits;
        let mut width = 1usize;
        let mut pages = 0u64;
        while remaining != 0 {
            // Before edit i, at most two pages per current level and one new
            // root can be appended. Prefix logarithms have bin widths 1, 2, 4, ...;
            // once the format height cap is reached all remaining edits share
            // its bound. Same-leaf batches, no-ops and deletes only save pages.
            let count = if height == MAX_HEIGHT {
                remaining
            } else {
                remaining.min(width)
            };
            let per_edit = (2 * height + 1) as u64;
            pages = per_edit
                .checked_mul(count as u64)
                .and_then(|additional| pages.checked_add(additional))
                .ok_or(CoreError::new(crate::CoreErrorCause::InvalidInput(
                    "directory transaction page bound overflow",
                )))?;
            remaining -= count;
            if remaining == 0 {
                break;
            }
            height = (height + 1).min(MAX_HEIGHT);
            width =
                width
                    .checked_mul(2)
                    .ok_or(CoreError::new(crate::CoreErrorCause::InvalidInput(
                        "directory transaction page bound overflow",
                    )))?;
        }
        Ok(pages)
    }
}
