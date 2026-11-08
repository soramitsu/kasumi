//! Copy several fitting leaves of a height-two tree and publish their root once.
use super::*;

#[derive(Clone, Copy, Default)]
struct LeafGroup {
    child: usize,
    parent_offset: usize,
    value_offset: usize,
    start: usize,
    end: usize,
}

#[derive(Clone, Copy, Default)]
struct PutPosition {
    offset: usize,
    inserted: bool,
}

impl DirectoryMutator<'_> {
    /// Return `None` before the first append if this run needs any split,
    /// changed separator or only one leaf. The caller drops speculative path
    /// observations before handing that case to the ordinary editor.
    pub(crate) fn try_set_branch_puts(
        &mut self,
        root: DirectoryRoot,
        generation: u64,
        edits: &[DirectoryEdit<'_>],
    ) -> Result<Option<DirectoryRoot>, CoreError> {
        self.validate_edit_batch(root, generation, edits)?;
        if root.height != 2
            || edits
                .iter()
                .any(|edit| edit.key.row.is_none() || edit.value.is_none())
        {
            return Ok(None);
        }
        let editor = Editor {
            backend: self.backend,
            admission: self.admission,
        };
        let (parent, leaf) = self.buffers.split_at_mut(DIRECTORY_PAGE_BYTES);
        let result = editor.branch_puts(root, generation, edits, parent, leaf);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}

impl Editor<'_> {
    fn branch_puts(
        &self,
        root: DirectoryRoot,
        generation: u64,
        edits: &[DirectoryEdit<'_>],
        parent: &mut [u8],
        leaf: &mut [u8],
    ) -> Result<Option<DirectoryRoot>, CoreError> {
        let reader = DirectoryReader::new(self.backend, self.admission.clone());
        let info = reader.load(
            parent,
            root,
            root.page.expect("height-two root"),
            &Bounds::root(root),
        )?;
        let mut groups = [LeafGroup::default(); MAX_DIRECTORY_BATCH_EDITS];
        let mut group_count = 0;
        let mut start = 0;
        let mut at = HEADER_BYTES;
        for child in 0..info.count {
            let (entry, next) = page_entry(parent, at, info.used)?;
            // Every leaf keeps its minimum, so every root separator keeps
            // its encoded width and order.
            if edits[start].key < entry.key {
                return Ok(None);
            }
            let count = if next < info.used {
                let upper = page_entry(parent, next, info.used)?.0.key;
                edits[start..].partition_point(|edit| edit.key < upper)
            } else {
                edits.len() - start
            };
            if count != 0 {
                groups[group_count] = LeafGroup {
                    child,
                    parent_offset: at,
                    value_offset: next - BRANCH_VALUE_BYTES,
                    start,
                    end: start + count,
                };
                group_count += 1;
                start += count;
                if start == edits.len() {
                    break;
                }
            }
            at = next;
        }
        if group_count < 2 {
            return Ok(None);
        }
        let groups = &groups[..group_count];
        let mut positions = [PutPosition::default(); MAX_DIRECTORY_BATCH_EDITS];
        let mut added = 0u64;
        // Preflight every changed path before the first append. Besides making
        // refusal effect-free, the recording backend now knows exactly which
        // original leaves this transaction supersedes.
        for group in groups {
            let mut bounds = Bounds::root(root);
            let reference = bounds.child_at(parent, info, group.child, group.parent_offset)?;
            let child = reader.load(leaf, root, reference, &bounds)?;
            let mut cursor = HEADER_BYTES;
            let mut new_used = child.used;
            for index in group.start..group.end {
                let key = edits[index].key;
                let mut inserted = true;
                while cursor < child.used {
                    let (entry, next) = page_entry(leaf, cursor, child.used)?;
                    if entry.key >= key {
                        inserted = entry.key != key;
                        break;
                    }
                    cursor = next;
                }
                positions[index] = PutPosition {
                    offset: cursor,
                    inserted,
                };
                if inserted {
                    new_used += key.encoded_len() + LEAF_VALUE_BYTES;
                    if new_used > DIRECTORY_PAGE_BYTES {
                        return Ok(None);
                    }
                    added += 1;
                }
            }
        }
        let entries = root.entries.checked_add(added).ok_or(CoreError::new(
            crate::CoreErrorCause::InvalidInput("directory entry count overflow"),
        ))?;
        for group in groups {
            let mut bounds = Bounds::root(root);
            let old = bounds.child_at(parent, info, group.child, group.parent_offset)?;
            let mut child = reader.load(leaf, root, old, &bounds)?;
            // Descending offsets preserve every earlier location from the
            // validated immutable input. Inserts in the same gap stay sorted.
            for index in (group.start..group.end).rev() {
                let edit = edits[index];
                let position = positions[index];
                let value_at = position.offset + edit.key.encoded_len();
                if position.inserted {
                    let record_bytes = edit.key.encoded_len() + LEAF_VALUE_BYTES;
                    leaf.copy_within(position.offset..child.used, position.offset + record_bytes);
                    edit.key.encode(&mut leaf[position.offset..value_at]);
                    child.used += record_bytes;
                    child.count += 1;
                    child.entries += 1;
                }
                edit.value
                    .expect("preflighted put")
                    .encode(&mut leaf[value_at..value_at + LEAF_VALUE_BYTES]);
            }
            leaf[36..44].copy_from_slice(&generation.to_le_bytes());
            leaf[46..48].copy_from_slice(&(child.count as u16).to_le_bytes());
            leaf[48..52].copy_from_slice(&(child.used as u32).to_le_bytes());
            leaf[52..60].copy_from_slice(&child.entries.to_le_bytes());
            let new = self.append_rewritten_page(leaf)?;
            let value = &mut parent[group.value_offset..group.value_offset + BRANCH_VALUE_BYTES];
            new.encode(&mut value[..PAGE_REF_BYTES]);
            value[PAGE_REF_BYTES..].copy_from_slice(&child.entries.to_le_bytes());
        }
        parent[36..44].copy_from_slice(&generation.to_le_bytes());
        parent[52..60].copy_from_slice(&entries.to_le_bytes());
        let page = self.append_rewritten_page(parent)?;
        Ok(Some(DirectoryRoot {
            generation,
            page: Some(page),
            entries,
            ..root
        }))
    }
}

// Both page buffers and this bounded planning state fit the existing edit
// workspace. Keep this checked if either the planner or its limits change.
const _: () = assert!(
    std::mem::size_of::<[LeafGroup; MAX_DIRECTORY_BATCH_EDITS]>()
        + std::mem::size_of::<[PutPosition; MAX_DIRECTORY_BATCH_EDITS]>()
        + 2 * std::mem::size_of::<Bounds>()
        + 2 * std::mem::size_of::<PageInfo>()
        + std::mem::size_of::<DirectoryReader<'_>>()
        < 3 * std::mem::size_of::<Replacement>()
);
