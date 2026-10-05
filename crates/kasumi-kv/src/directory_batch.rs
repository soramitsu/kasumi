//! Bounded same-leaf merges, with one rebuild of the selecting ancestor path.
use super::*;

pub(crate) const MAX_DIRECTORY_BATCH_EDITS: usize = 16;

/// Borrowed inputs; their enclosing owner admits the fixed array and key backing.
#[derive(Clone, Copy)]
pub(crate) struct DirectoryEdit<'a> {
    pub(crate) key: DirectoryKey<'a>,
    pub(crate) value: Option<DirectoryValue>,
}

impl DirectoryMutator<'_> {
    /// Merge the maximal prefix routed to the first edit's leaf. Success
    /// returns the new private root and the number of consumed edits (>= 2).
    /// `None` requires the ordinary editor: no page has been appended and this
    /// mutator remains reusable. A changed result appends one leaf and one copy
    /// of each ancestor; only the enclosing `finish` synchronizes the pages.
    pub(crate) fn try_set_leaf_batch(
        &mut self,
        root: DirectoryRoot,
        generation: u64,
        edits: &[DirectoryEdit<'_>],
    ) -> Result<Option<(DirectoryRoot, usize)>, CoreError> {
        if self.failed {
            return Err(CoreError::new(crate::CoreErrorCause::OwnerFailed));
        }
        if self.admission.check_owner().is_err() {
            self.failed = true;
            return Err(CoreError::new(crate::CoreErrorCause::OwnerFailed));
        }
        root.validate()?;
        if generation == 0 || generation < root.generation {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "directory mutation generation is invalid",
            )));
        }
        if !(2..=MAX_DIRECTORY_BATCH_EDITS).contains(&edits.len()) {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "directory batch edit count is invalid",
            )));
        }
        let mut previous = None;
        for edit in edits {
            edit.key.validate()?;
            if previous.is_some_and(|key| key >= edit.key) {
                return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                    "directory batch keys are not strictly ordered",
                )));
            }
            if let Some(value) = edit.value {
                value.validate(edit.key, generation).map_err(|_| {
                    CoreError::new(crate::CoreErrorCause::InvalidInput(
                        "directory value is invalid",
                    ))
                })?;
            }
            previous = Some(edit.key);
        }
        // The caller owns the borrowed input array. Its prepared write owner
        // already admits the merge/path state, split carries and both pages.
        self.require_mode(WriteMode::Edits)?;
        let editor = Editor {
            backend: self.backend,
            admission: self.admission,
        };
        let (input, output) = self.buffers.split_at_mut(DIRECTORY_PAGE_BYTES);
        let mut output = PendingPage::borrowed(output);
        let result = editor.merge_leaf_batch(root, generation, edits, input, &mut output);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}
impl Editor<'_> {
    fn merge_leaf_batch(
        &self,
        root: DirectoryRoot,
        generation: u64,
        edits: &[DirectoryEdit<'_>],
        input: &mut [u8],
        output: &mut PendingPage<&mut [u8]>,
    ) -> Result<Option<(DirectoryRoot, usize)>, CoreError> {
        let mut path = [None; MAX_HEIGHT];
        let mut separator_lengths = [0; MAX_HEIGHT];
        let mut depth = 0;
        let mut count = edits.len();
        let leaf = match root.page {
            Some(mut reference) => {
                let reader = DirectoryReader::new(self.backend, self.admission.clone());
                let mut bounds = Bounds::root(root);
                loop {
                    let info = reader.load(input, root, reference, &bounds)?;
                    if info.level == 0 {
                        break Some(info);
                    }
                    let mut selected = 0;
                    let mut at = HEADER_BYTES;
                    for index in 0..info.count {
                        let (entry, end) = page_entry(input, at, info.used)?;
                        if entry.key > edits[0].key {
                            break;
                        }
                        selected = index;
                        at = end;
                    }
                    // Routing chooses the first child even below the global
                    // minimum. Only its exclusive upper bound limits this
                    // sorted prefix; missing deletes follow that same route.
                    if selected + 1 < info.count {
                        let upper = nth_entry(input, info, selected + 1)?.key;
                        while count > 1 && edits[count - 1].key >= upper {
                            count -= 1;
                        }
                        if count == 1 {
                            return Ok(None);
                        }
                    }
                    separator_lengths[depth] = nth_entry(input, info, selected)?.key_bytes.len();
                    path[depth] = Some(Frame {
                        reference,
                        info,
                        child: selected,
                    });
                    depth += 1;
                    reference = bounds.child(input, info, selected)?;
                }
            }
            None => None,
        };
        let used = leaf.map_or(HEADER_BYTES, |info| info.used);
        let leaf_generation = leaf.map_or(root.generation, |info| info.generation);
        let edits = &edits[..count];
        let mut at = HEADER_BYTES;
        let mut next_edit = 0;
        let mut changed = false;
        let mut encoded = [0; LEAF_VALUE_BYTES];
        while at < used || next_edit < edits.len() {
            let existing = if at < used {
                Some(page_entry(input, at, used)?)
            } else {
                None
            };
            let edit = edits.get(next_edit);
            let ordering = match (existing.as_ref(), edit) {
                (Some((entry, _)), Some(edit)) => entry.key.cmp(&edit.key),
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => unreachable!("merge has an existing entry or edit"),
            };
            if ordering == Ordering::Less {
                let (entry, end) = existing.expect("existing entry precedes edit");
                if !output.fits(entry.key.encoded_len(), LEAF_VALUE_BYTES) {
                    return Ok(None);
                }
                output.append(entry.key, entry.value, 1)?;
                at = end;
                continue;
            }
            let edit = edit.expect("edit precedes or replaces existing entry");
            let old = if ordering == Ordering::Equal {
                let (entry, end) = existing.expect("matching existing entry");
                at = end;
                Some(DirectoryValue::decode(
                    entry.key,
                    entry.value,
                    leaf_generation,
                )?)
            } else {
                None
            };
            changed |= old != edit.value;
            if let Some(value) = edit.value {
                if !output.fits(edit.key.encoded_len(), LEAF_VALUE_BYTES) {
                    return Ok(None);
                }
                value.encode(&mut encoded);
                output.append(edit.key, &encoded, 1)?;
            }
            next_edit += 1;
        }

        let mut next_root = DirectoryRoot { generation, ..root };
        if !changed {
            return Ok(Some((next_root, count)));
        }
        // Removing a nonroot leaf changes topology. The ordinary editor owns
        // that case, and no append has happened yet.
        if depth != 0 && output.count == 0 {
            return Ok(None);
        }
        next_root.entries = root
            .entries
            .checked_sub(leaf.map_or(0, |info| info.entries))
            .and_then(|entries| entries.checked_add(output.entries))
            .ok_or(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "directory entry count overflow",
            )))?;
        if output.count != 0 {
            let minimum_len = decode_key(&output.buffer[HEADER_BYTES..output.used])?.1;
            for index in (0..depth).rev() {
                let frame = path[index].expect("descent recorded parent");
                // Replacing exactly one nonempty child preserves branch count
                // and fixed-size values. Only its separator length can grow.
                let payload =
                    frame.info.used - HEADER_BYTES - separator_lengths[index] + minimum_len;
                if payload > DIRECTORY_PAGE_BYTES - HEADER_BYTES {
                    return Ok(None);
                }
                // A changed first child propagates this same new minimum.
                // Otherwise this parent's minimum and all higher separators
                // remain unchanged, so their original fit is sufficient.
                if frame.child != 0 {
                    break;
                }
            }
        }
        let replacement = if output.count == 0 {
            Replacement::default()
        } else {
            // Leaf and every ancestor fit. This is the first append; reuse the
            // ordinary writer's canonical framing, digest checks and ascent.
            Output {
                backend: self.backend,
                admission: self.admission.as_ref(),
                page: output,
                group_id: root.group_id,
                generation,
                level: 0,
                split_target: usize::MAX,
                // This leaf was fully assembled and preflighted above.
                remaining: 0,
                replacement: Replacement::default(),
            }
            .finish()?
        };
        self.finish_path(
            root,
            next_root,
            &path[..depth],
            replacement,
            (input, output),
        )
        .map(|root| Some((root, count)))
    }
}

pub(super) fn scratch_bytes() -> usize {
    std::mem::size_of::<[Option<Frame>; MAX_HEIGHT]>()
        + std::mem::size_of::<[usize; MAX_HEIGHT]>()
        + 2 * std::mem::size_of::<Bounds>()
        + 3 * std::mem::size_of::<DirectoryRoot>()
        + 2 * std::mem::size_of::<PageInfo>()
        + 2 * std::mem::size_of::<Entry<'_>>()
        + 2 * std::mem::size_of::<DirectoryEdit<'_>>()
        + 2 * std::mem::size_of::<Option<DirectoryValue>>()
        + std::mem::size_of::<&[DirectoryEdit<'_>]>()
        + LEAF_VALUE_BYTES
        + 3 * std::mem::size_of::<Replacement>()
        + 2 * std::mem::size_of::<Carry>()
        + std::mem::size_of::<Output<'_, '_>>()
        + std::mem::size_of::<PendingPage<&mut [u8]>>()
        + 2 * std::mem::size_of::<DirectoryReader<'_>>()
}
