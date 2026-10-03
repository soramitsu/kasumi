//! Incremental private roots for the immutable directory.
//!
//! Mutations copy only the search path. The path contains references and child
//! positions, never retained page bodies. Two admitted page buffers suffice
//! regardless of the population, and all other scratch has a fixed ceiling.

use super::*;

#[path = "directory_batch.rs"]
mod batch;
pub(crate) use batch::{DirectoryEdit, MAX_DIRECTORY_BATCH_EDITS};

// A parent replaces one entry with at most two entries. Its payload can
// therefore grow by at most two maximum records. A half-byte split either
// reaches its target, or stops just before overflowing a page; in the latter
// case the remainder is smaller than three maximum records and still fits.
const _: () =
    assert!(3 * (MAX_ENCODED_KEY + BRANCH_VALUE_BYTES) <= DIRECTORY_PAGE_BYTES - HEADER_BYTES);

#[derive(Clone, Copy)]
struct Frame {
    reference: DirectoryPageRef,
    info: PageInfo,
    child: usize,
}

#[derive(Clone, Copy)]
struct Edit<'a> {
    root: DirectoryRoot,
    generation: u64,
    key: DirectoryKey<'a>,
    value: Option<DirectoryValue>,
    rewrite: bool,
}

#[derive(Default)]
struct Replacement {
    children: [Option<Carry>; 2],
}

impl Replacement {
    fn push(&mut self, carry: Carry) -> Result<(), CoreError> {
        let slot =
            self.children
                .iter_mut()
                .find(|slot| slot.is_none())
                .ok_or(CoreError::Corrupt(
                    "directory mutation split exceeds two pages",
                ))?;
        *slot = Some(carry);
        Ok(())
    }

    fn entries(&self) -> Result<u64, CoreError> {
        self.children.iter().flatten().try_fold(0u64, |sum, child| {
            sum.checked_add(child.entries)
                .ok_or(CoreError::Corrupt("directory mutation entries overflow"))
        })
    }
}

struct Output<'a, 'page> {
    backend: &'a dyn DirectoryBackend,
    admission: &'a dyn StorageAdmission,
    page: &'a mut PendingPage<&'page mut [u8]>,
    group_id: [u8; 16],
    generation: u64,
    level: u8,
    split_target: usize,
    remaining: usize,
    replacement: Replacement,
}

impl Output<'_, '_> {
    fn flush(&mut self) -> Result<(), CoreError> {
        if self.page.count == 0 {
            return Ok(());
        }
        let bytes = &mut self.page.buffer;
        bytes[..16].copy_from_slice(&MAGIC);
        bytes[16..20].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes[20..36].copy_from_slice(&self.group_id);
        bytes[36..44].copy_from_slice(&self.generation.to_le_bytes());
        bytes[44] = self.level;
        bytes[46..48].copy_from_slice(&self.page.count.to_le_bytes());
        bytes[48..52].copy_from_slice(&(self.page.used as u32).to_le_bytes());
        bytes[52..60].copy_from_slice(&self.page.entries.to_le_bytes());
        let key_len = decode_key(&bytes[HEADER_BYTES..self.page.used])?.1;
        let mut key = [0; MAX_ENCODED_KEY];
        key[..key_len].copy_from_slice(&bytes[HEADER_BYTES..HEADER_BYTES + key_len]);
        let sha256 = page_digest(bytes);
        self.admission
            .check_owner()
            .map_err(|_| CoreError::OwnerFailed)?;
        let reference = self.backend.append_page(bytes)?;
        self.admission
            .check_owner()
            .map_err(|_| CoreError::OwnerFailed)?;
        reference.validate()?;
        if reference.sha256 != sha256 {
            return Err(CoreError::Corrupt("appended directory page digest differs"));
        }
        self.replacement.push(Carry {
            key,
            key_len,
            page: reference,
            entries: self.page.entries,
        })?;
        self.page.reset();
        Ok(())
    }

    fn append(
        &mut self,
        key: DirectoryKey<'_>,
        value: &[u8],
        entries: u64,
    ) -> Result<(), CoreError> {
        if self.remaining == 0 {
            return Err(CoreError::Corrupt(
                "directory mutation record count exceeds plan",
            ));
        }
        if value.len() != value_bytes(self.level) {
            return Err(CoreError::Corrupt("directory mutation value size differs"));
        }
        // Split near half the byte population, but preserve at least two
        // records on each side. A short table minimum followed by maximum
        // row keys can otherwise split 3+1 and grow the left spine linearly.
        // Three maximum records fit, so an overflow also has >=3 on the left
        // and cannot occur after the penultimate-record boundary below.
        let balanced_split = self.replacement.children[0].is_none()
            && self.split_target != usize::MAX
            && self.page.count >= 2
            && self.remaining >= 2
            && (self.page.used - HEADER_BYTES >= self.split_target || self.remaining == 2);
        if !self.page.fits(key.encoded_len(), value.len()) || balanced_split {
            self.flush()?;
        }
        self.page.append(key, value, entries)?;
        self.remaining -= 1;
        Ok(())
    }

    fn append_child(&mut self, child: &Carry) -> Result<(), CoreError> {
        let mut value = [0; BRANCH_VALUE_BYTES];
        child.page.encode(&mut value[..PAGE_REF_BYTES]);
        value[PAGE_REF_BYTES..].copy_from_slice(&child.entries.to_le_bytes());
        self.append(
            decode_key(&child.key[..child.key_len])?.0,
            &value,
            child.entries,
        )
    }

    fn finish(mut self) -> Result<Replacement, CoreError> {
        if self.remaining != 0 {
            return Err(CoreError::Corrupt(
                "directory mutation record count is incomplete",
            ));
        }
        self.flush()?;
        Ok(self.replacement)
    }
}

/// A series of path-copying mutations followed by one page synchronization.
/// Returned roots are private until `finish` succeeds and the owner atomically
/// publishes a root with its matching durable log boundary. Old roots and all
/// pages reachable through them are unchanged, including after failures.
///
/// Any operational error poisons this instance: partial page appends are only
/// orphaned scratch and cannot be mistaken for a finished batch. The owner is
/// still responsible for backend failure fencing, growth admission and page
/// retention while an old root remains pinned.
pub(crate) struct DirectoryMutator<'a> {
    pub(super) backend: &'a dyn DirectoryBackend,
    pub(super) admission: &'a Arc<dyn StorageAdmission>,
    pub(super) failed: bool,
    pub(super) buffers: &'a mut [u8],
    pub(super) mode: WriteMode,
}

impl<'a> DirectoryMutator<'a> {
    pub(crate) fn new(
        backend: &'a dyn DirectoryBackend,
        workspace: &'a mut DirectoryWriteWorkspace,
    ) -> Result<Self, CoreError> {
        workspace
            .admission
            .check_owner()
            .map_err(|_| CoreError::OwnerFailed)?;
        Ok(Self {
            backend,
            admission: &workspace.admission,
            failed: false,
            buffers: &mut workspace.buffers,
            mode: workspace.mode,
        })
    }
    pub(super) fn require_mode(&self, mode: WriteMode) -> Result<(), CoreError> {
        if self.mode != mode {
            return Err(CoreError::InvalidInput(
                "directory write workspace operation differs",
            ));
        }
        Ok(())
    }

    pub(crate) fn get(
        &mut self,
        root: DirectoryRoot,
        key: DirectoryKey<'_>,
    ) -> Result<Option<DirectoryValue>, CoreError> {
        if self.failed {
            return Err(CoreError::OwnerFailed);
        }
        if self.admission.check_owner().is_err() {
            self.failed = true;
            return Err(CoreError::OwnerFailed);
        }
        root.validate()?;
        key.validate()?;
        let Some(reference) = root.page else {
            return Ok(None);
        };
        let result = DirectoryReader::new(self.backend, self.admission.clone()).get_in(
            root,
            key,
            reference,
            &mut self.buffers[..DIRECTORY_PAGE_BYTES],
        );
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    /// Insert/replace a value, or delete when `value` is `None`. Several
    /// operations in one batch may use the same generation; it must never
    /// precede the supplied root. A missing deletion still advances the
    /// private root's generation, without appending pages.
    pub(crate) fn set(
        &mut self,
        root: DirectoryRoot,
        generation: u64,
        key: DirectoryKey<'_>,
        value: Option<DirectoryValue>,
    ) -> Result<DirectoryRoot, CoreError> {
        self.edit(Edit {
            root,
            generation,
            key,
            value,
            rewrite: false,
        })
    }

    /// Insert/replace a maintenance record, copying its leaf and ancestor
    /// path even when the value is unchanged. Logical birth/batch versions
    /// remain exactly those supplied in `value`; only the copied pages and
    /// private root receive `generation`. The owner must durably publish the
    /// finished root before retiring any old page or value location.
    pub(crate) fn rewrite(
        &mut self,
        root: DirectoryRoot,
        generation: u64,
        key: DirectoryKey<'_>,
        value: DirectoryValue,
    ) -> Result<DirectoryRoot, CoreError> {
        self.edit(Edit {
            root,
            generation,
            key,
            value: Some(value),
            rewrite: true,
        })
    }

    /// Rewrite a whole validated leaf and each ancestor exactly once. Each
    /// replacement changes only a row's physical address; logical versions,
    /// keys, encoded lengths and entry counts remain unchanged. `None` keeps
    /// that record, but the leaf/path are copied even without replacements.
    pub(crate) fn rewrite_leaf(
        &mut self,
        root: DirectoryRoot,
        generation: u64,
        leaf: &DirectoryLeaf,
        replacements: &[Option<ValueLocation>],
    ) -> Result<DirectoryRoot, CoreError> {
        if self.failed {
            return Err(CoreError::OwnerFailed);
        }
        if self.admission.check_owner().is_err() {
            self.failed = true;
            return Err(CoreError::OwnerFailed);
        }
        if root != leaf.root {
            return Err(CoreError::InvalidInput(
                "directory leaf plan belongs to another root",
            ));
        }
        root.validate()?;
        if generation == 0 || generation < root.generation {
            return Err(CoreError::InvalidInput(
                "directory mutation generation is invalid",
            ));
        }
        if replacements.len() != leaf.len() {
            return Err(CoreError::InvalidInput(
                "directory leaf replacement count differs",
            ));
        }
        self.require_mode(WriteMode::LeafRewrite)?;
        match validate_page(&leaf.buffer.bytes, root, leaf.reference) {
            Ok(info) if info == leaf.info && info.level == 0 => {}
            result => {
                self.failed = true;
                return Err(result
                    .err()
                    .unwrap_or(CoreError::Corrupt("directory leaf plan page differs")));
            }
        }
        for ((_, value), replacement) in leaf.records().zip(replacements) {
            let Some(replacement) = replacement else {
                continue;
            };
            let DirectoryValue::Row { value, .. } = value else {
                return Err(CoreError::InvalidInput(
                    "directory table cannot have a physical replacement",
                ));
            };
            replacement.validate().map_err(|_| {
                CoreError::InvalidInput("directory replacement location is invalid")
            })?;
            if replacement.len != value.len || replacement.crc != value.crc {
                return Err(CoreError::InvalidInput(
                    "directory replacement changes logical value bytes",
                ));
            }
        }
        // Admission completes before path revalidation or any append. The
        // plan already owns the other page buffer and fixed ancestor path.
        let editor = Editor {
            backend: self.backend,
            admission: self.admission,
        };
        let result =
            editor.rewrite_leaf_admitted(root, generation, leaf, replacements, self.buffers);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}

struct Editor<'a> {
    backend: &'a dyn DirectoryBackend,
    admission: &'a Arc<dyn StorageAdmission>,
}
impl Editor<'_> {
    fn rewrite_leaf_admitted(
        &self,
        root: DirectoryRoot,
        generation: u64,
        leaf: &DirectoryLeaf,
        replacements: &[Option<ValueLocation>],
        input: &mut [u8],
    ) -> Result<DirectoryRoot, CoreError> {
        let reader = DirectoryReader::new(self.backend, self.admission.clone());
        leaf.validate_path(&reader, input)?;
        let mut at = HEADER_BYTES;
        for replacement in replacements {
            let (entry, end) = page_entry(input, at, leaf.info.used)?;
            if let Some(replacement) = replacement {
                let DirectoryValue::Row { batch_seq, .. } =
                    DirectoryValue::decode(entry.key, entry.value, leaf.info.generation)?
                else {
                    return Err(CoreError::Corrupt(
                        "validated leaf replacement is not a row",
                    ));
                };
                DirectoryValue::Row {
                    batch_seq,
                    value: *replacement,
                }
                .encode(&mut input[end - LEAF_VALUE_BYTES..end]);
            }
            at = end;
        }
        input[36..44].copy_from_slice(&generation.to_le_bytes());
        let mut child = self.append_rewritten_page(input)?;
        let mut old_child = leaf.reference;
        for frame in leaf.path[..leaf.depth].iter().rev() {
            let frame = frame.expect("validated leaf plan path");
            self.admission
                .check_owner()
                .map_err(|_| CoreError::OwnerFailed)?;
            self.backend.read_page(frame.reference, input)?;
            self.admission
                .check_owner()
                .map_err(|_| CoreError::OwnerFailed)?;
            let info = validate_page(input, root, frame.reference)?;
            if info != frame.info {
                return Err(CoreError::Corrupt(
                    "directory parent changed during leaf rewrite",
                ));
            }
            let mut at = HEADER_BYTES;
            for _ in 0..frame.child {
                at = page_entry(input, at, info.used)?.1;
            }
            let (entry, _) = page_entry(input, at, info.used)?;
            if DirectoryPageRef::decode(&entry.value[..PAGE_REF_BYTES])? != old_child {
                return Err(CoreError::Corrupt(
                    "directory parent selected another leaf path",
                ));
            }
            let value_at = at + entry.key_bytes.len();
            child.encode(&mut input[value_at..value_at + PAGE_REF_BYTES]);
            input[36..44].copy_from_slice(&generation.to_le_bytes());
            child = self.append_rewritten_page(input)?;
            old_child = frame.reference;
        }
        Ok(DirectoryRoot {
            generation,
            page: Some(child),
            ..root
        })
    }

    fn append_rewritten_page(&self, input: &[u8]) -> Result<DirectoryPageRef, CoreError> {
        let digest = page_digest(input);
        self.admission
            .check_owner()
            .map_err(|_| CoreError::OwnerFailed)?;
        let reference = self.backend.append_page(input)?;
        self.admission
            .check_owner()
            .map_err(|_| CoreError::OwnerFailed)?;
        reference.validate()?;
        if reference.sha256 != digest {
            return Err(CoreError::Corrupt("appended directory page digest differs"));
        }
        Ok(reference)
    }
}

impl DirectoryMutator<'_> {
    fn edit(&mut self, edit: Edit<'_>) -> Result<DirectoryRoot, CoreError> {
        let Edit {
            root,
            generation,
            key,
            value,
            ..
        } = edit;
        if self.failed {
            return Err(CoreError::OwnerFailed);
        }
        if self.admission.check_owner().is_err() {
            self.failed = true;
            return Err(CoreError::OwnerFailed);
        }
        root.validate()?;
        key.validate()?;
        if generation == 0 || generation < root.generation {
            return Err(CoreError::InvalidInput(
                "directory mutation generation is invalid",
            ));
        }
        if let Some(value) = value {
            value
                .validate(key, generation)
                .map_err(|_| CoreError::InvalidInput("directory value is invalid"))?;
        }
        // The operation-specific owner already admits the path, split carries,
        // helper frames and both actual pages before any private log effects.
        self.require_mode(WriteMode::Edits)?;
        let editor = Editor {
            backend: self.backend,
            admission: self.admission,
        };
        let (input, output) = self.buffers.split_at_mut(DIRECTORY_PAGE_BYTES);
        let mut output = PendingPage::borrowed(output);
        let result = editor.edit_admitted(edit, input, &mut output);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}

impl Editor<'_> {
    fn output<'b, 'page>(
        &'b self,
        page: &'b mut PendingPage<&'page mut [u8]>,
        root: DirectoryRoot,
        level: u8,
        payload: usize,
        count: usize,
    ) -> Output<'b, 'page> {
        debug_assert_eq!(page.count, 0);
        Output {
            backend: self.backend,
            admission: self.admission.as_ref(),
            page,
            group_id: root.group_id,
            generation: root.generation,
            level,
            split_target: if payload > DIRECTORY_PAGE_BYTES - HEADER_BYTES {
                payload.div_ceil(2)
            } else {
                usize::MAX
            },
            remaining: count,
            replacement: Replacement::default(),
        }
    }

    fn edit_admitted(
        &self,
        edit: Edit<'_>,
        input: &mut [u8],
        output: &mut PendingPage<&mut [u8]>,
    ) -> Result<DirectoryRoot, CoreError> {
        let Edit {
            root,
            generation,
            key,
            value,
            rewrite,
        } = edit;
        let mut next_root = DirectoryRoot { generation, ..root };
        let reader = DirectoryReader::new(self.backend, self.admission.clone());
        let mut path = [None; MAX_HEIGHT];
        let mut depth = 0;
        let replacement;
        if let Some(mut reference) = root.page {
            let mut bounds = Bounds::root(root);
            let info = loop {
                let info = reader.load(input, root, reference, &bounds)?;
                if info.level == 0 {
                    break info;
                }
                let mut selected = 0;
                let mut at = HEADER_BYTES;
                for index in 0..info.count {
                    let (entry, end) = page_entry(input, at, info.used)?;
                    if entry.key > key {
                        break;
                    }
                    selected = index;
                    at = end;
                }
                path[depth] = Some(Frame {
                    reference,
                    info,
                    child: selected,
                });
                depth += 1;
                reference = bounds.child(input, info, selected)?;
            };
            // Decide no-op cases before appending. Reading/validating the
            // selected leaf also ensures a miss cannot bypass corruption.
            let mut found = None;
            let mut at = HEADER_BYTES;
            for _ in 0..info.count {
                let (entry, end) = page_entry(input, at, info.used)?;
                if entry.key == key {
                    found = Some(DirectoryValue::decode(
                        entry.key,
                        entry.value,
                        info.generation,
                    )?);
                    break;
                }
                if entry.key > key {
                    break;
                }
                at = end;
            }
            if found == value && !rewrite {
                return Ok(next_root);
            }
            next_root.entries = match (found, value) {
                (None, Some(_)) => root
                    .entries
                    .checked_add(1)
                    .ok_or(CoreError::InvalidInput("directory entry count overflow"))?,
                (Some(_), None) => root.entries - 1,
                _ => root.entries,
            };
            let record_bytes = key.encoded_len() + LEAF_VALUE_BYTES;
            let payload = info.used - HEADER_BYTES - if found.is_some() { record_bytes } else { 0 }
                + if value.is_some() { record_bytes } else { 0 };
            let count = info.count - usize::from(found.is_some()) + usize::from(value.is_some());
            let mut writer = self.output(output, next_root, 0, payload, count);
            let mut inserted = false;
            let mut encoded = [0; LEAF_VALUE_BYTES];
            if let Some(value) = value {
                value.encode(&mut encoded);
            }
            let mut at = HEADER_BYTES;
            for _ in 0..info.count {
                let (entry, end) = page_entry(input, at, info.used)?;
                if !inserted && entry.key >= key {
                    if value.is_some() {
                        writer.append(key, &encoded, 1)?;
                    }
                    inserted = true;
                }
                if entry.key != key {
                    writer.append(entry.key, entry.value, 1)?;
                }
                at = end;
            }
            if !inserted && value.is_some() {
                writer.append(key, &encoded, 1)?;
            }
            replacement = writer.finish()?;
        } else {
            let Some(value) = value else {
                return Ok(next_root);
            };
            let mut encoded = [0; LEAF_VALUE_BYTES];
            value.encode(&mut encoded);
            let mut writer = self.output(
                output,
                next_root,
                0,
                key.encoded_len() + LEAF_VALUE_BYTES,
                1,
            );
            writer.append(key, &encoded, 1)?;
            replacement = writer.finish()?;
            next_root.entries = 1;
        }

        self.finish_path(
            root,
            next_root,
            &path[..depth],
            replacement,
            (input, output),
        )
    }

    /// Rebuild one previously validated path from its replacement leaf upward.
    /// The ordinary editor may split/collapse it. A batch caller proves its
    /// one-child replacement fits every parent before its first append.
    fn finish_path(
        &self,
        root: DirectoryRoot,
        mut next_root: DirectoryRoot,
        path: &[Option<Frame>],
        mut replacement: Replacement,
        (input, output): (&mut [u8], &mut PendingPage<&mut [u8]>),
    ) -> Result<DirectoryRoot, CoreError> {
        for frame in path.iter().rev() {
            let frame = frame.expect("descent recorded parent");
            self.admission
                .check_owner()
                .map_err(|_| CoreError::OwnerFailed)?;
            self.backend.read_page(frame.reference, input)?;
            self.admission
                .check_owner()
                .map_err(|_| CoreError::OwnerFailed)?;
            let info = validate_page(input, root, frame.reference)?;
            // The complete immutable reference was checked against ancestor
            // ranges on descent. Re-reading it cannot change its canonical
            // body or child choices; reject inconsistent backend results.
            if info.level != frame.info.level
                || info.count != frame.info.count
                || info.used != frame.info.used
                || info.entries != frame.info.entries
                || info.generation != frame.info.generation
            {
                return Err(CoreError::Corrupt(
                    "directory parent changed during mutation",
                ));
            }
            let replaced = nth_entry(input, info, frame.child)?;
            let payload = info.used - HEADER_BYTES - replaced.key_bytes.len() - BRANCH_VALUE_BYTES
                + replacement
                    .children
                    .iter()
                    .flatten()
                    .map(|child| child.key_len + BRANCH_VALUE_BYTES)
                    .sum::<usize>();
            let count = info.count - 1 + replacement.children.iter().flatten().count();
            let mut writer = self.output(output, next_root, info.level, payload, count);
            let mut at = HEADER_BYTES;
            for index in 0..info.count {
                let (entry, end) = page_entry(input, at, info.used)?;
                if index == frame.child {
                    for child in replacement.children.iter().flatten() {
                        writer.append_child(child)?;
                    }
                } else {
                    writer.append(
                        entry.key,
                        entry.value,
                        le_u64(&entry.value[PAGE_REF_BYTES..]),
                    )?;
                }
                at = end;
            }
            replacement = writer.finish()?;
        }
        if replacement.entries()? != next_root.entries {
            return Err(CoreError::Corrupt("directory mutation root count differs"));
        }
        let mut height = root.height.max(1);
        if replacement.children[1].is_some() {
            if height as usize == MAX_HEIGHT {
                return Err(CoreError::InvalidInput("directory exceeds maximum height"));
            }
            let payload = replacement
                .children
                .iter()
                .flatten()
                .map(|child| child.key_len + BRANCH_VALUE_BYTES)
                .sum();
            let mut writer = self.output(output, next_root, height, payload, 2);
            for child in replacement.children.iter().flatten() {
                writer.append_child(child)?;
            }
            replacement = writer.finish()?;
            height += 1;
        }
        next_root.page = replacement.children[0].as_ref().map(|child| child.page);
        next_root.height = if next_root.page.is_some() { height } else { 0 };
        // Deleting the last keys of sibling subtrees may leave several unary
        // root levels. Promote their only child, retaining uniform leaf depth
        // within every remaining non-root subtree.
        let reader = DirectoryReader::new(self.backend, self.admission.clone());
        while next_root.height > 1 {
            let reference = next_root.page.expect("nonempty root");
            let bounds = Bounds::root(next_root);
            let info = reader.load(input, next_root, reference, &bounds)?;
            if info.count != 1 {
                break;
            }
            let mut child_bounds = bounds;
            let child = child_bounds.child(input, info, 0)?;
            // Validate the promoted child before discarding its former
            // parent's minimum and generation constraints.
            reader.load(input, next_root, child, &child_bounds)?;
            next_root.page = Some(child);
            next_root.height -= 1;
        }
        next_root.validate()?;
        Ok(next_root)
    }
}

impl DirectoryMutator<'_> {
    /// Synchronize every appended page before handing the private root to
    /// the owner's durable root/log publication. This never publishes it.
    pub(crate) fn finish(&mut self, root: DirectoryRoot) -> Result<DirectoryRoot, CoreError> {
        if self.failed {
            return Err(CoreError::OwnerFailed);
        }
        root.validate()?;
        let result = self
            .admission
            .check_owner()
            .map_err(|_| CoreError::OwnerFailed)
            .and_then(|()| self.backend.sync_pages())
            .and_then(|()| {
                self.admission
                    .check_owner()
                    .map_err(|_| CoreError::OwnerFailed)
            });
        if result.is_err() {
            self.failed = true;
        }
        result.map(|()| root)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum WriteMode {
    Edits,
    LeafRewrite,
    Pack,
}

/// One actual grant owns the selected operation's fixed scratch, shell and page
/// backing. The private pages cannot outlive this owner or be used concurrently.
/// Construct before private log effects; all mutations and table checks reuse it.
pub(crate) struct DirectoryWriteWorkspace {
    buffers: Vec<u8>,
    admission: Arc<dyn StorageAdmission>,
    mode: WriteMode,
    _lease: Box<dyn ResidentLease>,
}
impl DirectoryWriteWorkspace {
    pub(crate) fn for_edits(admission: Arc<dyn StorageAdmission>) -> Result<Self, CoreError> {
        Self::new(
            admission,
            WriteMode::Edits,
            2,
            Self::edit_scratch_bytes().max(batch::scratch_bytes()),
        )
    }
    pub(crate) fn for_leaf_rewrite(
        admission: Arc<dyn StorageAdmission>,
    ) -> Result<Self, CoreError> {
        Self::new(
            admission,
            WriteMode::LeafRewrite,
            1,
            std::mem::size_of::<Bounds>()
                + std::mem::size_of::<DirectoryReader<'_>>()
                + 2 * std::mem::size_of::<PageInfo>()
                + 2 * std::mem::size_of::<DirectoryRoot>(),
        )
    }
    pub(crate) fn for_pack(admission: Arc<dyn StorageAdmission>) -> Result<Self, CoreError> {
        Self::new(
            admission,
            WriteMode::Pack,
            2,
            super::pack::write_scratch_bytes(),
        )
    }
    fn new(
        admission: Arc<dyn StorageAdmission>,
        mode: WriteMode,
        pages: usize,
        scratch: usize,
    ) -> Result<Self, CoreError> {
        let bytes = pages * DIRECTORY_PAGE_BYTES;
        let lease = reserve(
            &admission,
            bytes
                + scratch
                + std::mem::size_of::<Self>()
                + std::mem::size_of::<DirectoryMutator<'_>>()
                + std::mem::size_of::<Editor<'_>>()
                + ALLOCATION_ALLOWANCE,
        )?;
        let mut buffers = Vec::new();
        buffers
            .try_reserve_exact(bytes)
            .map_err(|_| CoreError::CapacityDenied)?;
        if buffers.capacity() != bytes {
            return Err(CoreError::CapacityDenied);
        }
        buffers.resize(bytes, 0);
        admission
            .check_owner()
            .map_err(|_| CoreError::OwnerFailed)?;
        Ok(Self {
            buffers,
            admission,
            mode,
            _lease: lease,
        })
    }
    fn edit_scratch_bytes() -> usize {
        std::mem::size_of::<[Option<Frame>; MAX_HEIGHT]>()
            + 2 * std::mem::size_of::<Bounds>()
            + 3 * std::mem::size_of::<Replacement>()
            + 2 * std::mem::size_of::<Carry>()
            + std::mem::size_of::<Output<'_, '_>>()
            + std::mem::size_of::<PendingPage<&mut [u8]>>()
            + 2 * std::mem::size_of::<DirectoryReader<'_>>()
            + std::mem::size_of::<Edit<'_>>()
    }
    pub(crate) fn get(
        &mut self,
        backend: &dyn DirectoryBackend,
        root: DirectoryRoot,
        key: DirectoryKey<'_>,
    ) -> Result<Option<DirectoryValue>, CoreError> {
        self.admission
            .check_owner()
            .map_err(|_| CoreError::OwnerFailed)?;
        root.validate()?;
        key.validate()?;
        let Some(reference) = root.page else {
            return Ok(None);
        };
        DirectoryReader::new(backend, self.admission.clone()).get_in(
            root,
            key,
            reference,
            &mut self.buffers[..DIRECTORY_PAGE_BYTES],
        )
    }
}
