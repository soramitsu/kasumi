//! Bounded adjacent-page packing, including neighbors across parent boundaries.

use super::*;

const PAYLOAD: usize = DIRECTORY_PAGE_BYTES - HEADER_BYTES;
const MAX_BRANCH_ENTRY: usize = MAX_ENCODED_KEY + BRANCH_VALUE_BYTES;
// A parent receiving two replacements can receive at most four carries. Its
// payload is at most P + 4M. Greedy closed pages use more than P - M bytes, so
// after two outputs the remainder is below 6M - P <= P. Shared ancestors
// replacing one child by at most three carries have a smaller bound.
const _: () = assert!(3 * MAX_BRANCH_ENTRY <= PAYLOAD);
const MAX_CARRIES: usize = 3;

/// One admitted logical continuation, independent of physical page lifetime.
pub(crate) struct DirectoryCursor {
    key: Vec<u8>,
    _lease: Box<dyn ResidentLease>,
}

impl DirectoryCursor {
    fn new(key: &[u8], admission: &Arc<dyn StorageAdmission>) -> Result<Self, CoreError> {
        let lease = reserve(
            admission,
            key.len() + std::mem::size_of::<Self>() + ALLOCATION_ALLOWANCE,
        )?;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(key.len())
            .map_err(|_| CoreError::CapacityDenied)?;
        if owned.capacity() != key.len() {
            return Err(CoreError::CapacityDenied);
        }
        owned.extend_from_slice(key);
        admission
            .check_owner()
            .map_err(|_| CoreError::OwnerFailed)?;
        Ok(Self {
            key: owned,
            _lease: lease,
        })
    }

    pub(crate) fn key(&self) -> DirectoryKey<'_> {
        decode_key(&self.key)
            .expect("cursor owns a validated key")
            .0
    }
}

#[derive(Clone, Copy)]
struct Frame {
    reference: DirectoryPageRef,
    info: PageInfo,
    child: usize,
}

struct PlannedPage {
    reference: DirectoryPageRef,
    info: PageInfo,
    buffer: PageBuffer,
    path: [Option<Frame>; MAX_HEIGHT],
    depth: usize,
}

impl PlannedPage {
    fn validate(
        &self,
        reader: &DirectoryReader<'_>,
        root: DirectoryRoot,
        input: &mut [u8],
    ) -> Result<(), CoreError> {
        let mut reference = root
            .page
            .ok_or(CoreError::Corrupt("packing plan has an empty root"))?;
        let mut bounds = Bounds::root(root);
        let expected_depth = root
            .height
            .checked_sub(self.info.level)
            .and_then(|height| height.checked_sub(1));
        if expected_depth.is_none_or(|depth| self.depth != usize::from(depth)) {
            return Err(CoreError::Corrupt("packing path depth differs"));
        }
        for frame in &self.path[..self.depth] {
            let frame = frame.ok_or(CoreError::Corrupt("packing path is incomplete"))?;
            if frame.reference != reference {
                return Err(CoreError::Corrupt("packing path reference differs"));
            }
            let info = reader.load(input, root, reference, &bounds)?;
            if info != frame.info || info.level == 0 {
                return Err(CoreError::Corrupt("packing ancestor differs"));
            }
            reference = bounds.child(input, info, frame.child)?;
        }
        if reference != self.reference {
            return Err(CoreError::Corrupt("packing selected reference differs"));
        }
        let info = reader.load(input, root, reference, &bounds)?;
        if info != self.info || &*input != self.buffer.bytes.as_slice() {
            return Err(CoreError::Corrupt("packing selected page differs"));
        }
        Ok(())
    }
}

/// Two adjacent pages at one exact root, or an explicit terminal single page.
/// Buffers/paths and the post-publication continuation are admitted together.
pub(crate) struct DirectoryPackPlan {
    root: DirectoryRoot,
    left: PlannedPage,
    right: Option<PlannedPage>,
    moved: usize,
    normalize_root: bool,
    next: Option<DirectoryCursor>,
    _lease: Box<dyn ResidentLease>,
}

impl DirectoryPackPlan {
    pub(crate) fn needs_pack(&self) -> bool {
        self.moved != 0 || self.normalize_root
    }
    pub(crate) fn level(&self) -> u8 {
        self.left.info.level
    }
    pub(crate) fn references(&self) -> (DirectoryPageRef, Option<DirectoryPageRef>) {
        (
            self.left.reference,
            self.right.as_ref().map(|right| right.reference),
        )
    }
    pub(crate) fn into_next(self) -> Option<DirectoryCursor> {
        self.next
    }

    /// Exact adjacency is a property of both paths, not just ordered keys.
    fn ancestor(&self) -> Result<usize, CoreError> {
        let right = self
            .right
            .as_ref()
            .ok_or(CoreError::InvalidInput("packing plan has no neighbor"))?;
        if right.depth != self.left.depth
            || right.info.level != self.left.info.level
            || right.reference == self.left.reference
        {
            return Err(CoreError::Corrupt("packing neighbor shape differs"));
        }
        for depth in 0..self.left.depth {
            let left = self.left.path[depth]
                .ok_or(CoreError::Corrupt("packing left path is incomplete"))?;
            let other =
                right.path[depth].ok_or(CoreError::Corrupt("packing right path is incomplete"))?;
            if left.reference != other.reference || left.info != other.info {
                return Err(CoreError::Corrupt(
                    "packing paths diverge before their ancestor",
                ));
            }
            if left.child == other.child {
                continue;
            }
            if left.child + 1 != other.child {
                return Err(CoreError::Corrupt("packing pages are not adjacent"));
            }
            for frame in &self.left.path[depth + 1..self.left.depth] {
                let frame = frame.ok_or(CoreError::Corrupt("packing left path is incomplete"))?;
                if frame.child + 1 != frame.info.count {
                    return Err(CoreError::Corrupt("packing left path is not rightmost"));
                }
            }
            for frame in &right.path[depth + 1..right.depth] {
                let frame = frame.ok_or(CoreError::Corrupt("packing right path is incomplete"))?;
                if frame.child != 0 {
                    return Err(CoreError::Corrupt("packing right path is not leftmost"));
                }
            }
            return Ok(depth);
        }
        Err(CoreError::Corrupt(
            "packing pages have no divergent ancestor",
        ))
    }
}

impl DirectoryReader<'_> {
    /// Select the page containing the first leaf key >= lower, and its next
    /// page at `level`. A removed level/empty suffix returns None. A terminal
    /// page returns a plan with no right page and no continuation. Such a plan
    /// can still require a directory-only commit to normalize a unary root.
    pub(crate) fn pack_after(
        &self,
        root: DirectoryRoot,
        level: u8,
        lower: DirectoryKey<'_>,
    ) -> Result<Option<DirectoryPackPlan>, CoreError> {
        self.admission
            .check_owner()
            .map_err(|_| CoreError::OwnerFailed)?;
        root.validate()?;
        lower.validate()?;
        if level >= root.height {
            return Ok(None);
        }
        let Some(first) = self.next(root, lower, false)? else {
            return Ok(None);
        };
        let lease = reserve(&self.admission, std::mem::size_of::<DirectoryPackPlan>())?;
        let _scratch = reserve(
            &self.admission,
            2 * std::mem::size_of::<Bounds>() + 2 * std::mem::size_of::<Frame>(),
        )?;
        let mut buffer = PageBuffer::new(&self.admission)?;
        let mut path = [None; MAX_HEIGHT];
        let mut depth = 0;
        let mut reference = root.page.expect("nonempty root");
        let mut bounds = Bounds::root(root);
        let info = loop {
            let info = self.load(&mut buffer, root, reference, &bounds)?;
            if info.level == level {
                break info;
            }
            let mut child = 0;
            let mut at = HEADER_BYTES;
            for index in 0..info.count {
                let (entry, end) = page_entry(&buffer.bytes, at, info.used)?;
                if entry.key > first.key() {
                    break;
                }
                child = index;
                at = end;
            }
            path[depth] = Some(Frame {
                reference,
                info,
                child,
            });
            depth += 1;
            reference = bounds.child(&buffer.bytes, info, child)?;
        };
        let left = PlannedPage {
            reference,
            info,
            buffer,
            path,
            depth,
        };
        let pivot = (0..depth).rev().find(|&index| {
            let frame = left.path[index].expect("descent records ancestors");
            frame.child + 1 < frame.info.count
        });
        let right = if let Some(pivot) = pivot {
            let mut buffer = PageBuffer::new(&self.admission)?;
            let mut bounds = Bounds::root(root);
            let mut path = [None; MAX_HEIGHT];
            let mut reference = root.page.expect("nonempty root");
            let mut depth = 0;
            let info = loop {
                let info = self.load(&mut buffer, root, reference, &bounds)?;
                if info.level == level {
                    break info;
                }
                let child = if depth <= pivot {
                    let frame = left.path[depth].expect("shared neighbor ancestor");
                    if info != frame.info || reference != frame.reference {
                        return Err(CoreError::Corrupt("packing neighbor ancestor changed"));
                    }
                    frame.child + usize::from(depth == pivot)
                } else {
                    0
                };
                path[depth] = Some(Frame {
                    reference,
                    info,
                    child,
                });
                depth += 1;
                reference = bounds.child(&buffer.bytes, info, child)?;
            };
            Some(PlannedPage {
                reference,
                info,
                buffer,
                path,
                depth,
            })
        } else {
            None
        };
        let mut moved = 0;
        let next = if let Some(right) = &right {
            let mut used = left.info.used;
            let mut at = HEADER_BYTES;
            for _ in 0..right.info.count {
                let (entry, end) = page_entry(&right.buffer.bytes, at, right.info.used)?;
                let len = entry.key_bytes.len() + entry.value.len();
                if used + len > DIRECTORY_PAGE_BYTES {
                    break;
                }
                used += len;
                moved += 1;
                at = end;
            }
            let entry = if moved == right.info.count {
                nth_entry(&left.buffer.bytes, left.info, 0)?
            } else {
                nth_entry(&right.buffer.bytes, right.info, moved)?
            };
            Some(DirectoryCursor::new(entry.key_bytes, &self.admission)?)
        } else {
            None
        };
        let root_info = left.path[0].map_or(left.info, |frame| frame.info);
        let normalize_root = right.is_none() && root.height > 1 && root_info.count == 1;
        let plan = DirectoryPackPlan {
            root,
            left,
            right,
            moved,
            normalize_root,
            next,
            _lease: lease,
        };
        if plan.right.is_some() {
            plan.ancestor()?;
        }
        self.admission
            .check_owner()
            .map_err(|_| CoreError::OwnerFailed)?;
        Ok(Some(plan))
    }
}

struct Replacement {
    items: [Option<Carry>; MAX_CARRIES],
    len: usize,
}
impl Default for Replacement {
    fn default() -> Self {
        Self {
            items: std::array::from_fn(|_| None),
            len: 0,
        }
    }
}
impl Replacement {
    fn push(&mut self, carry: Carry) -> Result<(), CoreError> {
        if self.len == MAX_CARRIES {
            return Err(CoreError::Corrupt("packing carry bound exceeded"));
        }
        self.items[self.len] = Some(carry);
        self.len += 1;
        Ok(())
    }
    fn entries(&self) -> Result<u64, CoreError> {
        self.items.iter().flatten().try_fold(0u64, |sum, carry| {
            sum.checked_add(carry.entries)
                .ok_or(CoreError::Corrupt("packing counts overflow"))
        })
    }
}

struct ChildEdit<'a> {
    index: usize,
    old: DirectoryPageRef,
    replacement: &'a Replacement,
}

struct Context<'a> {
    backend: &'a dyn DirectoryBackend,
    admission: &'a Arc<dyn StorageAdmission>,
    root: DirectoryRoot,
    generation: u64,
    input: &'a mut [u8],
    output: PendingPage<&'a mut [u8]>,
}

impl Context<'_> {
    fn flush(&mut self, level: u8, replacement: &mut Replacement) -> Result<(), CoreError> {
        if self.output.count == 0 {
            return Ok(());
        }
        let page = &mut self.output;
        let bytes = &mut page.buffer;
        bytes[..16].copy_from_slice(&MAGIC);
        bytes[16..20].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes[20..36].copy_from_slice(&self.root.group_id);
        bytes[36..44].copy_from_slice(&self.generation.to_le_bytes());
        bytes[44] = level;
        bytes[46..48].copy_from_slice(&page.count.to_le_bytes());
        bytes[48..52].copy_from_slice(&(page.used as u32).to_le_bytes());
        bytes[52..60].copy_from_slice(&page.entries.to_le_bytes());
        let key_len = decode_key(&bytes[HEADER_BYTES..page.used])?.1;
        let mut key = [0; MAX_ENCODED_KEY];
        key[..key_len].copy_from_slice(&bytes[HEADER_BYTES..HEADER_BYTES + key_len]);
        let digest = page_digest(bytes);
        self.admission
            .check_owner()
            .map_err(|_| CoreError::OwnerFailed)?;
        let reference = self.backend.append_page(bytes)?;
        self.admission
            .check_owner()
            .map_err(|_| CoreError::OwnerFailed)?;
        reference.validate()?;
        if reference.sha256 != digest {
            return Err(CoreError::Corrupt("packed page digest differs"));
        }
        replacement.push(Carry {
            key,
            key_len,
            page: reference,
            entries: page.entries,
        })?;
        page.reset();
        Ok(())
    }

    fn append(
        &mut self,
        level: u8,
        key: DirectoryKey<'_>,
        value: &[u8],
        entries: u64,
        replacement: &mut Replacement,
    ) -> Result<(), CoreError> {
        if !self.output.fits(key.encoded_len(), value.len()) {
            self.flush(level, replacement)?;
        }
        self.output.append(key, value, entries)
    }

    fn carry(
        &mut self,
        level: u8,
        carry: &Carry,
        replacement: &mut Replacement,
    ) -> Result<(), CoreError> {
        let mut value = [0; BRANCH_VALUE_BYTES];
        carry.page.encode(&mut value[..PAGE_REF_BYTES]);
        value[PAGE_REF_BYTES..].copy_from_slice(&carry.entries.to_le_bytes());
        self.append(
            level,
            decode_key(&carry.key[..carry.key_len])?.0,
            &value,
            carry.entries,
            replacement,
        )
    }

    fn pair(&mut self, plan: &DirectoryPackPlan) -> Result<Replacement, CoreError> {
        let mut replacement = Replacement::default();
        for page in [
            &plan.left,
            plan.right.as_ref().expect("changed pair has neighbor"),
        ] {
            let mut at = HEADER_BYTES;
            for _ in 0..page.info.count {
                let (entry, end) = page_entry(&page.buffer.bytes, at, page.info.used)?;
                let entries = if page.info.level == 0 {
                    1
                } else {
                    le_u64(&entry.value[PAGE_REF_BYTES..])
                };
                self.append(
                    page.info.level,
                    entry.key,
                    entry.value,
                    entries,
                    &mut replacement,
                )?;
                at = end;
            }
        }
        self.flush(plan.level(), &mut replacement)?;
        if !(1..=2).contains(&replacement.len) {
            return Err(CoreError::Corrupt("packed pair output bound differs"));
        }
        Ok(replacement)
    }

    fn parent(&mut self, frame: Frame, edits: &[ChildEdit<'_>]) -> Result<Replacement, CoreError> {
        self.admission
            .check_owner()
            .map_err(|_| CoreError::OwnerFailed)?;
        self.backend.read_page(frame.reference, self.input)?;
        self.admission
            .check_owner()
            .map_err(|_| CoreError::OwnerFailed)?;
        let info = validate_page(self.input, self.root, frame.reference)?;
        if info != frame.info || info.level == 0 {
            return Err(CoreError::Corrupt("packing parent changed"));
        }
        let mut result = Replacement::default();
        let mut at = HEADER_BYTES;
        let mut applied = 0;
        for index in 0..info.count {
            let (entry, end) = page_entry(self.input, at, info.used)?;
            if let Some(edit) = edits.iter().find(|edit| edit.index == index) {
                if DirectoryPageRef::decode(&entry.value[..PAGE_REF_BYTES])? != edit.old {
                    return Err(CoreError::Corrupt("packing parent selected another child"));
                }
                for carry in edit.replacement.items.iter().flatten() {
                    self.carry(info.level, carry, &mut result)?;
                }
                applied += 1;
            } else {
                // Borrowing the input page while output may flush needs only
                // one fixed maximum record, never a parent-sized key list.
                let mut record = [0; MAX_BRANCH_ENTRY];
                let key_len = entry.key_bytes.len();
                record[..key_len].copy_from_slice(entry.key_bytes);
                record[key_len..key_len + BRANCH_VALUE_BYTES].copy_from_slice(entry.value);
                let entries = le_u64(&entry.value[PAGE_REF_BYTES..]);
                self.append(
                    info.level,
                    decode_key(&record[..key_len])?.0,
                    &record[key_len..key_len + BRANCH_VALUE_BYTES],
                    entries,
                    &mut result,
                )?;
            }
            at = end;
        }
        if applied != edits.len() {
            return Err(CoreError::Corrupt("packing child edit was not applied"));
        }
        self.flush(info.level, &mut result)?;
        Ok(result)
    }

    fn finish_root(&mut self, replacement: Replacement) -> Result<DirectoryRoot, CoreError> {
        if replacement.entries()? != self.root.entries || replacement.len == 0 {
            return Err(CoreError::Corrupt("packed root entry count differs"));
        }
        let mut root = DirectoryRoot {
            generation: self.generation,
            ..self.root
        };
        if replacement.len == 1 {
            root.page = Some(replacement.items[0].as_ref().expect("one root carry").page);
        } else {
            if usize::from(root.height) == MAX_HEIGHT {
                return Err(CoreError::InvalidInput("directory exceeds maximum height"));
            }
            let mut top = Replacement::default();
            for carry in replacement.items.iter().flatten() {
                self.carry(root.height, carry, &mut top)?;
            }
            self.flush(root.height, &mut top)?;
            if top.len != 1 {
                return Err(CoreError::Corrupt("packing root exceeds one page"));
            }
            root.page = Some(top.items[0].as_ref().expect("one new root carry").page);
            root.height += 1;
        }
        let reader = DirectoryReader::new(self.backend, self.admission.clone());
        while root.height > 1 {
            let bounds = Bounds::root(root);
            let info = reader.load(
                self.input,
                root,
                root.page.expect("nonempty packed root"),
                &bounds,
            )?;
            if info.count != 1 {
                break;
            }
            let mut bounds = bounds;
            let child = bounds.child(self.input, info, 0)?;
            reader.load(self.input, root, child, &bounds)?;
            root.page = Some(child);
            root.height -= 1;
        }
        root.validate()?;
        Ok(root)
    }

    /// A valid terminal tree may consist only of unary ancestors. Normalize
    /// its root without fabricating a neighbor or appending any page. The new
    /// generation still needs the owner's durable DirectoryOnly publication.
    fn normalize_root(&mut self) -> Result<DirectoryRoot, CoreError> {
        let reference = self.root.page.expect("nonempty packing root");
        let reader = DirectoryReader::new(self.backend, self.admission.clone());
        let info = reader.load(self.input, self.root, reference, &Bounds::root(self.root))?;
        if info.level == 0 || info.count != 1 {
            return Err(CoreError::Corrupt("terminal packing root is not unary"));
        }
        let entry = nth_entry(self.input, info, 0)?;
        let mut key = [0; MAX_ENCODED_KEY];
        key[..entry.key_bytes.len()].copy_from_slice(entry.key_bytes);
        let mut replacement = Replacement::default();
        replacement.push(Carry {
            key,
            key_len: entry.key_bytes.len(),
            page: reference,
            entries: info.entries,
        })?;
        self.finish_root(replacement)
    }
}

impl DirectoryMutator<'_> {
    /// Copy the union of two adjacent paths into one private replacement root.
    /// Logical values are unchanged. The owner calls finish and publishes the
    /// root atomically before consuming the plan's admitted continuation.
    /// At height h, at most 2 + 4(h - 1) + 1 pages can be appended: two packed
    /// inputs, at most four outputs per divergent/common depth, one new root.
    pub(crate) fn pack_pair(
        &mut self,
        root: DirectoryRoot,
        generation: u64,
        plan: &DirectoryPackPlan,
    ) -> Result<DirectoryRoot, CoreError> {
        if self.failed {
            return Err(CoreError::OwnerFailed);
        }
        if self.admission.check_owner().is_err() {
            self.failed = true;
            return Err(CoreError::OwnerFailed);
        }
        if root != plan.root {
            return Err(CoreError::InvalidInput(
                "packing plan belongs to another root",
            ));
        }
        root.validate()?;
        if generation == 0 || generation < root.generation {
            return Err(CoreError::InvalidInput(
                "directory mutation generation is invalid",
            ));
        }
        // Include simultaneous pair/left/right/joined/returned carries and
        // helper-frame moves, plus bounds, record copying and root promotion.
        // Four page buffers total: two retained in the plan and these two.
        self.require_mode(update::WriteMode::Pack)?;
        let (input, output) = self.buffers.split_at_mut(DIRECTORY_PAGE_BYTES);
        let mut context = Context {
            backend: self.backend,
            admission: self.admission,
            root,
            generation,
            input,
            output: PendingPage::borrowed(output),
        };
        let result = (|| {
            let reader = DirectoryReader::new(self.backend, self.admission.clone());
            plan.left.validate(&reader, root, context.input)?;
            if let Some(right) = &plan.right {
                right.validate(&reader, root, context.input)?;
            }
            if !plan.needs_pack() {
                return Ok(root);
            }
            if plan.normalize_root {
                if plan.right.is_some() || plan.moved != 0 {
                    return Err(CoreError::Corrupt("terminal packing plan has a neighbor"));
                }
                return context.normalize_root();
            }
            let pivot = plan.ancestor()?;
            let right_page = plan.right.as_ref().expect("changed pair has neighbor");
            let mut pair = context.pair(plan)?;
            let mut left = Replacement::default();
            left.push(pair.items[0].take().expect("packed left output"))?;
            let mut right = Replacement::default();
            if let Some(carry) = pair.items[1].take() {
                right.push(carry)?;
            }
            let mut left_old = plan.left.reference;
            let mut right_old = right_page.reference;
            for depth in (pivot + 1..plan.left.depth).rev() {
                let frame = plan.left.path[depth].expect("validated left path");
                left = context.parent(
                    frame,
                    &[ChildEdit {
                        index: frame.child,
                        old: left_old,
                        replacement: &left,
                    }],
                )?;
                // A single old child becomes at most two carries. Payload
                // <= P + 2M leaves <3M <= P after its first greedy output.
                // This invariant bounds the later LCA input to four carries.
                if left.len > 2 {
                    return Err(CoreError::Corrupt("packing divergent carry bound exceeded"));
                }
                left_old = frame.reference;
            }
            for depth in (pivot + 1..right_page.depth).rev() {
                let frame = right_page.path[depth].expect("validated right path");
                right = context.parent(
                    frame,
                    &[ChildEdit {
                        index: frame.child,
                        old: right_old,
                        replacement: &right,
                    }],
                )?;
                if right.len > 2 {
                    return Err(CoreError::Corrupt("packing divergent carry bound exceeded"));
                }
                right_old = frame.reference;
            }
            let frame = plan.left.path[pivot].expect("validated common ancestor");
            let right_index = right_page.path[pivot]
                .expect("validated common ancestor")
                .child;
            let mut joined = context.parent(
                frame,
                &[
                    ChildEdit {
                        index: frame.child,
                        old: left_old,
                        replacement: &left,
                    },
                    ChildEdit {
                        index: right_index,
                        old: right_old,
                        replacement: &right,
                    },
                ],
            )?;
            let mut old = frame.reference;
            for depth in (0..pivot).rev() {
                let frame = plan.left.path[depth].expect("validated common path");
                joined = context.parent(
                    frame,
                    &[ChildEdit {
                        index: frame.child,
                        old,
                        replacement: &joined,
                    }],
                )?;
                old = frame.reference;
            }
            context.finish_root(joined)
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}

pub(super) fn write_scratch_bytes() -> usize {
    8 * std::mem::size_of::<Replacement>()
        + 4 * std::mem::size_of::<Carry>()
        + 3 * std::mem::size_of::<Bounds>()
        + 4 * MAX_BRANCH_ENTRY
        + std::mem::size_of::<Context<'_>>()
}
