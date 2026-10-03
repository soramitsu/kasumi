//! One admitted, validated leaf and the bounded path selecting it.

use super::*;

/// Shared ceiling for a single leaf's maintenance records and replacements.
pub(crate) const MAX_DIRECTORY_LEAF_RECORDS: usize = 512;
const _: () = assert!(
    (DIRECTORY_PAGE_BYTES - HEADER_BYTES) / (KEY_HEADER_BYTES + 1 + LEAF_VALUE_BYTES)
        <= MAX_DIRECTORY_LEAF_RECORDS
);

#[derive(Clone, Copy)]
pub(super) struct LeafFrame {
    pub(super) reference: DirectoryPageRef,
    pub(super) info: PageInfo,
    pub(super) child: usize,
}

/// Immutable capability for one exact published/private root. Constructed only
/// by validated descent; retaining it does not itself pin its physical files.
/// The enclosing owner keeps the root live until rewrite or cancellation.
pub(crate) struct DirectoryLeaf {
    pub(super) root: DirectoryRoot,
    pub(super) reference: DirectoryPageRef,
    pub(super) info: PageInfo,
    pub(super) path: [Option<LeafFrame>; MAX_HEIGHT],
    pub(super) depth: usize,
    pub(super) buffer: PageBuffer,
    first_index: usize,
    admission: Arc<dyn StorageAdmission>,
    _lease: Box<dyn ResidentLease>,
}

impl DirectoryLeaf {
    pub(crate) fn len(&self) -> usize {
        self.info.count
    }

    pub(crate) fn reference(&self) -> DirectoryPageRef {
        self.reference
    }

    pub(crate) fn first_index(&self) -> usize {
        self.first_index
    }

    /// All records in leaf order, including entries before `first_index`.
    /// The immutable page was fully validated before this plan was returned.
    pub(crate) fn records(
        &self,
    ) -> impl ExactSizeIterator<Item = (DirectoryKey<'_>, DirectoryValue)> {
        let mut at = HEADER_BYTES;
        (0..self.info.count).map(move |_| {
            let (entry, end) = page_entry(&self.buffer.bytes, at, self.info.used)
                .expect("leaf plan retains a validated immutable page");
            at = end;
            let value = DirectoryValue::decode(entry.key, entry.value, self.info.generation)
                .expect("leaf plan retains validated immutable values");
            (entry.key, value)
        })
    }

    /// Admit an owned cursor record before starting any maintenance effect.
    pub(crate) fn owned_record(&self, index: usize) -> Result<DirectoryRecord, CoreError> {
        self.admission
            .check_owner()
            .map_err(|_| CoreError::OwnerFailed)?;
        if index >= self.len() {
            return Err(CoreError::InvalidInput(
                "directory leaf record index is invalid",
            ));
        }
        let entry = nth_entry(&self.buffer.bytes, self.info, index)?;
        let lease = reserve(
            &self.admission,
            entry.key_bytes.len() + std::mem::size_of::<DirectoryRecord>() + ALLOCATION_ALLOWANCE,
        )?;
        let mut key = Vec::new();
        key.try_reserve_exact(entry.key_bytes.len())
            .map_err(|_| CoreError::CapacityDenied)?;
        if key.capacity() != entry.key_bytes.len() {
            return Err(CoreError::CapacityDenied);
        }
        key.extend_from_slice(entry.key_bytes);
        let value = DirectoryValue::decode(entry.key, entry.value, self.info.generation)?;
        self.admission
            .check_owner()
            .map_err(|_| CoreError::OwnerFailed)?;
        Ok(DirectoryRecord {
            key,
            value,
            _lease: lease,
        })
    }

    /// Revalidate the root-to-leaf relationship before any append. One scratch
    /// buffer suffices; every parent contributes checked bounds to its child.
    pub(super) fn validate_path(
        &self,
        reader: &DirectoryReader<'_>,
        input: &mut [u8],
    ) -> Result<(), CoreError> {
        let mut reference = self
            .root
            .page
            .ok_or(CoreError::Corrupt("leaf plan has an empty root"))?;
        let mut bounds = Bounds::root(self.root);
        for frame in &self.path[..self.depth] {
            let frame = frame.ok_or(CoreError::Corrupt("leaf plan path is incomplete"))?;
            if frame.reference != reference {
                return Err(CoreError::Corrupt("leaf plan path reference differs"));
            }
            let info = reader.load(input, self.root, reference, &bounds)?;
            if info != frame.info || info.level == 0 {
                return Err(CoreError::Corrupt("leaf plan parent differs"));
            }
            reference = bounds.child(input, info, frame.child)?;
        }
        if reference != self.reference {
            return Err(CoreError::Corrupt("leaf plan selected reference differs"));
        }
        let info = reader.load(input, self.root, reference, &bounds)?;
        if info != self.info || info.level != 0 || &*input != self.buffer.bytes.as_slice() {
            return Err(CoreError::Corrupt("leaf plan page differs"));
        }
        Ok(())
    }
}

impl DirectoryReader<'_> {
    /// Select the leaf holding the first key >= `lower` (or > when exclusive).
    /// A bounded successor lookup locates a nonempty eligible leaf, then one
    /// descent retains its path and page. No preceding keys are collected.
    pub(crate) fn leaf_after(
        &self,
        root: DirectoryRoot,
        lower: DirectoryKey<'_>,
        exclusive: bool,
    ) -> Result<Option<DirectoryLeaf>, CoreError> {
        let Some(first) = self.next(root, lower, exclusive)? else {
            return Ok(None);
        };
        let lease = reserve(&self.admission, std::mem::size_of::<DirectoryLeaf>())?;
        let _scratch = reserve(&self.admission, std::mem::size_of::<Bounds>())?;
        let mut buffer = PageBuffer::new(&self.admission)?;
        let mut reference = root.page.expect("next found a nonempty root");
        let mut bounds = Bounds::root(root);
        let mut path = [None; MAX_HEIGHT];
        let mut depth = 0;
        loop {
            let info = self.load(&mut buffer, root, reference, &bounds)?;
            let mut at = HEADER_BYTES;
            let mut selected = 0;
            for index in 0..info.count {
                let (entry, end) = page_entry(&buffer.bytes, at, info.used)?;
                if info.level == 0 && entry.key == first.key() {
                    if info.count > MAX_DIRECTORY_LEAF_RECORDS {
                        return Err(CoreError::Corrupt("directory leaf exceeds record ceiling"));
                    }
                    self.admission
                        .check_owner()
                        .map_err(|_| CoreError::OwnerFailed)?;
                    return Ok(Some(DirectoryLeaf {
                        root,
                        reference,
                        info,
                        path,
                        depth,
                        buffer,
                        first_index: index,
                        admission: self.admission.clone(),
                        _lease: lease,
                    }));
                }
                if entry.key > first.key() {
                    break;
                }
                selected = index;
                at = end;
            }
            if info.level == 0 {
                return Err(CoreError::Corrupt("leaf plan successor disappeared"));
            }
            path[depth] = Some(LeafFrame {
                reference,
                info,
                child: selected,
            });
            depth += 1;
            reference = bounds.child(&buffer.bytes, info, selected)?;
        }
    }
}
