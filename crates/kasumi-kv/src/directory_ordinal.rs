//! Bounded rank/select over an authenticated immutable directory root.
use super::*;

impl DirectoryReader<'_> {
    /// Select an exact zero-based worklist position using authenticated child
    /// counts. One page and fixed bounds suffice; no key list is retained.
    pub(crate) fn at_ordinal(
        &self,
        root: DirectoryRoot,
        mut ordinal: u64,
    ) -> Result<Option<DirectoryRecord>, CoreError> {
        self.admission
            .check_owner()
            .map_err(|_| CoreError::new(crate::CoreErrorCause::OwnerFailed))?;
        root.validate()?;
        if ordinal >= root.entries {
            return Ok(None);
        }
        let _scratch = reserve(&self.admission, std::mem::size_of::<Bounds>())?;
        let mut buffer = PageBuffer::new(&self.admission)?;
        let mut bounds = Bounds::root(root);
        let mut reference = root.page.expect("nonempty validated root");
        loop {
            let info = self.load(&mut buffer, root, reference, &bounds)?;
            if info.level == 0 {
                let entry = nth_entry(&buffer.bytes, info, ordinal as usize)?;
                let lease = reserve(
                    &self.admission,
                    entry.key_bytes.len()
                        + std::mem::size_of::<DirectoryRecord>()
                        + ALLOCATION_ALLOWANCE,
                )?;
                let mut key = Vec::new();
                key.try_reserve_exact(entry.key_bytes.len())
                    .map_err(|_| CoreError::new(crate::CoreErrorCause::CapacityDenied))?;
                if key.capacity() != entry.key_bytes.len() {
                    return Err(CoreError::new(crate::CoreErrorCause::CapacityDenied));
                }
                key.extend_from_slice(entry.key_bytes);
                let value = DirectoryValue::decode(entry.key, entry.value, info.generation)?;
                self.admission
                    .check_owner()
                    .map_err(|_| CoreError::new(crate::CoreErrorCause::OwnerFailed))?;
                return Ok(Some(DirectoryRecord {
                    key,
                    value,
                    _lease: lease,
                }));
            }
            let mut selected = None;
            let mut at = HEADER_BYTES;
            for index in 0..info.count {
                let (entry, end) = page_entry(&buffer.bytes, at, info.used)?;
                at = end;
                let count = le_u64(&entry.value[PAGE_REF_BYTES..]);
                if ordinal < count {
                    selected = Some(index);
                    break;
                }
                ordinal -= count;
            }
            let index = selected.ok_or(CoreError::new(crate::CoreErrorCause::Corrupt(
                "directory ordinal exceeds authenticated child counts",
            )))?;
            reference = bounds.child(&buffer.bytes, info, index)?;
        }
    }

    /// Number of immutable-root keys <= `key`, the exact next worklist
    /// position after a current leaf batch has processed through that key.
    pub(crate) fn ordinal_after(
        &self,
        root: DirectoryRoot,
        key: DirectoryKey<'_>,
    ) -> Result<u64, CoreError> {
        self.admission
            .check_owner()
            .map_err(|_| CoreError::new(crate::CoreErrorCause::OwnerFailed))?;
        root.validate()?;
        key.validate()?;
        let Some(mut reference) = root.page else {
            return Ok(0);
        };
        let _scratch = reserve(&self.admission, std::mem::size_of::<Bounds>())?;
        let mut buffer = PageBuffer::new(&self.admission)?;
        let mut bounds = Bounds::root(root);
        let mut ordinal = 0u64;
        loop {
            let info = self.load(&mut buffer, root, reference, &bounds)?;
            let mut selected = None;
            let mut at = HEADER_BYTES;
            for index in 0..info.count {
                let (entry, end) = page_entry(&buffer.bytes, at, info.used)?;
                at = end;
                if entry.key > key {
                    break;
                }
                if info.level == 0 {
                    ordinal = ordinal.checked_add(1).ok_or(CoreError::new(
                        crate::CoreErrorCause::Corrupt("directory ordinal overflows"),
                    ))?;
                } else {
                    if let Some((_, count)) = selected {
                        ordinal = ordinal.checked_add(count).ok_or(CoreError::new(
                            crate::CoreErrorCause::Corrupt("directory ordinal overflows"),
                        ))?;
                    }
                    selected = Some((index, le_u64(&entry.value[PAGE_REF_BYTES..])));
                }
            }
            if info.level == 0 || selected.is_none() {
                return Ok(ordinal);
            }
            reference = bounds.child(&buffer.bytes, info, selected.expect("selected child").0)?;
        }
    }
}
