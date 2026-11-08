//! A descending scan retains one validated immutable leaf for its pinned root.
use super::*;

pub(crate) struct ReverseLeafCursor {
    buffer: PageBuffer,
    resident: Option<CachedBytes>,
    info: Option<PageInfo>,
    // Variable-length records carry no backwards link. These byte offsets are
    // built once when a leaf is reached and consumed from the end.
    offsets: Vec<u16>,
    done: bool,
    _lease: NativeResidentLease,
}

impl ReverseLeafCursor {
    pub(crate) fn new(admission: &Arc<dyn StorageAdmission>) -> Result<Self, CoreError> {
        let lease = reserve(
            admission,
            std::mem::size_of::<crate::core::DescendingCursor>()
                + MAX_DIRECTORY_LEAF_RECORDS * std::mem::size_of::<u16>()
                + std::mem::size_of::<Bounds>()
                + MAX_ENCODED_KEY
                + ALLOCATION_ALLOWANCE,
        )?;
        let mut offsets = Vec::new();
        offsets
            .try_reserve_exact(MAX_DIRECTORY_LEAF_RECORDS)
            .map_err(|_| CoreError::new(crate::CoreErrorCause::CapacityDenied))?;
        if offsets.capacity() != MAX_DIRECTORY_LEAF_RECORDS {
            return Err(CoreError::new(crate::CoreErrorCause::CapacityDenied));
        }
        Ok(Self {
            buffer: PageBuffer::new(admission)?,
            resident: None,
            info: None,
            offsets,
            done: false,
            _lease: lease,
        })
    }

    fn page(&self) -> &[u8] {
        self.resident
            .as_ref()
            .map_or(&self.buffer, |bytes| bytes.as_bytes())
    }

    fn load(
        &mut self,
        reader: &DirectoryReader<'_>,
        root: DirectoryRoot,
        upper: DirectoryKey<'_>,
        exclusive: bool,
    ) -> Result<(), CoreError> {
        self.resident = None;
        let leaf =
            reader.with_previous_leaf(root, upper, exclusive, &mut self.buffer, |page, info| {
                if info.count > MAX_DIRECTORY_LEAF_RECORDS {
                    return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
                        "leaf exceeds record ceiling",
                    )));
                }
                let mut at = HEADER_BYTES;
                for _ in 0..info.count {
                    let (entry, end) = page_entry(&page, at, info.used)?;
                    if entry.key > upper || (exclusive && entry.key == upper) {
                        break;
                    }
                    self.offsets.push(at as u16);
                    at = end;
                }
                let resident = match page {
                    PageBytes::Buffer(_) => None,
                    PageBytes::Lent(page) => Some(page),
                };
                Ok(Some((info, resident)))
            })?;
        if let Some((info, resident)) = leaf {
            self.info = Some(info);
            self.resident = resident;
        }
        self.done = self.offsets.is_empty();
        Ok(())
    }

    /// The enclosing owner validates the snapshot pin on each step, including
    /// when the next record already lives in the cursor's leaf buffer.
    pub(crate) fn next<'c>(
        &'c mut self,
        reader: &DirectoryReader<'_>,
        root: DirectoryRoot,
        upper: DirectoryKey<'_>,
        exclusive: bool,
    ) -> Result<Option<(DirectoryKey<'c>, DirectoryValue)>, CoreError> {
        if self.done {
            return Ok(None);
        }
        if self.offsets.is_empty() {
            if let Some(info) = self.info {
                // The previous nonempty leaf has been fully consumed. Seek
                // strictly below its minimum; identical separator keys now
                // route into the predecessor subtree at every branch level.
                let mut boundary = [0u8; MAX_ENCODED_KEY];
                let entry = page_entry(self.page(), HEADER_BYTES, info.used)?.0;
                let len = entry.key_bytes.len();
                boundary[..len].copy_from_slice(entry.key_bytes);
                self.load(reader, root, decode_key(&boundary[..len])?.0, true)?;
            } else {
                self.load(reader, root, upper, exclusive)?;
            }
        }
        let Some(at) = self.offsets.pop() else {
            return Ok(None);
        };
        let info = self
            .info
            .expect("selected offset belongs to a validated leaf");
        let entry = page_entry(self.page(), usize::from(at), info.used)?.0;
        let value = DirectoryValue::decode(entry.key, entry.value, info.generation)?;
        Ok(Some((entry.key, value)))
    }
}
