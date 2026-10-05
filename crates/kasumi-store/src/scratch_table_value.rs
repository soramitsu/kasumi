//! A scratch point result retains its original admitted native value.
use super::ScratchTableRef;
use std::{fmt, ops::Deref};

/// An immutable scratch value with the exact native buffer, read snapshot and
/// scratch database owner. The native guard retires before the database owner;
/// no independent plaintext copy or replacement admission is created.
pub struct ScratchTableValue {
    value: kasumi_kv::AccessGuard<&'static [u8]>,
    _owner: ScratchTableRef,
}

impl ScratchTableValue {
    pub(super) fn new(
        value: kasumi_kv::AccessGuard<&'static [u8]>,
        owner: ScratchTableRef,
    ) -> Self {
        Self {
            value,
            _owner: owner,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.value.value()
    }

    pub fn len(&self) -> usize {
        self.as_bytes().len()
    }

    pub fn is_empty(&self) -> bool {
        self.as_bytes().is_empty()
    }
}

impl Deref for ScratchTableValue {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl AsRef<[u8]> for ScratchTableValue {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Debug for ScratchTableValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScratchTableValue")
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

impl<T: AsRef<[u8]>> PartialEq<T> for ScratchTableValue {
    fn eq(&self, other: &T) -> bool {
        self.as_bytes() == other.as_ref()
    }
}
impl Eq for ScratchTableValue {}
