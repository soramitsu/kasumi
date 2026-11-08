//! Preserve each immutable row's original physical storage ownership.
use std::ops::Deref;

pub(crate) enum MaterializationRow {
    Stored(kasumi_store::PlaintextValue),
    Staged(kasumi_store::ScratchTableValue),
    /// A row an earlier member of the same unpublished standalone group
    /// prepared; its group's publication commits it.
    Pending(std::sync::Arc<[u8]>),
}
impl Deref for MaterializationRow {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Self::Stored(value) => value.as_bytes(),
            Self::Staged(value) => value,
            Self::Pending(value) => value,
        }
    }
}
impl<T: AsRef<[u8]>> PartialEq<T> for MaterializationRow {
    fn eq(&self, other: &T) -> bool {
        &**self == other.as_ref()
    }
}
