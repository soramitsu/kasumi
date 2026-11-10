//! Length-framed pages returned by the Node binding.

use std::io;

pub(super) const MAX_RANGE_BYTES: usize = 64 << 20;

/// Append a complete binary row, including both big-endian byte lengths.
pub(super) fn append_row(page: &mut Vec<u8>, key: &[u8], value: &[u8]) -> io::Result<()> {
    let required = page
        .len()
        .saturating_add(8)
        .saturating_add(key.len())
        .saturating_add(value.len());
    if required > MAX_RANGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "range exceeds 64 MiB; reduce limit or narrow key bounds",
        ));
    }
    if required > page.capacity() {
        let next = required.max(page.capacity().saturating_mul(2).min(MAX_RANGE_BYTES));
        page.try_reserve_exact(next - page.len())
            .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
    }
    for field in [key, value] {
        page.extend_from_slice(&(field.len() as u32).to_be_bytes());
        page.extend_from_slice(field);
    }
    Ok(())
}
