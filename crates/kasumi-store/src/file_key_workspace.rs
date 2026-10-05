//! Two-phase pre-admission bounds for the concrete FileKeyProvider::open factory.
//! The read bound uses the fixed cap; decode uses the actual retained bytes;
//! it neither reads a file nor treats a caller's existing allocation as admitted.
use super::MAX_KEYRING_BYTES;
use std::{io, mem::size_of};

fn overflow() -> io::Error {
    io::ErrorKind::InvalidInput.into()
}
fn add(a: u64, b: u64) -> io::Result<u64> {
    a.checked_add(b).ok_or_else(overflow)
}
fn mul(a: u64, b: u64) -> io::Result<u64> {
    a.checked_mul(b).ok_or_else(overflow)
}
fn backing(bytes: usize) -> io::Result<u64> {
    if bytes == 0 {
        return Ok(0);
    }
    if bytes > isize::MAX as usize {
        return Err(overflow());
    }
    bytes
        .checked_next_power_of_two()
        .and_then(|n| n.checked_add(64))
        .and_then(|n| u64::try_from(n).ok())
        .ok_or_else(overflow)
}
pub(super) fn retained(path_capacity: usize, reference_capacity: usize) -> io::Result<u64> {
    add(backing(path_capacity)?, backing(reference_capacity)?)
}
pub(super) fn read(path_bytes: usize) -> io::Result<u64> {
    // private_files::read uses take(cap + 1).read_to_end, so retain old/new
    // doubled capacities even for the one-byte-over-cap refusal. Reading and
    // parsing are separate phases; this conservative sum covers both.
    let input = mul(backing(2 * (MAX_KEYRING_BYTES + 1))?, 2)?;
    let paths = mul(backing(path_bytes.checked_add(1).ok_or_else(overflow)?)?, 3)?;
    add(add(input, paths)?, 4096)
}
pub(super) fn decode(
    input_len: usize,
    input_capacity: usize,
    path_bytes: usize,
) -> io::Result<u64> {
    if input_len > MAX_KEYRING_BYTES || input_capacity < input_len {
        return Err(overflow());
    }
    // The original input remains live through decoder/validator/Keyring Drop.
    let input = backing(input_capacity)?;
    // An entry in the u64->String map needs at least six encoded bytes (even
    // ignoring commas); the B=6 tree has at most 1+(n-1)/5 nonempty nodes.
    // Three additional full nodes cover split/root transition overlap. Count
    // the full internal allocation, its 11 key/value slots and header/edges.
    let entries = input_len / 6 + 1;
    let nodes = 4 + (entries - 1) / 5;
    let node_bytes = 11 * (size_of::<u64>() + size_of::<String>()) + 16 * size_of::<usize>();
    let tree = mul(
        u64::try_from(nodes).map_err(|_| overflow())?,
        backing(node_bytes)?,
    )?;
    // Across all nonempty owned strings, decoded content cannot exceed wire
    // bytes. Round each length by <2x and include per-allocation slack; even a
    // one-byte string requires three wire bytes. Temporary parser scratch is
    // separate and covers growing old/new storage and final string overlap.
    let strings = add(2 * input_len as u64, mul((input_len / 3 + 3) as u64, 64)?)?;
    let parser = mul(backing(2 * input_len)?, 3)?;
    // Validation decodes one Base64 key at a time, including invalid oversized
    // candidates. Canonical comparison streams back into the original input.
    let validate = backing(input_len + 3)?;
    // Serde can escape one complete input string in an error. Include old/new
    // formatting growth and boxed-string shrink, plus bounded error headers.
    // Optional anyhow/std Backtrace captures remain separately owned diagnostics.
    let message = 8 * input_len + 1024;
    let diagnostics = add(
        add(mul(backing(2 * message)?, 2)?, backing(message)?)?,
        4096,
    )?;
    // C-string path conversion and retained PathBuf never exceed input length;
    // allow concurrent syscall/output paths. key_ref has a validated <=256-byte
    // domain, UUID and fixed prefix, with old/new String formatting overlap.
    let paths = mul(backing(path_bytes.checked_add(1).ok_or_else(overflow)?)?, 3)?;
    let reference = mul(backing(2 * (256 + 36 + 16))?, 3)?;
    add(
        add(add(input, tree)?, add(strings, parser)?)?,
        add(add(validate, diagnostics)?, add(paths, reference)?)?,
    )
}

#[cfg(test)]
#[path = "file_key_workspace_tests.rs"]
mod tests;
