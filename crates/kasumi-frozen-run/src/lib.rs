//! Immutable LZ4-compressed sorted runs and Unix-native mutable binary-key storage.
//! Seal a strictly ascending stream and retain its returned digest in a trusted
//! manifest. Opening authenticates the sparse directory against that digest.
//! Each accessed block is authenticated and its key order and boundaries
//! verified before any data from that block reaches the caller.

#[cfg(unix)]
mod live;
#[cfg(unix)]
mod live_files;
#[cfg(unix)]
mod live_levels;
#[cfg(unix)]
mod live_merge;
#[cfg(unix)]
mod live_wal;
mod prefix;
mod read;
mod write;

#[cfg(unix)]
pub use live::{
    LIVE_CHECKPOINT_BYTES, LIVE_DEFAULT_BUFFER_BYTES, LIVE_GROUP_MAX_BATCHES, LIVE_GROUP_MAX_BYTES,
    LiveDb, LiveStats, ReadOnlyLiveDb,
};
#[cfg(unix)]
pub use live_wal::{MAX_WAL_BATCH_BYTES, MAX_WAL_BATCH_OPS, WalOp};
pub use read::FrozenRun;
pub use write::seal;

use std::io;

const DIRECTORY_MAGIC_V1: &[u8; 8] = b"KSFRDIR1";
const FOOTER_MAGIC_V1: &[u8; 8] = b"KSFRIDX1";
const DIRECTORY_MAGIC: &[u8; 8] = b"KSFRDIR2";
const FOOTER_MAGIC: &[u8; 8] = b"KSFRIDX2";
const PREFIX_FLAG: u32 = 1 << 31;
const BLOCK_TARGET: usize = 32 << 10;
/// Maximum byte length of an individual binary key.
pub const MAX_KEY: usize = 4096;
/// Maximum byte length of an individual binary value.
pub const MAX_VALUE: usize = 32 << 20;
const ROW_HEADER: usize = 6;
const MAX_RAW: usize = MAX_KEY + MAX_VALUE + ROW_HEADER;
const MAX_DIRECTORY: usize = 64 << 20;
const MAX_BLOCKS: usize = 1 << 18;
const DIRECTORY_ENTRY_HEADER: usize = 44;

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

// Every length is checked against the remaining bytes before slicing.
fn take<'a>(input: &mut &'a [u8], len: usize) -> io::Result<&'a [u8]> {
    let (found, rest) = input
        .split_at_checked(len)
        .ok_or_else(|| invalid("truncated sorted run"))?;
    *input = rest;
    Ok(found)
}
fn u16_from(input: &mut &[u8]) -> io::Result<usize> {
    Ok(u16::from_le_bytes(take(input, 2)?.try_into().unwrap()) as usize)
}
fn u32_from(input: &mut &[u8]) -> io::Result<usize> {
    Ok(u32::from_le_bytes(take(input, 4)?.try_into().unwrap()) as usize)
}

#[cfg(test)]
mod tests;
