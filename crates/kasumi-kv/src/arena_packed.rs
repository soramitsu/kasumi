//! Packed arena references address contiguous bytes. Their ordering is the
//! physical append ordering used by append floors. Length 16 KiB denotes an
//! uncompressed page, all shorter payloads are ordinary LZ4 blocks.
use super::*;
use lz4_flex::block::{
    CompressTable, compress_into_with_table, decompress_into, get_maximum_output_size,
};

const LENGTH_BITS: u32 = DIRECTORY_PAGE_BYTES.trailing_zeros();
const _: () =
    assert!(DIRECTORY_PAGE_BYTES.is_power_of_two() && DIRECTORY_PAGE_BYTES < u16::MAX as usize);
const OUTPUT_BYTES: usize = get_maximum_output_size(DIRECTORY_PAGE_BYTES);
const DICTIONARY_BYTES: usize = 4096 * size_of::<u16>(); // lz4_flex 0.13.1 CompressTable::small
pub(super) const SCRATCH_BYTES: usize = OUTPUT_BYTES
    + DICTIONARY_BYTES
    + DIRECTORY_PAGE_BYTES
    + size_of::<Encoder>()
    + 4 * ALLOCATION_ALLOWANCE
    + align_of::<Encoder>();
pub(super) const MAGIC: [u8; 16] = *b"KASUMI-KVARENA02";

/// All memory used by encoding and decoding is funded at open, before a
/// transaction can enter an effect. CompressTable::small never upgrades for a 16 KiB page.
pub(super) struct Encoder {
    table: CompressTable,
    output: Vec<u8>,
}
pub(super) fn scratch(size: usize) -> Result<Vec<u8>, CoreError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| CoreError::new(crate::CoreErrorCause::CapacityDenied))?;
    if bytes.capacity() != size {
        return Err(CoreError::new(crate::CoreErrorCause::CapacityDenied));
    }
    bytes.resize(size, 0);
    Ok(bytes)
}
impl Encoder {
    pub(super) fn new() -> Result<Box<Self>, CoreError> {
        Ok(Box::new(Self {
            output: scratch(OUTPUT_BYTES)?,
            table: CompressTable::small(),
        }))
    }

    pub(super) fn encode<'a>(&'a mut self, page: &'a [u8]) -> Result<&'a [u8], CoreError> {
        let n =
            compress_into_with_table(page, &mut self.output, &mut self.table).map_err(|_| {
                CoreError::new(crate::CoreErrorCause::InvalidInput(
                    "directory codec workspace is too small",
                ))
            })?;
        Ok(if n < DIRECTORY_PAGE_BYTES {
            &self.output[..n]
        } else {
            page
        })
    }
}
pub(super) fn reference(offset: u64, length: usize) -> u64 {
    (offset << LENGTH_BITS) | (length as u64 - 1)
}
pub(super) fn floor(offset: u64) -> u64 {
    offset << LENGTH_BITS
}
pub(super) fn extent(reference: u64) -> Result<(u64, usize), CoreError> {
    let relative = reference >> LENGTH_BITS;
    let length = ((reference & (DIRECTORY_PAGE_BYTES as u64 - 1)) + 1) as usize;
    if relative > ARENA_BYTES - HEADER_BYTES as u64 - length as u64 {
        return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
            "packed directory page is outside its arena",
        )));
    }
    Ok((HEADER_BYTES as u64 + relative, length))
}
pub(super) fn decode(payload: &[u8], page: &mut [u8]) -> Result<(), CoreError> {
    if decompress_into(payload, page).ok() != Some(DIRECTORY_PAGE_BYTES) {
        return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
            "invalid packed directory page",
        )));
    }
    Ok(())
}
