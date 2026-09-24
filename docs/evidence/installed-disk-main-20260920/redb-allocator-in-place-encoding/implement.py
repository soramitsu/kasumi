from pathlib import Path
import re
ROOT=Path('/Users/mtakemiya/dev/kasumi/target/installed-disk-validation/redb-allocator-in-place-encoding')
SUB=Path('vendor/redb-4.2.0/src/tree_store/page_store')

def replacements(filename, makers):
    path=ROOT/'proposed'/SUB/filename
    source=(ROOT/'base'/SUB/filename).read_text()
    matches=list(re.finditer(r'    pub(?:\([^)]*\))? fn to_vec\(&self\) -> Vec<u8> \{',source))
    assert len(matches)==len(makers),(filename,len(matches))
    for match,maker in reversed(list(zip(matches,makers))):
        begin=source.index('{',match.start());end=begin+1;depth=1
        while depth:
            depth+=int(source[end]=='{')-int(source[end]=='}');end+=1
        original=source[match.start():end]
        reference=original.replace('fn to_vec(', 'fn reference_to_vec(',1).replace('.to_vec()', '.reference_to_vec()').replace('BtreeBitmap::to_vec','BtreeBitmap::reference_to_vec')
        new=maker+'\n\n    #[cfg(test)]\n'+reference
        source=source[:match.start()]+new+source[end:]
    path.write_text(source)

def allocating_wrapper(visibility,kind,test_only=False):
    return ('    #[cfg(test)]\n' if test_only else '')+f'''    {visibility} fn to_vec(&self) -> Vec<u8> {{
        // The existing infallible internal API rejects invalid geometry before
        // allocating output. The checked caller-buffer API returns a scalar error.
        let Some(encoded_len) = self.checked_encoded_len() else {{
            panic!("Invalid {kind} encoding geometry");
        }};
        let mut result = vec![0; encoded_len];
        if let Err(error) = self.encode_into(&mut result) {{
            panic!("Validated {kind} encoding failed: {{error:?}}");
        }}
        result
    }}'''

bitmap_encode='''    /// Encode into an exact-sized caller buffer without allocation. Every
    /// geometry and length check completes before the first output byte changes.
    #[cfg(test)]
    pub(crate) fn encode_into(&self, output: &mut [u8]) -> Result<(), AllocatorEncodingError> {
        check_encoding_buffer(self.checked_encoded_len(), output.len())?;
        self.write_encoded_validated(output);
        Ok(())
    }

    // Only called after a complete recursive length check while self remains
    // immutably borrowed. A child receives the remaining tail and reports the
    // prefix it wrote, avoiding child images or a retained length inventory.
    pub(super) fn write_encoded_validated(&self, output: &mut [u8]) -> usize {
        let header_len = END_OFFSETS + self.heights.len() * size_of::<u32>();
        let (header, mut remaining) = output.split_at_mut(header_len);
        header[..size_of::<u32>()]
            .copy_from_slice(&(self.heights.len() as u32).to_le_bytes());
        let mut end = header_len;
        for (offset, height) in header[END_OFFSETS..]
            .chunks_exact_mut(size_of::<u32>())
            .zip(&self.heights)
        {
            let written = height.write_encoded_validated(remaining);
            end += written;
            offset.copy_from_slice(&(end as u32).to_le_bytes());
            remaining = &mut remaining[written..];
        }
        end
    }

'''+allocating_wrapper('pub(crate)','bitmap',True)

grouped_encode='''    #[cfg(test)]
    fn encode_into(&self, output: &mut [u8]) -> Result<(), AllocatorEncodingError> {
        check_encoding_buffer(self.checked_encoded_len(), output.len())?;
        self.write_encoded_validated(output);
        Ok(())
    }

    fn write_encoded_validated(&self, output: &mut [u8]) -> usize {
        let words = Self::required_words(self.len);
        let end = size_of::<u32>() + words * size_of::<u64>();
        output[..size_of::<u32>()].copy_from_slice(&self.len.to_le_bytes());
        for (encoded, word) in output[size_of::<u32>()..end]
            .chunks_exact_mut(size_of::<u64>())
            .zip(&self.data[..words])
        {
            encoded.copy_from_slice(&word.to_le_bytes());
        }
        end
    }

'''+allocating_wrapper('pub','grouped bitmap',True)

replacements('bitmap.rs',[bitmap_encode,grouped_encode])
p=ROOT/'proposed'/SUB/'bitmap.rs';s=p.read_text();anchor='const HEIGHT_OFFSET: usize = 0;'
s=s.replace(anchor,'''#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AllocatorEncodingError {
    InvalidGeometry,
    WrongBufferLength,
}

pub(super) fn check_encoding_buffer(
    encoded_len: Option<usize>,
    buffer_len: usize,
) -> Result<(), AllocatorEncodingError> {
    match encoded_len {
        Some(len) if len == buffer_len => Ok(()),
        Some(_) => Err(AllocatorEncodingError::WrongBufferLength),
        None => Err(AllocatorEncodingError::InvalidGeometry),
    }
}

'''+anchor,1);p.write_text(s)

buddy_encode='''    /// Encode exactly the current canonical allocator into caller-owned backing.
    /// Refusal leaves every byte unchanged and does not allocate.
    pub(crate) fn encode_into(&self, output: &mut [u8]) -> Result<(), AllocatorEncodingError> {
        check_encoding_buffer(self.checked_encoded_len(), output.len())?;
        let header_len = FREE_END_OFFSETS + self.free.len() * size_of::<u32>();
        let (header, mut remaining) = output.split_at_mut(header_len);
        header[MAX_ORDER_OFFSET] = self.max_order;
        header[(MAX_ORDER_OFFSET + size_of::<u8>())..NUM_PAGES_OFFSET].fill(0);
        header[NUM_PAGES_OFFSET..FREE_END_OFFSETS].copy_from_slice(&self.len.to_le_bytes());
        let mut end = header_len;
        for (offset, bitmap) in header[FREE_END_OFFSETS..]
            .chunks_exact_mut(size_of::<u32>())
            .zip(&self.free)
        {
            let written = bitmap.write_encoded_validated(remaining);
            end += written;
            offset.copy_from_slice(&(end as u32).to_le_bytes());
            remaining = &mut remaining[written..];
        }
        Ok(())
    }

'''+allocating_wrapper('pub(crate)','buddy allocator')
replacements('buddy_allocator.rs',[buddy_encode])
p=ROOT/'proposed'/SUB/'buddy_allocator.rs';s=p.read_text();s=s.replace('use crate::tree_store::page_store::bitmap::{BtreeBitmap, checked_offset_encoded_len};','use crate::tree_store::page_store::bitmap::{AllocatorEncodingError, BtreeBitmap, check_encoding_buffer, checked_offset_encoded_len};',1);p.write_text(s)

region_encode='''    /// Encode exactly the current canonical tracker into caller-owned backing.
    /// All nested geometry and output-length checks precede the first write.
    pub(super) fn encode_into(&self, output: &mut [u8]) -> Result<(), AllocatorEncodingError> {
        check_encoding_buffer(self.checked_encoded_len(), output.len())?;
        let header_len = size_of::<u32>() + self.order_trackers.len() * size_of::<u32>();
        let (header, mut remaining) = output.split_at_mut(header_len);
        header[..size_of::<u32>()]
            .copy_from_slice(&(self.order_trackers.len() as u32).to_le_bytes());
        for (length, bitmap) in header[size_of::<u32>()..]
            .chunks_exact_mut(size_of::<u32>())
            .zip(&self.order_trackers)
        {
            let written = bitmap.write_encoded_validated(remaining);
            length.copy_from_slice(&(written as u32).to_le_bytes());
            remaining = &mut remaining[written..];
        }
        Ok(())
    }

'''+allocating_wrapper('pub(super)','region tracker')
replacements('region.rs',[region_encode])
p=ROOT/'proposed'/SUB/'region.rs';s=p.read_text();s=s.replace('use crate::tree_store::page_store::bitmap::BtreeBitmap;','use crate::tree_store::page_store::bitmap::{AllocatorEncodingError, BtreeBitmap, check_encoding_buffer};',1);p.write_text(s)
print('Wrote target-only single-buffer encoders and test-only original references')
