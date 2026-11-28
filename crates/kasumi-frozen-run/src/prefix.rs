//! Block-local front coding. The cache always contains canonical complete rows.
use super::*;

/// One additional u16 per row is the largest possible encoding overhead.
pub(super) fn max_encoded_len(raw: usize) -> usize {
    raw + 2 * (raw / ROW_HEADER)
}

pub(super) fn encode(mut rows: &[u8]) -> io::Result<Vec<u8>> {
    let mut encoded = Vec::with_capacity(rows.len());
    let mut previous: &[u8] = &[];
    while !rows.is_empty() {
        let key_len = u16_from(&mut rows)?;
        let value_len = u32_from(&mut rows)?;
        let key = take(&mut rows, key_len)?;
        let value = take(&mut rows, value_len)?;
        let shared = key.iter().zip(previous).take_while(|(a, b)| a == b).count();
        let suffix = &key[shared..];
        encoded.extend_from_slice(&(shared as u16).to_le_bytes());
        encoded.extend_from_slice(&(suffix.len() as u16).to_le_bytes());
        encoded.extend_from_slice(&(value_len as u32).to_le_bytes());
        encoded.extend_from_slice(suffix);
        encoded.extend_from_slice(value);
        previous = key;
    }
    Ok(encoded)
}

/// Expand, verify and index a prefix-coded block in one pass.
pub(super) fn decode(
    mut input: &[u8],
    raw_len: usize,
    first: &[u8],
    last: &[u8],
    offsets: &mut Vec<u16>,
) -> io::Result<Vec<u8>> {
    debug_assert!(raw_len <= BLOCK_TARGET);
    let mut rows = Vec::with_capacity(raw_len);
    let mut previous_key = 0..0;
    while !input.is_empty() {
        let shared = u16_from(&mut input)?;
        let suffix_len = u16_from(&mut input)?;
        let value_len = u32_from(&mut input)?;
        let key_len = shared + suffix_len;
        if shared > previous_key.len() || key_len > MAX_KEY || value_len > MAX_VALUE {
            return Err(invalid("invalid sorted-run key prefix or row length"));
        }
        let suffix = take(&mut input, suffix_len)?;
        let value = take(&mut input, value_len)?;
        if ROW_HEADER + key_len + value_len > raw_len - rows.len() {
            return Err(invalid(
                "sorted-run prefix expands past the authenticated length",
            ));
        }
        // Both keys share the copied prefix, even if the writer could have
        // copied more. Their remaining suffixes determine strict byte order.
        let ordered = if rows.is_empty() {
            suffix == first
        } else {
            suffix > &rows[previous_key.start + shared..previous_key.end]
        };
        if !ordered {
            return Err(invalid("sorted-run keys or first boundary differ"));
        }
        offsets.push(rows.len() as u16);
        rows.extend_from_slice(&(key_len as u16).to_le_bytes());
        rows.extend_from_slice(&(value_len as u32).to_le_bytes());
        let key_start = rows.len();
        rows.extend_from_within(previous_key.start..previous_key.start + shared);
        rows.extend_from_slice(suffix);
        rows.extend_from_slice(value);
        previous_key = key_start..key_start + key_len;
    }
    if rows.len() != raw_len {
        return Err(invalid("sorted-run prefix expanded length differs"));
    }
    if offsets.is_empty() || &rows[previous_key] != last {
        return Err(invalid("sorted-run last boundary differs"));
    }
    Ok(rows)
}
