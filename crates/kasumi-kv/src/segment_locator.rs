//! Recover a cached value's logical key from its trusted key-length locator.
//!
//! This helper owns no allocation. Its caller admits the fixed scratch buffer,
//! keeps the immutable cached payload charged, and supplies an owner-checked
//! backend. The result borrows scratch and is valid only for that inspection.

use super::*;

pub(crate) const CACHED_VALUE_LOCATOR_BYTES: usize =
    RECORD_HEADER_BYTES + RELOCATE_PREFIX_BYTES + MAX_TABLE_BYTES + MAX_KEY_BYTES;

#[derive(Debug)]
pub(crate) struct CachedValueIdentity<'a> {
    pub(crate) table: &'a str,
    pub(crate) key: &'a [u8],
    pub(crate) logical_batch_seq: u64,
}

/// Validate both fixed possible envelopes without scanning for record magic.
///
/// Trusted table/key lengths were retained when the cache identity was created.
/// They locate the exact suffix immediately before either Put or Relocate's
/// payload. At most one bounded envelope read and one file-length query occur;
/// no payload bytes are read from disk. Checksums consume the admitted cached
/// payload, so CPU work is proportional to its length, up to MAX_VALUE_BYTES.
/// Invalid locator lengths are caller input errors. A mismatching stored image,
/// payload, extent, or ambiguous envelope is corruption and never authorizes
/// cache retirement. This proves the logical identity, not snapshot membership
/// or authority to unlink a file.
pub(crate) fn inspect_cached_value_identity<'a>(
    backend: &dyn SegmentGroupBackend,
    group_id: &[u8; 16],
    location: ValueLocation,
    table_len: u16,
    key_len: u16,
    cached_payload: &[u8],
    workspace: &'a mut [u8; CACHED_VALUE_LOCATOR_BYTES],
) -> Result<CachedValueIdentity<'a>, CoreError> {
    let table_len = usize::from(table_len);
    let key_len = usize::from(key_len);
    if table_len == 0 || table_len > MAX_TABLE_BYTES || key_len > MAX_KEY_BYTES {
        return Err(CoreError::InvalidInput(
            "cached value locator lengths are invalid",
        ));
    }
    location.validate()?;
    if cached_payload.len() != location.len as usize || crc32c(cached_payload) != location.crc {
        return Err(CoreError::Corrupt("cached value payload identity differs"));
    }
    let suffix_len = table_len + key_len;
    let put_bytes = RECORD_HEADER_BYTES + PUT_PREFIX_BYTES + suffix_len;
    let earliest_put = location
        .offset
        .checked_sub(put_bytes as u64)
        .filter(|&at| at >= SEGMENT_HEADER_BYTES)
        .ok_or(CoreError::Corrupt(
            "cached value envelope precedes its segment",
        ))?;
    let relocation_bytes = RECORD_HEADER_BYTES + RELOCATE_PREFIX_BYTES + suffix_len;
    let earliest_relocation = location
        .offset
        .checked_sub(relocation_bytes as u64)
        .filter(|&at| at >= SEGMENT_HEADER_BYTES);
    let start = earliest_relocation.unwrap_or(earliest_put);
    let visible = (location.offset - start) as usize;
    let file = GroupFile::segment(location.segment_id);
    let file_len = backend.len(file)?;
    if file_len > SEGMENT_BYTES || location.end() > file_len {
        return Err(CoreError::Corrupt("cached value exceeds its segment"));
    }
    backend.read(file, start, &mut workspace[..visible])?;
    let bytes = &workspace[..visible];
    let mut sequence = None;
    for (kind, at) in [
        (RecordKind::Put, Some(earliest_put)),
        (RecordKind::Relocate, earliest_relocation),
    ] {
        let Some(at) = at else { continue };
        let candidate = &bytes[(at - start) as usize..];
        let inspected = match inspect_envelope(
            candidate,
            group_id,
            LogPosition {
                segment_id: location.segment_id,
                offset: at,
            },
            kind,
            location,
            (table_len, key_len),
            cached_payload,
        ) {
            Ok(sequence) => sequence,
            // The other fixed position can start in arbitrary predecessor
            // bytes. Even a checksum-valid malformed header there is not
            // evidence against a fully verified envelope at the real position.
            Err(CoreError::Corrupt(_)) => None,
            Err(error) => return Err(error),
        };
        if let Some(logical_batch_seq) = inspected
            && sequence.replace(logical_batch_seq).is_some()
        {
            return Err(CoreError::Corrupt("cached value envelope is ambiguous"));
        }
    }
    let logical_batch_seq =
        sequence.ok_or(CoreError::Corrupt("cached value envelope identity differs"))?;
    let suffix = &bytes[visible - suffix_len..];
    let table = std::str::from_utf8(&suffix[..table_len])
        .map_err(|_| CoreError::Corrupt("cached value table is not UTF-8"))?;
    Ok(CachedValueIdentity {
        table,
        key: &suffix[table_len..],
        logical_batch_seq,
    })
}

fn inspect_envelope(
    candidate: &[u8],
    group_id: &[u8; 16],
    at: LogPosition,
    kind: RecordKind,
    location: ValueLocation,
    lengths: (usize, usize),
    cached_payload: &[u8],
) -> Result<Option<u64>, CoreError> {
    let header = candidate[..RECORD_HEADER_BYTES]
        .try_into()
        .expect("fixed envelope header");
    let Some(head) = decode_record_header(header, group_id, at)? else {
        return Ok(None);
    };
    if head.kind != kind {
        return Ok(None);
    }
    let prefix_len = if kind == RecordKind::Put {
        PUT_PREFIX_BYTES
    } else {
        RELOCATE_PREFIX_BYTES
    };
    let inline = &candidate[RECORD_HEADER_BYTES..];
    let (table_len, key_len) = lengths;
    if inline.len() != prefix_len + table_len + key_len
        || usize::from(le_u16(&inline[..2])) != table_len
        || usize::from(le_u16(&inline[2..4])) != key_len
        || le_u32(&inline[4..8]) != location.len
        || le_u32(&inline[8..12]) != location.crc
        || inline[12..16].iter().any(|&byte| byte != 0)
        || head.body_len as usize != inline.len() + cached_payload.len()
    {
        return Err(CoreError::Corrupt("cached value envelope fields differ"));
    }
    let logical_batch_seq = if kind == RecordKind::Put {
        head.batch_seq
    } else {
        let sequence = le_u64(&inline[PUT_PREFIX_BYTES..RELOCATE_PREFIX_BYTES]);
        if sequence == 0 || sequence > head.base_seq {
            return Err(CoreError::Corrupt(
                "cached value logical version is invalid",
            ));
        }
        sequence
    };
    let mut checksum = Crc32c::new();
    checksum.update(inline);
    checksum.update(cached_payload);
    if checksum.finish() != head.body_crc {
        return Err(CoreError::Corrupt("cached value envelope checksum differs"));
    }
    Ok(Some(logical_batch_seq))
}

#[cfg(test)]
mod tests {
    use super::*;
    include!("segment_locator_tests.rs");
}
