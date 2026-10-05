//! Before-clone charges for typed query output. These describe owned Rust
//! allocations, with explicit container and allocation slack; they are not an
//! RSS bound or an accounting model for query planning/third-party scratch.
use kasumi_types::{
    ChangeEvent, ChangeRecord, Document, Error, ErrorCode, QueryResponse, QueryRow, Result,
};
use serde_json::Value;
use std::mem::size_of;
use std::ops::Range;

fn overflow() -> Error {
    Error::new(
        ErrorCode::ResourceExhausted,
        "query allocation size overflow",
    )
}

pub(crate) fn add(left: u64, right: u64) -> Result<u64> {
    left.checked_add(right).ok_or_else(overflow)
}

/// Round each nonempty allocation upward to a power of two and charge another
/// 64 bytes for allocation metadata/alignment. This is the admission policy's
/// conservative slack, not a portable promise about an arbitrary allocator.
fn allocation_bytes(requested: u64) -> Result<u64> {
    if requested == 0 {
        return Ok(0);
    }
    add(
        requested.checked_next_power_of_two().ok_or_else(overflow)?,
        64,
    )
}

/// Backing for a vector of exactly `len` elements, with allocation slack.
pub fn vec_bytes<T>(len: usize) -> Result<u64> {
    let requested = len.checked_mul(size_of::<T>()).ok_or_else(overflow)?;
    allocation_bytes(u64::try_from(requested).map_err(|_| overflow())?)
}

pub(crate) fn string_clone_bytes(value: &str) -> Result<u64> {
    // String::clone copies its length, not spare capacity in the source.
    allocation_bytes(u64::try_from(value.len()).map_err(|_| overflow())?)
}

pub(crate) fn object_entry_bytes() -> Result<u64> {
    // serde_json's pinned, non-preserve_order Map uses std BTreeMap. Rust's
    // B=6 node holds 11 keys/values and an internal node has 12 child pointers.
    // Four additional pointer widths cover the leaf header and alignment.
    // Charge a complete internal node for EVERY entry, including unused slots:
    // the number of nonempty nodes cannot exceed the number of entries.
    // Key string and child Value heaps are charged separately below.
    let slots = size_of::<String>()
        .checked_add(size_of::<Value>())
        .and_then(|size| size.checked_mul(11))
        .and_then(|size| size.checked_add(16 * size_of::<usize>()))
        .ok_or_else(overflow)?;
    allocation_bytes(u64::try_from(slots).map_err(|_| overflow())?)
}

/// Count only allocations cloned by the Value, excluding its inline root slot.
/// The walk borrows strings, number lexemes and container iterators, so admission
/// does not itself serialize a document or allocate a traversal stack.
pub(crate) fn json_clone_bytes(value: &Value) -> Result<u64> {
    match value {
        Value::Null | Value::Bool(_) => Ok(0),
        Value::String(text) => string_clone_bytes(text),
        // arbitrary_precision stores even integer JSON numbers as strings.
        Value::Number(number) => string_clone_bytes(number.as_str()),
        Value::Array(values) => {
            let mut bytes = vec_bytes::<Value>(values.len())?;
            for value in values {
                bytes = add(bytes, json_clone_bytes(value)?)?;
            }
            Ok(bytes)
        }
        Value::Object(values) => {
            // The pinned std BTreeMap clone short-circuits empty maps, even if
            // the source retained an empty root after deleting its last entry.
            let entries = u64::try_from(values.len()).map_err(|_| overflow())?;
            let mut bytes = object_entry_bytes()?
                .checked_mul(entries)
                .ok_or_else(overflow)?;
            for (key, value) in values {
                bytes = add(bytes, string_clone_bytes(key)?)?;
                bytes = add(bytes, json_clone_bytes(value)?)?;
            }
            Ok(bytes)
        }
    }
}

/// Count backing allocated by cloning a document's ID and JSON body. This
/// borrowed walk allocates nothing and excludes the inline Document, any Arc
/// backing and the enclosing output owner; those require separate admission.
/// Claim before cloning and retain that claim through the clone's destruction.
/// Source spare capacity is not copied: this is not a retained-source heap
/// quote and must not be used to account a shared source document.
pub fn document_clone_bytes(document: &Document) -> Result<u64> {
    document_parts_clone_bytes(&document.id, &document.body)
}

/// Preflight the allocations for cloning the selected rows, all aggregates,
/// and the existing cursor of a response. The source keeps its independent
/// charge while the clone is built and retained. Call before allocating and
/// keep the admitted charge with the resulting payload through destruction.
/// A newly generated cursor/token and enclosing owner's allocation require
/// their own admission; the inline QueryResponse is not counted here.
pub fn query_response_clone_bytes(response: &QueryResponse, rows: Range<usize>) -> Result<u64> {
    let rows = response.rows.get(rows).ok_or_else(|| {
        Error::new(
            ErrorCode::InvalidArgument,
            "query response row range outside bounds",
        )
    })?;
    let mut bytes = vec_bytes::<QueryRow>(rows.len())?;
    for row in rows {
        bytes = add(bytes, string_clone_bytes(&row.id)?)?;
        bytes = add(bytes, json_clone_bytes(&row.body)?)?;
    }
    bytes = add(bytes, vec_bytes::<Value>(response.aggregates.len())?)?;
    for aggregate in &response.aggregates {
        bytes = add(bytes, json_clone_bytes(aggregate)?)?;
    }
    if let Some(cursor) = &response.cursor {
        bytes = add(bytes, string_clone_bytes(cursor)?)?;
    }
    Ok(bytes)
}

/// Destination backing for a newly cloned document ID and body. The caller
/// separately admits the inline Document and its concrete owner. Never use this
/// quote to adopt arbitrary existing String/Vec capacities.
pub fn document_parts_clone_bytes(id: &str, body: &Value) -> Result<u64> {
    add(string_clone_bytes(id)?, json_clone_bytes(body)?)
}

/// Before-clone workspace for one feed page: its cursor strings/set, the
/// explicitly allocated event vector, and bounded borrowed imbl range cursors.
/// Per-event document/string heaps are admitted by `change_event_clone_bytes`.
/// The output may conservatively retain this peak after iterator destruction.
pub fn change_feed_page_workspace_bytes(
    tenant: &str,
    incarnation: &str,
    principal: &str,
    collections: &std::collections::BTreeSet<String>,
    event_capacity: usize,
) -> Result<u64> {
    let mut bytes = vec_bytes::<ChangeEvent>(event_capacity)?;
    for value in [tenant, incarnation, principal] {
        bytes = add(bytes, string_clone_bytes(value)?)?;
    }
    for collection in collections {
        // A complete JSON-map node is larger than a String BTreeSet node.
        // Charge one per entry, retaining the shared allocation slack model.
        bytes = add(bytes, object_entry_bytes()?)?;
        bytes = add(bytes, string_clone_bytes(collection)?)?;
    }
    add(bytes, crate::workspace::imbl_iterator_bytes()?)
}

/// Heap backing copied from one internal shared record into an owned public
/// after-image. The inline event and Document slots belong to the page vector.
/// This borrowed walk must run before any field or JSON body is cloned.
pub fn change_event_clone_bytes(record: &ChangeRecord) -> Result<u64> {
    let mut bytes = add(
        string_clone_bytes(&record.collection)?,
        string_clone_bytes(&record.id)?,
    )?;
    if let Some(document) = &record.document {
        bytes = add(bytes, document_clone_bytes(document)?)?;
    }
    Ok(bytes)
}

/// Resolve a validated Kasumi JSON Pointer without allocating decoded tokens.
/// Validation remains responsible for reporting malformed/oversized pointers;
/// this helper fails closed for them. Escapes only shorten a token, so the
/// maximum 1024-byte input also bounds the stack buffer for any decoded token.
pub(crate) fn pointer<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    if path.len() > 1024 {
        return None;
    }
    if path.is_empty() {
        return Some(value);
    }
    let mut target = value;
    let mut decoded = [0u8; 1024];
    for token in path.strip_prefix('/')?.split('/') {
        let token = if token.as_bytes().contains(&b'~') {
            let mut input = token.bytes();
            let mut written = 0;
            while let Some(byte) = input.next() {
                decoded[written] = if byte == b'~' {
                    match input.next()? {
                        b'0' => b'~',
                        b'1' => b'/',
                        _ => return None,
                    }
                } else {
                    byte
                };
                written += 1;
            }
            std::str::from_utf8(&decoded[..written]).ok()?
        } else {
            token
        };
        target = match target {
            Value::Object(values) => values.get(token)?,
            Value::Array(values) => {
                if token.starts_with('+') || (token.starts_with('0') && token.len() != 1) {
                    return None;
                }
                values.get(token.parse::<usize>().ok()?)?
            }
            _ => return None,
        };
    }
    Some(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn pointer_preserves_escaped_unicode_empty_and_array_semantics() {
        let value = json!({
            "": {"": "empty"},
            "日本語/~": {"~1": [0, {"/": "東京"}]},
            "array": [false, null, "last"],
            "0": "object key",
        });
        for path in [
            "",
            "/",
            "//",
            "/日本語~1~0/~01/1/~1",
            "/0",
            "/array/0",
            "/array/2",
            "/array/3",
            "/array/00",
            "/array/+0",
            "/array/-0",
            "/array/-",
            "/array/",
            "/array/184467440737095516160",
            "/missing",
        ] {
            assert_eq!(pointer(&value, path), value.pointer(path), "{path}");
        }
        for path in ["a", "/~", "/~2"] {
            assert!(pointer(&value, path).is_none());
        }
        let key = "a".repeat(1023);
        let value = json!({key.clone(): true});
        assert_eq!(
            pointer(&value, &format!("/{key}")),
            Some(&Value::Bool(true))
        );
        assert!(pointer(&value, &format!("/{key}a")).is_none());
    }

    #[test]
    fn allocation_overflow_and_invalid_page_ranges_fail_closed() {
        assert_eq!(
            vec_bytes::<Value>(usize::MAX).unwrap_err().code,
            ErrorCode::ResourceExhausted
        );
        let response = QueryResponse {
            revision: 0,
            rows: vec![],
            aggregates: vec![],
            cursor: None,
        };
        assert_eq!(
            query_response_clone_bytes(&response, 0..1)
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
        assert_eq!(query_response_clone_bytes(&response, 0..0).unwrap(), 0);
    }
}
