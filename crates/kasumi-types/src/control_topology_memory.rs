//! Destination and synchronous scratch for the concrete borrowed-Value decoder.
//! This is a conservative pinned-allocator policy, not an RSS/source-heap quote.
//! Serde 1.0.229 inserts BTreeMap/BTreeSet entries directly (no collect/sort Vec).
//! Requalify with Rust, Serde, serde_json, URL dependencies or allocator changes.
use super::{ControlNode, ControlTopology, TenantRoute};
use crate::{Error, ErrorCode, Result};
use serde_json::Value;
use std::mem::size_of;

/// Heap allocated by decoding and validating one ControlTopology from &Value.
/// The inline DTO, enclosing owner, cancellation and admission metadata are not
/// included. Retain `retained_bytes` with the result; `peak_bytes` additionally
/// covers simultaneous partial-decode, error-formatting and validation scratch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TopologyMemory {
    pub retained_bytes: u64,
    pub peak_bytes: u64,
}
fn overflow() -> Error {
    Error::new(
        ErrorCode::ResourceExhausted,
        "topology workspace size overflow",
    )
}
fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).ok_or_else(overflow)
}
fn mul(a: u64, b: u64) -> Result<u64> {
    a.checked_mul(b).ok_or_else(overflow)
}
fn count(n: usize) -> Result<u64> {
    u64::try_from(n).map_err(|_| overflow())
}
fn backing(bytes: u64) -> Result<u64> {
    if bytes == 0 {
        return Ok(0);
    }
    if bytes > isize::MAX as u64 {
        return Err(overflow());
    }
    add(bytes.checked_next_power_of_two().ok_or_else(overflow)?, 64)
}
fn string(value: Option<&Value>) -> Result<u64> {
    value
        .and_then(Value::as_str)
        .map_or(Ok(0), |s| backing(count(s.len())?))
}
fn tree<K, V>(entries: usize) -> Result<u64> {
    // Rust B=6: 11 K/V slots,12 children,4 pointer widths for header/alignment.
    // One full internal node per INPUT entry covers sparse nodes and duplicates.
    let bytes = add(
        mul(count(size_of::<K>() + size_of::<V>())?, 11)?,
        count(16 * size_of::<usize>())?,
    )?;
    mul(count(entries)?, backing(bytes)?)
}
fn field<'a>(value: &'a Value, name: &str, ordinal: usize) -> Option<&'a Value> {
    // Derived struct Deserialize also accepts a positional JSON array. Quote it
    // without tightening the existing accepted/error shape.
    match value {
        Value::Object(fields) => fields.get(name),
        Value::Array(fields) => fields.get(ordinal),
        _ => None,
    }
}
fn longest_text(value: &Value) -> usize {
    match value {
        Value::String(s) => s.len(),
        Value::Number(n) => n.as_str().len(),
        Value::Array(values) => values.iter().map(longest_text).max().unwrap_or(0),
        Value::Object(values) => values
            .iter()
            .map(|(key, value)| key.len().max(longest_text(value)))
            .max()
            .unwrap_or(0),
        _ => 0,
    }
}
fn error_scratch(value: &Value) -> Result<u64> {
    // Concrete DTO diagnostics format at most one input string/key plus fixed
    // field/variant lists. Eight bytes per source byte covers Rust Debug escapes;
    // 512 bytes covers their fixed templates and scalar formatting. RawVec's
    // growing String can hold<2*requested; count old+new growth and boxed-str
    // shrink overlap. Eight pointer words cover serde_json's ErrorImpl box.
    let text = add(mul(count(longest_text(value))?, 8)?, 512)?;
    add(
        add(mul(backing(mul(text, 2)?)?, 2)?, backing(text)?)?,
        backing(count(size_of::<[usize; 8]>())?)?,
    )
}

impl ControlTopology {
    /// Count before the concrete `ControlTopology::deserialize(&value)` and
    /// `validate()` calls. This walk borrows source containers and allocates no
    /// traversal storage; source JSON already obeys the document nesting bound.
    /// It deliberately does not validate shapes or change decoder error order.
    pub fn memory_from_value(value: &Value) -> Result<TopologyMemory> {
        let mut retained = 0;
        let mut key_scratch = 0;
        let mut pins = 0usize;
        let mut url_peak = 0;
        if let Some(nodes) = field(value, "nodes", 0).and_then(Value::as_object) {
            retained = add(retained, tree::<u64, ControlNode>(nodes.len())?)?;
            for (key, node) in nodes {
                // Canonical unsigned-map decoder holds owned key and id.to_string
                // while next_value decodes; the longest canonical u64 has20digits.
                key_scratch = key_scratch.max(add(backing(count(key.len())?)?, backing(20)?)?);
                let endpoint = field(node, "endpoint", 0);
                retained = add(retained, string(endpoint)?)?;
                retained = add(retained, string(field(node, "failure_domain", 1))?)?;
                if let Some(endpoint) = endpoint.and_then(Value::as_str) {
                    url_peak = url_peak.max(Self::endpoint_workspace_bytes(endpoint)?);
                }
                if let Some(values) = field(node, "certificate_pins", 2).and_then(Value::as_array) {
                    pins = pins.checked_add(values.len()).ok_or_else(overflow)?;
                    retained = add(retained, tree::<String, ()>(values.len())?)?;
                    for value in values {
                        retained = add(retained, string(Some(value))?)?;
                    }
                }
            }
        }
        let mut max_voters = 0;
        if let Some(tenants) = field(value, "tenants", 1).and_then(Value::as_object) {
            retained = add(retained, tree::<String, TenantRoute>(tenants.len())?)?;
            for (name, route) in tenants {
                retained = add(retained, backing(count(name.len())?)?)?;
                retained = add(retained, string(field(route, "incarnation", 0))?)?;
                if let Some(voters) = field(route, "voters", 2).and_then(Value::as_array) {
                    retained = add(retained, tree::<u64, ()>(voters.len())?)?;
                    max_voters = max_voters.max(voters.len());
                }
            }
        }
        // Global pins coexist with every later URL and route-domain set. The
        // URL result remains live while its own node's pins are inserted.
        let validation = add(
            tree::<&String, ()>(pins)?,
            url_peak.max(add(tree::<&String, ()>(max_voters)?, backing(36)?)?),
        )?;
        // Validator messages are fixed literals and bounded by Error's canonical
        // message limit. Its failure String can coexist with URL/pin/domain heaps.
        let validation = add(validation, backing(Error::MAX_MESSAGE_BYTES as u64)?)?;
        let decode = add(key_scratch, error_scratch(value)?)?;
        Ok(TopologyMemory {
            retained_bytes: retained,
            peak_bytes: add(retained, decode.max(validation))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn checked_topology_math_refuses_unrepresentable_allocations() {
        assert!(add(u64::MAX, 1).is_err());
        assert!(mul(u64::MAX, 2).is_err());
        assert!(backing(u64::MAX).is_err());
        assert!(tree::<String, TenantRoute>(usize::MAX).is_err());
    }
}
