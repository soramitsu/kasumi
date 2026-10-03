//! Conservative workspace for the closed Document/ArchivedDocument/CollectionDefinition DTOs.
//! The visitor has no owned fields; serde_json's escape scratch is separately
//! quoted before preflight. This is not a generic JSON allocation guarantee.
use anyhow::{Context, Result};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use std::fmt;

const ALLOWANCE: u64 = 64;
const FIXED: u64 = 16 << 10;

#[derive(Default)]
struct Shape {
    nodes: u64,
    string_bytes: u64,
}
struct Seed<'a>(&'a mut Shape);
impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = ();
    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        self.0.nodes = self
            .0
            .nodes
            .checked_add(1)
            .ok_or_else(|| de::Error::custom("primary DTO shape overflow"))?;
        deserializer.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Seed<'_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a bounded canonical metadata record")
    }
    fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_none<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E: de::Error>(self, value: &str) -> Result<(), E> {
        self.0.string_bytes = self
            .0
            .string_bytes
            .checked_add(value.len() as u64)
            .ok_or_else(|| de::Error::custom("primary DTO string quote overflow"))?;
        Ok(())
    }
    fn visit_borrowed_str<E: de::Error>(self, value: &'de str) -> Result<(), E> {
        self.visit_str(value)
    }
    fn visit_bytes<E: de::Error>(self, value: &[u8]) -> Result<(), E> {
        // The pinned arbitrary_precision parser lends its synthetic number
        // marker as bytes. Counting shape is not interpreting marker objects.
        self.0.string_bytes = self
            .0
            .string_bytes
            .checked_add(value.len() as u64)
            .ok_or_else(|| de::Error::custom("primary DTO byte quote overflow"))?;
        Ok(())
    }
    fn visit_borrowed_bytes<E: de::Error>(self, value: &'de [u8]) -> Result<(), E> {
        self.visit_bytes(value)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut values: A) -> Result<(), A::Error> {
        while values.next_element_seed(Seed(&mut *self.0))?.is_some() {}
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut values: A) -> Result<(), A::Error> {
        while values.next_key_seed(Seed(&mut *self.0))?.is_some() {
            values.next_value_seed(Seed(&mut *self.0))?;
        }
        Ok(())
    }
}
fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b)
        .context("primary DTO allocation quote overflow")
}
fn mul(a: u64, b: u64) -> Result<u64> {
    a.checked_mul(b)
        .context("primary DTO allocation quote overflow")
}
fn round(a: u64) -> Result<u64> {
    a.checked_next_power_of_two()
        .context("primary DTO allocation quote overflow")
}

pub(super) fn preflight(wire_bytes: usize) -> Result<u64> {
    // Retained wire plus serde_json escape scratch including realloc overlap.
    add(mul(5, u64::try_from(wire_bytes)?)?, FIXED)
}

pub(super) fn quote(bytes: &[u8]) -> Result<u64> {
    let mut shape = Shape::default();
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    Seed(&mut shape).deserialize(&mut decoder)?;
    decoder.end()?;
    drop(decoder);
    // Pinned Rust B=6: one full internal String/Value BTree node per
    // input token overquotes all map inserts, including rejected duplicates.
    // JSON arrays, definition index vectors, and borrowed canonical sort
    // scratch are charged together. No decoder-owned allocation escapes.
    let tree_node = add(
        round(add(
            mul(
                11,
                (std::mem::size_of::<String>() + std::mem::size_of::<serde_json::Value>()) as u64,
            )?,
            mul(16, std::mem::size_of::<usize>() as u64)?,
        )?)?,
        ALLOWANCE,
    )?;
    let element = std::mem::size_of::<serde_json::Value>()
        .max(std::mem::size_of::<kasumi_types::IndexDefinition>())
        .max(std::mem::size_of::<kasumi_types::IndexField>())
        .max(std::mem::size_of::<(&String, &serde_json::Value)>());
    let vector_element = add(mul(4, element as u64)?, ALLOWANCE)?;
    let per_token = add(add(tree_node, vector_element)?, ALLOWANCE)?;
    let retained = add(
        add(mul(shape.nodes, per_token)?, mul(2, shape.string_bytes)?)?,
        FIXED,
    )?;
    // Serde escape scratch and its growth overlap remain live with decoded
    // containers. Canonical validation streams to a comparing writer, with
    // borrowed sort vectors covered by the per-token allowance above.
    // Unexpected::Str error text Debug-escapes at most six output bytes per
    // decoded UTF-8 byte (raw DEL is the tight ASCII case). The 32× term covers
    // that formatting chain and String growth/old+new overlap. Optional local
    // anyhow backtrace capture is not included in this buffer/diagnostic quote.
    let peak = add(
        retained,
        add(preflight(bytes.len())?, mul(32, shape.string_bytes)?)?,
    )?;
    Ok(peak)
}

struct Counter(u64);
impl std::io::Write for Counter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len() as u64)
            .ok_or(std::io::ErrorKind::InvalidInput)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(super) fn encoded_bytes(value: &impl serde::Serialize) -> Result<u64> {
    let mut count = Counter(0);
    serde_json::to_writer(&mut count, value)?;
    Ok(count.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        admission::{AdmissionConfig, NodeAdmission},
        document_pool::allocation_tests::measure_topology_input,
    };
    use kasumi_query::QueryWorkspace;
    use kasumi_types::{CollectionDefinition, Document};

    fn measured<T: serde::de::DeserializeOwned + serde::Serialize>(
        wire: &[u8],
        accepts: bool,
    ) -> Result<()> {
        let node = NodeAdmission::with_fixed_memory(
            AdmissionConfig {
                high_water_bytes: Some(128 << 20),
                max_inflight_bytes: Some(64 << 20),
                ..Default::default()
            },
            256 << 20,
            0,
        )?;
        let before = node.snapshot().reserved_bytes;
        let first = preflight(wire.len())?;
        let mut reservation = node.reserve_document_source(first)?;
        let (quoted, live, peak, _) = measure_topology_input(|| quote(wire));
        assert!(
            peak as u64 <= first,
            "preflight peak {} exceeds {}",
            peak,
            first
        );
        let quoted = quoted?;
        assert_eq!(live, 0);
        reservation.ensure_peak(quoted)?;
        let (accepted, live, peak, _) = measure_topology_input(|| {
            let decoded = serde_json::from_slice::<T>(wire);
            let accepted = match &decoded {
                Ok(value) => crate::current_json::require_current_writer_bytes(
                    wire,
                    value,
                    "selected primary DTO",
                )
                .is_ok(),
                Err(_) => false,
            };
            drop(decoded);
            accepted
        });
        assert_eq!(accepted, accepts);
        assert!(
            peak as u64 <= quoted,
            "typed peak {} exceeds {}",
            peak,
            quoted
        );
        assert_eq!(
            live, 0,
            "decode leaked retained allocation outside the window"
        );
        drop(reservation);
        assert_eq!(node.snapshot().reserved_bytes, before);
        Ok(())
    }
    #[test]
    fn primary_decode_real_allocations_fit_grants_for_nested_and_precise_values() -> Result<()> {
        let precise: serde_json::Value =
            serde_json::from_str("12345678901234567890.123456789012345678901234567890")?;
        let mut body = serde_json::json!({"marker": {"$serde_json::private::Number": "literal"}, "number": precise, "float": 1.25});
        for _ in 0..24 {
            body = serde_json::json!([body, {"a": "界🌸", "b": [1, 2, 3]}]);
        }
        let document = Document {
            id: "nested".into(),
            version: 1,
            body,
        };
        measured::<Document>(&serde_json::to_vec(&document)?, true)?;
        let huge: serde_json::Value = serde_json::from_str(&"9".repeat(10_000))?;
        measured::<Document>(
            &serde_json::to_vec(&Document {
                id: "number".into(),
                version: 1,
                body: huge,
            })?,
            true,
        )?;
        // Escapes decode successfully but fail current-writer canonicality.
        measured::<Document>(
            br#"{"id":"escaped","version":1,"body":"\u754c\ud83c\udf38"}"#,
            false,
        )?;
        Ok(())
    }
    #[test]
    fn primary_decode_real_allocations_fit_grants_for_definition_and_typed_errors() -> Result<()> {
        let definition = CollectionDefinition {
            name: "docs".into(),
            write_mode: kasumi_types::CollectionWriteMode::Mutable,
            retention_class: kasumi_types::CollectionRetentionClass::Operational,
            schema: serde_json::json!({"required":["a"],"properties":{"a":{"type":"string"}}}),
            indexes: (0..64)
                .map(|n| kasumi_types::IndexDefinition {
                    name: format!("index-{n}"),
                    fields: vec![kasumi_types::IndexField {
                        path: format!("field-{n}"),
                        kind: kasumi_types::ScalarType::String,
                    }],
                    unique: false,
                    text: None,
                })
                .collect(),
            strict_read_audit: false,
        };
        measured::<CollectionDefinition>(&serde_json::to_vec(&definition)?, true)?;
        measured::<Document>(br#"{"id":"a","id":"b","version":1,"body":null}"#, false)?;
        let mut wrong = serde_json::to_value(&definition)?;
        wrong["write_mode"] = serde_json::Value::String("\u{7f}".repeat(10_000));
        measured::<CollectionDefinition>(&serde_json::to_vec(&wrong)?, false)?;
        Ok(())
    }
}
