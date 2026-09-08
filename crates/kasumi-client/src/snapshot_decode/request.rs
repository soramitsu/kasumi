//! Walk borrowed request values before JSON encoding or cloning metadata. The
//! serializer stores no values and rejects recursive/counted work at its entry.
use super::resources::{Call, exhausted};
use crate::ClientError;
use serde::{Serialize, ser::*};
use std::fmt;
#[derive(Debug)]
struct Bounds;
impl fmt::Display for Bounds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("snapshot request exceeds admitted structural bounds")
    }
}
impl std::error::Error for Bounds {}
impl serde::ser::Error for Bounds {
    fn custom<T: fmt::Display>(_: T) -> Self {
        Self
    }
}
struct Budget<'a> {
    call: &'a Call,
    depth: usize,
    nodes: usize,
    bytes: usize,
    live_map_workspace: u64,
    numeric: bool,
}
impl<'b> Budget<'b> {
    fn node(&mut self, bytes: usize) -> Result<(), Bounds> {
        self.call.check().map_err(|_| Bounds)?;
        self.nodes = self.nodes.checked_add(1).ok_or(Bounds)?;
        self.bytes = self.bytes.checked_add(bytes).ok_or(Bounds)?;
        if self.nodes > self.call.limits.max_nodes
            || self.bytes > self.call.limits.max_request_bytes
        {
            return Err(Bounds);
        }
        self.check_workspace(self.live_map_workspace)
    }
    fn check_workspace(&self, live_map_workspace: u64) -> Result<(), Bounds> {
        let bytes = (self.nodes as u64)
            .checked_mul(512)
            .and_then(|n| n.checked_add((self.bytes as u64).checked_mul(8)?))
            .and_then(|n| n.checked_add(live_map_workspace))
            .ok_or(Bounds)?;
        if bytes > self.call.limits.max_decoded_bytes {
            return Err(Bounds);
        }
        Ok(())
    }
    fn number(&mut self, value: impl fmt::Display) -> Result<(), Bounds> {
        struct Count {
            bytes: usize,
            max: usize,
        }
        impl fmt::Write for Count {
            fn write_str(&mut self, text: &str) -> fmt::Result {
                self.bytes = self.bytes.checked_add(text.len()).ok_or(fmt::Error)?;
                if self.bytes > self.max {
                    return Err(fmt::Error);
                }
                Ok(())
            }
        }
        let mut count = Count {
            bytes: 0,
            max: self.call.limits.max_number_bytes,
        };
        fmt::write(&mut count, format_args!("{value}")).map_err(|_| Bounds)?;
        self.node(0)
    }
    fn string(&mut self, value: &str) -> Result<(), Bounds> {
        if value.len() > self.call.limits.max_string_bytes {
            return Err(Bounds);
        }
        self.node(value.len())
    }
    fn begin<'a>(&'a mut self, length: Option<usize>) -> Result<Compound<'a, 'b>, Bounds> {
        self.node(0)?;
        if self.depth >= self.call.limits.max_depth
            || length.is_some_and(|n| n > self.call.limits.max_nodes.saturating_sub(self.nodes))
        {
            return Err(Bounds);
        }
        self.depth += 1;
        let numeric_before = self.numeric;
        Ok(Compound {
            budget: self,
            numeric_before,
            map_workspace: 0,
        })
    }
}
pub(crate) fn admit(value: &impl Serialize, call: &Call) -> Result<(), ClientError> {
    call.check()?;
    value
        .serialize(&mut Budget {
            call,
            depth: 0,
            nodes: 0,
            bytes: 0,
            live_map_workspace: 0,
            numeric: false,
        })
        .map_err(|_| exhausted())?;
    call.check()
}
struct Compound<'a, 'b> {
    budget: &'a mut Budget<'b>,
    numeric_before: bool,
    map_workspace: u64,
}
impl Drop for Compound<'_, '_> {
    fn drop(&mut self) {
        self.budget.depth -= 1;
        self.budget.numeric = self.numeric_before;
        self.budget.live_map_workspace = self
            .budget
            .live_map_workspace
            .checked_sub(self.map_workspace)
            .expect("map workspace belongs to its live compound");
    }
}
macro_rules! primitive { ($($method:ident($value:ident: $ty:ty)),* $(,)?) => { $(fn $method(self, $value: $ty) -> Result<(), Bounds> { self.number($value) })* }; }
impl<'a, 'b> Serializer for &'a mut Budget<'b> {
    type Ok = ();
    type Error = Bounds;
    type SerializeSeq = Compound<'a, 'b>;
    type SerializeTuple = Compound<'a, 'b>;
    type SerializeTupleStruct = Compound<'a, 'b>;
    type SerializeTupleVariant = Compound<'a, 'b>;
    type SerializeMap = Compound<'a, 'b>;
    type SerializeStruct = Compound<'a, 'b>;
    type SerializeStructVariant = Compound<'a, 'b>;
    primitive! { serialize_i8(v: i8), serialize_i16(v: i16), serialize_i32(v: i32), serialize_i64(v: i64), serialize_u8(v: u8), serialize_u16(v: u16), serialize_u32(v: u32), serialize_u64(v: u64), serialize_i128(v: i128), serialize_u128(v: u128), serialize_f32(v: f32), serialize_f64(v: f64) }
    fn serialize_bool(self, _: bool) -> Result<(), Bounds> {
        self.node(0)
    }
    fn serialize_char(self, value: char) -> Result<(), Bounds> {
        self.node(value.len_utf8())
    }
    fn serialize_str(self, value: &str) -> Result<(), Bounds> {
        if self.numeric {
            // This is a Number's lexical payload, not a JSON string. Literal
            // object keys use SerializeMap and never enter this trusted branch.
            if value.len() > self.call.limits.max_number_bytes {
                return Err(Bounds);
            }
            self.node(value.len())
        } else {
            self.string(value)
        }
    }
    fn serialize_bytes(self, value: &[u8]) -> Result<(), Bounds> {
        if value.len() > self.call.limits.max_nodes.saturating_sub(self.nodes) {
            return Err(Bounds);
        }
        self.node(value.len())
    }
    fn serialize_none(self) -> Result<(), Bounds> {
        self.node(0)
    }
    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<(), Bounds> {
        self.node(0)?;
        value.serialize(self)
    }
    fn serialize_unit(self) -> Result<(), Bounds> {
        self.node(0)
    }
    fn serialize_unit_struct(self, _: &'static str) -> Result<(), Bounds> {
        self.node(0)
    }
    fn serialize_unit_variant(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
    ) -> Result<(), Bounds> {
        self.string(variant)
    }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        value: &T,
    ) -> Result<(), Bounds> {
        let compound = self.begin(Some(1))?;
        value.serialize(&mut *compound.budget)
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<(), Bounds> {
        self.string(variant)?;
        let compound = self.begin(Some(1))?;
        value.serialize(&mut *compound.budget)
    }
    fn serialize_seq(self, length: Option<usize>) -> Result<Self::SerializeSeq, Bounds> {
        self.begin(length)
    }
    fn serialize_tuple(self, length: usize) -> Result<Self::SerializeTuple, Bounds> {
        self.begin(Some(length))
    }
    fn serialize_tuple_struct(
        self,
        _: &'static str,
        length: usize,
    ) -> Result<Self::SerializeTupleStruct, Bounds> {
        self.begin(Some(length))
    }
    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
        length: usize,
    ) -> Result<Self::SerializeTupleVariant, Bounds> {
        self.string(variant)?;
        self.begin(Some(length))
    }
    fn serialize_map(self, length: Option<usize>) -> Result<Self::SerializeMap, Bounds> {
        let mut compound = self.begin(length)?;
        // CanonicalJsonValue may retain borrowed entries for an unsorted map
        // immediately after this callback. Admit that workspace before returning
        // to its body, and retain every parent's charge while visiting children.
        // Charging sorted maps too keeps admission independent of Cargo features.
        let workspace = u64::try_from(length.unwrap_or(0))
            .ok()
            .and_then(|n| {
                n.checked_mul(std::mem::size_of::<(&String, &serde_json::Value)>() as u64)
            })
            .ok_or(Bounds)?;
        let live = compound
            .budget
            .live_map_workspace
            .checked_add(workspace)
            .ok_or(Bounds)?;
        compound.budget.check_workspace(live)?;
        compound.budget.live_map_workspace = live;
        compound.map_workspace = workspace;
        Ok(compound)
    }
    fn serialize_struct(
        self,
        name: &'static str,
        length: usize,
    ) -> Result<Self::SerializeStruct, Bounds> {
        let compound = self.begin(Some(length))?;
        compound.budget.numeric = name == "$serde_json::private::Number";
        Ok(compound)
    }
    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
        length: usize,
    ) -> Result<Self::SerializeStructVariant, Bounds> {
        self.string(variant)?;
        self.begin(Some(length))
    }
}
macro_rules! sequence {
    ($trait:ident, $method:ident) => {
        impl $trait for Compound<'_, '_> {
            type Ok = ();
            type Error = Bounds;
            fn $method<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Bounds> {
                value.serialize(&mut *self.budget)
            }
            fn end(self) -> Result<(), Bounds> {
                Ok(())
            }
        }
    };
}
sequence!(SerializeSeq, serialize_element);
sequence!(SerializeTuple, serialize_element);
sequence!(SerializeTupleStruct, serialize_field);
sequence!(SerializeTupleVariant, serialize_field);
impl SerializeMap for Compound<'_, '_> {
    type Ok = ();
    type Error = Bounds;
    fn serialize_key<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Bounds> {
        value.serialize(&mut *self.budget)
    }
    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Bounds> {
        value.serialize(&mut *self.budget)
    }
    fn end(self) -> Result<(), Bounds> {
        Ok(())
    }
}
macro_rules! structure {
    ($trait:ident) => {
        impl $trait for Compound<'_, '_> {
            type Ok = ();
            type Error = Bounds;
            fn serialize_field<T: ?Sized + Serialize>(
                &mut self,
                key: &'static str,
                value: &T,
            ) -> Result<(), Bounds> {
                // serde_json's Number serializer uses one synthetic struct
                // field. That field name is absent from JSON and must not use a
                // caller's string limit. Real object keys are visited by Map.
                if !self.budget.numeric {
                    self.budget.string(key)?;
                }
                value.serialize(&mut *self.budget)
            }
            fn end(self) -> Result<(), Bounds> {
                Ok(())
            }
        }
    };
}
structure!(SerializeStruct);
structure!(SerializeStructVariant);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ClientDecodeLimits, ClientResources, JsonReadOptions};
    use std::{cell::Cell, time::Duration};

    // Models the canonical serializer's exact ordering: map-entry callback,
    // borrowed-entry allocation/sort, then recursive field visits. The counter
    // observes whether rejected work got past that admission callback.
    enum Probe<'a> {
        Number,
        Map {
            entries: Vec<(String, Probe<'a>)>,
            bodies: &'a Cell<usize>,
        },
    }
    impl Serialize for Probe<'_> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            match self {
                Self::Number => serializer.serialize_u64(1),
                Self::Map { entries, bodies } => {
                    let mut map = serializer.serialize_map(Some(entries.len()))?;
                    bodies.set(bodies.get() + 1);
                    let mut sorted: Vec<_> =
                        entries.iter().map(|(key, value)| (key, value)).collect();
                    sorted.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
                    for (key, value) in sorted {
                        map.serialize_entry(key, value)?;
                    }
                    map.end()
                }
            }
        }
    }
    fn probe(width: usize, nested: bool, bodies: &Cell<usize>) -> Probe<'_> {
        Probe::Map {
            entries: (0..width)
                .rev()
                .map(|i| {
                    (
                        format!("{i:04}"),
                        if i == 0 && nested {
                            probe(width, false, bodies)
                        } else {
                            Probe::Number
                        },
                    )
                })
                .collect(),
            bodies,
        }
    }
    fn options(decoded: u64) -> JsonReadOptions {
        JsonReadOptions {
            resources: ClientResources::new(16 << 20, 2).unwrap(),
            limits: ClientDecodeLimits {
                max_request_bytes: 1 << 20,
                max_wire_bytes: 1024,
                max_json_bytes: 1024,
                max_nodes: usize::MAX,
                max_decoded_bytes: decoded,
                ..Default::default()
            },
            deadline: tokio::time::Instant::now() + Duration::from_secs(30),
        }
    }
    fn budget(call: &Call) -> Budget<'_> {
        Budget {
            call,
            depth: 0,
            nodes: 0,
            bytes: 0,
            live_map_workspace: 0,
            numeric: false,
        }
    }
    #[test]
    fn canonical_wrapper_admission_bounds_actual_sorting_workspace() {
        fn object(nested: bool) -> serde_json::Value {
            let mut map = serde_json::Map::new();
            for i in (0..32).rev() {
                map.insert(
                    format!("{i:04}"),
                    if i == 0 && nested {
                        object(false)
                    } else {
                        serde_json::Value::Bool(true)
                    },
                );
            }
            serde_json::Value::Object(map)
        }
        // With the external consumer's preserve_order feature these reverse
        // insertions require the actual canonical borrowed-entry sorter. The
        // probe tests independently prove rejection precedes that body entry.
        let value = object(true);
        let original = serde_json::to_vec(&value).unwrap();
        let canonical = kasumi_types::CanonicalJsonValue(&value);
        let small = options(2200);
        let call = small.admit().unwrap();
        assert!(crate::snapshot_decode::encode(&canonical, &call).is_err());
        assert_eq!(small.resources.usage().live_owners, 1);
        drop(call);
        assert_eq!(small.resources.usage().live_owners, 0);
        let large = options(100_000);
        let call = large.admit().unwrap();
        assert_eq!(
            crate::snapshot_decode::encode(&canonical, &call).unwrap(),
            serde_json::to_vec(&canonical).unwrap(),
        );
        assert_eq!(serde_json::to_vec(&value).unwrap(), original);
        drop(call);
        assert_eq!(large.resources.usage().accounted_bytes, 0);
    }
    #[test]
    fn map_workspace_admission_precedes_sorting_body() {
        let call = options(4096).admit().unwrap();
        let bodies = Cell::new(0);
        let wide = probe(1024, false, &bodies);
        assert!(admit(&wide, &call).is_err());
        assert_eq!(
            bodies.get(),
            0,
            "sorting body must not begin before admission"
        );

        struct DeclaredMap<'a>(&'a Cell<usize>);
        impl Serialize for DeclaredMap<'_> {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let map = serializer.serialize_map(Some(usize::MAX / 2))?;
                self.0.set(self.0.get() + 1);
                map.end()
            }
        }
        // Checked multiplication (64-bit) or the decoded bound (32-bit) rejects
        // impossible metadata before the declared map body can allocate it.
        assert!(admit(&DeclaredMap(&bodies), &call).is_err());
        assert_eq!(bodies.get(), 0);
    }
    #[test]
    fn map_workspace_sums_live_parents_and_releases_on_success_and_error() {
        let call = options(2200).admit().unwrap();
        let bodies = Cell::new(0);
        let nested = probe(32, true, &bodies);
        let mut failed = budget(&call);
        assert!(nested.serialize(&mut failed).is_err());
        assert_eq!(
            bodies.get(),
            1,
            "child sort must retain the parent's workspace"
        );
        assert_eq!(failed.live_map_workspace, 0);
        assert_eq!(failed.depth, 0);

        let call = options(100_000).admit().unwrap();
        let mut successful = budget(&call);
        nested.serialize(&mut successful).unwrap();
        assert_eq!(bodies.get(), 3);
        assert_eq!(successful.live_map_workspace, 0);
        assert_eq!(successful.depth, 0);
    }
}
