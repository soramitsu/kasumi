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
    numeric: bool,
}
impl<'b> Budget<'b> {
    fn node(&mut self, bytes: usize) -> Result<(), Bounds> {
        self.call.check().map_err(|_| Bounds)?;
        self.nodes = self.nodes.checked_add(1).ok_or(Bounds)?;
        self.bytes = self.bytes.checked_add(bytes).ok_or(Bounds)?;
        if self.nodes > self.call.limits.max_nodes
            || self.bytes > self.call.limits.max_request_bytes
            || (self.nodes as u64)
                .checked_mul(512)
                .and_then(|n| n.checked_add((self.bytes as u64).checked_mul(8)?))
                .ok_or(Bounds)?
                > self.call.limits.max_decoded_bytes
        {
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
            numeric: false,
        })
        .map_err(|_| exhausted())?;
    call.check()
}
struct Compound<'a, 'b> {
    budget: &'a mut Budget<'b>,
    numeric_before: bool,
}
impl Drop for Compound<'_, '_> {
    fn drop(&mut self) {
        self.budget.depth -= 1;
        self.budget.numeric = self.numeric_before;
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
        if self.numeric && value.len() > self.call.limits.max_number_bytes {
            return Err(Bounds);
        }
        self.string(value)
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
        self.begin(length)
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
                self.budget.string(key)?;
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
