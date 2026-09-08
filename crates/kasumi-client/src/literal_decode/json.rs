//! Only scalar/metadata types use stock Deserialize. Document spans are built
//! literally after the complete unary input has passed token admission.
use crate::{
    ClientError,
    snapshot_decode::{
        resources::{Call, invalid},
        tokens,
    },
};
use kasumi_types::*;
use serde::{
    Deserialize,
    de::{MapAccess, Visitor},
};
use serde_json::value::RawValue;
use std::{collections::BTreeMap, fmt, sync::Arc};

pub(super) struct Object<'a>(BTreeMap<String, &'a RawValue>);
impl<'de> Deserialize<'de> for Object<'de> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = Object<'de>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a typed JSON object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut input: A) -> Result<Self::Value, A::Error> {
                let mut fields = BTreeMap::new();
                while let Some((key, value)) = input.next_entry::<String, &'de RawValue>()? {
                    if fields.insert(key, value).is_some() {
                        return Err(serde::de::Error::custom("duplicate typed JSON field"));
                    }
                }
                Ok(Object(fields))
            }
        }
        d.deserialize_map(Fields)
    }
}
impl<'a> Object<'a> {
    pub(super) fn new(raw: &'a RawValue) -> Result<Self, ClientError> {
        Ok(serde_json::from_str(raw.get())?)
    }
    pub(super) fn raw(&mut self, name: &'static str) -> Result<&'a RawValue, ClientError> {
        self.0
            .remove(name)
            .ok_or_else(|| invalid("missing typed JSON field"))
    }
    // Call sites use only metadata types without any Value-bearing field.
    pub(super) fn field<T: Deserialize<'a>>(
        &mut self,
        name: &'static str,
    ) -> Result<T, ClientError> {
        Ok(serde_json::from_str(self.raw(name)?.get())?)
    }
    pub(super) fn finish(self) -> Result<(), ClientError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(invalid("unknown typed JSON field"))
        }
    }
}
pub(super) fn array(raw: &RawValue, max: usize) -> Result<Vec<&RawValue>, ClientError> {
    struct Rows(usize);
    impl<'de> Visitor<'de> for Rows {
        type Value = Vec<&'de RawValue>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("bounded JSON rows")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut input: A,
        ) -> Result<Self::Value, A::Error> {
            let mut rows = Vec::new();
            while let Some(raw) = input.next_element::<&'de RawValue>()? {
                if rows.len() >= self.0 {
                    return Err(serde::de::Error::custom("too many admitted JSON rows"));
                }
                rows.push(raw);
            }
            Ok(rows)
        }
    }
    let mut decoder = serde_json::Deserializer::from_str(raw.get());
    let rows = serde::Deserializer::deserialize_seq(&mut decoder, Rows(max))?;
    decoder.end()?;
    Ok(rows)
}
pub(super) fn document(
    raw: &RawValue,
    call: &Call,
    maximum_version: u64,
) -> Result<Document, ClientError> {
    call.check()?;
    let mut object = Object::new(raw)?;
    let id: String = object.field("id")?;
    let version: u64 = object.field("version")?;
    let body = object.raw("body")?;
    object.finish()?;
    if id.is_empty() || version == 0 || version > maximum_version {
        return Err(invalid("invalid native document identity/version"));
    }
    Ok(Document {
        id,
        version,
        body: tokens::literal(body.get().as_bytes(), call)?,
    })
}
pub(super) fn definition(raw: &RawValue, call: &Call) -> Result<CollectionDefinition, ClientError> {
    call.check()?;
    let mut object = Object::new(raw)?;
    let result = CollectionDefinition {
        name: object.field("name")?,
        write_mode: object.field("write_mode")?,
        retention_class: object.field("retention_class")?,
        schema: tokens::literal(object.raw("schema")?.get().as_bytes(), call)?,
        indexes: object.field("indexes")?,
        strict_read_audit: object.field("strict_read_audit")?,
    };
    object.finish()?;
    Ok(result)
}
pub(super) fn schema(
    raw: &RawValue,
    request: &ReadSchema,
    call: &Call,
) -> Result<SchemaSnapshot, ClientError> {
    let mut object = Object::new(raw)?;
    let incarnation: String = object.field("incarnation")?;
    let revision = object.field("revision")?;
    let policy_epoch = object.field("policy_epoch")?;
    let schema_epoch = object.field("schema_epoch")?;
    let values = Object::new(object.raw("collections")?)?;
    object.finish()?;
    if uuid::Uuid::parse_str(&incarnation)
        .ok()
        .is_none_or(|id| id.is_nil() || id.to_string() != incarnation)
        || values.0.len() > call.limits.max_rows
        || values.0.len() != request.collections.len()
    {
        return Err(invalid("schema collection/identity differs"));
    }
    let mut collections = BTreeMap::new();
    for (name, raw) in values.0 {
        call.check()?;
        if !request.collections.contains(&name) {
            return Err(invalid("unexpected schema collection"));
        }
        let value = if raw.get() == "null" {
            None
        } else {
            let mut value = Object::new(raw)?;
            let definition = definition(value.raw("definition")?, call)?;
            let data_epoch = value.field("data_epoch")?;
            let archived_document_count = value.field("archived_document_count")?;
            value.finish()?;
            if definition.name != name || data_epoch > revision {
                return Err(invalid("schema collection epoch/name differs"));
            }
            Some(SchemaCollection {
                definition,
                data_epoch,
                archived_document_count,
            })
        };
        collections.insert(name, value);
    }
    Ok(SchemaSnapshot {
        incarnation,
        revision,
        policy_epoch,
        schema_epoch,
        collections,
    })
}
pub(super) fn feed(
    raw: &RawValue,
    request: &ReadChangeFeed,
    call: &Call,
) -> Result<ChangeFeedPage, ClientError> {
    let mut object = Object::new(raw)?;
    let kind: &str = object.field("kind")?;
    let page = match kind {
        "retention_gap" => ChangeFeedPage::RetentionGap {
            first_available_sequence: object.field("first_available_sequence")?,
            head_sequence: object.field("head_sequence")?,
            requested_after_sequence: object.field("requested_after_sequence")?,
        },
        "events" => {
            let revision: u64 = object.field("revision")?;
            let first_available_sequence = object.field("first_available_sequence")?;
            let head_sequence = object.field("head_sequence")?;
            let next: ChangeFeedCursor = object.field("next")?;
            let caught_up: bool = object.field("caught_up")?;
            let rows = array(
                object.raw("events")?,
                request.limit.min(call.limits.max_rows),
            )?;
            if next.collections != request.collections
                || next.after_sequence > head_sequence
                || caught_up != (next.after_sequence == head_sequence)
            {
                return Err(invalid("change feed cursor/range differs"));
            }
            let mut previous = match &request.start {
                ChangeFeedStart::After { cursor } => {
                    if cursor.tenant != next.tenant
                        || cursor.principal != next.principal
                        || cursor.incarnation != next.incarnation
                        || cursor.collections != next.collections
                        || next.after_sequence < cursor.after_sequence
                    {
                        return Err(invalid("change feed changed original cursor scope"));
                    }
                    cursor.after_sequence
                }
                ChangeFeedStart::Now => head_sequence,
                ChangeFeedStart::Beginning => 0,
            };
            let mut events = Vec::with_capacity(rows.len());
            for row in rows {
                call.check()?;
                let mut event = Object::new(row)?;
                let sequence: u64 = event.field("sequence")?;
                let event_revision: u64 = event.field("revision")?;
                let ordinal: usize = event.field("ordinal")?;
                let commit_event_count: usize = event.field("commit_event_count")?;
                let collection: String = event.field("collection")?;
                let id: String = event.field("id")?;
                let raw = event.raw("document")?;
                event.finish()?;
                if sequence <= previous
                    || sequence > next.after_sequence
                    || event_revision > revision
                    || ordinal >= commit_event_count
                    || !request.collections.contains(&collection)
                {
                    return Err(invalid("change feed event differs from admitted range"));
                }
                let document = if raw.get() == "null" {
                    None
                } else {
                    let document = document(raw, call, event_revision)?;
                    if document.id != id {
                        return Err(invalid("change feed document ID differs"));
                    }
                    Some(Arc::new(document))
                };
                previous = sequence;
                events.push(ChangeEvent {
                    sequence,
                    revision: event_revision,
                    ordinal,
                    commit_event_count,
                    collection,
                    id,
                    document,
                });
            }
            ChangeFeedPage::Events {
                revision,
                first_available_sequence,
                head_sequence,
                events,
                next,
                caught_up,
            }
        }
        _ => return Err(invalid("unknown change feed result")),
    };
    object.finish()?;
    Ok(page)
}
pub(super) fn audit(
    raw: &RawValue,
    request: &SecurityAuditExportRequest,
    call: &Call,
) -> Result<SecurityAuditPage, ClientError> {
    let mut object = Object::new(raw)?;
    let stream_id = object.field("stream_id")?;
    let through_sequence = object.field("through_sequence")?;
    let next_sequence = object.field("next_sequence")?;
    let rows = array(
        object.raw("records")?,
        usize::from(request.limit).min(call.limits.max_rows),
    )?;
    object.finish()?;
    let mut records = Vec::with_capacity(rows.len());
    for row in rows {
        records.push(tokens::literal(row.get().as_bytes(), call)?);
    }
    let page = SecurityAuditPage {
        stream_id,
        through_sequence,
        next_sequence,
        records,
    };
    crate::security_audit::validate_page(request, &page)?;
    Ok(page)
}
