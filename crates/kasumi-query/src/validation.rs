use crate::scalar::{Scalar, decimal, indexed_values, invalid, validate_pointer};
use crate::{
    CollectionRecords, ReadResult, Record, index_input::CheckedRecords, structured::Structured,
};
use kasumi_types::*;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, OnceLock, Weak},
};

const MAX_SCHEMA_BYTES: usize = 256 * 1024;
const MAX_DEPTH: usize = 48;
/// A validator keeps every compiled pattern for as long as a generation holds
/// it, on every replica, and none of it is charged to admission. The schema's
/// own size does not bound that: 200 KiB of schema holding 6,000 patterns such
/// as `(?:\w{40}){40}` compiled to about 1.3 GiB. With these two limits the
/// largest accepted schema, 256 patterns of `\w{2500}`, measured about 75 MiB.
const MAX_SCHEMA_PATTERNS: usize = 256;
/// Bound on one pattern's compiled program, and separately on the transition
/// cache a search may grow for it. A pattern over the first is rejected with
/// its schema. The second never rejects: a search that outgrows its cache
/// continues on a slower engine with the same result.
const MAX_PATTERN_PROGRAM_BYTES: usize = 256 * 1024;

#[cfg(test)]
thread_local! {
    static COMPILATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static SCHEMA_DIGESTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn compilation_count() -> usize {
    COMPILATIONS.with(std::cell::Cell::get)
}

#[cfg(test)]
pub(crate) fn schema_digest_count() -> usize {
    SCHEMA_DIGESTS.with(std::cell::Cell::get)
}

pub(crate) fn schema_sha256(schema: &Value) -> Result<[u8; 32]> {
    #[cfg(test)]
    SCHEMA_DIGESTS.with(|count| count.set(count.get() + 1));
    serde_json::to_vec(schema)
        .map(|encoded| Sha256::digest(encoded).into())
        .map_err(|e| invalid(e.to_string()))
}

fn inspect(value: &Value, depth: usize, nodes: &mut usize) -> Result<()> {
    *nodes += 1;
    if depth > MAX_DEPTH || *nodes > 20_000 {
        return Err(invalid("JSON exceeds the depth or node-count limit"));
    }
    match value {
        Value::Object(map) => {
            for value in map.values() {
                inspect(value, depth + 1, nodes)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                inspect(value, depth + 1, nodes)?;
            }
        }
        Value::Number(n) => {
            decimal(&n.to_string())?;
        }
        _ => {}
    }
    Ok(())
}

/// Resolve a local JSON Pointer with the same URI decoding and array-index
/// interpretation as jsonschema's resolver. Plain-name anchors are reached by
/// the schema traversal itself; the validator checks that their names resolve.
fn local_schema_pointer<'a>(root: &'a Value, fragment: &str) -> Result<Option<&'a Value>> {
    if fragment.is_empty() {
        return Ok(Some(root));
    }
    if !fragment.starts_with('/') {
        return Ok(None);
    }
    let mut decoded = Vec::with_capacity(fragment.len());
    let bytes = fragment.as_bytes();
    let mut offset = 0;
    while offset < bytes.len() {
        if bytes[offset] == b'%'
            && offset + 2 < bytes.len()
            && let (Some(high), Some(low)) = (
                char::from(bytes[offset + 1]).to_digit(16),
                char::from(bytes[offset + 2]).to_digit(16),
            )
        {
            decoded.push((high * 16 + low) as u8);
            offset += 3;
        } else {
            decoded.push(bytes[offset]);
            offset += 1;
        }
    }
    let pointer =
        std::str::from_utf8(&decoded).map_err(|_| invalid("local schema pointer is not UTF-8"))?;
    let mut target = root;
    for segment in pointer[1..].split('/') {
        let next = if let Some(array) = target.as_array() {
            segment
                .parse::<usize>()
                .ok()
                .and_then(|index| array.get(index))
        } else {
            target.get(segment.replace("~1", "/").replace("~0", "~"))
        };
        target = next.ok_or_else(|| invalid("local schema pointer does not resolve"))?;
    }
    Ok(Some(target))
}

/// Visit schema locations and the targets of local references. A reference may
/// turn an otherwise literal enum/default/extension value into a schema, while
/// unreferenced data may legitimately contain `$ref`, `$id` or `pattern` keys.
/// Each location is inspected once: references can cycle or share a target,
/// and jsonschema shares compiled patterns across references to that target.
fn inspect_schema(root: &Value) -> Result<()> {
    let mut pending = vec![root];
    let mut visited = BTreeSet::new();
    let mut patterns = 0;
    while let Some(schema) = pending.pop() {
        if !visited.insert(std::ptr::from_ref(schema)) {
            continue;
        }
        let Some(map) = schema.as_object() else {
            continue;
        };
        if matches!(map.get("pattern"), Some(Value::String(_))) {
            patterns += 1;
        }
        if let Some(Value::Object(schemas)) = map.get("patternProperties") {
            patterns += schemas.len();
        }
        if patterns > MAX_SCHEMA_PATTERNS {
            return Err(invalid("schema has more than 256 patterns"));
        }
        for key in ["$ref", "$dynamicRef", "$recursiveRef"] {
            if let Some(reference) = map.get(key) {
                let fragment = reference
                    .as_str()
                    .and_then(|s| s.strip_prefix('#'))
                    .ok_or_else(|| invalid("schemas may reference only local fragments"))?;
                if let Some(target) = local_schema_pointer(root, fragment)? {
                    pending.push(target);
                }
            }
        }
        if let Some(draft) = map.get("$schema")
            && !matches!(
                draft.as_str(),
                Some(
                    "https://json-schema.org/draft/2020-12/schema"
                        | "https://json-schema.org/draft/2020-12/schema#"
                )
            )
        {
            return Err(invalid("only JSON Schema Draft 2020-12 is supported"));
        }
        if map.contains_key("$id") {
            return Err(invalid("schema $id is not supported; use local $defs"));
        }
        for key in [
            "$defs",
            "definitions",
            "properties",
            "patternProperties",
            "dependentSchemas",
            // jsonschema still compiles legacy dependencies in Draft 2020-12.
            "dependencies",
        ] {
            if let Some(Value::Object(schemas)) = map.get(key) {
                pending.extend(schemas.values());
            }
        }
        // Referenced literals are not covered by root meta-validation; the
        // compiler accepts legacy tuple items in them as well.
        for key in ["allOf", "anyOf", "oneOf", "prefixItems", "items"] {
            if let Some(Value::Array(schemas)) = map.get(key) {
                pending.extend(schemas);
            }
        }
        for key in [
            "not",
            "if",
            "then",
            "else",
            "items",
            "contains",
            "additionalProperties",
            "additionalItems",
            "unevaluatedProperties",
            "unevaluatedItems",
            "propertyNames",
            "contentSchema",
        ] {
            if let Some(schema) = map.get(key) {
                pending.push(schema);
            }
        }
    }
    Ok(())
}

struct NoExternalResources;
impl jsonschema::Retrieve for NoExternalResources {
    fn retrieve(
        &self,
        _: &jsonschema::Uri<String>,
    ) -> std::result::Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        Err("external schema retrieval is disabled".into())
    }
}

pub(crate) fn compile(schema: &Value) -> Result<Arc<jsonschema::Validator>> {
    let encoded = serde_json::to_vec(schema).map_err(|e| invalid(e.to_string()))?;
    if encoded.len() > MAX_SCHEMA_BYTES {
        return Err(invalid("schema exceeds 256 KiB"));
    }
    inspect(schema, 0, &mut 0)?;
    inspect_schema(schema)?;
    let key: [u8; 32] = Sha256::digest(encoded).into();
    // The cache never owns tenant schema plaintext. Published generations hold
    // validators strongly; sealing/dropping them releases enum/const literals too.
    static CACHE: OnceLock<Mutex<BTreeMap<[u8; 32], Weak<jsonschema::Validator>>>> =
        OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    if let Some(validator) = cache
        .lock()
        .map_err(|_| invalid("validator cache poisoned"))?
        .get(&key)
        .and_then(Weak::upgrade)
    {
        return Ok(validator);
    }
    #[cfg(test)]
    COMPILATIONS.with(|count| count.set(count.get() + 1));
    jsonschema::draft202012::meta::validate(schema)
        .map_err(|e| invalid(format!("invalid schema: {e}")))?;
    let validator = Arc::new(
        jsonschema::draft202012::options()
            .with_pattern_options(
                jsonschema::PatternOptions::regex()
                    .size_limit(MAX_PATTERN_PROGRAM_BYTES)
                    .dfa_size_limit(MAX_PATTERN_PROGRAM_BYTES),
            )
            .with_retriever(NoExternalResources)
            .should_validate_formats(true)
            .build(schema)
            .map_err(|e| invalid(format!("invalid schema: {e}")))?,
    );
    let mut entries = cache
        .lock()
        .map_err(|_| invalid("validator cache poisoned"))?;
    if entries.len() >= 64 {
        entries.pop_first();
    }
    entries.insert(key, Arc::downgrade(&validator));
    Ok(validator)
}

pub fn validate_document(definition: &CollectionDefinition, body: &Value) -> Result<()> {
    validate_document_shape(body)?;
    let validator = compile(&definition.schema)?;
    validate_document_fields(definition, body, &validator)
}

pub(crate) fn validate_document_with_validator(
    definition: &CollectionDefinition,
    body: &Value,
    validator: &jsonschema::Validator,
) -> Result<()> {
    validate_document_shape(body)?;
    validate_document_fields(definition, body, validator)
}

fn validate_document_shape(body: &Value) -> Result<()> {
    if !body.is_object() {
        return Err(Error::new(
            ErrorCode::SchemaViolation,
            "document body must be a JSON object",
        ));
    }
    inspect(body, 0, &mut 0)
}

fn validate_document_fields(
    definition: &CollectionDefinition,
    body: &Value,
    validator: &jsonschema::Validator,
) -> Result<()> {
    validator.validate(body).map_err(|e| {
        Error::new(
            ErrorCode::SchemaViolation,
            format!("{}: {}", e.instance_path(), e.masked()),
        )
    })?;
    for index in &definition.indexes {
        for field in &index.fields {
            indexed_values(body.pointer(&field.path), field.kind).map_err(|e| {
                Error::new(
                    ErrorCode::SchemaViolation,
                    format!("{}: {}", field.path, e.message),
                )
            })?;
        }
    }
    crate::search::validate_text_document(definition, body)?;
    Ok(())
}

pub fn validate_collection<R: CollectionRecords + ?Sized>(
    source: &R,
) -> ReadResult<(), R::Failure> {
    let source = CheckedRecords::new(source)?;
    validate_collection_and_compile(&source)?;
    Structured::build_unique(&source)?;
    Ok(())
}

pub(crate) fn validate_collection_and_compile<R: CollectionRecords + ?Sized>(
    source: &R,
) -> ReadResult<Arc<jsonschema::Validator>, R::Failure> {
    let validator = validate_definition_and_compile(source.definition())?;
    source.visit_records(|_, record| {
        if let Record::Live(document) = record {
            validate_document_with_validator(source.definition(), &document.body, &validator)?;
        }
        Ok(())
    })?;
    Ok(validator)
}

pub(crate) fn validate_definition_and_compile(
    definition: &CollectionDefinition,
) -> Result<Arc<jsonschema::Validator>> {
    validate_name(&definition.name)?;
    if definition.retention_class == CollectionRetentionClass::ArchivableHistory
        && definition.write_mode != CollectionWriteMode::AppendOnly
    {
        return Err(invalid("archivable history must be append-only"));
    }
    let validator = compile(&definition.schema)?;
    if definition.indexes.len() > 64 {
        return Err(invalid("a collection supports at most 64 indexes"));
    }
    let mut names = BTreeSet::new();
    let mut types = BTreeMap::new();
    for index in &definition.indexes {
        validate_name(&index.name)?;
        if !names.insert(&index.name) {
            return Err(invalid("duplicate index name"));
        }
        if index.fields.is_empty() || index.fields.len() > 8 {
            return Err(invalid("indexes require 1–8 fields"));
        }
        let mut paths = BTreeSet::new();
        for field in &index.fields {
            validate_pointer(&field.path)?;
            if !paths.insert(&field.path) {
                return Err(invalid("duplicate field in index"));
            }
            if let Some(previous) = types.insert(&field.path, field.kind)
                && previous != field.kind
            {
                return Err(invalid("conflicting declared types for indexed path"));
            }
            if index.text.is_some()
                && !matches!(field.kind, ScalarType::String | ScalarType::StringArray)
            {
                return Err(invalid(
                    "text indexes require string or string_array fields",
                ));
            }
            if index.unique
                && matches!(
                    field.kind,
                    ScalarType::StringArray | ScalarType::NumberArray
                )
            {
                return Err(invalid("unique indexes require scalar fields"));
            }
        }
        if index.text.is_some() && index.unique {
            return Err(invalid("text indexes cannot be unique"));
        }
    }
    Ok(validator)
}

pub fn check_unique<R: CollectionRecords + ?Sized>(source: &R) -> ReadResult<(), R::Failure> {
    let source = CheckedRecords::new(source)?;
    Structured::build_unique(&source).map(|_| ())
}

/// A bounded, canonical equality key for one unique index. Missing fields are
/// sparse; decimal spellings normalize exactly as the resident unique index does.
/// The caller supplies durable or temporary point-addressed uniqueness storage.
pub fn unique_index_key(index: &IndexDefinition, body: &Value) -> Result<Option<Vec<u8>>> {
    if !index.unique {
        return Err(invalid("equality key requires a unique index"));
    }
    let mut key = Vec::new();
    let mut missing = false;
    for field in &index.fields {
        let mut values = indexed_values(body.pointer(&field.path), field.kind)?;
        if values.len() != 1 {
            return Err(invalid("unique index has a non-scalar field"));
        }
        let encoded = match values.remove(0) {
            Scalar::Missing => {
                missing = true;
                serde_json::json!(["missing"])
            }
            Scalar::Null => serde_json::json!(["null"]),
            Scalar::Boolean(value) => serde_json::json!(["boolean", value]),
            Scalar::Number(value) => serde_json::json!(["number", value.normalized().to_string()]),
            Scalar::String(value) => serde_json::json!(["string", value]),
            Scalar::UpperBound => return Err(invalid("internal bound cannot be an indexed value")),
        };
        key.push(encoded);
    }
    if missing {
        return Ok(None);
    }
    serde_json::to_vec(&key)
        .map(Some)
        .map_err(|_| invalid("unique equality key encoding failed"))
}
