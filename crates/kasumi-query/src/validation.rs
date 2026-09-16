use crate::scalar::{Scalar, decimal, indexed_values, invalid, validate_pointer};
use kasumi_types::*;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, OnceLock, Weak},
};

const MAX_SCHEMA_BYTES: usize = 256 * 1024;
const MAX_DEPTH: usize = 48;

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

/// Traverse only schema locations, not property names or enum/default values.
/// A document may legitimately have a property named `$ref` or `$id`.
fn inspect_schema(schema: &Value) -> Result<()> {
    let Some(map) = schema.as_object() else {
        return Ok(());
    };
    for key in ["$ref", "$dynamicRef", "$recursiveRef"] {
        if let Some(reference) = map.get(key)
            && !reference.as_str().is_some_and(|s| s.starts_with('#'))
        {
            return Err(invalid("schemas may reference only local fragments"));
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
    ] {
        if let Some(Value::Object(schemas)) = map.get(key) {
            for schema in schemas.values() {
                inspect_schema(schema)?;
            }
        }
    }
    for key in ["allOf", "anyOf", "oneOf", "prefixItems"] {
        if let Some(Value::Array(schemas)) = map.get(key) {
            for schema in schemas {
                inspect_schema(schema)?;
            }
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
        "unevaluatedProperties",
        "unevaluatedItems",
        "propertyNames",
        "contentSchema",
    ] {
        if let Some(schema) = map.get(key) {
            inspect_schema(schema)?;
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
    jsonschema::draft202012::meta::validate(schema)
        .map_err(|e| invalid(format!("invalid schema: {e}")))?;
    let validator = Arc::new(
        jsonschema::draft202012::options()
            .with_pattern_options(jsonschema::PatternOptions::regex())
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
    if !body.is_object() {
        return Err(Error::new(
            ErrorCode::SchemaViolation,
            "document body must be a JSON object",
        ));
    }
    inspect(body, 0, &mut 0)?;
    compile(&definition.schema)?.validate(body).map_err(|e| {
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

pub fn validate_collection(
    definition: &CollectionDefinition,
    documents: &imbl::OrdMap<String, std::sync::Arc<Document>>,
) -> Result<()> {
    validate_name(&definition.name)?;
    if definition.retention_class == CollectionRetentionClass::ArchivableHistory
        && definition.write_mode != CollectionWriteMode::AppendOnly
    {
        return Err(invalid("archivable history must be append-only"));
    }
    let _validator = compile(&definition.schema)?;
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
    for (id, document) in documents {
        validate_name(id)?;
        if id != &document.id {
            return Err(invalid("document map key differs from its id"));
        }
        validate_document(definition, &document.body)?;
    }
    check_unique(&CollectionState {
        archived_documents: Default::default(),
        archived_document_bytes: 0,
        data_epoch: 0,
        definition: definition.clone(),
        documents: documents.clone(),
    })
}

pub fn check_unique(collection: &CollectionState) -> Result<()> {
    for index in collection.definition.indexes.iter().filter(|i| i.unique) {
        let mut seen: BTreeMap<Vec<Scalar>, &str> = BTreeMap::new();
        for document in collection.documents.values() {
            let mut key = Vec::new();
            for field in &index.fields {
                let mut values = indexed_values(document.body.pointer(&field.path), field.kind)?;
                if values.len() != 1 {
                    return Err(invalid("unique index has a non-scalar field"));
                }
                key.push(values.remove(0));
            }
            // Sparse uniqueness: absent fields do not participate, explicit null does.
            if key.contains(&Scalar::Missing) {
                continue;
            }
            if let Some(previous) = seen.insert(key, &document.id) {
                return Err(Error::new(
                    ErrorCode::Conflict,
                    format!(
                        "unique index {} conflicts between {} and {}",
                        index.name, previous, document.id
                    ),
                ));
            }
        }
    }
    Ok(())
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
