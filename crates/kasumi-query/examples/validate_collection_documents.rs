//! Offline check of exact collection definitions against representative writes.
//!
//! Usage: cargo run -p kasumi-query --example validate_collection_documents --
//!   /absolute/collections.json /absolute/cases.json
//! This checks the current Kasumi JSON Schema compiler and document validator;
//! it does not attest a signed manifest or activate a tenant.

use kasumi_types::CollectionDefinition;
use serde::Deserialize;
use serde_json::Value;
use std::{collections::BTreeMap, env, fs, process};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: u8,
    collections: Vec<CollectionDefinition>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    name: String,
    collection: String,
    document: Value,
    admit: bool,
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let manifest_path = args.next().ok_or("missing collection manifest")?;
    let cases_path = args.next().ok_or("missing document cases")?;
    if args.next().is_some() {
        return Err("expected exactly two file arguments".into());
    }
    let manifest: Manifest = serde_json::from_slice(
        &fs::read(&manifest_path).map_err(|e| format!("cannot read collection manifest: {e}"))?,
    )
    .map_err(|e| format!("invalid collection manifest: {e}"))?;
    if manifest.format != 1 {
        return Err("collection manifest must use format 1".into());
    }
    let mut definitions = BTreeMap::new();
    for definition in &manifest.collections {
        if definitions
            .insert(definition.name.as_str(), definition)
            .is_some()
        {
            return Err("duplicate collection definition".into());
        }
    }
    let cases: Vec<Case> = serde_json::from_slice(
        &fs::read(&cases_path).map_err(|e| format!("cannot read document cases: {e}"))?,
    )
    .map_err(|e| format!("invalid document cases: {e}"))?;
    if cases.is_empty() {
        return Err("no document cases supplied".into());
    }
    for case in &cases {
        let definition = definitions
            .get(case.collection.as_str())
            .ok_or_else(|| format!("{}: unknown collection", case.name))?;
        let admitted = kasumi_query::validate_document(definition, &case.document).is_ok();
        if admitted != case.admit {
            return Err(format!(
                "{}: document admission differs from expectation",
                case.name
            ));
        }
    }
    println!("validated {} document admissions", cases.len());
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        process::exit(1);
    }
}
