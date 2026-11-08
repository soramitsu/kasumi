//! Independent byte-for-byte replay of the raw indexer operations.
use kasumi_frozen_run::WalOp;
use std::{
    collections::BTreeMap,
    error::Error,
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};

pub(super) type Rows = BTreeMap<Vec<u8>, Vec<u8>>;

type Batch = Vec<(Vec<u8>, Option<Vec<u8>>)>;

pub(super) struct Trace {
    pub batches: Vec<Batch>,
    pub rows: Rows,
}

impl Trace {
    pub fn load(path: &Path) -> Result<Self, Box<dyn Error>> {
        let mut rows = Rows::new();
        let mut batches = Vec::new();
        for line in BufReader::new(File::open(path)?).lines() {
            let entry: serde_json::Value = serde_json::from_str(&line?)?;
            let operations = entry["ops"].as_array().ok_or("missing operations")?;
            if operations.is_empty() {
                return Err("empty block batch".into());
            }
            let mut batch = Vec::with_capacity(operations.len());
            for operation in operations {
                let fields = operation.as_array().ok_or("invalid operation")?;
                let field = |i: usize| {
                    fields
                        .get(i)
                        .and_then(|v| v.as_str())
                        .ok_or("invalid field")
                };
                let key = hex::decode(field(1)?)?;
                if key.is_empty() {
                    return Err("empty key".into());
                }
                let value = match (field(0)?, fields.len()) {
                    ("put", 3) => {
                        let value = hex::decode(field(2)?)?;
                        rows.insert(key.clone(), value.clone());
                        Some(value)
                    }
                    ("del", 2) => {
                        rows.remove(&key);
                        None
                    }
                    _ => return Err("invalid trace operation".into()),
                };
                batch.push((key, value));
            }
            batches.push(batch);
        }
        if rows.is_empty() {
            return Err("fixture must leave at least one live row".into());
        }
        Ok(Self { batches, rows })
    }

    pub fn writes(&self) -> Vec<Vec<WalOp<'_>>> {
        self.batches
            .iter()
            .map(|batch| {
                batch
                    .iter()
                    .map(|(k, v)| match v {
                        Some(bytes) => WalOp::Put(k, bytes),
                        None => WalOp::Delete(k),
                    })
                    .collect()
            })
            .collect()
    }
}
