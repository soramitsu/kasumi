//! Shared raw-map baseline for the embedded and installed benchmark drivers.
use crate::{Measurement, Samples};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{collections::HashMap, hint::black_box, time::Instant};

pub fn document_body(ordinal: usize, version: usize, tenants: usize) -> Value {
    let local_ordinal = ordinal / tenants;
    let mut value = json!({"ordinal":ordinal,"version":version,"text":format!("searchable document token{:04} feature{:04} {} revision{version} ",local_ordinal%1000,local_ordinal%1000,if local_ordinal.is_multiple_of(1000) {"図書館"}else{"動物"}),"padding":""});
    let encoded = serde_json::to_vec(&value).unwrap().len();
    value["padding"] = Value::String("x".repeat(1024usize.saturating_sub(encoded)));
    value
}

pub struct RawCorpus {
    tenants: Vec<HashMap<String, Value>>,
    documents: usize,
}

impl RawCorpus {
    pub fn new(tenants: usize) -> Result<Self> {
        ensure!((1..=1_000).contains(&tenants), "invalid raw tenant count");
        Ok(Self {
            tenants: (0..tenants).map(|_| HashMap::new()).collect(),
            documents: 0,
        })
    }

    pub fn load(&mut self, documents: usize) -> Result<usize> {
        let tenants = self.tenants.len();
        ensure!(
            self.documents == 0 && (tenants..=1_000_000).contains(&documents),
            "invalid raw corpus"
        );
        let mut bytes = 0;
        for ordinal in 0..documents {
            let value = document_body(ordinal, 0, tenants);
            bytes += serde_json::to_vec(&value)?.len();
            self.tenants[ordinal % tenants].insert(ordinal.to_string(), value);
        }
        self.documents = self.tenants.iter().map(HashMap::len).sum();
        ensure!(
            self.documents == documents,
            "raw corpus cardinality differs"
        );
        Ok(bytes)
    }

    pub fn measure(&self, operations: usize, retain_samples: bool) -> Result<Measurement> {
        ensure!(
            self.documents > 0 && (1..=1_000_000).contains(&operations),
            "invalid raw workload"
        );
        let keys: Vec<_> = (0..operations)
            .map(|i| ((i.wrapping_mul(7919)) % self.documents).to_string())
            .collect();
        let mut samples = Samples::new("raw_hashmap_borrowed_lookup", keys.len());
        for (i, key) in keys.iter().enumerate() {
            let ordinal = (i.wrapping_mul(7919)) % self.documents;
            let start = Instant::now();
            let result = black_box(self.tenants[ordinal % self.tenants.len()].get(key))
                .context("raw document missing")
                .map(|_| ());
            if !samples.record(start.elapsed(), result) {
                break;
            }
        }
        Ok(samples.finish_with_samples(retain_samples))
    }
}
