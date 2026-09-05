//! Focused mechanism benchmark; no persistence, validation, indexes, or network.
//! Run: cargo run --release -p kasumi-engine --example map_sharing -- OUTPUT.json
use imbl::HashMap;
use kasumi_types::Document;
use serde_json::{Value, json};
use std::{
    collections::hash_map::RandomState,
    hint::black_box,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

const DOCUMENTS: usize = 100_000;
const UPDATES: usize = 8_192;
const SAMPLES: usize = 5;
static DEEP_CLONES: AtomicU64 = AtomicU64::new(0);

fn document(index: usize, bytes: usize) -> Document {
    Document {
        id: index.to_string(),
        version: 1,
        body: json!({"ordinal":index,"array":[1,2,3,4],"padding":"x".repeat(bytes.saturating_sub(64))}),
    }
}

fn trial<V: Clone>(initial: &HashMap<String, V>, updates: Vec<(String, V)>, batch: usize) -> u64 {
    let mut current = initial.clone();
    let mut updates = updates.into_iter();
    let started = Instant::now();
    while updates.len() != 0 {
        // Keep the preceding generation alive during all updates in one batch.
        // The old generation is released after the atomic batch is complete.
        let previous = current.clone();
        for (key, value) in updates.by_ref().take(batch) {
            black_box(current.insert(key, value));
        }
        black_box(&current);
        drop(previous);
    }
    let elapsed = started.elapsed().as_nanos() as u64;
    black_box(current.len());
    elapsed
}

fn updates<V>(bytes: usize, wrap: impl Fn(Document) -> V) -> Vec<(String, V)> {
    (0..UPDATES)
        .map(|n| {
            let id = (n * 7919) % DOCUMENTS;
            let mut document = document(id, bytes);
            document.version = 2;
            (id.to_string(), wrap(document))
        })
        .collect()
}

struct Counted(Document);
impl Clone for Counted {
    fn clone(&self) -> Self {
        DEEP_CLONES.fetch_add(1, Ordering::Relaxed);
        Self(self.0.clone())
    }
}
fn diagnostics(hasher: RandomState, batch: usize) -> (u64, u64) {
    // Untimed instrumented run, separate from timing results. Counted::clone is
    // called only when a stored value is copied, not when a new write is built.
    let mut owned = HashMap::with_hasher(hasher.clone());
    for n in 0..DOCUMENTS {
        owned.insert(n.to_string(), Counted(document(n, 128)));
    }
    let input = updates(128, Counted);
    DEEP_CLONES.store(0, Ordering::Relaxed);
    trial(&owned, input, batch);
    let owned_count = DEEP_CLONES.load(Ordering::Relaxed);
    drop(owned);
    let mut shared = HashMap::with_hasher(hasher);
    for n in 0..DOCUMENTS {
        shared.insert(n.to_string(), Arc::new(Counted(document(n, 128))));
    }
    let input = updates(128, |doc| Arc::new(Counted(doc)));
    DEEP_CLONES.store(0, Ordering::Relaxed);
    trial(&shared, input, batch);
    (owned_count, DEEP_CLONES.load(Ordering::Relaxed))
}

fn main() -> anyhow::Result<()> {
    let output = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "benchmarks/results/map-sharing.json".into());
    let hasher = RandomState::new();
    let mut results = Vec::<Value>::new();
    for bytes in [1024, 8192] {
        let mut owned = HashMap::with_hasher(hasher.clone());
        let mut shared = HashMap::with_hasher(hasher.clone());
        for n in 0..DOCUMENTS {
            owned.insert(n.to_string(), document(n, bytes));
            shared.insert(n.to_string(), Arc::new(document(n, bytes)));
        }
        for batch in [1, 256] {
            let mut owned_ns = Vec::new();
            let mut shared_ns = Vec::new();
            for sample in 0..SAMPLES {
                // Allocate incoming write bodies outside timing. Alternate order
                // to reduce systematic cache/thermal bias within this process.
                if sample % 2 == 0 {
                    owned_ns.push(trial(&owned, updates(bytes, |doc| doc), batch));
                    shared_ns.push(trial(&shared, updates(bytes, Arc::new), batch));
                } else {
                    shared_ns.push(trial(&shared, updates(bytes, Arc::new), batch));
                    owned_ns.push(trial(&owned, updates(bytes, |doc| doc), batch));
                }
            }
            let median = |values: &[u64]| {
                let mut values = values.to_vec();
                values.sort_unstable();
                values[values.len() / 2] as f64 / UPDATES as f64
            };
            let owned_median = median(&owned_ns);
            let shared_median = median(&shared_ns);
            eprintln!(
                "{bytes} bytes, batch {batch}: owned {owned_median:.1} ns/update; Arc {shared_median:.1} ns/update; {:.2}x",
                owned_median / shared_median
            );
            results.push(json!({"document_target_bytes":bytes,"batch_operations":batch,"owned_samples_ns":owned_ns,"arc_samples_ns":shared_ns,
                "owned_median_ns_per_update":owned_median,"arc_median_ns_per_update":shared_median,"ratio_owned_over_arc":owned_median/shared_median}));
        }
    }
    let mut clone_counts = Vec::new();
    for batch in [1, 256] {
        let (owned, shared) = diagnostics(hasher.clone(), batch);
        clone_counts.push(json!({"batch_operations":batch,"owned_payload_clones":owned,"arc_payload_clones":shared,"owned_payload_clones_per_update":owned as f64/UPDATES as f64}));
    }
    let evidence = json!({"mechanism":"imbl 7.0.1 immutable-generation leaf updates; identical RandomState cloned across variants",
        "documents":DOCUMENTS,"updates_per_sample":UPDATES,"samples":SAMPLES,"architecture":std::env::consts::ARCH,"os":std::env::consts::OS,
        "limitations":"Microbenchmark excludes validation, Raft, redb durability and index updates. Timing is exploratory, not publication capacity evidence; inspect competing_work metadata. RandomState is identical within a run but randomized between runs.",
        "competing_work":std::env::var("KASUMI_MAP_BENCH_CONTEXT").unwrap_or_else(|_| "Machine isolation was not asserted; record concurrent workloads separately.".into()),
        "results":results,"untimed_deep_clone_diagnostics":clone_counts});
    if let Some(parent) = std::path::Path::new(&output).parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&output, serde_json::to_vec_pretty(&evidence)?)?;
    println!("{output}");
    Ok(())
}
