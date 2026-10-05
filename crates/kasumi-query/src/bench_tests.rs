//! Release-mode planner/executor measurements. Run explicitly:
//! `cargo test -p kasumi-query --release bench_ -- --ignored --nocapture`
use super::*;
use crate::source_test_utils::FixtureQueries;
use serde_json::json;
use std::time::Instant;

const DOCUMENTS: usize = 50_000;

fn collections(filler: usize) -> BTreeMap<String, CollectionState> {
    let index = |name: &str, path: &str, kind| IndexDefinition {
        name: name.into(),
        fields: vec![IndexField {
            path: path.into(),
            kind,
        }],
        unique: false,
        text: None,
    };
    let definition = CollectionDefinition {
        retention_class: CollectionRetentionClass::Operational,
        write_mode: CollectionWriteMode::Mutable,
        name: "invoices".into(),
        schema: json!({"type":"object"}),
        strict_read_audit: false,
        indexes: vec![
            index("status", "/status", ScalarType::String),
            index("region", "/region", ScalarType::String),
            index("amount", "/amount", ScalarType::Number),
            index("tags", "/tags", ScalarType::StringArray),
        ],
    };
    let statuses = ["open", "paid", "void", "draft", "late"];
    let documents = (0..DOCUMENTS)
        .map(|i| {
            let id = format!("inv-{i:06}");
            let body = json!({
                "status": statuses[i % statuses.len()],
                "region": format!("r{}", (i * 7) % 50),
                "amount": (i * 7919) % 10_000,
                "tags": [format!("t{}", i % 13)],
                "note": "x".repeat(filler),
            });
            (
                id.clone(),
                Arc::new(Document {
                    id,
                    version: 1,
                    body,
                }),
            )
        })
        .collect();
    BTreeMap::from([(
        "invoices".into(),
        CollectionState {
            archived_documents: Default::default(),
            archived_document_bytes: 0,
            data_epoch: 1,
            definition,
            documents,
        },
    )])
}

/// Median of 15 runs, in milliseconds, and the last outcome.
fn time<T>(mut run: impl FnMut() -> Result<T>, describe: impl Fn(&T) -> String) -> (f64, String) {
    let mut samples = Vec::new();
    let mut outcome = String::new();
    for _ in 0..15 {
        let started = Instant::now();
        let result = run();
        samples.push(started.elapsed().as_secs_f64() * 1000.0);
        outcome = match result {
            Ok(value) => describe(&value),
            Err(error) => format!("{:?}: {}", error.code, error.message),
        };
    }
    samples.sort_by(f64::total_cmp);
    (samples[samples.len() / 2], outcome)
}

/// The engine's path (copy the first page, pin the rest by shared handle)
/// against materializing every row, as pagination used to.
fn measure(
    name: &str,
    indexes: &QueryIndexes,
    collections: &BTreeMap<String, CollectionState>,
    query: Value,
) {
    let request: QueryRequest = serde_json::from_value(query).unwrap();
    let limits = Limits::default();
    let collection = &collections[&request.collection];
    let source = crate::source_test_utils::ResidentSource {
        collection,
        indexes,
    };
    let bound = PageBound {
        rows: request.page_size(),
        bytes: limits.max_result_bytes,
    };
    let (page, outcome) = time(
        || {
            indexes
                .execute_page(
                    &source,
                    &request,
                    &limits,
                    bound,
                    &QueryCancellation::default(),
                    &mut crate::source_test_utils::query_memory(),
                    |remaining, _| {
                        let mut pins = Vec::with_capacity(remaining.len());
                        let mut bytes = 0;
                        for (id, score) in remaining {
                            let document = collection.documents.get(id).unwrap();
                            bytes += document_clone_bytes(document)?;
                            pins.push((document.clone(), score));
                        }
                        Ok(((pins, bytes), 0))
                    },
                )
                .map_err(ReadFailure::into_query_error)
        },
        |(response, (pins, _))| {
            format!(
                "rows={} pinned={} aggregates={}",
                response.rows.len(),
                pins.len(),
                response.aggregates.len()
            )
        },
    );
    let (complete, _) = time(
        || indexes.execute_fixture(collections, &request, &limits),
        |response| response.rows.len().to_string(),
    );
    println!("BENCH {name:<34} page {page:>8.3} ms  all rows {complete:>8.3} ms  {outcome}");
}

#[test]
#[ignore = "release-mode measurement"]
fn bench_query_planner_and_materialization() {
    let small = collections(120);
    let indexes = QueryIndexes::build_fixture(&small).unwrap();
    println!("BENCH corpus: {DOCUMENTS} documents, ~200-byte bodies");
    measure(
        "eq status (10k matches) limit 20",
        &indexes,
        &small,
        json!({"collection":"invoices","filter":{"/status":"open"},"limit":20}),
    );
    measure(
        "range+eq: amount>=5000 AND region",
        &indexes,
        &small,
        json!({"collection":"invoices","filter":{"/amount":{"gte":5000},"/region":"r7"},"limit":20}),
    );
    measure(
        "bounded range 1000<=amount<1010",
        &indexes,
        &small,
        json!({"collection":"invoices","filter":{"/amount":{"gte":1000,"lt":1010}},"limit":20}),
    );
    measure(
        "count where status=open",
        &indexes,
        &small,
        json!({"collection":"invoices","filter":{"/status":"open"},"aggregate":{"n":{"count":"*"}}}),
    );
    measure(
        "sum(amount) group by status",
        &indexes,
        &small,
        json!({"collection":"invoices","group_by":["/status"],"aggregate":{"total":{"sum":"/amount"}}}),
    );
    measure(
        "status=open sort -amount limit 20",
        &indexes,
        &small,
        json!({"collection":"invoices","filter":{"/status":"open"},"sort":["-/amount"],"limit":20}),
    );
    measure(
        "status!=open (not eq) limit 20",
        &indexes,
        &small,
        json!({"collection":"invoices","filter":{"/status":{"ne":"open"}},"limit":20}),
    );
    let large = collections(1000);
    let indexes = QueryIndexes::build_fixture(&large).unwrap();
    println!("BENCH corpus: {DOCUMENTS} documents, ~1.1 KiB bodies");
    measure(
        "eq status (10k matches) limit 20",
        &indexes,
        &large,
        json!({"collection":"invoices","filter":{"/status":"open"},"limit":20}),
    );
    measure(
        "count where status=open",
        &indexes,
        &large,
        json!({"collection":"invoices","filter":{"/status":"open"},"aggregate":{"n":{"count":"*"}}}),
    );
}

#[test]
#[ignore = "release-mode measurement"]
fn bench_per_row_costs() {
    let small = collections(120);
    let documents = &small["invoices"].documents;
    let rows: Vec<_> = documents.values().take(10_000).cloned().collect();
    let time = |name: &str, f: &mut dyn FnMut()| {
        let mut samples = Vec::new();
        for _ in 0..15 {
            let started = Instant::now();
            f();
            samples.push(started.elapsed().as_secs_f64() * 1000.0);
        }
        samples.sort_by(f64::total_cmp);
        println!(
            "BENCH {name:<40} median {:>8.3} ms per 10k rows",
            samples[7]
        );
    };
    time("map lookup + Arc clone", &mut || {
        let pinned: Vec<_> = rows
            .iter()
            .map(|row| documents.get(&row.id).unwrap().clone())
            .collect();
        std::hint::black_box(pinned);
    });
    time("json_clone_bytes walk", &mut || {
        let total: u64 = rows
            .iter()
            .map(|row| allocation::json_clone_bytes(&row.body).unwrap())
            .sum();
        std::hint::black_box(total);
    });
    time("encoded length (counting writer)", &mut || {
        let mut budget = ResultBudget::new(usize::MAX);
        for row in &rows {
            budget.account(&row.body).unwrap();
        }
        std::hint::black_box(budget.bytes);
    });
    time("deep clone of body", &mut || {
        let cloned: Vec<_> = rows.iter().map(|row| row.body.clone()).collect();
        std::hint::black_box(cloned);
    });
}
