//! Real allocator census for borrowed ControlTopology decode+validation.
//! Source fixtures exist before observation; no source clone is counted as output.
use kasumi_types::control_topology::ControlTopology;
use serde::Deserialize;
use serde_json::{Value, json};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

struct Counting;
#[global_allocator]
static ALLOCATOR: Counting = Counting;
#[derive(Clone, Copy, Default)]
struct Counts {
    live: i64,
    peak: i64,
    allocations: usize,
}
thread_local! {
    static COUNTS: Cell<Option<Counts>> = const { Cell::new(None) };
}
fn allocated(bytes: usize) {
    let _ = COUNTS.try_with(|slot| {
        if let Some(mut value) = slot.get() {
            value.live += bytes as i64;
            value.peak = value.peak.max(value.live);
            value.allocations += 1;
            slot.set(Some(value));
        }
    });
}
fn deallocated(bytes: usize) {
    let _ = COUNTS.try_with(|slot| {
        if let Some(mut value) = slot.get() {
            value.live -= bytes as i64;
            slot.set(Some(value));
        }
    });
}
// SAFETY: every operation forwards unchanged to System; observation is only
// thread-local fixed-size arithmetic, with no allocation or pointer access.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            allocated(layout.size());
        }
        p
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc_zeroed(layout) };
        if !p.is_null() {
            allocated(layout.size());
        }
        p
    }
    unsafe fn realloc(&self, p: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let next = unsafe { System.realloc(p, layout, size) };
        if !next.is_null() {
            allocated(size); // model allocate/copy/free even for in-place growth
            deallocated(layout.size());
        }
        next
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        unsafe { System.dealloc(p, layout) };
        deallocated(layout.size());
    }
}
struct Measurement;
impl Measurement {
    fn begin() -> Self {
        COUNTS.with(|slot| {
            assert!(slot.get().is_none());
            slot.set(Some(Counts::default()));
        });
        Self
    }
    fn finish(self) -> Counts {
        COUNTS.with(|slot| slot.take().unwrap())
    }
}
impl Drop for Measurement {
    fn drop(&mut self) {
        COUNTS.with(|slot| slot.set(None));
    }
}
fn check(value: &Value) {
    let sizing = Measurement::begin();
    let quote = ControlTopology::memory_from_value(value).unwrap();
    let counts = sizing.finish();
    assert_eq!(counts.allocations, 0, "borrowed census allocated");
    assert_eq!(counts.live, 0);
    // Prior algorithm is the oracle for both accepted positional/map shapes and
    // exact malformed/validation messages; it executes outside the measurement.
    let expected = serde_json::from_value::<ControlTopology>(value.clone())
        .map_err(|error| error.to_string())
        .and_then(|value| value.validate().map_err(|error| error.to_string()));
    let measuring = Measurement::begin();
    let decoded = ControlTopology::deserialize(value);
    if decoded.is_ok() {
        let live = COUNTS.with(|slot| slot.get().unwrap().live);
        assert!(
            live as u64 <= quote.retained_bytes,
            "retained={live} quote={quote:?}"
        );
    }
    let actual = match &decoded {
        Ok(topology) => topology.validate().map_err(|error| error.to_string()),
        Err(error) => Err(error.to_string()),
    };
    // Error display materialization above is part of this test's peak too.
    let agrees = actual == expected;
    drop((actual, decoded));
    let counts = measuring.finish();
    assert!(agrees, "decoder changed prior behavior");
    assert!(
        counts.peak as u64 <= quote.peak_bytes,
        "peak={} quote={quote:?}",
        counts.peak
    );
    assert_eq!(
        counts.live, 0,
        "decode/validation retained allocations after drop"
    );
}
fn topology(routes: usize) -> Value {
    let mut tenants = serde_json::Map::new();
    for id in 0..routes {
        tenants.insert(format!("tenant-{id}"), json!({"incarnation":"00000000-0000-4000-8000-000000000001","mode":"local","voters":[1]}));
    }
    json!({"nodes":{"1":{"endpoint":"https://node.invalid:8443/","failure_domain":"zone","certificate_pins":["01".repeat(32)]}},"tenants":tenants})
}
#[test]
fn concrete_topology_quote_covers_typed_containers_positional_and_invalid_inputs() {
    for routes in [0, 1, 11, 12, 64, 1024] {
        check(&topology(routes));
    }
    let value = topology(1);
    check(&json!([value["nodes"], value["tenants"]]));
    let mut positional = topology(1);
    positional["nodes"]["1"] = json!(["https://node.invalid/", "zone", ["01".repeat(32)]]);
    positional["tenants"]["tenant-0"] =
        json!(["00000000-0000-4000-8000-000000000001", "local", [1]]);
    check(&positional);
    for endpoint in [
        "https://例え.テスト/",
        "https://xn--bcher-kva.invalid/",
        "https://node.invalid:65536/",
        "not a URL",
    ] {
        let mut value = topology(1);
        value["nodes"]["1"]["endpoint"] = json!(endpoint);
        check(&value);
    }
    // Fail at a late node while prior global pin nodes and this URL result live.
    let mut late = topology(1);
    for id in 2..=64u64 {
        late["nodes"].as_object_mut().unwrap().insert(id.to_string(), json!({"endpoint":format!("https://node-{id}.invalid/"),"failure_domain":format!("zone-{id}"),"certificate_pins":[format!("{id:064x}")]}));
    }
    for (field, value) in [
        ("endpoint", json!("https://bad.invalid/path")),
        ("certificate_pins", json!(["bad"])),
        ("failure_domain", json!("")),
    ] {
        let mut invalid = late.clone();
        invalid["nodes"]["64"][field] = value;
        check(&invalid);
    }
    let mut duplicate = topology(1);
    duplicate["nodes"]["1"]["certificate_pins"] = json!(vec!["01".repeat(32); 2048]);
    duplicate["tenants"]["tenant-0"]["voters"] = json!(vec![1; 2048]);
    check(&duplicate);
    let mut invalid = topology(1);
    invalid["nodes"]["1"]["certificate_pins"] =
        json!((0..2048).map(|i| i.to_string()).collect::<Vec<_>>());
    check(&invalid);
    for body in [
        Value::Null,
        json!({"nodes":[],"tenants":{}}),
        json!({"nodes":{"01":{}},"tenants":{}}),
        json!({"nodes":{},"tenants":{"bad":["invalid","local",[]]}}),
    ] {
        check(&body);
    }
    let mut error = topology(1);
    error
        .as_object_mut()
        .unwrap()
        .insert("\u{1}".repeat(16 << 10), json!(null));
    check(&error);
    let mut error = topology(1);
    error["tenants"]["tenant-0"]["mode"] = json!("\u{1}".repeat(16 << 10));
    check(&error);
    let mut error = topology(1);
    error["nodes"]["1"]["failure_domain"] = json!(["nested"]);
    check(&error);
    let mut error = topology(1);
    error["tenants"]["tenant-0"]["voters"] = serde_json::from_str("[1e100000]").unwrap();
    check(&error);
}
