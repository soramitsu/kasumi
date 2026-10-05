use super::*;
use serde_json::json;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

struct Counting;
#[global_allocator]
static ALLOCATOR: Counting = Counting;
#[derive(Clone, Copy, Default)]
struct Counts {
    live: usize,
    peak: usize,
    invalid: bool,
    allocations: usize,
}
thread_local! {
    static COUNTS: Cell<Option<Counts>> = const { Cell::new(None) };
}
fn allocated(bytes: usize) {
    let _ = COUNTS.try_with(|slot| {
        if let Some(mut value) = slot.get() {
            if let Some(live) = value.live.checked_add(bytes) {
                value.live = live;
                value.peak = value.peak.max(live);
            } else {
                value.invalid = true;
            }
            if let Some(count) = value.allocations.checked_add(1) {
                value.allocations = count;
            } else {
                value.invalid = true;
            }
            slot.set(Some(value));
        }
    });
}
fn deallocated(bytes: usize) {
    let _ = COUNTS.try_with(|slot| {
        if let Some(mut value) = slot.get() {
            if let Some(live) = value.live.checked_sub(bytes) {
                value.live = live;
            } else {
                value.invalid = true;
            }
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
            crate::recovery_allocation_watch::allocated(p as usize, layout.size(), layout.align());
        }
        p
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc_zeroed(layout) };
        if !p.is_null() {
            allocated(layout.size());
            crate::recovery_allocation_watch::allocated(p as usize, layout.size(), layout.align());
        }
        p
    }
    unsafe fn realloc(&self, p: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let next = unsafe { System.realloc(p, layout, size) };
        if !next.is_null() {
            allocated(size); // model allocate/copy/free even for in-place growth
            deallocated(layout.size());
            crate::recovery_allocation_watch::deallocated(p as usize);
            crate::recovery_allocation_watch::allocated(next as usize, size, layout.align());
        }
        next
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        unsafe { System.dealloc(p, layout) };
        deallocated(layout.size());
        crate::recovery_allocation_watch::deallocated(p as usize);
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

fn body() -> Value {
    json!({
        "format":1,"tenant":"tenant-東京",
        "route":{"incarnation":"b63744c9-1caf-4a95-884b-c7c4d261a12f","mode":"local","voters":[1]},
        "nodes":{"1":{"endpoint":"https://node.invalid/","failure_domain":"rack","certificate_pins":["01".repeat(32)]}},
        "initial_policy":{"grants":[{"principal":"owner","collection":null,"actions":["read","write","admin","audit"]}],"strict_read_audit":true},
        "initial_limits":kasumi_types::Limits::default(),
        "application_keys":{"kind":"file","identity":"file-東京-\"\\"},
        "custody_keys":{"kind":"transit","endpoint":"https://vault.invalid","key_name":"custody"},
        "authority_id":null
    })
}
fn check(value: &Value) {
    let measuring = Measurement::begin();
    let bound = quote(value).unwrap();
    let counts = measuring.finish();
    assert!(
        !counts.invalid,
        "quote census encountered unobserved retirement/overflow"
    );
    assert_eq!(counts.allocations, 0, "before-decode quote allocated");
    let measuring = Measurement::begin();
    let decoded = Proposal::deserialize(value);
    let actual = match &decoded {
        Ok(proposal) => proposal.digest().map_err(|error| error.to_string()),
        Err(error) => Err(error.to_string()),
    };
    if let Ok(digest) = &actual {
        assert!(backing(digest.capacity()).unwrap() <= bound.digest);
    }
    drop((actual, decoded));
    let counts = measuring.finish();
    assert!(
        !counts.invalid,
        "decode census encountered unobserved retirement/overflow"
    );
    assert_eq!(
        counts.live, 0,
        "decoder/digest did not retire its allocations"
    );
    assert!(
        counts.peak as u64 <= bound.peak,
        "peak={} quote={}",
        counts.peak,
        bound.peak
    );
    let expected = serde_json::from_value::<Proposal>(value.clone())
        .map_err(|e| e.to_string())
        .and_then(|p| p.digest().map_err(|e| e.to_string()));
    let decoded = Proposal::deserialize(value)
        .map_err(|e| e.to_string())
        .and_then(|p| p.digest().map_err(|e| e.to_string()));
    assert_eq!(
        decoded, expected,
        "borrowed decoding changed existing result/error"
    );
}
#[test]
fn approval_workspace_covers_concrete_decode_hash_and_malformed_inputs() {
    const CHILD: &str = "KASUMI_APPROVAL_ALLOCATION_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "administration::configured_tenant_enrollment::approval::tests::approval_workspace_covers_concrete_decode_hash_and_malformed_inputs", "--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .env("RUST_BACKTRACE", "0")
            .env("RUST_LIB_BACKTRACE", "0")
            .output().unwrap();
        assert!(
            output.status.success(),
            "isolated approval allocation census failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(
            stdout.contains("1 passed"),
            "child must execute its exact census: {stdout}"
        );
        return;
    }
    check(&body());
    check_work_owner(&body());
    let mut value = body();
    value["nodes"]["1"]["endpoint"] = json!("https://例え.テスト/");
    check(&value);
    for count in [1, 3, 4, 5, 11, 12, 256, 2048] {
        let mut value = body();
        let grant = value["initial_policy"]["grants"][0].clone();
        value["initial_policy"]["grants"] = json!(vec![grant; count]);
        value["application_keys"] = json!(
            (0..count)
                .map(|n| (format!("field-{n}"), json!([n, "payload"])))
                .collect::<std::collections::BTreeMap<_, _>>()
        );
        check(&value);
        value["application_keys"] = json!(
            (0..count)
                .map(|n| json!([n, [n], [[], "nested"]]))
                .collect::<Vec<_>>()
        );
        check(&value);
    }
    let mut value = body();
    value["application_keys"] =
        serde_json::from_str(r#"{"decimal":1.2300,"large":123456789012345678901234567890}"#)
            .unwrap();
    value["custody_keys"] = serde_json::from_str(r#"[9.2500e+42,{"key\"":"value"}]"#).unwrap();
    check(&value);
    let fields = [
        "format",
        "tenant",
        "route",
        "nodes",
        "initial_policy",
        "initial_limits",
        "application_keys",
        "custody_keys",
        "authority_id",
    ];
    check(&Value::Array(
        fields.iter().map(|field| value[*field].clone()).collect(),
    ));
    for invalid in [
        Value::Null,
        json!({"format":"invalid"}),
        json!({"format":1,"tenant":[]}),
    ] {
        check(&invalid);
    }
    for field in ["route", "initial_policy", "nodes"] {
        let mut value = body();
        value[field] = json!("\u{1}".repeat(16 << 10));
        check(&value);
        check_work_owner(&value);
    }
    let mut value = body();
    value
        .as_object_mut()
        .unwrap()
        .insert("\u{1}".repeat(16 << 10), Value::Null);
    check(&value);
    let mut value = body();
    value["route"]["voters"] = json!(vec![1; 2048]);
    check(&value);
    let mut value = body();
    value["initial_policy"]["grants"][0]["actions"] = json!(vec!["read"; 2048]);
    check(&value);
    let mut value = body();
    value["initial_policy"]["grants"] = json!([]);
    check(&value);
    check_work_owner(&value);
    let mut value = body();
    value["nodes"]["1"]["certificate_pins"] = json!(vec!["01".repeat(32); 2048]);
    check(&value);
    let mut value = body();
    value["nodes"]["1"] = Value::Array(
        ["endpoint", "failure_domain", "certificate_pins"]
            .iter()
            .map(|k| value["nodes"]["1"][*k].clone())
            .collect(),
    );
    value["route"] = Value::Array(
        ["incarnation", "mode", "voters"]
            .iter()
            .map(|k| value["route"][*k].clone())
            .collect(),
    );
    value["initial_policy"] = Value::Array(
        ["grants", "strict_read_audit"]
            .iter()
            .map(|k| value["initial_policy"][*k].clone())
            .collect(),
    );
    check(&value);
}

fn check_work_owner(value: &Value) {
    let bound = quote(value).unwrap();
    let node = node(source_bytes(value) + bound.peak);
    let input = source(&node, value);
    let baseline = node.snapshot();
    // Keep the original admitted source outside this census. Work owns one
    // clone of that exact handle, so its retirement cannot free unobserved input.
    let measuring = Measurement::begin();
    let mut work = Work::new(&node, input.clone()).unwrap();
    match work.evaluate(&node, None) {
        Ok(()) => {
            let output = work.finish();
            assert!(backing(output.digest.capacity()).unwrap() <= bound.digest);
            drop(output);
        }
        Err(error) => {
            let error = work.fail(error);
            // Downcast moves the whole original-error-plus-grant owner.
            drop(error.downcast::<Failure>().unwrap());
        }
    }
    let counts = measuring.finish();
    assert!(
        !counts.invalid,
        "owner census encountered unobserved retirement/overflow"
    );
    assert_eq!(
        counts.live, 0,
        "work/owner final drop must retire all observed backing"
    );
    assert!(
        counts.peak as u64 <= bound.peak,
        "owner peak={} quote={}",
        counts.peak,
        bound.peak
    );
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);
    assert_eq!(node.snapshot().inflight_operations, 0);
    assert_eq!(
        node.snapshot().live_reservations,
        baseline.live_reservations
    );
    drop(input);
}

fn node(payload: u64) -> Arc<NodeAdmission> {
    NodeAdmission::new(
        kasumi_engine::test_utils::admission_config_with_bookkeeping(
            kasumi_engine::admission::AdmissionConfig {
                max_inflight_bytes: Some(payload),
                max_inflight_operations: 1,
                max_reservations: 16,
                max_snapshot_startups: 2,
                max_startup_scopes: 2,
                ..Default::default()
            },
        )
        .unwrap(),
    )
    .unwrap()
}
struct Source {
    document: kasumi_types::Document,
    _reservation: Reservation,
}
impl kasumi_types::AdmittedDocumentOwner for Source {
    fn document(&self) -> &kasumi_types::Document {
        &self.document
    }
}
fn source_bytes(value: &Value) -> u64 {
    kasumi_query::document_parts_clone_bytes("tenant-東京", value).unwrap()
        + backing(size_of::<Source>() + 2 * size_of::<usize>()).unwrap()
}
fn source(node: &Arc<NodeAdmission>, value: &Value) -> SharedDocument {
    let reservation = node.reserve_resident(source_bytes(value)).unwrap();
    SharedDocument::from_admitted_owner(Arc::new(Source {
        document: kasumi_types::Document {
            id: "tenant-東京".into(),
            version: 7,
            body: value.clone(),
        },
        _reservation: reservation,
    }))
}
#[test]
fn approval_denial_cancel_error_and_digest_retire_their_real_owners() {
    let value = body();
    let required = quote(&value).unwrap().peak;
    let denied = node(source_bytes(&value) + required - 1);
    let baseline = denied.snapshot();
    let input = source(&denied, &value);
    let error = Work::new(&denied, input)
        .err()
        .expect("one-byte shortage must deny before decode");
    assert_eq!(
        error.downcast_ref::<Error>().unwrap().code,
        ErrorCode::ResourceExhausted
    );
    assert_eq!(denied.snapshot().reserved_bytes, baseline.reserved_bytes);
    assert_eq!(
        denied.snapshot().live_reservations,
        baseline.live_reservations
    );

    let node = node(source_bytes(&value) + required);
    let baseline = node.snapshot();
    let mut work = Work::new(&node, source(&node, &value)).unwrap();
    work.token.cancel();
    let error = work.evaluate(&node, Some("tenant-東京")).unwrap_err();
    let error = work.fail(error);
    assert_eq!(node.snapshot().inflight_operations, 0);
    assert!(node.snapshot().reserved_bytes > baseline.reserved_bytes);
    let error = error.downcast::<Failure>().unwrap();
    assert_eq!(
        error.validation_error().unwrap().code,
        ErrorCode::ResourceExhausted
    );
    drop(error);
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);

    let mut work = Work::new(&node, source(&node, &value)).unwrap();
    let error = work.evaluate(&node, Some("other-tenant")).unwrap_err();
    assert_eq!(error.to_string(), "Control enrollment identity differs");
    let error = work.fail(error).downcast::<Failure>().unwrap();
    assert!(
        error.validation_error().is_none(),
        "original anyhow identity failure stays unclassified"
    );
    assert_eq!(node.snapshot().inflight_operations, 0);
    std::thread::spawn(move || drop(error)).join().unwrap();
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);

    let mut invalid = value.clone();
    invalid["initial_policy"]["grants"] = json!([]);
    let mut work = Work::new(&node, source(&node, &invalid)).unwrap();
    let error = work.evaluate(&node, Some("tenant-東京")).unwrap_err();
    let mut owned = work.fail(error);
    assert!(
        owned.downcast_mut::<Error>().is_none(),
        "original mutable error extraction is unavailable"
    );
    let classified = crate::administration::administrative_error(&owned).unwrap();
    assert_eq!(classified.code, ErrorCode::InvalidArgument);
    assert!(std::ptr::eq(
        classified,
        owned
            .downcast_ref::<Failure>()
            .unwrap()
            .validation_error()
            .unwrap()
    ));
    let error = owned.downcast::<Failure>().unwrap();
    assert_eq!(
        error.validation_error().unwrap().code,
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        error.validation_error().unwrap().message,
        "tenant needs an administrator"
    );
    assert_eq!(
        error.to_string(),
        error.validation_error().unwrap().to_string()
    );
    assert_eq!(node.snapshot().inflight_operations, 0);
    assert_eq!(
        node.snapshot().live_reservations,
        baseline.live_reservations + 1
    );
    drop(error);
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);

    let mut work = Work::new(&node, source(&node, &value)).unwrap();
    work.evaluate(&node, Some("tenant-東京")).unwrap();
    let output = work.finish();
    assert_eq!(node.snapshot().inflight_operations, 0);
    assert_eq!(
        node.snapshot().live_reservations,
        baseline.live_reservations + 1
    );
    assert_eq!(
        node.snapshot().reserved_bytes - baseline.reserved_bytes,
        quote(&value).unwrap().digest
    );
    std::thread::spawn(move || {
        assert!(output.digest().starts_with("enrollment-v1-"));
        drop(output);
    })
    .join()
    .unwrap();
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);
    assert_eq!(
        node.snapshot().live_reservations,
        baseline.live_reservations
    );
}

// Share the one Server test allocator with sibling concrete topology tests.
// Observation still encloses complete allocation lifetimes on this thread.
pub(super) fn measure_topology<T>(work: impl FnOnce() -> T) -> (T, usize, usize, bool, usize) {
    let measuring = Measurement::begin();
    let result = work();
    let counts = measuring.finish();
    (
        result,
        counts.live,
        counts.peak,
        counts.invalid,
        counts.allocations,
    )
}
