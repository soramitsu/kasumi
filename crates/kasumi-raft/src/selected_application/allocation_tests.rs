//! One allocator in the Raft lib-test executable. Observation is thread-local,
//! allocation-free, unwind-safe and restricted to concrete synchronous serde.
use super::*;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};
thread_local! {
    static ACTIVE: Cell<bool> = const { Cell::new(false) };
    static LIVE: Cell<usize> = const { Cell::new(0) };
    static PEAK: Cell<usize> = const { Cell::new(0) };
    static REQUESTS: Cell<usize> = const { Cell::new(0) };
    static INVALID: Cell<bool> = const { Cell::new(false) };
}
struct Observed;
#[global_allocator]
static ALLOCATOR: Observed = Observed;
fn allocated(bytes: usize) {
    if ACTIVE.try_with(Cell::get).unwrap_or(false) {
        LIVE.with(|live| {
            live.set(live.get().checked_add(bytes).unwrap_or_else(|| {
                INVALID.with(|invalid| invalid.set(true));
                usize::MAX
            }));
            PEAK.with(|peak| peak.set(peak.get().max(live.get())));
        });
        REQUESTS.with(|count| {
            count.set(count.get().checked_add(1).unwrap_or_else(|| {
                INVALID.with(|invalid| invalid.set(true));
                usize::MAX
            }))
        });
    }
}
fn retired(bytes: usize) {
    if ACTIVE.try_with(Cell::get).unwrap_or(false) {
        LIVE.with(|live| {
            live.set(live.get().checked_sub(bytes).unwrap_or_else(|| {
                // Never silently hide an unobserved allocation's retirement.
                INVALID.with(|invalid| invalid.set(true));
                0
            }))
        });
    }
}
// SAFETY: unchanged contracts are forwarded to System; counters allocate no
// storage and conservatively count realloc's old and new backing concurrently.
unsafe impl GlobalAlloc for Observed {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let result = unsafe { System.alloc(layout) };
        if !result.is_null() {
            allocated(layout.size());
        }
        result
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let result = unsafe { System.alloc_zeroed(layout) };
        if !result.is_null() {
            allocated(layout.size());
        }
        result
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let result = unsafe { System.realloc(ptr, layout, size) };
        if !result.is_null() {
            allocated(size);
            retired(layout.size());
        }
        result
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        retired(layout.size());
    }
}
struct Reset;
impl Drop for Reset {
    fn drop(&mut self) {
        ACTIVE.with(|flag| flag.set(false));
    }
}
#[derive(Clone, Copy)]
struct Observation {
    peak: usize,
    live: usize,
    invalid: bool,
}
fn measure<T>(work: impl FnOnce() -> T) -> (T, Observation) {
    ACTIVE.with(|flag| assert!(!flag.replace(true)));
    LIVE.with(|value| value.set(0));
    PEAK.with(|value| value.set(0));
    REQUESTS.with(|value| value.set(0));
    INVALID.with(|value| value.set(false));
    let reset = Reset;
    let value = work();
    let observed = Observation {
        peak: PEAK.with(Cell::get),
        live: LIVE.with(Cell::get),
        invalid: INVALID.with(Cell::get),
    };
    drop(reset);
    (value, observed)
}
pub(crate) fn require_no_allocations<T>(work: impl FnOnce() -> T) -> T {
    let (output, observed) = measure(work);
    assert!(!observed.invalid);
    assert_eq!((observed.live, observed.peak), (0, 0));
    assert_eq!(REQUESTS.with(Cell::get), 0);
    output
}
fn census<T: DeserializeOwned + Serialize + allocation::RetainedMetadata>(
    wire: &[u8],
    success: bool,
) -> Result<()> {
    let preflight = allocation::preflight_bytes(wire.len())?;
    let (quote, observed) = measure(|| allocation::decode_quote(wire).expect("valid JSON shape"));
    assert!(
        !observed.invalid,
        "unmatched preflight allocation/retirement"
    );
    assert_eq!(observed.live, 0, "preflight scratch survived");
    assert!(observed.peak as u64 + wire.len() as u64 <= preflight);
    let mut admitted = quote.peak;
    let ((decoded_ok, retained_live, retained_quote), observed) = measure(|| {
        let decoded = crate::control::decode_canonical_admitted::<T>(wire, |value| {
            let before = REQUESTS.with(Cell::get);
            let bytes = allocation::canonical_bytes(value)?;
            assert_eq!(
                REQUESTS.with(Cell::get),
                before,
                "canonical census allocated"
            );
            admitted =
                admitted.max(quote.retained + allocation::encode_workspace(wire.len(), bytes)?);
            Ok(())
        });
        let retained_live = LIVE.with(Cell::get);
        let retained_quote = decoded
            .as_ref()
            .ok()
            .map(|value| value.retained_bytes().expect("typed retained quote"));
        let decoded_ok = decoded.is_ok();
        // Keep observation active through both actual DTO and error destruction.
        drop(decoded);
        (decoded_ok, retained_live, retained_quote)
    });
    assert_eq!(decoded_ok, success);
    assert!(!observed.invalid, "unmatched decode allocation/retirement");
    assert_eq!(
        observed.live, 0,
        "decoded payload/error survived final drop"
    );
    assert!(
        observed.peak as u64 + wire.len() as u64 <= admitted,
        "peak {}, wire {}, admitted {admitted}",
        observed.peak,
        wire.len()
    );
    if let Some(retained) = retained_quote {
        assert!(retained <= quote.retained);
        assert!(
            retained_live as u64 <= retained,
            "retained {retained_live}, typed quote {retained}"
        );
    }
    Ok(())
}

fn isolated_census(test: &str) -> Result<bool> {
    const MARKER: &str = "KASUMI_SELECTED_PROOF_DIAGNOSTIC_CHILD";
    if std::env::var_os(MARKER).is_none() {
        let module = module_path!().split_once("::").unwrap().1;
        let name = format!("{module}::{test}");
        let result = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", &name, "--nocapture"])
            .env(MARKER, "1")
            .env("RUST_BACKTRACE", "0")
            .env("RUST_LIB_BACKTRACE", "0")
            .output()?;
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(String::from_utf8_lossy(&result.stdout).contains("1 passed"));
        return Ok(true);
    }
    Ok(false)
}

#[test]
fn selected_application_allocation_census_covers_membership_and_noncanonical_defaults() -> Result<()>
{
    if isolated_census(
        "selected_application_allocation_census_covers_membership_and_noncanonical_defaults",
    )? {
        return Ok(());
    }
    let mut context = fixture::entry(1);
    context.membership = StoredMembership::new(
        Some(context.log_id),
        openraft::Membership::new(
            vec![(0..128).collect::<std::collections::BTreeSet<_>>()],
            (0..128)
                .map(|id| {
                    (
                        id,
                        BasicNode::new(format!("node-{id}-\\\"-é-{}", "p".repeat(512))),
                    )
                })
                .collect::<std::collections::BTreeMap<_, _>>(),
        ),
    );
    let cursor = AppliedCursor::Entry(context.record());
    let bytes = serde_json::to_vec(&cursor)?;
    census::<AppliedCursor>(&bytes, true)?;
    let mut omitted = serde_json::to_value(&cursor)?;
    omitted["Entry"].as_object_mut().unwrap().remove("previous");
    let bytes = serde_json::to_vec(&omitted)?;
    let decoded: AppliedCursor = serde_json::from_slice(&bytes)?;
    assert!(allocation::canonical_bytes(&decoded)? > bytes.len() as u64);
    drop(decoded);
    // Typed decode accepts omitted Option, canonical output grows. Its actual
    // size is counted/claimed before allocation and comparison rejects it.
    census::<AppliedCursor>(&bytes, false)?;
    Ok(())
}

#[test]
fn selected_application_allocation_census_covers_expanding_typed_diagnostics() -> Result<()> {
    if isolated_census("selected_application_allocation_census_covers_expanding_typed_diagnostics")?
    {
        return Ok(());
    }
    for text in [
        "\u{7f}".repeat(64 << 10),
        "\0\n\r\t".repeat(16 << 10),
        "\u{ad}\u{10ffff}é".repeat(8 << 10),
    ] {
        let mut wire = b"{\"version\":".to_vec();
        wire.extend(serde_json::to_vec(&text)?);
        wire.extend_from_slice(b",\"sha256\":\"a\",\"id\":\"b\",\"bytes\":1,\"chunks\":1}");
        census::<SnapshotManifest>(&wire, false)?;
    }
    Ok(())
}
