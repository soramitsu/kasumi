//! Real allocator qualification for the pinned default endpoint parser only.
//! One test owns all parses in this executable: the first Unicode parse is cold.
use kasumi_types::control_topology::ControlTopology;
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
    exact_size: usize,
    exact_hits: usize,
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
            value.exact_hits += usize::from(bytes == value.exact_size);
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
    fn begin(exact_size: usize) -> Self {
        COUNTS.with(|slot| {
            assert!(slot.get().is_none());
            slot.set(Some(Counts {
                exact_size,
                ..Counts::default()
            }));
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
fn check(input: &str, accepted: bool, exact_size: usize) -> Counts {
    let measuring = Measurement::begin(0);
    let quote = ControlTopology::endpoint_workspace_bytes(input).unwrap();
    let sizing = measuring.finish();
    assert_eq!(sizing.allocations, 0, "quote must not execute the parser");
    assert_eq!(sizing.live, 0);

    let measuring = Measurement::begin(exact_size);
    let parsed = url::Url::parse(input);
    let actual = parsed.is_ok();
    drop(parsed); // include the actual returned serialization and its retirement
    let counts = measuring.finish();
    assert_eq!(actual, accepted, "fixture classification: {input:?}");
    assert!(
        counts.peak as u64 <= quote,
        "len={} peak={} quote={quote}",
        input.len(),
        counts.peak
    );
    assert_eq!(counts.live, 0, "parser retained heap after result drop");
    counts
}

fn report(label: &str, input: &str, counts: Counts) {
    eprintln!(
        "endpoint_workspace probe={label} bytes={} quote={} peak={} allocations={}",
        input.len(),
        ControlTopology::endpoint_workspace_bytes(input).unwrap(),
        counts.peak,
        counts.allocations
    );
}

#[test]
fn endpoint_quote_covers_first_use_valid_invalid_and_growth_paths() {
    // No URL/IDNA entry point has run earlier in this executable. This includes
    // any real first-use allocation; compiled ICU tables are static borrowed data.
    let cold = check("https://例え.テスト/", true, 0);
    assert!(cold.allocations > 0);
    report("cold_unicode", "https://例え.テスト/", cold);
    let warm = check("https://例え.テスト/", true, 0);
    assert!(warm.allocations > 0);
    report("warm_unicode", "https://例え.テスト/", warm);
    for (label, input) in [
        ("plain_https", "https://node.invalid:8443/"),
        ("ace", "https://xn--bcher-kva.invalid/"),
        ("escaped_unicode", "https://%E4%BE%8B%E3%81%88.invalid/"),
    ] {
        report(label, input, check(input, true, 0));
    }
    for (input, accepted) in [
        ("", false),
        ("not a URL", false),
        ("https://node.invalid:8443/", true),
        ("https://NODE.invalid/", true),
        ("https://node.invalid:443", true),
        ("https://node.invalid:65536/", false),
        ("http://node.invalid:80/", true),
        ("ftp:node.invalid/path", true),
        ("HTTPS:\\\\user:pass@node.invalid:443/path?q=é", true),
        ("https:\t/\n/first@second@node.invalid/", true),
        ("https://node.invalid\\next", true),
        ("https://%65xample.invalid/", true),
        ("https://ab--node.invalid/", true),
        ("https://x\tn--bcher-kva.invalid/", true),
        ("https://127.0.0.1/", true),
        ("https://1.2.3.4.5/", false),
        ("https://[::1]/", true),
        ("https://[::1/", false),
        ("https://[[::1]]/", false),
        ("https://]node:90/", false),
        ("https://node[broken:90/path", false),
        ("https://[::1]:notaport/", false),
        ("\u{0000}\u{001f}https://node.invalid/\u{000b}", true),
        ("ht\ttps://node.invalid/", true),
        ("https://%E4%BE%8B%E3%81%88.invalid/", true),
        ("https://no\tde.inva\nlid/", true),
        ("https://node.invalid/ \n", true),
        ("https://user:pass@node.invalid/path?q=é#fragment", true),
        ("file://node.invalid/東京", true),
        ("custom://node.invalid/東京?q=é", true),
        ("data:text/plain,東京", true),
        ("https://xn--bcher-kva.invalid/", true),
        ("https://a\u{200d}.invalid/", false),
        ("https://aא.invalid/", false),
    ] {
        check(input, accepted, 0);
    }
    // Accepted here means Url::parse succeeds, not that Control accepts a node
    // with a non-TLS scheme, credentials, path, query or fragment.
    for count in [
        8, 9, 17, 18, 59, 60, 127, 128, 253, 254, 511, 512, 1023, 1024,
    ] {
        let labels = format!("https://{}invalid/", "É.".repeat(count));
        check(&labels, true, 0);
        let numeric = format!("https://{}1/", "1.".repeat(count));
        check(&numeric, false, 0);
    }
    for count in [255, 256, 511, 512, 1023, 1024, 4095, 4096, 65535, 262144] {
        check(&format!("https://{}.invalid/", "a".repeat(count)), true, 0);
        if count <= 65535 {
            let input = format!(
                "https://node.invalid/{}?{}#{}",
                "東京".repeat(count),
                "é".repeat(count),
                "é".repeat(count)
            );
            let counts = check(&input, true, 0);
            if count == 65535 {
                report("large_path_query_fragment", &input, counts);
            }
        }
    }
    for (label, host) in [
        ("unicode_host_long_path", "例え.テスト"),
        ("ace_host_long_path", "xn--bcher-kva.invalid"),
    ] {
        let input = format!(
            "https://{host}/{}?{}",
            "東京".repeat(8192),
            "é".repeat(8192)
        );
        report(label, &input, check(&input, true, 0));
    }
    for count in [59, 60, 999, 1000, 1001] {
        let input = format!("https://{}.invalid/", "é".repeat(count));
        check(&input, count <= 1000, 0);
        if count <= 1000 {
            // Prepare a real ACE encoding outside measurement. Then measure
            // decode/validation rather than only malformed ACE early exits.
            let encoded = url::Url::parse(&input).unwrap().to_string();
            check(&encoded, true, 0);
        }
    }
    for count in [1999, 2000, 2001] {
        check(&format!("https://xn--{}/", "z".repeat(count)), false, 0);
    }
    // ICU's stable sort must actually allocate:1026 mixed combining classes
    // need4104 bytes of scratch, beyond its4096-byte inline buffer. This exact
    // allocation size differs from the surrounding power-of-two SmallVecs.
    let combining = format!("https://a{}.invalid/", "\u{0315}\u{0300}".repeat(513));
    let sorted = check(&combining, false, 1026 * size_of::<u32>());
    assert!(
        sorted.exact_hits > 0,
        "fixture did not enter stable-sort heap path"
    );
    let late_invalid = format!(
        "https://a{}\u{200d}.invalid/",
        "\u{0315}\u{0300}".repeat(513)
    );
    check(&late_invalid, false, 0);
    for piece in ["\u{fdfa}", "각", "ﬃ", "Ａ", "。"] {
        let input = format!("https://{}example.invalid/", piece.repeat(1000));
        // Classification is checked against one real preliminary parse outside
        // measurement for these normalization families; allocation still uses
        // a fresh parse/result and must drain and fit the source-derived quote.
        let accepted = url::Url::parse(&input).is_ok();
        check(&input, accepted, 0);
    }
}
