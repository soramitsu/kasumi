//! Check before-clone output quotes against actual allocator requests. Fixtures
//! predate measurement; only the borrowed quote and owned page clone are tracked.
use kasumi_query::query_response_clone_bytes;
use kasumi_types::{QueryResponse, QueryRow};
use serde_json::{Map, Value, json};
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
fn note(delta: i64, allocation: bool) {
    let _ = COUNTS.try_with(|slot| {
        if let Some(mut counts) = slot.get() {
            counts.live += delta;
            counts.peak = counts.peak.max(counts.live);
            counts.allocations += usize::from(allocation);
            slot.set(Some(counts));
        }
    });
}
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            note(layout.size() as i64, true);
        }
        pointer
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            note(layout.size() as i64, true);
        }
        pointer
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let moved = unsafe { System.realloc(pointer, layout, size) };
        if !moved.is_null() {
            // Conservatively model an allocate/copy/free overlap even if this
            // particular system allocation grew in place.
            note(size as i64, true);
            note(-(layout.size() as i64), false);
        }
        moved
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
        note(-(layout.size() as i64), false);
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
        let counts = COUNTS.with(|slot| slot.replace(None).unwrap());
        drop(self);
        counts
    }
}
impl Drop for Measurement {
    fn drop(&mut self) {
        COUNTS.with(|slot| slot.set(None));
    }
}

fn fixture() -> QueryResponse {
    // Include source capacities much larger than lengths, exact number lexemes,
    // a broad BTreeMap and multi-level arrays. Quotes concern destination clones.
    let mut short = String::with_capacity(65536);
    short.push_str("short");
    let exact: Value =
        serde_json::from_str("12345678901234567890.123456789012345678901234567890").unwrap();
    let mut emptied = Map::new();
    emptied.insert("removed".into(), json!([1, 2]));
    emptied.remove("removed");
    let mut rows = Vec::new();
    for count in [0, 1, 10, 11, 12, 32, 127, 1024] {
        let mut fields = Map::new();
        // Descending construction exercises a different source tree shape.
        for index in (0..count).rev() {
            fields.insert(
                format!("k{index:04}"),
                json!([short, exact, {"/日本語~": index}]),
            );
        }
        rows.push(QueryRow {
            id: format!("row{count}"),
            version: 1,
            body: Value::Object(fields),
            score: Some(0.5),
        });
    }
    rows.push(QueryRow {
        id: String::new(),
        version: 2,
        body: Value::Object(emptied),
        score: None,
    });
    let mut spare_id = String::with_capacity(65536);
    spare_id.push_str("spare");
    let mut spare_body = String::with_capacity(65536);
    spare_body.push_str("tiny");
    rows.push(QueryRow {
        id: spare_id,
        version: 3,
        body: Value::String(spare_body),
        score: None,
    });
    QueryResponse {
        revision: 2,
        rows,
        aggregates: vec![json!({"group": {"a": short}, "values": {"sum": exact}})],
        cursor: Some("retained-cursor".repeat(100)),
    }
}

#[test]
fn typed_page_quotes_allocate_nothing_and_cover_real_clone_peaks() {
    let response = fixture();
    for range in [0..0, 0..1, 1..4, 0..response.rows.len(), 8..9, 9..10] {
        let measuring = Measurement::begin();
        let quote = query_response_clone_bytes(&response, range.clone()).unwrap();
        let walk = measuring.finish();
        assert_eq!(walk.allocations, 0, "sizing itself must borrow");
        assert_eq!(walk.live, 0);

        let measuring = Measurement::begin();
        let page = QueryResponse {
            revision: response.revision,
            rows: response.rows[range.clone()].to_vec(),
            aggregates: response.aggregates.clone(),
            cursor: response.cursor.clone(),
        };
        let clone_counts = COUNTS.with(Cell::get).unwrap();
        drop(page);
        let drained = measuring.finish();
        assert!(clone_counts.allocations > 0);
        assert!(
            clone_counts.peak as u64 <= quote,
            "{range:?}: peak={} quote={quote}",
            clone_counts.peak
        );
        assert_eq!(
            drained.live, 0,
            "page heap drains independently of the full result"
        );
    }
}

#[test]
fn object_node_cost_is_visible_despite_a_small_wire_result() {
    let mut fields = Map::new();
    for index in 0..256 {
        fields.insert(index.to_string(), Value::Null);
    }
    let response = QueryResponse {
        revision: 0,
        rows: vec![QueryRow {
            id: "a".into(),
            version: 0,
            body: Value::Object(fields),
            score: None,
        }],
        aggregates: vec![],
        cursor: None,
    };
    let old_wire_allowance = 3 * serde_json::to_vec(&response).unwrap().len();
    let quote = query_response_clone_bytes(&response, 0..1).unwrap();
    let measuring = Measurement::begin();
    let clone = response.clone();
    let clone_counts = COUNTS.with(Cell::get).unwrap();
    drop(clone);
    let drained = measuring.finish();
    assert!(clone_counts.peak as usize > old_wire_allowance);
    assert!(clone_counts.peak as u64 <= quote);
    assert_eq!(drained.live, 0);
}

#[test]
fn typed_feed_quotes_borrow_and_cover_owned_cursor_and_after_image_clones() {
    use kasumi_query::{change_event_clone_bytes, change_feed_page_workspace_bytes};
    use kasumi_types::{ChangeEvent, ChangeFeedCursor, ChangeFeedPage, ChangeRecord, Document};
    use std::{collections::BTreeSet, sync::Arc};
    let response = fixture();
    let records: Vec<_> = response
        .rows
        .iter()
        .map(|row| ChangeRecord {
            collection: "docs".into(),
            id: row.id.clone(),
            document: Some(Arc::new(Document {
                id: row.id.clone(),
                version: row.version,
                body: row.body.clone(),
            })),
        })
        .collect();
    let collections = BTreeSet::from(["docs".to_owned(), "other".to_owned()]);
    let measuring = Measurement::begin();
    let mut quote = change_feed_page_workspace_bytes(
        "tenant",
        "incarnation",
        "owner",
        &collections,
        records.len(),
    )
    .unwrap();
    for record in &records {
        quote += change_event_clone_bytes(record).unwrap();
    }
    let walked = measuring.finish();
    assert_eq!(walked.allocations, 0);
    assert_eq!(walked.live, 0);
    let measuring = Measurement::begin();
    let mut events = Vec::with_capacity(records.len());
    for (ordinal, record) in records.iter().enumerate() {
        events.push(ChangeEvent {
            sequence: ordinal as u64 + 1,
            revision: 1,
            ordinal,
            commit_event_count: records.len(),
            collection: record.collection.clone(),
            id: record.id.clone(),
            document: record.document.as_deref().cloned(),
        });
    }
    let page = ChangeFeedPage::Events {
        revision: 1,
        first_available_sequence: 1,
        head_sequence: records.len() as u64,
        events,
        next: ChangeFeedCursor {
            tenant: "tenant".into(),
            incarnation: "incarnation".into(),
            principal: "owner".into(),
            collections: collections.clone(),
            after_sequence: records.len() as u64,
        },
        caught_up: true,
    };
    let cloned = COUNTS.with(Cell::get).unwrap();
    drop(page);
    let drained = measuring.finish();
    assert!(cloned.allocations > 0);
    assert!(
        cloned.peak as u64 <= quote,
        "peak={} quote={quote}",
        cloned.peak
    );
    assert_eq!(drained.live, 0);
}

#[test]
fn typed_document_quotes_allocate_nothing_and_cover_real_clone_peaks() {
    use kasumi_query::document_clone_bytes;
    use kasumi_types::Document;
    for row in fixture().rows {
        let document = Document {
            id: row.id,
            version: row.version,
            body: row.body,
        };
        let measuring = Measurement::begin();
        let quote = document_clone_bytes(&document).unwrap();
        let walk = measuring.finish();
        assert_eq!(walk.allocations, 0, "document sizing itself must borrow");
        assert_eq!(walk.live, 0);

        let measuring = Measurement::begin();
        let clone = document.clone();
        let cloned = COUNTS.with(Cell::get).unwrap();
        drop(clone);
        let drained = measuring.finish();
        assert!(
            cloned.peak as u64 <= quote,
            "{}: peak={} quote={quote}",
            document.id,
            cloned.peak,
        );
        assert_eq!(drained.live, 0, "cloned document heap must drain");
    }
}
