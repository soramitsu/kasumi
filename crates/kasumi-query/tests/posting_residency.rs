//! Measure the resident structured postings an applying generation retains.
//! Each case builds the same indexes cold reopen builds, then advances them
//! through ordinary single-document writes, under the real allocator.
use kasumi_query::{
    CollectionRecords, DocumentChanges, DocumentDelta, IndexUpdate, QueryIndexes, ReadResult,
    Record, SourceIdentity,
};
use kasumi_types::*;
use serde_json::{Value, json};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::convert::Infallible;

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

fn measure<T>(work: impl FnOnce() -> T) -> (T, Counts) {
    COUNTS.with(|slot| {
        assert!(slot.get().is_none());
        slot.set(Some(Counts::default()));
    });
    let value = work();
    let counts = COUNTS.with(|slot| slot.replace(None).unwrap());
    (value, counts)
}

struct Rows {
    state: CollectionState,
}
impl CollectionRecords for &Rows {
    type Failure = Infallible;
    fn identity(&self) -> SourceIdentity<'_> {
        SourceIdentity::new(
            &self.state,
            "tenant",
            "incarnation",
            &self.state.definition.name,
        )
    }
    fn definition(&self) -> &CollectionDefinition {
        &self.state.definition
    }
    fn visit_records(
        &self,
        mut lend: impl for<'a> FnMut(&'a str, Record<'a>) -> Result<()>,
    ) -> ReadResult<(), Infallible> {
        for (id, slot) in &self.state.documents {
            let DocumentSlot::Pending(document) = slot.as_ref() else {
                unreachable!("fixture rows are pending")
            };
            lend(id, Record::Live(document))?;
        }
        Ok(())
    }
}

struct Change<'a> {
    old: &'a Rows,
    new: &'a Rows,
    indexes: &'a QueryIndexes,
    id: &'a str,
}
impl DocumentChanges for Change<'_> {
    type Failure = Infallible;
    fn old_identity(&self) -> SourceIdentity<'_> {
        self.old.identity()
    }
    fn new_identity(&self) -> SourceIdentity<'_> {
        self.new.identity()
    }
    fn old_definition(&self) -> &CollectionDefinition {
        &self.old.state.definition
    }
    fn new_definition(&self) -> &CollectionDefinition {
        &self.new.state.definition
    }
    fn indexes(&self) -> &QueryIndexes {
        self.indexes
    }
    fn visit_changes(
        &self,
        mut lend: impl for<'a> FnMut(DocumentDelta<'a>) -> Result<()>,
    ) -> ReadResult<(), Infallible> {
        let record = |rows: &'_ Rows| {
            rows.state
                .documents
                .get(self.id)
                .map(|slot| match slot.as_ref() {
                    DocumentSlot::Pending(document) => document.clone(),
                    DocumentSlot::Stored(_) | DocumentSlot::Located(_) => unreachable!(),
                })
        };
        let (old, new) = (record(self.old), record(self.new));
        lend(DocumentDelta {
            id: self.id,
            old: old.as_deref().map(Record::Live),
            new: new.as_deref().map(Record::Live),
        })?;
        Ok(())
    }
}

fn index(name: &str, path: &str, kind: ScalarType, unique: bool) -> IndexDefinition {
    IndexDefinition {
        name: name.into(),
        fields: vec![IndexField {
            path: path.into(),
            kind,
        }],
        unique,
        text: None,
    }
}

fn rows(indexes: Vec<IndexDefinition>, documents: usize, body: impl Fn(usize) -> Value) -> Rows {
    let definition = std::sync::Arc::new(CollectionDefinition {
        name: "docs".into(),
        write_mode: CollectionWriteMode::Mutable,
        retention_class: CollectionRetentionClass::Operational,
        schema: json!({"type":"object"}),
        indexes,
        strict_read_audit: false,
    });
    let documents = (0..documents)
        .map(|i| {
            let id = format!("doc-{i:08}");
            let slot = std::sync::Arc::new(DocumentSlot::Pending(std::sync::Arc::new(Document {
                id: id.clone(),
                version: 1,
                body: body(i),
            })));
            (id, slot)
        })
        .collect();
    Rows {
        state: CollectionState {
            definition,
            data_epoch: 1,
            documents,
            archived_documents: Default::default(),
            archived_document_bytes: 0,
        },
    }
}

const DOCUMENTS: usize = 16_384;
const WRITES: usize = 256;

fn case(label: &str, indexes: Vec<IndexDefinition>, body: impl Fn(usize) -> Value + Copy) {
    let rows = rows(indexes, DOCUMENTS, body);
    let (built, cold) = measure(|| QueryIndexes::build([&rows]).unwrap());
    // Ordinary writes: each replaces one existing document with a new value.
    let mut current = rows;
    let mut indexes = built;
    let mut writes = Counts::default();
    for step in 0..WRITES {
        let id = format!("doc-{:08}", (step * 61) % DOCUMENTS);
        let mut next = Rows {
            state: current.state.clone(),
        };
        next.state.documents.insert(
            id.clone(),
            std::sync::Arc::new(DocumentSlot::Pending(std::sync::Arc::new(Document {
                id: id.clone(),
                version: 2,
                body: body(DOCUMENTS + step),
            }))),
        );
        let (updated, counts) = measure(|| {
            indexes
                .update([IndexUpdate::<&Rows, Change<'_>>::Delta(Change {
                    old: &current,
                    new: &next,
                    indexes: &indexes,
                    id: &id,
                })])
                .unwrap()
        });
        writes.live += counts.live;
        writes.allocations += counts.allocations;
        writes.peak = writes.peak.max(counts.peak);
        indexes = updated;
        current = next;
    }
    let (_, rebuilt) = measure(|| QueryIndexes::build([&current]).unwrap());
    println!(
        "KASUMI_POSTING_RESIDENCY {}",
        json!({
            "case": label,
            "documents": DOCUMENTS,
            "cold_build_retained_bytes": cold.live,
            "cold_build_peak_bytes": cold.peak,
            "cold_build_allocations": cold.allocations,
            "retained_bytes_per_document": cold.live as f64 / DOCUMENTS as f64,
            "writes": WRITES,
            "write_live_growth_bytes": writes.live,
            "write_allocations": writes.allocations,
            "write_peak_bytes": writes.peak,
            "post_write_rebuild_retained_bytes": rebuilt.live,
        })
    );
}

#[test]
#[ignore = "measurement: cargo test -p kasumi-query --test posting_residency -- --ignored --nocapture"]
fn measure_resident_structured_postings() {
    let statuses = ["open", "paid", "void", "draft", "late"];
    case(
        "unique_email",
        vec![index("email", "/email", ScalarType::String, true)],
        |i| json!({"email": format!("user-{i:08}@example.com")}),
    );
    case(
        "distinct_timestamp",
        vec![index("ts", "/ts", ScalarType::Number, false)],
        |i| json!({"ts": 1_700_000_000_000u64 + (i as u64) * 7}),
    );
    case(
        "low_cardinality_status",
        vec![index("status", "/status", ScalarType::String, false)],
        move |i| json!({"status": statuses[i % statuses.len()]}),
    );
    case(
        "mixed_four_fields",
        vec![
            index("email", "/email", ScalarType::String, true),
            index("ts", "/ts", ScalarType::Number, false),
            index("status", "/status", ScalarType::String, false),
            index("tags", "/tags", ScalarType::StringArray, false),
        ],
        move |i| {
            json!({
                "email": format!("user-{i:08}@example.com"),
                "ts": 1_700_000_000_000u64 + (i as u64) * 7,
                "status": statuses[i % statuses.len()],
                "tags": [format!("t{}", i % 997), format!("u{}", (i * 31) % 1009)],
            })
        },
    );
    case(
        "pair_cardinality",
        vec![index("account", "/account", ScalarType::String, false)],
        |i| json!({"account": format!("acct-{:06}", i / 2)}),
    );
    descriptors();
}

/// The installed collection's descriptor map, which every generation also
/// retains: one slot per live document, keyed by its ID. A complete
/// descriptor is what an unpublished candidate and a retained feed record
/// hold; a published generation whose primary directory is current keeps the
/// located form, whose body identity is read from that directory's row.
fn descriptors() {
    for case in ["stored_descriptor_map", "located_descriptor_map"] {
        let (documents, counts) = measure(|| {
            (0..DOCUMENTS)
                .map(|i| {
                    let id = format!("doc-{i:08}");
                    let descriptor = StoredDocument {
                        id: id.clone(),
                        version: 1,
                        body_bytes: 64,
                        document_bytes: 96,
                        body_sha256: [7; 32],
                        body_object: [9; 32],
                        body_object_bytes: 80,
                        body_decode_work: 64,
                        body_manifest_work: 80,
                    };
                    let slot = if case == "stored_descriptor_map" {
                        DocumentSlot::stored_descriptor(descriptor)
                    } else {
                        DocumentSlot::Located(LocatedDocument::of(&descriptor).unwrap())
                    };
                    (id, std::sync::Arc::new(slot))
                })
                .collect::<DocumentMap>()
        });
        assert_eq!(documents.len(), DOCUMENTS);
        println!(
            "KASUMI_DESCRIPTOR_RESIDENCY {}",
            json!({
                "case": case,
                "documents": DOCUMENTS,
                "retained_bytes": counts.live,
                "retained_bytes_per_document": counts.live as f64 / DOCUMENTS as f64,
                "allocations": counts.allocations,
            })
        );
    }
}

/// The type of `CollectionState::documents`.
type DocumentMap = imbl::OrdMap<String, std::sync::Arc<DocumentSlot>>;
