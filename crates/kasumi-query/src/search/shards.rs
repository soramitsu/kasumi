//! Bounded, immutable Tantivy shards for a persisted text directory.
//!
//! A shard is one single-segment Tantivy index of at most
//! [`MAX_SHARD_DOCUMENTS`] rows and [`MAX_SHARD_BYTES`] of files, built from
//! the definition's [`TextShardLayout`]. Every row stores its document ID and
//! version. A shard is never edited: a later write indexes the new version in
//! another shard, and a reader keeps only rows whose stored version is the
//! selected live record. Merges copy surviving rows into a new shard.
//!
//! The storage owner supplies files and statistics; this module has no
//! storage, encryption or publication responsibilities.
use super::*;
use std::path::{Path, PathBuf};
use tantivy::directory::error::{DeleteError, LockError, OpenReadError, OpenWriteError};
use tantivy::directory::{
    DirectoryLock, FileHandle, Lock, OwnedBytes, RamDirectory, WatchCallback, WatchHandle, WritePtr,
};
use tantivy::fastfield::AliveBitSet;
use tantivy::indexer::NoMergePolicy;
use tantivy::{Directory, IndexSettings};

/// Rows per shard. A merge never produces a larger shard.
pub const MAX_SHARD_DOCUMENTS: u32 = 16_384;
/// Files per shard, `meta.json` included. Opening a shard loads at most this.
pub const MAX_SHARD_BYTES: u64 = 16 << 20;
/// A shard holds one segment's components plus its metadata.
const MAX_SHARD_FILES: usize = 16;
const META: &str = "meta.json";

/// One definition's text layout, shared by every shard built for it.
#[derive(Clone)]
pub struct TextShardLayout(pub(crate) Arc<TextLayout>);

impl std::fmt::Debug for TextShardLayout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TextShardLayout")
            .field("indexes", &self.0.indexes.keys())
            .finish_non_exhaustive()
    }
}

impl TextShardLayout {
    /// `None` when the definition has no text index.
    pub fn for_definition(definition: &CollectionDefinition) -> Option<Self> {
        TextLayout::new(definition).map(|layout| Self(Arc::new(layout)))
    }
    /// Identity of the indexed paths, analyzers and shard format. A shard
    /// written under another identity is never opened under this one.
    pub fn sha256(&self) -> [u8; 32] {
        self.0.sha256
    }
    /// Number of schema fields; token statistics are indexed by field ID.
    pub fn field_count(&self) -> usize {
        self.0.schema.num_fields()
    }
    /// Whether any text-indexed path differs between two live bodies.
    pub fn changed(&self, old: &Value, new: &Value) -> bool {
        self.0.indexes.values().any(|index| {
            index
                .paths
                .iter()
                .any(|(path, ..)| old.pointer(path) != new.pointer(path))
        })
    }
    /// Normalized text bytes one body contributes, for shard cut decisions.
    pub fn text_bytes(&self, body: &Value) -> u64 {
        self.0
            .indexes
            .values()
            .flat_map(|index| index.paths.iter())
            .flat_map(|(path, ..)| text_values(body, path))
            .map(|text| text.len() as u64)
            .sum()
    }
}

/// Files and statistics of one finished shard.
pub struct BuiltTextShard {
    /// `(name, bytes)` in name order, `meta.json` included.
    pub files: Vec<(String, Vec<u8>)>,
    /// Rows, which is also the shard's BM25 `max_doc`.
    pub documents: u32,
    /// Total tokens per schema field ID, superseded rows included.
    pub tokens: Vec<u64>,
}
impl BuiltTextShard {
    pub fn bytes(&self) -> u64 {
        self.files.iter().map(|(_, bytes)| bytes.len() as u64).sum()
    }
}

/// Accumulates rows of one new shard in a private RAM index.
pub struct TextShardWriter {
    layout: TextShardLayout,
    index: Index,
    directory: RamDirectory,
    writer: tantivy::IndexWriter<TantivyDocument>,
    documents: u32,
    text_bytes: u64,
}

impl TextShardWriter {
    /// Tantivy's configured arena for the single indexing worker.
    pub const ARENA_BYTES: usize = 15_000_000;

    pub fn new(layout: &TextShardLayout) -> Result<Self> {
        let directory = RamDirectory::create();
        let index = Index::create(
            directory.clone(),
            layout.0.schema.clone(),
            IndexSettings::default(),
        )
        .map_err(search_error)?;
        layout.0.register(&index)?;
        let writer = index
            .writer_with_num_threads::<TantivyDocument>(1, Self::ARENA_BYTES)
            .map_err(search_error)?;
        writer.set_merge_policy(Box::new(NoMergePolicy));
        Ok(Self {
            layout: layout.clone(),
            index,
            directory,
            writer,
            documents: 0,
            text_bytes: 0,
        })
    }
    /// Index one live version. Bodies were validated against the text limits
    /// when they were admitted.
    pub fn add(&mut self, id: &str, version: u64, body: &Value) -> Result<()> {
        kasumi_types::validate_name(id)?;
        if self.documents >= MAX_SHARD_DOCUMENTS {
            return Err(search_error("text shard row bound reached"));
        }
        self.writer
            .add_document(self.layout.0.document(id, version, body))
            .map_err(search_error)?;
        self.documents += 1;
        self.text_bytes = self.text_bytes.saturating_add(self.layout.text_bytes(body));
        Ok(())
    }
    pub fn documents(&self) -> u32 {
        self.documents
    }
    pub fn text_bytes(&self) -> u64 {
        self.text_bytes
    }
    /// The finished shard, or `None` when no row was added.
    pub fn finish(mut self) -> Result<Option<BuiltTextShard>> {
        if self.documents == 0 {
            return Ok(None);
        }
        self.writer.commit().map_err(search_error)?;
        let segments = self.index.searchable_segment_ids().map_err(search_error)?;
        if segments.len() > 1 {
            // The arena flushed early: fold every partial segment into one.
            self.writer.merge(&segments).wait().map_err(search_error)?;
        }
        self.writer.wait_merging_threads().map_err(search_error)?;
        extract(&self.layout, &self.index, &self.directory).map(Some)
    }
}

/// Read every file of a single-segment RAM index, with its statistics.
fn extract(
    layout: &TextShardLayout,
    index: &Index,
    directory: &RamDirectory,
) -> Result<BuiltTextShard> {
    let metas = index.searchable_segment_metas().map_err(search_error)?;
    let [meta] = metas.as_slice() else {
        return Err(search_error("text shard is not one segment"));
    };
    if meta.has_deletes() {
        return Err(search_error("text shard segment has deletes"));
    }
    let mut names: Vec<PathBuf> = meta.list_files().into_iter().collect();
    names.push(PathBuf::from(META));
    names.sort();
    let mut files = Vec::with_capacity(names.len().min(MAX_SHARD_FILES));
    let mut total = 0u64;
    for name in names {
        if !directory.exists(&name).map_err(search_error)? {
            continue;
        }
        // The underlying immutable file includes Tantivy's footer. Reading
        // through ManagedDirectory would strip it from exported segment files.
        let handle = directory.get_file_handle(&name).map_err(search_error)?;
        total = total.saturating_add(handle.len() as u64);
        if files.len() == MAX_SHARD_FILES || total > MAX_SHARD_BYTES {
            return Err(exhausted("text shard exceeds its file bound"));
        }
        let bytes = handle
            .read_bytes(0..handle.len())
            .map_err(search_error)?
            .to_vec();
        let name = name
            .to_str()
            .ok_or_else(|| search_error("non-UTF-8 shard file name"))?
            .to_owned();
        files.push((name, bytes));
    }
    let searcher = capture(index)?;
    let mut tokens = vec![0u64; layout.field_count()];
    for (field, _) in layout.0.schema.fields() {
        if layout.0.schema.get_field_entry(field).is_indexed()
            && matches!(
                layout.0.schema.get_field_entry(field).field_type(),
                tantivy::schema::FieldType::Str(_)
            )
        {
            tokens[field.field_id() as usize] =
                Bm25StatisticsProvider::total_num_tokens(&searcher, field).map_err(search_error)?;
        }
    }
    Ok(BuiltTextShard {
        files,
        documents: meta.max_doc(),
        tokens,
    })
}

/// An opened immutable shard. It owns its file bytes; dropping it frees them.
pub struct TextShard {
    layout: TextShardLayout,
    index: Index,
    searcher: Searcher,
    bytes: u64,
}

impl std::fmt::Debug for TextShard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TextShard")
            .field("documents", &self.documents())
            .field("bytes", &self.bytes)
            .finish()
    }
}

impl TextShard {
    /// Open one shard from its exact files. The schema must be the layout's
    /// and the shard must be one undeleted segment of `documents` rows.
    pub fn open(
        layout: &TextShardLayout,
        files: Vec<(String, Vec<u8>)>,
        documents: u32,
    ) -> Result<Self> {
        if files.len() > MAX_SHARD_FILES {
            return Err(search_error("text shard has too many files"));
        }
        let mut map = BTreeMap::new();
        let mut bytes = 0u64;
        for (name, data) in files {
            if name.contains('/') || name.starts_with('.') || name.is_empty() {
                return Err(search_error("invalid text shard file name"));
            }
            bytes = bytes.saturating_add(data.len() as u64);
            if map
                .insert(PathBuf::from(name), OwnedBytes::new(data))
                .is_some()
            {
                return Err(search_error("duplicate text shard file"));
            }
        }
        if bytes > MAX_SHARD_BYTES {
            return Err(search_error("text shard exceeds its file bound"));
        }
        let index = Index::open(ShardDirectory {
            files: Arc::new(map),
        })
        .map_err(search_error)?;
        if index.schema() != layout.0.schema {
            return Err(search_error(
                "text shard schema differs from its definition",
            ));
        }
        layout.0.register(&index)?;
        let searcher = capture(&index)?;
        let readers = searcher.segment_readers();
        if readers.len() != 1
            || readers[0].max_doc() != documents
            || readers[0].num_deleted_docs() != 0
        {
            return Err(search_error("text shard rows differ from its descriptor"));
        }
        Ok(Self {
            layout: layout.clone(),
            index,
            searcher,
            bytes,
        })
    }
    pub fn documents(&self) -> u32 {
        self.searcher.segment_readers()[0].max_doc()
    }
    /// File bytes this shard retains.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
    pub(crate) fn searcher(&self) -> &Searcher {
        &self.searcher
    }
    /// Visit every stored `(id, version)` in row order until `visit` stops.
    pub fn visit_rows(&self, mut visit: impl FnMut(&str, u64) -> Result<bool>) -> Result<()> {
        let segment = &self.searcher.segment_readers()[0];
        let store = segment.get_store_reader(1).map_err(search_error)?;
        for doc in 0..segment.max_doc() {
            let record: TantivyDocument = store.get(doc).map_err(search_error)?;
            let (id, version) = self.layout.0.row(&record)?;
            if !visit(id, version)? {
                break;
            }
        }
        Ok(())
    }
}

/// Copy the rows `keep` accepts from `shards` into one new shard. `None` when
/// no row survives. The result obeys the shard bounds or the merge fails.
pub fn merge_text_shards(
    layout: &TextShardLayout,
    shards: &[&TextShard],
    mut keep: impl FnMut(&str, u64) -> Result<bool>,
) -> Result<Option<BuiltTextShard>> {
    let mut segments = Vec::with_capacity(shards.len());
    let mut filters = Vec::with_capacity(shards.len());
    let mut survivors = 0u64;
    for shard in shards {
        if shard.index.schema() != layout.0.schema {
            return Err(search_error("merged text shard schema differs"));
        }
        let max_doc = shard.documents();
        let mut alive = vec![false; max_doc as usize];
        let mut doc = 0usize;
        shard.visit_rows(|id, version| {
            alive[doc] = keep(id, version)?;
            doc += 1;
            Ok(true)
        })?;
        let count = alive.iter().filter(|alive| **alive).count();
        if count == 0 {
            continue;
        }
        survivors += count as u64;
        filters.push(Some(alive_bitset(&alive)));
        let mut shard_segments = shard.index.searchable_segments().map_err(search_error)?;
        if shard_segments.len() != 1 {
            return Err(search_error("merged text shard is not one segment"));
        }
        segments.push(shard_segments.remove(0));
    }
    if survivors == 0 {
        return Ok(None);
    }
    if survivors > u64::from(MAX_SHARD_DOCUMENTS) {
        return Err(exhausted("merged text shard exceeds its row bound"));
    }
    let directory = RamDirectory::create();
    let merged = tantivy::indexer::merge_filtered_segments(
        &segments,
        IndexSettings::default(),
        filters,
        directory.clone(),
    )
    .map_err(search_error)?;
    layout.0.register(&merged)?;
    let built = extract(layout, &merged, &directory)?;
    if u64::from(built.documents) != survivors {
        return Err(search_error("merged text shard row count differs"));
    }
    Ok(Some(built))
}

/// Tantivy's serialized bitset: the bound, then little-endian 64-bit words.
fn alive_bitset(alive: &[bool]) -> AliveBitSet {
    let max = alive.len() as u32;
    let mut bytes = Vec::with_capacity(4 + alive.len().div_ceil(64) * 8);
    bytes.extend_from_slice(&max.to_le_bytes());
    for chunk in alive.chunks(64) {
        let mut word = 0u64;
        for (bit, alive) in chunk.iter().enumerate() {
            if *alive {
                word |= 1 << bit;
            }
        }
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    AliveBitSet::open(OwnedBytes::new(bytes))
}

/// Read-only files of one opened shard. Nothing writes, locks or watches it.
#[derive(Clone)]
struct ShardDirectory {
    files: Arc<BTreeMap<PathBuf, OwnedBytes>>,
}
impl std::fmt::Debug for ShardDirectory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShardDirectory")
            .field("files", &self.files.len())
            .finish()
    }
}
fn read_only() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "text shard is read-only",
    )
}
impl Directory for ShardDirectory {
    fn get_file_handle(
        &self,
        path: &Path,
    ) -> std::result::Result<Arc<dyn FileHandle>, OpenReadError> {
        self.files
            .get(path)
            .map(|bytes| Arc::new(bytes.clone()) as Arc<dyn FileHandle>)
            .ok_or_else(|| OpenReadError::FileDoesNotExist(path.to_path_buf()))
    }
    fn delete(&self, path: &Path) -> std::result::Result<(), DeleteError> {
        Err(DeleteError::IoError {
            io_error: Arc::new(read_only()),
            filepath: path.to_path_buf(),
        })
    }
    fn exists(&self, path: &Path) -> std::result::Result<bool, OpenReadError> {
        Ok(self.files.contains_key(path))
    }
    fn open_write(&self, path: &Path) -> std::result::Result<WritePtr, OpenWriteError> {
        Err(OpenWriteError::IoError {
            io_error: Arc::new(read_only()),
            filepath: path.to_path_buf(),
        })
    }
    fn atomic_read(&self, path: &Path) -> std::result::Result<Vec<u8>, OpenReadError> {
        self.files
            .get(path)
            .map(|bytes| bytes.as_slice().to_vec())
            .ok_or_else(|| OpenReadError::FileDoesNotExist(path.to_path_buf()))
    }
    fn atomic_write(&self, _path: &Path, _data: &[u8]) -> std::io::Result<()> {
        Err(read_only())
    }
    fn sync_directory(&self) -> std::io::Result<()> {
        Ok(())
    }
    /// Readers take the meta lock while loading; nothing can write here.
    fn acquire_lock(&self, _lock: &Lock) -> std::result::Result<DirectoryLock, LockError> {
        Ok(DirectoryLock::from(Box::new(())))
    }
    fn watch(&self, _callback: WatchCallback) -> tantivy::Result<WatchHandle> {
        Ok(WatchHandle::empty())
    }
}

/// A persisted shard directory for one collection at one selected generation.
/// Implementations bind shards, statistics and liveness to that generation.
pub trait TextShardSet {
    fn layout(&self) -> &TextShardLayout;
    fn shard_count(&self) -> usize;
    /// Lend one shard; at most one is open at a time during a search.
    fn with_shard(
        &self,
        shard: usize,
        visit: &mut dyn FnMut(&TextShard) -> Result<()>,
    ) -> Result<()>;
    /// Rows of every shard, superseded rows included.
    fn indexed_documents(&self) -> u64;
    /// Tokens of one schema field over every shard, superseded rows included.
    fn total_tokens(&self, field: usize) -> u64;
    /// Whether `(id, version)` is the selected live record.
    fn current(&self, id: &str, version: u64) -> Result<bool>;
}

struct DiskShards<'a, S: TextShardSet + ?Sized>(&'a S);
impl<S: TextShardSet + ?Sized> ShardAccess for DiskShards<'_, S> {
    fn shard_count(&self) -> usize {
        self.0.shard_count()
    }
    fn with_searcher(
        &self,
        shard: usize,
        visit: &mut dyn FnMut(&Searcher) -> Result<()>,
    ) -> Result<()> {
        let layout = self.0.layout().sha256();
        self.0.with_shard(shard, &mut |opened| {
            if opened.layout.sha256() != layout {
                return Err(search_error("text shard layout differs"));
            }
            visit(opened.searcher())
        })
    }
    fn indexed_documents(&self) -> Result<u64> {
        Ok(self.0.indexed_documents())
    }
    fn total_tokens(&self, field: Field) -> Result<u64> {
        Ok(self.0.total_tokens(field.field_id() as usize))
    }
    fn current(&self, id: &str, version: u64) -> Result<bool> {
        self.0.current(id, version)
    }
}

/// Search a persisted shard directory with the resident index's planner,
/// budgets and ranking: `(id, score)` of every current matching row.
pub fn search_shards<S: TextShardSet + ?Sized>(
    shards: &S,
    request: &TextSearch,
    cap: usize,
    cancellation: &QueryCancellation,
) -> Result<BTreeMap<String, f32>> {
    let layout = shards.layout().0.clone();
    run_search(&layout, &DiskShards(shards), request, cap, cancellation)
}

#[cfg(test)]
#[path = "shard_tests.rs"]
mod tests;
