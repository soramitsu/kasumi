mod japanese;
mod shards;

pub use shards::search_shards;
pub use shards::{
    BuiltTextShard, MAX_SHARD_BYTES, MAX_SHARD_DOCUMENTS, TextShard, TextShardLayout, TextShardSet,
    TextShardWriter, merge_text_shards,
};

use crate::scalar::{exhausted, invalid};
use crate::{CollectionRecords, DocumentChanges, QueryCancellation, ReadResult, Record};
use kasumi_types::{
    Analyzer, CollectionDefinition, Error, ErrorCode, Result, TextMode, TextSearch,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::{Arc, Mutex, OnceLock},
};
use tantivy::query::{
    Bm25StatisticsProvider, BooleanQuery, BoostQuery, DisjunctionMaxQuery, EmptyQuery,
    EnableScoring, Occur, PhraseQuery, Query, TermQuery,
};
use tantivy::schema::{
    Field, IndexRecordOption, STORED, STRING, Schema, TextFieldIndexing, TextOptions, Value as _,
};
use tantivy::tokenizer::{
    Language, LowerCaser, SimpleTokenizer, Stemmer, TextAnalyzer, TokenStream,
};
use tantivy::{
    DocSet, Index, IndexReader, ReloadPolicy, Searcher, TERMINATED, TantivyDocument, Term,
};
use tantivy_fst::Automaton;
use unicode_normalization::UnicodeNormalization;

struct TextFields {
    analyzer: Analyzer,
    paths: Vec<(String, Field, Field)>,
}

/// The Tantivy schema one collection definition's text indexes produce. The
/// resident index and every persisted shard of that definition share it, so a
/// field identifier means the same ranked or surface field in each.
pub(crate) struct TextLayout {
    schema: Schema,
    indexes: BTreeMap<String, TextFields>,
    id_field: Field,
    version_field: Field,
    sha256: [u8; 32],
}

/// Bumped whenever the persisted shard schema or tokenization changes.
const LAYOUT_FORMAT: &str = "kasumi.text.shard.v1";

impl TextLayout {
    fn new(definition: &CollectionDefinition) -> Option<Self> {
        if definition.indexes.iter().all(|index| index.text.is_none()) {
            return None;
        }
        let mut builder = Schema::builder();
        let id_field = builder.add_text_field("_kasumi_id", STRING | STORED);
        let version_field = builder.add_u64_field("_kasumi_version", STORED);
        let mut indexes = BTreeMap::new();
        let mut identity = Vec::new();
        let mut sequence = 0;
        for definition in &definition.indexes {
            let Some(text) = &definition.text else {
                continue;
            };
            let mut paths = Vec::new();
            for field in &definition.fields {
                let options = |surface| {
                    TextOptions::default().set_indexing_options(
                        TextFieldIndexing::default()
                            .set_tokenizer(&analyzer_name(text.analyzer, surface))
                            .set_index_option(IndexRecordOption::WithFreqsAndPositions),
                    )
                };
                let ranked = builder.add_text_field(&format!("text_{sequence}"), options(false));
                let surface = builder.add_text_field(&format!("surface_{sequence}"), options(true));
                sequence += 1;
                paths.push((field.path.clone(), ranked, surface));
            }
            identity.push((
                definition.name.clone(),
                format!("{:?}", text.analyzer),
                paths
                    .iter()
                    .map(|(path, ..)| path.clone())
                    .collect::<Vec<_>>(),
            ));
            indexes.insert(
                definition.name.clone(),
                TextFields {
                    analyzer: text.analyzer,
                    paths,
                },
            );
        }
        let mut hash = Sha256::new();
        hash.update(LAYOUT_FORMAT.as_bytes());
        hash.update(serde_json::to_vec(&identity).expect("text layout identity encodes"));
        Some(Self {
            schema: builder.build(),
            indexes,
            id_field,
            version_field,
            sha256: hash.finalize().into(),
        })
    }

    fn register(&self, index: &Index) -> Result<()> {
        for fields in self.indexes.values() {
            for surface in [false, true] {
                index.tokenizers().register(
                    &analyzer_name(fields.analyzer, surface),
                    analyzer(fields.analyzer, surface)?,
                );
            }
        }
        Ok(())
    }

    fn document(&self, id: &str, version: u64, body: &Value) -> TantivyDocument {
        let mut indexed = TantivyDocument::default();
        indexed.add_text(self.id_field, id);
        indexed.add_u64(self.version_field, version);
        for fields in self.indexes.values() {
            for (path, ranked, surface) in &fields.paths {
                for text in text_values(body, path) {
                    let normalized: String = text.nfkc().collect();
                    indexed.add_text(*ranked, &normalized);
                    indexed.add_text(*surface, &normalized);
                }
            }
        }
        indexed
    }

    /// The stored identity of one indexed row.
    fn row<'d>(&self, document: &'d TantivyDocument) -> Result<(&'d str, u64)> {
        let mut ids = document.get_all(self.id_field);
        let id = ids
            .next()
            .and_then(|id| id.as_str())
            .filter(|id| kasumi_types::validate_name(id).is_ok())
            .ok_or_else(|| search_error("missing or invalid stored document ID"))?;
        let mut versions = document.get_all(self.version_field);
        let version = versions
            .next()
            .and_then(|version| version.as_u64())
            .ok_or_else(|| search_error("missing stored document version"))?;
        if ids.next().is_some() || versions.next().is_some() {
            return Err(search_error("duplicate stored document identity"));
        }
        Ok((id, version))
    }
}

fn text_values<'a>(body: &'a Value, path: &str) -> impl Iterator<Item = &'a str> {
    let values = match body.pointer(path) {
        Some(Value::Array(values)) => values.as_slice(),
        Some(value) => std::slice::from_ref(value),
        None => &[],
    };
    values.iter().filter_map(Value::as_str)
}

struct TextCore {
    index: Index,
    layout: Arc<TextLayout>,
    // None means an interrupted/failed update poisoned this writer corridor.
    // Older immutable readers remain usable, but new applies must recover.
    active: Mutex<Option<u64>>,
}

pub(crate) struct TextSnapshot {
    core: Arc<TextCore>,
    searcher: Searcher,
    generation: u64,
}

impl std::fmt::Debug for TextSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TextSnapshot")
            .field("indexes", &self.core.layout.indexes.keys())
            .field("documents", &self.searcher.num_docs())
            .finish()
    }
}

fn search_error(error: impl std::fmt::Display) -> Error {
    Error::new(ErrorCode::Unavailable, format!("text index: {error}"))
}

fn analyzer(kind: Analyzer, surface: bool) -> Result<TextAnalyzer> {
    match kind {
        Analyzer::UnicodeV1 => Ok(TextAnalyzer::builder(SimpleTokenizer::default())
            .filter(LowerCaser)
            .build()),
        Analyzer::EnglishV1 if !surface => Ok(TextAnalyzer::builder(SimpleTokenizer::default())
            .filter(LowerCaser)
            .filter(Stemmer::new(Language::English))
            .build()),
        Analyzer::EnglishV1 => Ok(TextAnalyzer::builder(SimpleTokenizer::default())
            .filter(LowerCaser)
            .build()),
        Analyzer::JapaneseV1 => {
            static JAPANESE: OnceLock<Result<TextAnalyzer>> = OnceLock::new();
            JAPANESE
                .get_or_init(|| {
                    let dictionary = lindera::dictionary::load_dictionary("embedded://ipadic")
                        .map_err(search_error)?;
                    let segmenter = lindera::segmenter::Segmenter::new(
                        lindera::mode::Mode::Normal,
                        dictionary,
                        None,
                    );
                    let tokenizer = japanese::JapaneseTokenizer::new(segmenter);
                    Ok(TextAnalyzer::builder(tokenizer).filter(LowerCaser).build())
                })
                .clone()
        }
    }
}

fn analyzer_name(kind: Analyzer, surface: bool) -> String {
    format!("{kind:?}_{}", if surface { "surface" } else { "ranked" })
}

fn visit_tokens(
    kind: Analyzer,
    text: &str,
    surface: bool,
    max_tokens: usize,
    mut visit: impl FnMut(usize, &str),
) -> Result<usize> {
    let normalized: String = text.nfkc().collect();
    let mut analyzer = analyzer(kind, surface)?;
    let mut stream = analyzer.token_stream(&normalized);
    let mut count = 0;
    while stream.advance() {
        let token = stream.token();
        if token.text.len() > 240 {
            return Err(invalid("text token exceeds 240 UTF-8 bytes"));
        }
        if count == max_tokens {
            return Err(exhausted("text token budget exceeded"));
        }
        visit(token.position, &token.text);
        count += 1;
    }
    Ok(count)
}

/// Deterministic text limits must reject proposals before index materialization;
/// otherwise a single oversized token could make every replica fail on apply.
pub(crate) fn validate_text_document(
    definition: &CollectionDefinition,
    body: &Value,
) -> Result<()> {
    let mut total = 0;
    for index in &definition.indexes {
        let Some(text) = &index.text else {
            continue;
        };
        for field in &index.fields {
            for value in text_values(body, &field.path) {
                // Prefix and fuzzy fields are unstemmed; validate both versions.
                total += visit_tokens(text.analyzer, value, false, 65_536, |_, _| {})?;
                visit_tokens(text.analyzer, value, true, 65_536, |_, _| {})?;
                if total > 65_536 {
                    return Err(exhausted("document text-index token budget exceeded"));
                }
            }
        }
    }
    Ok(())
}

/// Whether a text-indexed field of any changed live pair differs. Shared by the
/// resident index and the persisted-shard layout: both index the same paths.
fn text_fields_changed<D: DocumentChanges + ?Sized>(
    layout: &TextLayout,
    changes: &D,
) -> ReadResult<bool, D::Failure> {
    let mut changed = false;
    // The enclosing index preparation has validated every new live body,
    // including text limits, before this comparison-only pass. Visit every
    // delta so a later source failure cannot hide behind an earlier change.
    changes.visit_changes(|delta| {
        changed |= match (delta.old, delta.new) {
            (Some(Record::Live(old)), Some(Record::Live(new))) => {
                layout.indexes.values().any(|index| {
                    index
                        .paths
                        .iter()
                        .any(|(path, _, _)| old.body.pointer(path) != new.body.pointer(path))
                })
            }
            (Some(Record::Live(_)), _) | (_, Some(Record::Live(_))) => true,
            _ => false,
        };
        Ok(())
    })?;
    Ok(changed)
}

impl TextSnapshot {
    pub fn build<R: CollectionRecords + ?Sized>(
        source: &R,
    ) -> ReadResult<Option<Self>, R::Failure> {
        let Some(layout) = TextLayout::new(source.definition()) else {
            return Ok(None);
        };
        let index = Index::create_in_ram(layout.schema.clone());
        layout.register(&index)?;
        let core = Arc::new(TextCore {
            index,
            layout: Arc::new(layout),
            active: Mutex::new(Some(0)),
        });
        // Reopen the same RAM index per apply; no idle generation retains a
        // worker thread or a 15 MB writer allocation for every collection.
        let mut writer = core
            .index
            .writer_with_num_threads::<TantivyDocument>(1, 15_000_000)
            .map_err(search_error)?;
        // The checked source lends logical IDs in strict order. Archived rows
        // have no resident text body; only live rows receive a text row, as in
        // the original build. No collection-sized ID sort buffer is needed.
        // A source failure drops this private writer and returns its original
        // owner before any TextSnapshot can be published.
        source.visit_records(|id, record| {
            let Record::Live(document) = record else {
                return Ok(());
            };
            writer
                .add_document(core.layout.document(id, document.version, &document.body))
                .map_err(search_error)?;
            Ok(())
        })?;
        writer.commit().map_err(search_error)?;
        writer.wait_merging_threads().map_err(search_error)?;
        let searcher = core.capture()?;
        Ok(Some(Self {
            core,
            searcher,
            generation: 0,
        }))
    }

    pub fn fields_changed<D: DocumentChanges + ?Sized>(
        &self,
        changes: &D,
    ) -> ReadResult<bool, D::Failure> {
        text_fields_changed(&self.core.layout, changes)
    }

    pub fn update<D: DocumentChanges + ?Sized>(&self, changes: &D) -> ReadResult<Self, D::Failure> {
        let mut active = self
            .core
            .active
            .lock()
            .map_err(|_| search_error("text writer unavailable"))?;
        if *active != Some(self.generation) {
            return Err(search_error("cannot advance a stale or failed text generation").into());
        }
        *active = None;
        let mut writer = self
            .core
            .index
            .writer_with_num_threads::<TantivyDocument>(1, 15_000_000)
            .map_err(search_error)?;
        // Any replay/read error after this point leaves active=None. The old
        // reader remains immutable, but the shared writer corridor must recover;
        // a source failure is never flattened into a deterministic query error.
        changes.visit_changes(|delta| {
            let id = delta.id;
            if matches!(delta.old, Some(Record::Live(_))) {
                writer.delete_term(Term::from_field_text(self.core.layout.id_field, id));
            }
            if let Some(Record::Live(document)) = delta.new {
                writer
                    .add_document(
                        self.core
                            .layout
                            .document(id, document.version, &document.body),
                    )
                    .map_err(search_error)?;
            }
            Ok(())
        })?;
        writer.commit().map_err(search_error)?;
        writer.wait_merging_threads().map_err(search_error)?;
        let searcher = self.core.capture()?;
        let generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| search_error("text generation exhausted"))?;
        *active = Some(generation);
        Ok(Self {
            core: self.core.clone(),
            searcher,
            generation,
        })
    }

    pub fn search(
        &self,
        request: &TextSearch,
        cap: usize,
        cancellation: &QueryCancellation,
    ) -> Result<BTreeMap<String, f32>> {
        run_search(&self.core.layout, self, request, cap, cancellation)
    }
}

/// One searched set of immutable shards. The resident index is a single shard
/// whose statistics and rows are its own; a persisted directory supplies
/// statistics from its descriptors and filters rows superseded since a shard
/// was written.
pub(crate) trait ShardAccess {
    fn shard_count(&self) -> usize;
    fn with_searcher(
        &self,
        shard: usize,
        visit: &mut dyn FnMut(&Searcher) -> Result<()>,
    ) -> Result<()>;
    /// Every indexed row, including superseded ones, as Tantivy's own BM25
    /// `max_doc` statistic: a term's document frequency never exceeds it.
    fn indexed_documents(&self) -> Result<u64>;
    fn total_tokens(&self, field: Field) -> Result<u64>;
    /// Whether this stored row is the selected live record.
    fn current(&self, id: &str, version: u64) -> Result<bool>;
}

impl ShardAccess for TextSnapshot {
    fn shard_count(&self) -> usize {
        1
    }
    fn with_searcher(
        &self,
        _shard: usize,
        visit: &mut dyn FnMut(&Searcher) -> Result<()>,
    ) -> Result<()> {
        visit(&self.searcher)
    }
    fn indexed_documents(&self) -> Result<u64> {
        Bm25StatisticsProvider::total_num_docs(&self.searcher).map_err(search_error)
    }
    fn total_tokens(&self, field: Field) -> Result<u64> {
        Bm25StatisticsProvider::total_num_tokens(&self.searcher, field).map_err(search_error)
    }
    fn current(&self, _id: &str, _version: u64) -> Result<bool> {
        // Deletes are applied to the resident index itself.
        Ok(true)
    }
}

/// BM25 statistics fixed before any shard is scored: every shard's weight
/// uses the same totals, so a row scores as it would in one index.
struct Statistics {
    documents: u64,
    tokens: HashMap<Field, u64>,
    doc_freq: HashMap<Term, u64>,
}
impl Bm25StatisticsProvider for Statistics {
    fn total_num_tokens(&self, field: Field) -> tantivy::Result<u64> {
        self.tokens.get(&field).copied().ok_or_else(|| {
            tantivy::TantivyError::InternalError("text field statistic not prepared".into())
        })
    }
    fn total_num_docs(&self) -> tantivy::Result<u64> {
        Ok(self.documents)
    }
    fn doc_freq(&self, term: &Term) -> tantivy::Result<u64> {
        self.doc_freq.get(term).copied().ok_or_else(|| {
            tantivy::TantivyError::InternalError("uncharged text term in scoring".into())
        })
    }
}

#[derive(Clone)]
enum Expander {
    Fuzzy(Arc<levenshtein_automata::DFA>),
    Prefix(Vec<u8>),
}

struct Expansion {
    field: Field,
    expander: Expander,
    terms: BTreeSet<String>,
}

enum Clause {
    Term(Field, String),
    Fuzzy(usize),
    Prefix(usize),
}

enum Alternative {
    Phrase(Field, Vec<(usize, String)>),
    /// One field must hold every term.
    Conjunction(Vec<Clause>),
}

/// Plan, expand, charge and score one request across `access`'s shards. Every
/// shard is opened once to expand fuzzy and prefix terms, once to read global
/// document frequencies and once to score; one shard is open at a time.
pub(crate) fn run_search(
    layout: &TextLayout,
    access: &dyn ShardAccess,
    request: &TextSearch,
    cap: usize,
    cancellation: &QueryCancellation,
) -> Result<BTreeMap<String, f32>> {
    cancellation.check()?;
    if request.query.len() > 4096 {
        return Err(invalid("text query exceeds 4096 UTF-8 bytes"));
    }
    let fields = layout
        .indexes
        .get(&request.index)
        .ok_or_else(|| Error::new(ErrorCode::IndexRequired, "named text index does not exist"))?;
    let fuzzy = request.mode == TextMode::Fuzzy;
    let surface_query = fuzzy || request.mode == TextMode::Prefix;
    if fuzzy && request.fuzzy_distance() > 2 {
        return Err(invalid("fuzzy distance must be 0, 1, or 2"));
    }
    let mut terms = Vec::new();
    visit_tokens(
        fields.analyzer,
        &request.query,
        surface_query,
        64,
        |position, term| {
            terms.push((position, term.to_owned()));
        },
    )?;
    if terms.is_empty() {
        return Err(invalid("text query contains no searchable tokens"));
    }
    let mut tokenizations = vec![terms];
    if fuzzy && fields.analyzer == Analyzer::JapaneseV1 {
        // A typo can alter morphological segmentation (図書官 -> 図書 + 官,
        // while 図書館 is a single indexed term). Try the unsegmented words
        // as an alternative, with the same expansion and postings budgets.
        let normalized: String = request.query.nfkc().flat_map(char::to_lowercase).collect();
        let words: Vec<(usize, String)> = normalized
            .split_whitespace()
            .enumerate()
            .map(|(position, word)| (position, word.to_owned()))
            .collect();
        if !words.is_empty()
            && words.len() <= 64
            && words.iter().all(|(_, word)| word.len() <= 240)
            && words != tokenizations[0]
        {
            tokenizations.push(words);
        }
    }
    let searched: Vec<Field> = fields
        .paths
        .iter()
        .map(|(_, ranked, surface)| if surface_query { *surface } else { *ranked })
        .collect();

    // Plan every alternative before reading any shard.
    let mut alternatives = Vec::new();
    let mut expansions: Vec<Expansion> = Vec::new();
    for terms in &tokenizations {
        cancellation.check()?;
        if request.mode == TextMode::Phrase && terms.len() > 1 {
            for &field in &searched {
                alternatives.push(Alternative::Phrase(field, terms.clone()));
            }
            continue;
        }
        let mut clauses: Vec<Vec<Clause>> = searched.iter().map(|_| Vec::new()).collect();
        for (i, (_, text)) in terms.iter().enumerate() {
            cancellation.check()?;
            // A term's fuzzy automaton depends only on its text, so one is
            // built per term and shared by every field.
            let dfa = if fuzzy {
                let japanese = fields.analyzer == Analyzer::JapaneseV1;
                if !japanese && request.fuzzy_distance() > 0 && text.chars().count() < 3 {
                    return Err(invalid("fuzzy term is too short"));
                }
                // Single-character Japanese particles remain exact; editing
                // them would expand to nearly the entire term dictionary.
                let distance = if japanese && text.chars().count() < 2 {
                    0
                } else {
                    request.fuzzy_distance()
                };
                Some(fuzzy_automaton(text, distance)?)
            } else {
                None
            };
            for (&field, field_clauses) in searched.iter().zip(&mut clauses) {
                let clause = if let Some(dfa) = &dfa {
                    expansions.push(Expansion {
                        field,
                        expander: Expander::Fuzzy(dfa.clone()),
                        terms: BTreeSet::new(),
                    });
                    Clause::Fuzzy(expansions.len() - 1)
                } else if request.mode == TextMode::Prefix && i + 1 == terms.len() {
                    expansions.push(Expansion {
                        field,
                        expander: Expander::Prefix(text.as_bytes().to_vec()),
                        terms: BTreeSet::new(),
                    });
                    Clause::Prefix(expansions.len() - 1)
                } else {
                    Clause::Term(field, text.clone())
                };
                field_clauses.push(clause);
            }
        }
        alternatives.extend(clauses.into_iter().map(Alternative::Conjunction));
    }

    // Expand fuzzy and prefix terms over every shard's dictionary.
    if !expansions.is_empty() {
        let mut expanded_count = 0;
        for shard in 0..access.shard_count() {
            cancellation.check()?;
            access.with_searcher(shard, &mut |searcher| {
                for expansion in &mut expansions {
                    match expansion.expander.clone() {
                        Expander::Fuzzy(dfa) => expand(
                            searcher,
                            expansion.field,
                            Dfa(dfa),
                            &mut expansion.terms,
                            &mut expanded_count,
                            cancellation,
                        )?,
                        Expander::Prefix(prefix) => expand(
                            searcher,
                            expansion.field,
                            Prefix(prefix),
                            &mut expansion.terms,
                            &mut expanded_count,
                            cancellation,
                        )?,
                    }
                }
                Ok(())
            })?;
        }
        cancellation.check()?;
    }

    // Charge planned postings against global document frequencies. Intersecting
    // two very common terms can produce few hits while reading huge postings
    // lists. Limit planned postings, as well as returned hits.
    let mut occurrences: Vec<Term> = Vec::new();
    for alternative in &alternatives {
        match alternative {
            Alternative::Phrase(field, terms) => occurrences.extend(
                terms
                    .iter()
                    .map(|(_, text)| Term::from_field_text(*field, text)),
            ),
            Alternative::Conjunction(clauses) => {
                for clause in clauses {
                    match clause {
                        Clause::Term(field, text) => {
                            occurrences.push(Term::from_field_text(*field, text))
                        }
                        Clause::Fuzzy(index) | Clause::Prefix(index) => {
                            let expansion = &expansions[*index];
                            occurrences.extend(
                                expansion
                                    .terms
                                    .iter()
                                    .map(|term| Term::from_field_text(expansion.field, term)),
                            );
                        }
                    }
                }
            }
        }
    }
    let mut doc_freq: HashMap<Term, u64> = occurrences.iter().map(|t| (t.clone(), 0)).collect();
    for shard in 0..access.shard_count() {
        cancellation.check()?;
        access.with_searcher(shard, &mut |searcher| {
            for (term, frequency) in doc_freq.iter_mut() {
                cancellation.check()?;
                *frequency =
                    frequency.saturating_add(searcher.doc_freq(term).map_err(search_error)?);
            }
            Ok(())
        })?;
    }
    let posting_limit = cap.saturating_mul(8) as u64;
    let mut posting_work = 0u64;
    for term in &occurrences {
        posting_work = posting_work.saturating_add(doc_freq[term]);
        if posting_work > posting_limit {
            return Err(exhausted(
                "text postings budget exceeded (8 times candidate budget)",
            ));
        }
    }

    // Assemble the query tree once; each shard builds its own weight from it.
    let mut queries: Vec<Box<dyn Query>> = Vec::new();
    for alternative in &alternatives {
        match alternative {
            Alternative::Phrase(field, terms) => {
                queries.push(Box::new(PhraseQuery::new_with_offset(
                    terms
                        .iter()
                        .map(|(position, text)| (*position, Term::from_field_text(*field, text)))
                        .collect(),
                )))
            }
            Alternative::Conjunction(clauses) => {
                let mut must: Vec<(Occur, Box<dyn Query>)> = Vec::new();
                for clause in clauses {
                    let query: Box<dyn Query> = match clause {
                        Clause::Term(field, text) => Box::new(TermQuery::new(
                            Term::from_field_text(*field, text),
                            IndexRecordOption::WithFreqs,
                        )),
                        Clause::Fuzzy(index) => {
                            let expansion = &expansions[*index];
                            let Expander::Fuzzy(dfa) = &expansion.expander else {
                                unreachable!("fuzzy clause has a fuzzy expansion")
                            };
                            disjunction(
                                expansion
                                    .terms
                                    .iter()
                                    .map(|term| {
                                        let state = term
                                            .bytes()
                                            .fold(dfa.initial_state(), |s, b| dfa.transition(s, b));
                                        let distance = match dfa.distance(state) {
                                            levenshtein_automata::Distance::Exact(d) => d,
                                            _ => 2,
                                        };
                                        Box::new(BoostQuery::new(
                                            Box::new(TermQuery::new(
                                                Term::from_field_text(expansion.field, term),
                                                IndexRecordOption::WithFreqs,
                                            )),
                                            1.0 / (1 + distance) as f32,
                                        )) as Box<dyn Query>
                                    })
                                    .collect(),
                            )
                        }
                        Clause::Prefix(index) => {
                            let expansion = &expansions[*index];
                            disjunction(
                                expansion
                                    .terms
                                    .iter()
                                    .map(|term| {
                                        Box::new(TermQuery::new(
                                            Term::from_field_text(expansion.field, term),
                                            IndexRecordOption::WithFreqs,
                                        )) as Box<dyn Query>
                                    })
                                    .collect(),
                            )
                        }
                    };
                    must.push((Occur::Must, query));
                }
                queries.push(Box::new(BooleanQuery::new(must)));
            }
        }
    }
    let query = disjunction(queries);
    let mut tokens_by_field = HashMap::new();
    for &field in &searched {
        tokens_by_field.insert(field, access.total_tokens(field)?);
    }
    let statistics = Statistics {
        documents: access.indexed_documents()?,
        tokens: tokens_by_field,
        doc_freq,
    };
    let mut matches = BTreeMap::new();
    for shard in 0..access.shard_count() {
        cancellation.check()?;
        access.with_searcher(shard, &mut |searcher| {
            score_shard(
                layout,
                access,
                searcher,
                query.as_ref(),
                &statistics,
                cap,
                &mut matches,
                cancellation,
            )
        })?;
    }
    Ok(matches)
}

#[allow(clippy::too_many_arguments)]
fn score_shard(
    layout: &TextLayout,
    access: &dyn ShardAccess,
    searcher: &Searcher,
    query: &dyn Query,
    statistics: &Statistics,
    cap: usize,
    matches: &mut BTreeMap<String, f32>,
    cancellation: &QueryCancellation,
) -> Result<()> {
    let weight = query
        .weight(EnableScoring::enabled_from_statistics_provider(
            statistics, searcher,
        ))
        .map_err(search_error)?;
    // Drive scorers ourselves: TopDocs(limit) limits output, not matching work.
    for segment in searcher.segment_readers() {
        cancellation.check()?;
        // Reuse at most one decompressed ID block for this segment and
        // query. Nothing in the captured generation retains the block.
        let stored = segment.get_store_reader(1).map_err(search_error)?;
        let mut scorer = weight.scorer(segment, 1.0).map_err(search_error)?;
        while scorer.doc() != TERMINATED {
            cancellation.check()?;
            let doc = scorer.doc();
            if segment.is_deleted(doc) {
                scorer.advance();
                continue;
            }
            let record: TantivyDocument = stored.get(doc).map_err(search_error)?;
            let (id, version) = layout.row(&record)?;
            if !access.current(id, version)? {
                scorer.advance();
                continue;
            }
            if matches.len() >= cap {
                return Err(exhausted("text candidate budget exceeded"));
            }
            if matches.insert(id.to_owned(), scorer.score()).is_some() {
                return Err(search_error("duplicate stored document ID"));
            }
            scorer.advance();
        }
    }
    Ok(())
}

fn expand<A: Automaton>(
    searcher: &Searcher,
    field: Field,
    automaton: A,
    expansions: &mut BTreeSet<String>,
    total: &mut usize,
    cancellation: &QueryCancellation,
) -> Result<()>
where
    A::State: Clone,
{
    let automaton = CancellableAutomaton {
        inner: automaton,
        cancellation,
    };
    for segment in searcher.segment_readers() {
        cancellation.check()?;
        let inverted = segment.inverted_index(field).map_err(search_error)?;
        let mut stream = inverted
            .terms()
            .search(&automaton)
            .into_stream()
            .map_err(search_error)?;
        while stream.advance() {
            cancellation.check()?;
            let term = std::str::from_utf8(stream.key())
                .map_err(search_error)?
                .to_owned();
            if expansions.insert(term) {
                *total += 1;
                if expansions.len() > 64 || *total > 256 {
                    return Err(exhausted(
                        "text expansion budget exceeded (64 per term, 256 per query)",
                    ));
                }
            }
        }
    }
    cancellation.check()?;
    Ok(())
}

fn disjunction(mut queries: Vec<Box<dyn Query>>) -> Box<dyn Query> {
    match queries.len() {
        0 => Box::new(EmptyQuery),
        1 => queries.pop().unwrap(),
        _ => Box::new(DisjunctionMaxQuery::new(queries)),
    }
}

#[cfg(test)]
thread_local! {
    static AUTOMATA: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn automaton_count() -> usize {
    AUTOMATA.with(std::cell::Cell::get)
}

/// The parametric Levenshtein builder for one edit distance (0–2), with
/// adjacent transpositions. Building one takes milliseconds at distance two
/// and depends on nothing else, so each is built once per process.
pub(crate) fn levenshtein_builder(
    distance: u8,
) -> Result<&'static levenshtein_automata::LevenshteinAutomatonBuilder> {
    static BUILDERS: [OnceLock<levenshtein_automata::LevenshteinAutomatonBuilder>; 3] =
        [OnceLock::new(), OnceLock::new(), OnceLock::new()];
    let builder = BUILDERS
        .get(usize::from(distance))
        .ok_or_else(|| invalid("fuzzy distance must be 0, 1, or 2"))?;
    Ok(builder
        .get_or_init(|| levenshtein_automata::LevenshteinAutomatonBuilder::new(distance, true)))
}

/// One fuzzy term's automaton, shared by every field that term searches.
fn fuzzy_automaton(text: &str, distance: u8) -> Result<Arc<levenshtein_automata::DFA>> {
    let builder = levenshtein_builder(distance)?;
    #[cfg(test)]
    AUTOMATA.with(|count| count.set(count.get() + 1));
    Ok(Arc::new(builder.build_dfa(text)))
}

// FST traversal may visit many nonmatching dictionary branches between yielded
// terms. Consult cancellation in the automaton itself to prune that traversal.
struct CancellableAutomaton<'a, A> {
    inner: A,
    cancellation: &'a QueryCancellation,
}
impl<A: Automaton> Automaton for CancellableAutomaton<'_, A> {
    type State = Option<A::State>;
    fn start(&self) -> Self::State {
        Some(self.inner.start())
    }
    fn is_match(&self, state: &Self::State) -> bool {
        !self.cancellation.is_cancelled()
            && state
                .as_ref()
                .is_some_and(|state| self.inner.is_match(state))
    }
    fn can_match(&self, state: &Self::State) -> bool {
        !self.cancellation.is_cancelled()
            && state
                .as_ref()
                .is_some_and(|state| self.inner.can_match(state))
    }
    fn accept(&self, state: &Self::State, byte: u8) -> Self::State {
        if self.cancellation.is_cancelled() {
            None
        } else {
            state.as_ref().map(|state| self.inner.accept(state, byte))
        }
    }
}

#[derive(Clone)]
struct Dfa(Arc<levenshtein_automata::DFA>);
impl Automaton for Dfa {
    type State = u32;
    fn start(&self) -> u32 {
        self.0.initial_state()
    }
    fn is_match(&self, state: &u32) -> bool {
        matches!(
            self.0.distance(*state),
            levenshtein_automata::Distance::Exact(_)
        )
    }
    fn can_match(&self, state: &u32) -> bool {
        *state != levenshtein_automata::SINK_STATE
    }
    fn accept(&self, state: &u32, byte: u8) -> u32 {
        self.0.transition(*state, byte)
    }
}

struct Prefix(Vec<u8>);
impl Automaton for Prefix {
    type State = usize;
    fn start(&self) -> usize {
        0
    }
    fn is_match(&self, state: &usize) -> bool {
        *state == self.0.len()
    }
    fn can_match(&self, state: &usize) -> bool {
        *state <= self.0.len()
    }
    fn accept(&self, state: &usize, byte: u8) -> usize {
        if *state == self.0.len() {
            *state
        } else if self.0.get(*state) == Some(&byte) {
            *state + 1
        } else {
            self.0.len() + 1
        }
    }
}

impl TextCore {
    fn capture(&self) -> Result<Searcher> {
        capture(&self.index)
    }
}

fn capture(index: &Index) -> Result<Searcher> {
    let reader: IndexReader = index
        .reader_builder()
        .doc_store_cache_num_blocks(0)
        .reload_policy(ReloadPolicy::Manual)
        .try_into()
        .map_err(search_error)?;
    reader.reload().map_err(search_error)?;
    Ok(reader.searcher())
}

#[cfg(test)]
mod lending_tests {
    use super::*;
    use crate::{DocumentDelta, QueryIndexes, ReadFailure, SourceIdentity};
    use kasumi_types::{ArchivedDocument, Document};
    use serde_json::json;
    use std::cell::Cell;

    #[derive(Debug)]
    struct SourceFailure(Arc<()>);
    impl std::fmt::Display for SourceFailure {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("original text input failure")
        }
    }
    impl std::error::Error for SourceFailure {}

    enum Stored {
        Live(Document),
        Archived(ArchivedDocument),
    }
    impl Stored {
        fn record(&self) -> Record<'_> {
            match self {
                Self::Live(document) => Record::Live(document),
                Self::Archived(document) => Record::Archived(document),
            }
        }
    }
    fn live(id: &str, body: Value) -> Stored {
        Stored::Live(Document {
            id: id.to_owned(),
            version: 1,
            body,
        })
    }
    fn archived() -> Stored {
        Stored::Archived(ArchivedDocument {
            version: 1,
            archive_id: "archive".to_owned(),
            chunk_index: 0,
            document_sha256: "12".repeat(32),
            document_bytes: 64,
            indexed_fields: BTreeMap::new(),
        })
    }
    fn definition() -> CollectionDefinition {
        serde_json::from_value(json!({
            "name":"docs", "schema":{"type":"object"},
            "write_mode":"mutable", "retention_class":"operational",
            "strict_read_audit":false,
            "indexes":[{"name":"text", "fields":[{"path":"/title", "kind":"string"}],
                "unique":false, "text":{"analyzer":"unicode_v1"}}]
        }))
        .unwrap()
    }
    struct Records {
        definition: CollectionDefinition,
        rows: Vec<(&'static str, Stored)>,
        fail_after: Option<usize>,
        failure: Arc<()>,
    }
    impl Records {
        fn new(rows: Vec<(&'static str, Stored)>) -> Self {
            Self {
                definition: definition(),
                rows,
                fail_after: None,
                failure: Arc::new(()),
            }
        }
    }
    impl CollectionRecords for Records {
        type Failure = SourceFailure;
        fn identity(&self) -> SourceIdentity<'_> {
            SourceIdentity::new(self, "tenant", "incarnation", "docs")
        }
        fn definition(&self) -> &CollectionDefinition {
            &self.definition
        }
        fn visit_records(
            &self,
            mut lend: impl for<'a> FnMut(&'a str, Record<'a>) -> Result<()>,
        ) -> ReadResult<(), Self::Failure> {
            for (index, (id, record)) in self.rows.iter().enumerate() {
                if self.fail_after == Some(index) {
                    return Err(ReadFailure::Source(SourceFailure(self.failure.clone())));
                }
                lend(id, record.record())?;
            }
            Ok(())
        }
    }
    type Pair = (&'static str, Option<Stored>, Option<Stored>);
    struct Changes {
        definition: CollectionDefinition,
        indexes: QueryIndexes,
        owners: [u8; 2],
        pairs: Vec<Pair>,
        fail_after: Option<usize>,
        failure: Arc<()>,
        visits: Cell<usize>,
    }
    impl Changes {
        fn new(pairs: Vec<Pair>) -> Self {
            Self {
                definition: definition(),
                indexes: QueryIndexes::default(),
                owners: [0, 1],
                pairs,
                fail_after: None,
                failure: Arc::new(()),
                visits: Cell::new(0),
            }
        }
    }
    impl DocumentChanges for Changes {
        type Failure = SourceFailure;
        fn old_identity(&self) -> SourceIdentity<'_> {
            SourceIdentity::new(&self.owners[0], "tenant", "incarnation", "docs")
        }
        fn new_identity(&self) -> SourceIdentity<'_> {
            SourceIdentity::new(&self.owners[1], "tenant", "incarnation", "docs")
        }
        fn old_definition(&self) -> &CollectionDefinition {
            &self.definition
        }
        fn new_definition(&self) -> &CollectionDefinition {
            &self.definition
        }
        fn indexes(&self) -> &QueryIndexes {
            &self.indexes
        }
        fn visit_changes(
            &self,
            mut lend: impl for<'a> FnMut(DocumentDelta<'a>) -> Result<()>,
        ) -> ReadResult<(), Self::Failure> {
            for (index, (id, old, new)) in self.pairs.iter().enumerate() {
                if self.fail_after == Some(index) {
                    return Err(ReadFailure::Source(SourceFailure(self.failure.clone())));
                }
                self.visits.set(self.visits.get() + 1);
                lend(DocumentDelta {
                    id,
                    old: old.as_ref().map(Stored::record),
                    new: new.as_ref().map(Stored::record),
                })?;
            }
            Ok(())
        }
    }
    fn hits(snapshot: &TextSnapshot, query: &str) -> Vec<String> {
        snapshot
            .search(
                &TextSearch::new("text", query),
                10,
                &QueryCancellation::default(),
            )
            .unwrap()
            .into_keys()
            .collect()
    }
    fn original(error: ReadFailure<SourceFailure>, expected: &Arc<()>) {
        let ReadFailure::Source(SourceFailure(owner)) = error else {
            panic!("text input failure lost its original owner")
        };
        assert!(Arc::ptr_eq(&owner, expected));
    }

    #[test]
    fn private_text_build_preserves_source_error_and_skips_archived_rows() {
        let mut records = Records::new(vec![
            ("a", live("a", json!({"title":"live alpha"}))),
            ("b", archived()),
            ("c", live("c", json!({"title":"live gamma"}))),
        ]);
        records.fail_after = Some(2);
        original(TextSnapshot::build(&records).unwrap_err(), &records.failure);
        // Dropping the failed private writer must not publish or poison a
        // separate build from the same authoritative input.
        records.fail_after = None;
        let snapshot = TextSnapshot::build(&records).unwrap().unwrap();
        assert_eq!(snapshot.searcher.num_docs(), 2);
        assert_eq!(hits(&snapshot, "alpha"), vec!["a"]);
        assert_eq!(hits(&snapshot, "gamma"), vec!["c"]);
        assert_eq!(hits(&snapshot, "live"), vec!["a", "c"]);
    }

    #[test]
    fn text_pair_detection_preserves_live_presence_and_selected_field_semantics() {
        let records = Records::new(vec![("a", live("a", json!({"title":"old"})))]);
        let snapshot = TextSnapshot::build(&records).unwrap().unwrap();
        for (old, new, expected) in [
            (None, None, false),
            (None, Some(archived()), false),
            (Some(archived()), Some(archived()), false),
            (
                Some(live("a", json!({"other":1}))),
                Some(live("a", json!({"other":2}))),
                false,
            ),
            (
                Some(live("a", json!({"title":"old","other":1}))),
                Some(live("a", json!({"title":"old","other":2}))),
                false,
            ),
            (
                Some(live("a", json!({}))),
                Some(live("a", json!({"title":"new"}))),
                true,
            ),
            (Some(live("a", json!({"title":"old"}))), None, true),
            (None, Some(live("a", json!({"title":"new"}))), true),
            (Some(live("a", json!({}))), Some(archived()), true),
            (Some(archived()), Some(live("a", json!({}))), true),
        ] {
            let changes = Changes::new(vec![("a", old, new)]);
            assert_eq!(snapshot.fields_changed(&changes).unwrap(), expected);
            assert_eq!(*snapshot.core.active.lock().unwrap(), Some(0));
        }
    }

    #[test]
    fn text_preparation_failure_stays_private_but_materialization_failure_fences_writer() {
        let records = Records::new(vec![
            ("a", live("a", json!({"title":"old alpha"}))),
            ("b", live("b", json!({"title":"old beta"}))),
        ]);
        let snapshot = TextSnapshot::build(&records).unwrap().unwrap();
        let mut changes = Changes::new(vec![
            (
                "a",
                Some(live("a", json!({"title":"old alpha"}))),
                Some(live("a", json!({"title":"new alpha"}))),
            ),
            (
                "b",
                Some(live("b", json!({"title":"old beta"}))),
                Some(live("b", json!({"title":"new beta"}))),
            ),
        ]);
        changes.fail_after = Some(1);
        original(
            snapshot.fields_changed(&changes).unwrap_err(),
            &changes.failure,
        );
        assert_eq!(*snapshot.core.active.lock().unwrap(), Some(0));
        changes.fail_after = None;
        assert!(snapshot.fields_changed(&changes).unwrap());

        // Replay can fail after a delete/add has touched the shared writer.
        // Preserve that original failure and require recovery, while the old
        // published immutable reader continues to see only the old contents.
        changes.fail_after = Some(1);
        original(snapshot.update(&changes).unwrap_err(), &changes.failure);
        assert_eq!(*snapshot.core.active.lock().unwrap(), None);
        assert_eq!(hits(&snapshot, "old"), vec!["a", "b"]);
        assert!(hits(&snapshot, "new").is_empty());
        changes.fail_after = None;
        let visits = changes.visits.get();
        assert!(matches!(snapshot.update(&changes),
            Err(ReadFailure::Query(error)) if error.code == ErrorCode::Unavailable));
        assert_eq!(changes.visits.get(), visits);
    }
}
