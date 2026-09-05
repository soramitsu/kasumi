use crate::QueryCancellation;
use crate::scalar::{exhausted, invalid};
use kasumi_types::{
    Analyzer, CollectionDefinition, CollectionState, Error, ErrorCode, Result, TextMode, TextSearch,
};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, OnceLock},
};
use tantivy::query::{
    BooleanQuery, BoostQuery, DisjunctionMaxQuery, EmptyQuery, EnableScoring, Occur, PhraseQuery,
    Query, TermQuery,
};
use tantivy::schema::{
    FAST, Field, IndexRecordOption, STRING, Schema, TextFieldIndexing, TextOptions,
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

struct TextCore {
    index: Index,
    indexes: BTreeMap<String, TextFields>,
    row_field: Field,
    id_field: Field,
    // None means an interrupted/failed update poisoned this writer corridor.
    // Older immutable readers remain usable, but new applies must recover.
    active: Mutex<Option<u64>>,
}

pub(crate) struct TextSnapshot {
    core: Arc<TextCore>,
    searcher: Searcher,
    ids: imbl::HashMap<u64, String>,
    rows: imbl::HashMap<String, u64>,
    next_row: u64,
    generation: u64,
}

impl std::fmt::Debug for TextSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TextSnapshot")
            .field("indexes", &self.core.indexes.keys())
            .field("documents", &self.ids.len())
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
                    let tokenizer =
                        lindera_tantivy::tokenizer::LinderaTokenizer::from_segmenter(segmenter);
                    Ok(TextAnalyzer::builder(tokenizer).filter(LowerCaser).build())
                })
                .clone()
        }
    }
}

fn analyzer_name(kind: Analyzer, surface: bool) -> String {
    format!("{kind:?}_{}", if surface { "surface" } else { "ranked" })
}

fn tokens(
    kind: Analyzer,
    text: &str,
    surface: bool,
    max_tokens: usize,
) -> Result<Vec<(usize, String)>> {
    let normalized: String = text.nfkc().collect();
    let mut analyzer = analyzer(kind, surface)?;
    let mut stream = analyzer.token_stream(&normalized);
    let mut tokens = Vec::new();
    while stream.advance() {
        let token = stream.token();
        if token.text.len() > 240 {
            return Err(invalid("text token exceeds 240 UTF-8 bytes"));
        }
        tokens.push((token.position, token.text.clone()));
        if tokens.len() > max_tokens {
            return Err(exhausted("text token budget exceeded"));
        }
    }
    Ok(tokens)
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
            let values: Vec<&str> = match body.pointer(&field.path) {
                Some(Value::String(value)) => vec![value.as_str()],
                Some(Value::Array(values)) => values.iter().filter_map(Value::as_str).collect(),
                _ => Vec::new(),
            };
            for value in values {
                // Prefix and fuzzy fields are unstemmed; validate both versions.
                total += tokens(text.analyzer, value, false, 65_536)?.len();
                tokens(text.analyzer, value, true, 65_536)?;
                if total > 65_536 {
                    return Err(exhausted("document text-index token budget exceeded"));
                }
            }
        }
    }
    Ok(())
}

impl TextSnapshot {
    pub fn build(collection: &CollectionState) -> Result<Option<Self>> {
        if collection
            .definition
            .indexes
            .iter()
            .all(|i| i.text.is_none())
        {
            return Ok(None);
        }
        let mut builder = Schema::builder();
        let row_field = builder.add_u64_field("_kasumi_row", FAST);
        let id_field = builder.add_text_field("_kasumi_id", STRING);
        let mut indexes = BTreeMap::new();
        let mut sequence = 0;
        for definition in &collection.definition.indexes {
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
            indexes.insert(
                definition.name.clone(),
                TextFields {
                    analyzer: text.analyzer,
                    paths,
                },
            );
        }
        let index = Index::create_in_ram(builder.build());
        for fields in indexes.values() {
            for surface in [false, true] {
                index.tokenizers().register(
                    &analyzer_name(fields.analyzer, surface),
                    analyzer(fields.analyzer, surface)?,
                );
            }
        }
        let core = Arc::new(TextCore {
            index,
            indexes,
            row_field,
            id_field,
            active: Mutex::new(Some(0)),
        });
        // Reopen the same RAM index per apply; no idle generation retains a
        // worker thread or a 15 MB writer allocation for every collection.
        let mut writer = core
            .index
            .writer_with_num_threads::<TantivyDocument>(1, 15_000_000)
            .map_err(search_error)?;
        let mut sorted: Vec<String> = collection.documents.keys().cloned().collect();
        sorted.sort();
        let mut ids = imbl::HashMap::new();
        let mut rows = imbl::HashMap::new();
        for (row, id) in sorted.iter().enumerate() {
            let row = row as u64;
            writer
                .add_document(core.document(id, row, &collection.documents[id].body))
                .map_err(search_error)?;
            ids.insert(row, id.clone());
            rows.insert(id.clone(), row);
        }
        writer.commit().map_err(search_error)?;
        writer.wait_merging_threads().map_err(search_error)?;
        let searcher = core.capture()?;
        Ok(Some(Self {
            core,
            searcher,
            ids,
            rows,
            next_row: sorted.len() as u64,
            generation: 0,
        }))
    }

    pub fn fields_changed(
        &self,
        old: &CollectionState,
        new: &CollectionState,
        changed: &BTreeSet<String>,
    ) -> bool {
        changed
            .iter()
            .any(|id| match (old.documents.get(id), new.documents.get(id)) {
                (Some(old), Some(new)) => self.core.indexes.values().any(|index| {
                    index
                        .paths
                        .iter()
                        .any(|(path, _, _)| old.body.pointer(path) != new.body.pointer(path))
                }),
                (None, None) => false,
                _ => true,
            })
    }

    pub fn update(&self, collection: &CollectionState, changed: &BTreeSet<String>) -> Result<Self> {
        let mut active = self
            .core
            .active
            .lock()
            .map_err(|_| search_error("text writer unavailable"))?;
        if *active != Some(self.generation) {
            return Err(search_error(
                "cannot advance a stale or failed text generation",
            ));
        }
        *active = None;
        let mut writer = self
            .core
            .index
            .writer_with_num_threads::<TantivyDocument>(1, 15_000_000)
            .map_err(search_error)?;
        let mut ids = self.ids.clone();
        let mut rows = self.rows.clone();
        let mut next_row = self.next_row;
        for id in changed {
            let old_row = rows.remove(id);
            if let Some(row) = old_row {
                ids.remove(&row);
                writer.delete_term(Term::from_field_text(self.core.id_field, id));
            }
            if let Some(document) = collection.documents.get(id) {
                let row = if let Some(row) = old_row {
                    row
                } else {
                    let row = next_row;
                    next_row = next_row
                        .checked_add(1)
                        .ok_or_else(|| search_error("text row identifier exhausted"))?;
                    row
                };
                writer
                    .add_document(self.core.document(id, row, &document.body))
                    .map_err(search_error)?;
                ids.insert(row, id.clone());
                rows.insert(id.clone(), row);
            }
        }
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
            ids,
            rows,
            next_row,
            generation,
        })
    }

    pub fn search(
        &self,
        request: &TextSearch,
        cap: usize,
        cancellation: &QueryCancellation,
    ) -> Result<BTreeMap<String, f32>> {
        cancellation.check()?;
        if request.query.len() > 4096 {
            return Err(invalid("text query exceeds 4096 UTF-8 bytes"));
        }
        let fields = self.core.indexes.get(&request.index).ok_or_else(|| {
            Error::new(ErrorCode::IndexRequired, "named text index does not exist")
        })?;
        let fuzzy = request.mode == TextMode::Fuzzy;
        let surface_query = fuzzy || request.mode == TextMode::Prefix;
        if fuzzy && request.distance > 2 {
            return Err(invalid("fuzzy distance must be 0, 1, or 2"));
        }
        let terms = tokens(fields.analyzer, &request.query, surface_query, 64)?;
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
        let mut alternatives: Vec<Box<dyn Query>> = Vec::new();
        let mut expanded_count = 0;
        let mut posting_work = 0u64;
        // Intersecting two very common terms can produce few hits while reading
        // huge postings lists. Limit planned postings, as well as returned hits.
        let posting_limit = cap.saturating_mul(8) as u64;
        for terms in &tokenizations {
            cancellation.check()?;
            for (_, ranked, surface) in &fields.paths {
                cancellation.check()?;
                let field = if surface_query { *surface } else { *ranked };
                if request.mode == TextMode::Phrase && terms.len() > 1 {
                    for (_, text) in terms {
                        self.charge_term(field, text, &mut posting_work, posting_limit)?;
                    }
                    alternatives.push(Box::new(PhraseQuery::new_with_offset(
                        terms
                            .iter()
                            .map(|(position, text)| (*position, Term::from_field_text(field, text)))
                            .collect(),
                    )));
                    continue;
                }
                let mut clauses: Vec<(Occur, Box<dyn Query>)> = Vec::new();
                for (i, (_, text)) in terms.iter().enumerate() {
                    cancellation.check()?;
                    let query: Box<dyn Query> = if fuzzy {
                        let japanese = fields.analyzer == Analyzer::JapaneseV1;
                        if !japanese && request.distance > 0 && text.chars().count() < 3 {
                            return Err(invalid("fuzzy term is too short"));
                        }
                        // Single-character Japanese particles remain exact; editing
                        // them would expand to nearly the entire term dictionary.
                        let distance = if japanese && text.chars().count() < 2 {
                            0
                        } else {
                            request.distance
                        };
                        let dfa = Arc::new(
                            levenshtein_automata::LevenshteinAutomatonBuilder::new(distance, true)
                                .build_dfa(text),
                        );
                        let expansions = self.expand(
                            field,
                            Dfa(dfa.clone()),
                            &mut expanded_count,
                            cancellation,
                        )?;
                        for term in &expansions {
                            self.charge_term(field, term, &mut posting_work, posting_limit)?;
                        }
                        let queries: Vec<Box<dyn Query>> = expansions
                            .into_iter()
                            .map(|term| {
                                let state = term
                                    .bytes()
                                    .fold(dfa.initial_state(), |state, b| dfa.transition(state, b));
                                let distance = match dfa.distance(state) {
                                    levenshtein_automata::Distance::Exact(d) => d,
                                    _ => 2,
                                };
                                Box::new(BoostQuery::new(
                                    Box::new(TermQuery::new(
                                        Term::from_field_text(field, &term),
                                        IndexRecordOption::WithFreqs,
                                    )),
                                    1.0 / (1 + distance) as f32,
                                )) as Box<dyn Query>
                            })
                            .collect();
                        disjunction(queries)
                    } else if request.mode == TextMode::Prefix && i + 1 == terms.len() {
                        let expansions = self.expand(
                            field,
                            Prefix(text.as_bytes().to_vec()),
                            &mut expanded_count,
                            cancellation,
                        )?;
                        for term in &expansions {
                            self.charge_term(field, term, &mut posting_work, posting_limit)?;
                        }
                        disjunction(
                            expansions
                                .into_iter()
                                .map(|term| {
                                    Box::new(TermQuery::new(
                                        Term::from_field_text(field, &term),
                                        IndexRecordOption::WithFreqs,
                                    )) as Box<dyn Query>
                                })
                                .collect(),
                        )
                    } else {
                        self.charge_term(field, text, &mut posting_work, posting_limit)?;
                        Box::new(TermQuery::new(
                            Term::from_field_text(field, text),
                            IndexRecordOption::WithFreqs,
                        ))
                    };
                    clauses.push((Occur::Must, query));
                }
                alternatives.push(Box::new(BooleanQuery::new(clauses)));
            }
        }
        let query = disjunction(alternatives);
        let weight = query
            .weight(EnableScoring::enabled_from_searcher(&self.searcher))
            .map_err(search_error)?;
        let mut matches = BTreeMap::new();
        // Drive scorers ourselves: TopDocs(limit) limits output, not matching work.
        for segment in self.searcher.segment_readers() {
            cancellation.check()?;
            let rows = segment
                .fast_fields()
                .u64("_kasumi_row")
                .map_err(search_error)?;
            let mut scorer = weight.scorer(segment, 1.0).map_err(search_error)?;
            while scorer.doc() != TERMINATED {
                cancellation.check()?;
                let doc = scorer.doc();
                if segment.is_deleted(doc) {
                    scorer.advance();
                    continue;
                }
                let row = rows
                    .first(doc)
                    .ok_or_else(|| search_error("missing internal row identifier"))?;
                let id = self
                    .ids
                    .get(&row)
                    .ok_or_else(|| search_error("invalid internal row identifier"))?;
                matches.insert(id.clone(), scorer.score());
                if matches.len() > cap {
                    return Err(exhausted("text candidate budget exceeded"));
                }
                scorer.advance();
            }
        }
        Ok(matches)
    }

    fn charge_term(&self, field: Field, text: &str, work: &mut u64, limit: u64) -> Result<()> {
        *work = work.saturating_add(
            self.searcher
                .doc_freq(&Term::from_field_text(field, text))
                .map_err(search_error)?,
        );
        if *work > limit {
            return Err(exhausted(
                "text postings budget exceeded (8 times candidate budget)",
            ));
        }
        Ok(())
    }

    fn expand<A: Automaton>(
        &self,
        field: Field,
        automaton: A,
        total: &mut usize,
        cancellation: &QueryCancellation,
    ) -> Result<BTreeSet<String>>
    where
        A::State: Clone,
    {
        let automaton = CancellableAutomaton {
            inner: automaton,
            cancellation,
        };
        let mut expansions = BTreeSet::new();
        for segment in self.searcher.segment_readers() {
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
        Ok(expansions)
    }
}

fn disjunction(mut queries: Vec<Box<dyn Query>>) -> Box<dyn Query> {
    match queries.len() {
        0 => Box::new(EmptyQuery),
        1 => queries.pop().unwrap(),
        _ => Box::new(DisjunctionMaxQuery::new(queries)),
    }
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
    fn document(&self, id: &str, row: u64, body: &Value) -> TantivyDocument {
        let mut indexed = TantivyDocument::default();
        indexed.add_u64(self.row_field, row);
        indexed.add_text(self.id_field, id);
        for fields in self.indexes.values() {
            for (path, ranked, surface) in &fields.paths {
                let values: Vec<&str> = match body.pointer(path) {
                    Some(Value::String(text)) => vec![text.as_str()],
                    Some(Value::Array(values)) => values.iter().filter_map(Value::as_str).collect(),
                    _ => Vec::new(),
                };
                for text in values {
                    let normalized: String = text.nfkc().collect();
                    indexed.add_text(*ranked, &normalized);
                    indexed.add_text(*surface, &normalized);
                }
            }
        }
        indexed
    }
    fn capture(&self) -> Result<Searcher> {
        let reader: IndexReader = self
            .index
            .reader_builder()
            .reload_policy(ReloadPolicy::Manual)
            .try_into()
            .map_err(search_error)?;
        reader.reload().map_err(search_error)?;
        Ok(reader.searcher())
    }
}
