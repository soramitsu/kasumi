use crate::scalar::{exhausted, invalid};
use crate::{CollectionRecords, DocumentChanges, QueryCancellation, ReadResult, Record};
use kasumi_types::{
    Analyzer, CollectionDefinition, Error, ErrorCode, Result, TextMode, TextSearch,
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
    pub fn build<R: CollectionRecords + ?Sized>(
        source: &R,
    ) -> ReadResult<Option<Self>, R::Failure> {
        if source.definition().indexes.iter().all(|i| i.text.is_none()) {
            return Ok(None);
        }
        let mut builder = Schema::builder();
        let row_field = builder.add_u64_field("_kasumi_row", FAST);
        let id_field = builder.add_text_field("_kasumi_id", STRING);
        let mut indexes = BTreeMap::new();
        let mut sequence = 0;
        for definition in &source.definition().indexes {
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
        let mut ids = imbl::HashMap::new();
        let mut rows = imbl::HashMap::new();
        let mut next_row = 0u64;
        // The checked source lends logical IDs in strict order. Archived rows
        // have no resident text body; only live rows receive a text row, as in
        // the original build. No collection-sized ID sort buffer is needed.
        // A source failure drops this private writer and returns its original
        // owner before any TextSnapshot can be published.
        source.visit_records(|id, record| {
            let Record::Live(document) = record else {
                return Ok(());
            };
            let row = next_row;
            next_row = next_row
                .checked_add(1)
                .ok_or_else(|| search_error("text row identifier exhausted"))?;
            writer
                .add_document(core.document(id, row, &document.body))
                .map_err(search_error)?;
            ids.insert(row, id.to_owned());
            rows.insert(id.to_owned(), row);
            Ok(())
        })?;
        writer.commit().map_err(search_error)?;
        writer.wait_merging_threads().map_err(search_error)?;
        let searcher = core.capture()?;
        Ok(Some(Self {
            core,
            searcher,
            ids,
            rows,
            next_row,
            generation: 0,
        }))
    }

    pub fn fields_changed<D: DocumentChanges + ?Sized>(
        &self,
        changes: &D,
    ) -> ReadResult<bool, D::Failure> {
        let mut changed = false;
        // The enclosing index preparation has validated every new live body,
        // including text limits, before this comparison-only pass. Visit every
        // delta so a later source failure cannot hide behind an earlier change.
        changes.visit_changes(|delta| {
            changed |= match (delta.old, delta.new) {
                (Some(Record::Live(old)), Some(Record::Live(new))) => {
                    self.core.indexes.values().any(|index| {
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
        let mut ids = self.ids.clone();
        let mut rows = self.rows.clone();
        let mut next_row = self.next_row;
        // Any replay/read error after this point leaves active=None. The old
        // reader remains immutable, but the shared writer corridor must recover;
        // a source failure is never flattened into a deterministic query error.
        changes.visit_changes(|delta| {
            let id = delta.id;
            let old_row = rows.remove(id);
            if let Some(row) = old_row {
                ids.remove(&row);
                writer.delete_term(Term::from_field_text(self.core.id_field, id));
            }
            if let Some(Record::Live(document)) = delta.new {
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
                ids.insert(row, id.to_owned());
                rows.insert(id.to_owned(), row);
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
                &TextSearch {
                    index: "text".to_owned(),
                    query: query.to_owned(),
                    mode: TextMode::Terms,
                    distance: 1,
                },
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
        assert_eq!(snapshot.next_row, 2);
        assert_eq!(snapshot.rows.get("a"), Some(&0));
        assert_eq!(snapshot.rows.get("c"), Some(&1));
        assert!(!snapshot.rows.contains_key("b"));
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
