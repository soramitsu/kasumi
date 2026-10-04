use crate::scalar::{Scalar, exhausted, indexed_values, invalid, scalar, validate_pointer};
use crate::{
    CollectionRecords, DocumentChanges, DocumentSource, QueryCancellation, ReadResult, Record,
    document_source,
};
use imbl::{OrdMap, OrdSet};
use kasumi_types::*;
use serde_json::Value;
use std::collections::BTreeMap;
use std::ops::{Bound, RangeBounds};

pub(crate) type IdSet = OrdSet<String>;

#[derive(Debug, Clone)]
pub(crate) struct FieldIndex {
    pub kind: ScalarType,
    pub entries: OrdMap<Scalar, IdSet>,
    pub present: IdSet,
}

#[derive(Debug, Clone)]
pub(crate) struct Structured {
    pub fields: BTreeMap<String, FieldIndex>,
    pub ids: IdSet,
    pub(crate) unique: BTreeMap<String, UniqueIndex>,
}

#[derive(Debug, Clone)]
pub(crate) struct UniqueIndex {
    pub(crate) fields: Vec<IndexField>,
    pub(crate) entries: OrdMap<Vec<Scalar>, String>,
}

pub(crate) fn record_value<'a>(record: Record<'a>, path: &str) -> Option<&'a Value> {
    match record {
        Record::Live(document) => document.body.pointer(path),
        Record::Archived(document) => document.indexed_fields.get(path),
    }
}
impl UniqueIndex {
    fn key(&self, record: Record<'_>) -> Result<Option<Vec<Scalar>>> {
        let key = self
            .fields
            .iter()
            .map(|field| scalar(record_value(record, &field.path), Some(field.kind)))
            .collect::<Result<Vec<_>>>()?;
        Ok((!key.contains(&Scalar::Missing)).then_some(key))
    }
    fn insert(&mut self, name: &str, id: &str, record: Record<'_>) -> Result<()> {
        if let Some(key) = self.key(record)?
            && self.entries.insert(key, id.to_owned()).is_some()
        {
            return Err(Error::new(
                ErrorCode::Conflict,
                format!("unique index {name} conflicts"),
            ));
        }
        Ok(())
    }
}

impl Structured {
    pub fn update<D: DocumentChanges + ?Sized>(&self, changes: &D) -> ReadResult<Self, D::Failure> {
        let mut next = self.clone();
        next.unique = self.unique_delta(changes)?;
        changes.visit_changes(|delta| {
            let previous = delta.old;
            let current = delta.new;
            let id = delta.id;
            if previous.is_none() && current.is_none() {
                return Ok(());
            }
            if current.is_none() {
                next.ids.remove(id);
            } else if previous.is_none() {
                next.ids.insert(id.to_owned());
            }
            for (path, index) in &mut next.fields {
                let old_value = previous.and_then(|record| record_value(record, path));
                let new_value = current.and_then(|record| record_value(record, path));
                if previous.is_some() && current.is_some() && old_value == new_value {
                    continue;
                }
                if previous.is_some() {
                    index.present.remove(id);
                    for key in indexed_values(old_value, index.kind)? {
                        if let Some(ids) = index.entries.get_mut(&key) {
                            ids.remove(id);
                            if ids.is_empty() {
                                index.entries.remove(&key);
                            }
                        }
                    }
                }
                if current.is_some() {
                    if new_value.is_some() {
                        index.present.insert(id.to_owned());
                    }
                    for key in indexed_values(new_value, index.kind)? {
                        index.entries.entry(key).or_default().insert(id.to_owned());
                    }
                }
            }
            Ok(())
        })?;
        Ok(next)
    }
    fn unique_delta<D: DocumentChanges + ?Sized>(
        &self,
        changes: &D,
    ) -> ReadResult<BTreeMap<String, UniqueIndex>, D::Failure> {
        let mut unique = self.unique.clone();
        // Remove every old mapping across the batch before adding any new one.
        // Private COW roots are discarded on rejection; published roots stay intact.
        changes.visit_changes(|delta| {
            if let Some(old) = delta.old {
                for index in unique.values_mut() {
                    if let Some(key) = index.key(old)? {
                        if index
                            .entries
                            .get(&key)
                            .is_none_or(|owner| owner != delta.id)
                        {
                            return Err(Error::new(
                                ErrorCode::Corruption,
                                "old unique mapping differs from delta",
                            ));
                        }
                        index.entries.remove(&key);
                    }
                }
            }
            Ok(())
        })?;
        changes.visit_changes(|delta| {
            if let Some(new) = delta.new {
                for (name, index) in &mut unique {
                    index.insert(name, delta.id, new)?;
                }
            }
            Ok(())
        })?;
        Ok(unique)
    }
    pub fn validate_unique_changes<D: DocumentChanges + ?Sized>(
        &self,
        changes: &D,
    ) -> ReadResult<(), D::Failure> {
        self.unique_delta(changes).map(|_| ())
    }

    fn empty_unique(definition: &CollectionDefinition) -> BTreeMap<String, UniqueIndex> {
        definition
            .indexes
            .iter()
            .filter(|index| index.unique)
            .map(|index| {
                (
                    index.name.clone(),
                    UniqueIndex {
                        fields: index.fields.clone(),
                        entries: OrdMap::new(),
                    },
                )
            })
            .collect()
    }
    pub(crate) fn build_unique<R: CollectionRecords + ?Sized>(
        source: &R,
    ) -> ReadResult<BTreeMap<String, UniqueIndex>, R::Failure> {
        let mut unique = Self::empty_unique(source.definition());
        source.visit_records(|id, record| {
            for (name, index) in &mut unique {
                index.insert(name, id, record)?;
            }
            Ok(())
        })?;
        Ok(unique)
    }
    pub fn build<R: CollectionRecords + ?Sized>(source: &R) -> ReadResult<Self, R::Failure> {
        let mut fields = BTreeMap::new();
        for index in &source.definition().indexes {
            for field in &index.fields {
                fields
                    .entry(field.path.clone())
                    .or_insert_with(|| FieldIndex {
                        kind: field.kind,
                        entries: OrdMap::new(),
                        present: IdSet::new(),
                    });
            }
        }
        let mut ids = IdSet::new();
        let mut unique = Self::empty_unique(source.definition());
        source.visit_records(|id, record| {
            ids.insert(id.to_owned());
            for (path, index) in &mut fields {
                let value = record_value(record, path);
                if value.is_some() {
                    index.present.insert(id.to_owned());
                }
                for key in indexed_values(value, index.kind)? {
                    index.entries.entry(key).or_default().insert(id.to_owned());
                }
            }
            for (name, index) in &mut unique {
                index.insert(name, id, record)?;
            }
            Ok(())
        })?;
        Ok(Self {
            fields,
            ids,
            unique,
        })
    }

    pub fn field_kind(&self, path: &str, allow_scan: bool) -> Result<Option<ScalarType>> {
        validate_pointer(path)?;
        match self.fields.get(path) {
            Some(index) => Ok(Some(index.kind)),
            None if allow_scan => Ok(None),
            None => Err(Error::new(
                ErrorCode::IndexRequired,
                format!("declare an index for {path} or explicitly allow_scan"),
            )),
        }
    }
}

pub(crate) fn check_size(size: usize, limit: usize) -> Result<()> {
    if size > limit {
        Err(exhausted("query candidate budget exceeded"))
    } else {
        Ok(())
    }
}

const MAX_FILTER_DEPTH: usize = 16;
const MAX_FILTER_NODES: usize = 256;
/// Index entries a range estimate may visit before it is ranked as broad.
const RANGE_ESTIMATE_BUDGET: usize = 4096;

/// A filter normalized to one node per test. A field's bounds form a single
/// range, so `{"gte": a, "lt": b}` is one ordered index walk.
#[derive(Debug)]
pub(crate) enum Node<'a> {
    All,
    Leaf { path: &'a str, test: Test<'a> },
    And(Vec<Node<'a>>),
    Or(Vec<Node<'a>>),
    Not(Box<Node<'a>>),
}

#[derive(Debug)]
pub(crate) enum Test<'a> {
    Eq(&'a Value),
    In(&'a [Value]),
    Range {
        lower: Bound<&'a Value>,
        upper: Bound<&'a Value>,
    },
    Exists(bool),
    Contains(&'a Value),
}

/// Shape checks and normalization, independent of indexes and documents, so
/// empty collections and short-circuiting cannot accept malformed filters.
pub(crate) fn plan(filter: &Filter) -> Result<Node<'_>> {
    plan_filter(filter, 0, &mut 0)
}

fn count(nodes: &mut usize) -> Result<()> {
    *nodes += 1;
    if *nodes > MAX_FILTER_NODES {
        return Err(invalid("filter exceeds 256 conditions"));
    }
    Ok(())
}

fn plan_filter<'a>(filter: &'a Filter, depth: usize, nodes: &mut usize) -> Result<Node<'a>> {
    if depth > MAX_FILTER_DEPTH {
        return Err(invalid("filter exceeds 16 nesting levels"));
    }
    let mut children = Vec::new();
    for (path, condition) in &filter.fields {
        validate_pointer(path)?;
        plan_condition(path, condition, nodes, &mut children)?;
    }
    for nested in &filter.and {
        count(nodes)?;
        children.push(plan_filter(nested, depth + 1, nodes)?);
    }
    if !filter.or.is_empty() {
        count(nodes)?;
        let alternatives = filter
            .or
            .iter()
            .map(|alternative| plan_filter(alternative, depth + 1, nodes))
            .collect::<Result<_>>()?;
        children.push(Node::Or(alternatives));
    }
    if let Some(negated) = &filter.not {
        count(nodes)?;
        children.push(Node::Not(Box::new(plan_filter(negated, depth + 1, nodes)?)));
    }
    Ok(match children.len() {
        0 => Node::All,
        1 => children.pop().expect("one child"),
        _ => Node::And(children),
    })
}

fn plan_condition<'a>(
    path: &'a str,
    condition: &'a Condition,
    nodes: &mut usize,
    out: &mut Vec<Node<'a>>,
) -> Result<()> {
    if condition.is_empty() {
        return Err(invalid(format!("{path}: empty field condition")));
    }
    if condition.gt.is_some() && condition.gte.is_some() {
        return Err(invalid(format!("{path}: use either gt or gte")));
    }
    if condition.lt.is_some() && condition.lte.is_some() {
        return Err(invalid(format!("{path}: use either lt or lte")));
    }
    let leaf = |test| Node::Leaf { path, test };
    let mut push = |node| -> Result<()> {
        count(nodes)?;
        out.push(node);
        Ok(())
    };
    if let Some(value) = &condition.eq {
        push(leaf(Test::Eq(value)))?;
    }
    if let Some(value) = &condition.ne {
        push(Node::Not(Box::new(leaf(Test::Eq(value)))))?;
    }
    let lower = match (&condition.gt, &condition.gte) {
        (Some(value), _) => Bound::Excluded(value),
        (_, Some(value)) => Bound::Included(value),
        _ => Bound::Unbounded,
    };
    let upper = match (&condition.lt, &condition.lte) {
        (Some(value), _) => Bound::Excluded(value),
        (_, Some(value)) => Bound::Included(value),
        _ => Bound::Unbounded,
    };
    if !matches!((lower, upper), (Bound::Unbounded, Bound::Unbounded)) {
        push(leaf(Test::Range { lower, upper }))?;
    }
    for (values, negated) in [(&condition.r#in, false), (&condition.nin, true)] {
        if let Some(values) = values {
            if values.len() > MAX_FILTER_IN_VALUES {
                return Err(invalid("in/nin are limited to 256 values"));
            }
            let node = leaf(Test::In(values));
            push(if negated {
                Node::Not(Box::new(node))
            } else {
                node
            })?;
        }
    }
    if let Some(exists) = condition.exists {
        push(leaf(Test::Exists(exists)))?;
    }
    if let Some(value) = &condition.contains {
        push(leaf(Test::Contains(value)))?;
    }
    Ok(())
}

fn bound_value<'a>(bound: &Bound<&'a Value>) -> Option<&'a Value> {
    match bound {
        Bound::Included(value) | Bound::Excluded(value) => Some(value),
        Bound::Unbounded => None,
    }
}

fn scalar_bound(bound: Bound<&Value>, kind: Option<ScalarType>) -> Result<Bound<Scalar>> {
    Ok(match bound {
        Bound::Included(value) => Bound::Included(scalar(Some(value), kind)?),
        Bound::Excluded(value) => Bound::Excluded(scalar(Some(value), kind)?),
        Bound::Unbounded => Bound::Unbounded,
    })
}

/// Index range for a validated test. Absent and null entries sort first and
/// never satisfy a range, so an open lower bound starts after them.
fn index_range(
    lower: Bound<&Value>,
    upper: Bound<&Value>,
    kind: Option<ScalarType>,
) -> Result<(Bound<Scalar>, Bound<Scalar>)> {
    let lower = match scalar_bound(lower, kind)? {
        Bound::Unbounded => Bound::Excluded(Scalar::Null),
        bound => bound,
    };
    Ok((lower, scalar_bound(upper, kind)?))
}

fn empty_range(range: &(Bound<Scalar>, Bound<Scalar>)) -> bool {
    use Bound::{Excluded, Included};
    match range {
        (Included(lower), Included(upper)) => lower > upper,
        (Included(lower) | Excluded(lower), Included(upper) | Excluded(upper)) => lower >= upper,
        _ => false,
    }
}

fn validate_test(path: &str, test: &Test<'_>, kind: Option<ScalarType>) -> Result<()> {
    let array = matches!(
        kind,
        Some(ScalarType::StringArray | ScalarType::NumberArray)
    );
    let array_error = || {
        invalid(format!(
            "{path} is an array field; use contains to match its elements"
        ))
    };
    match test {
        Test::Exists(_) => Ok(()),
        Test::Contains(value) => {
            if kind.is_some() && !array {
                return Err(invalid(format!("{path}: contains requires an array field")));
            }
            if value.is_null() {
                return Err(invalid("array membership requires a non-null scalar"));
            }
            scalar(Some(value), kind).map(drop)
        }
        Test::Eq(value) => {
            if array && !value.is_null() {
                return Err(array_error());
            }
            scalar(Some(value), kind).map(drop)
        }
        Test::In(values) => {
            if array {
                return Err(array_error());
            }
            values
                .iter()
                .try_for_each(|value| scalar(Some(value), kind).map(drop))
        }
        Test::Range { lower, upper } => {
            if array {
                return Err(array_error());
            }
            let mut first: Option<Scalar> = None;
            for value in [bound_value(lower), bound_value(upper)]
                .into_iter()
                .flatten()
            {
                let key = scalar(Some(value), kind)?;
                if key == Scalar::Null {
                    return Err(invalid("ordered comparison requires a non-null scalar"));
                }
                if let Some(first) = &first
                    && std::mem::discriminant(first) != std::mem::discriminant(&key)
                {
                    return Err(invalid(format!("{path}: range bounds must have one type")));
                }
                first = Some(key);
            }
            Ok(())
        }
    }
}

/// Unindexed values that cannot be compared never match a scanned leaf.
fn scanned_scalar(value: Option<&Value>, kind: Option<ScalarType>) -> Option<Scalar> {
    scalar(value, kind).ok()
}

pub(crate) fn evaluate(
    test: &Test<'_>,
    actual: Option<&Value>,
    kind: Option<ScalarType>,
    cancellation: &QueryCancellation,
) -> Result<bool> {
    if let Test::Exists(exists) = test {
        return Ok(actual.is_some() == *exists);
    }
    if let Test::Contains(value) = test {
        let Some(Value::Array(elements)) = actual else {
            return Ok(false);
        };
        let expected = scalar(Some(value), kind)?;
        for element in elements {
            cancellation.check()?;
            if scanned_scalar(Some(element), kind).as_ref() == Some(&expected) {
                return Ok(true);
            }
        }
        return Ok(false);
    }
    if actual.is_none() {
        return Ok(false);
    }
    let Some(actual) = scanned_scalar(actual, kind) else {
        return Ok(false);
    };
    match test {
        Test::Eq(value) => Ok(actual == scalar(Some(value), kind)?),
        Test::In(values) => {
            for value in *values {
                cancellation.check()?;
                if actual == scalar(Some(value), kind)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Test::Range { lower, upper } => {
            if matches!(actual, Scalar::Missing | Scalar::Null) {
                return Ok(false);
            }
            let (lower, upper) = (scalar_bound(*lower, kind)?, scalar_bound(*upper, kind)?);
            for bound in [&lower, &upper] {
                if let Bound::Included(key) | Bound::Excluded(key) = bound
                    && std::mem::discriminant(key) != std::mem::discriminant(&actual)
                {
                    return Ok(false);
                }
            }
            Ok((lower, upper).contains(&actual))
        }
        Test::Exists(_) | Test::Contains(_) => unreachable!("handled above"),
    }
}

impl Structured {
    /// Type-check every leaf against declared indexes before any evaluation.
    pub(crate) fn validate(&self, node: &Node<'_>, allow_scan: bool) -> Result<()> {
        match node {
            Node::All => Ok(()),
            Node::And(children) | Node::Or(children) => children
                .iter()
                .try_for_each(|child| self.validate(child, allow_scan)),
            Node::Not(child) => self.validate(child, allow_scan),
            Node::Leaf { path, test } => {
                validate_test(path, test, self.field_kind(path, allow_scan)?)
            }
        }
    }

    /// Upper bound on matching IDs, read from index cardinalities without
    /// touching documents. `None` means the node needs document scans or a
    /// complement over its input; such nodes are evaluated last.
    fn estimate(&self, node: &Node<'_>, universe: usize, budget: usize) -> Result<Option<usize>> {
        Ok(match node {
            Node::All => Some(universe),
            Node::Not(_) => None,
            Node::And(children) => {
                let mut best = None;
                for child in children {
                    if let Some(estimate) = self.estimate(child, universe, budget)? {
                        best = Some(best.map_or(estimate, |best: usize| best.min(estimate)));
                    }
                }
                best
            }
            Node::Or(children) => {
                let mut total = 0usize;
                for child in children {
                    match self.estimate(child, universe, budget)? {
                        Some(estimate) => total = total.saturating_add(estimate),
                        None => return Ok(None),
                    }
                }
                Some(total.min(universe))
            }
            Node::Leaf { path, test } => {
                let Some(index) = self.fields.get(*path) else {
                    return Ok(None);
                };
                let kind = Some(index.kind);
                let ids = |value: &Value| -> Result<usize> {
                    Ok(index
                        .entries
                        .get(&scalar(Some(value), kind)?)
                        .map_or(0, IdSet::len))
                };
                Some(match test {
                    Test::Eq(value) | Test::Contains(value) => ids(value)?,
                    Test::In(values) => values.iter().try_fold(0usize, |total, value| {
                        ids(value).map(|count| total.saturating_add(count))
                    })?,
                    Test::Exists(true) => index.present.len(),
                    Test::Exists(false) => universe.saturating_sub(index.present.len()),
                    Test::Range { lower, upper } => {
                        let range = index_range(*lower, *upper, kind)?;
                        if empty_range(&range) {
                            return Ok(Some(0));
                        }
                        let limit = budget.min(RANGE_ESTIMATE_BUDGET);
                        let mut total = 0usize;
                        for (visited, (_, ids)) in index.entries.range(range).enumerate() {
                            total = total.saturating_add(ids.len());
                            if total > limit || visited >= limit {
                                return Ok(Some(universe.max(total)));
                            }
                        }
                        total
                    }
                })
            }
        })
    }

    /// Conjuncts run from the most selective indexed test to scans and
    /// complements, each over the survivors of the previous ones.
    fn conjunct_order(&self, children: &[Node<'_>], universe: usize) -> Result<Vec<usize>> {
        let mut ranked = Vec::with_capacity(children.len());
        let mut budget = universe;
        // Exact posting sizes first, so range walks stop at the best of them.
        let range = |node: &Node<'_>| {
            matches!(
                node,
                Node::Leaf {
                    test: Test::Range { .. },
                    ..
                }
            )
        };
        for pass in [false, true] {
            for (position, child) in children.iter().enumerate() {
                if range(child) != pass {
                    continue;
                }
                let estimate = self.estimate(child, universe, budget)?;
                if let Some(estimate) = estimate {
                    budget = budget.min(estimate);
                }
                ranked.push((estimate.is_none(), estimate.unwrap_or(usize::MAX), position));
            }
        }
        ranked.sort_unstable();
        Ok(ranked
            .into_iter()
            .map(|(_, _, position)| position)
            .collect())
    }

    pub(crate) fn candidates<S: DocumentSource + ?Sized>(
        &self,
        source: &S,
        node: &Node<'_>,
        universe: &IdSet,
        allow_scan: bool,
        cap: usize,
        cancellation: &QueryCancellation,
    ) -> ReadResult<IdSet, S::Failure> {
        cancellation.check()?;
        match node {
            Node::All => {
                check_size(universe.len(), cap)?;
                Ok(universe.clone())
            }
            Node::And(children) => {
                let mut survivors: Option<IdSet> = None;
                for position in self.conjunct_order(children, universe.len())? {
                    let input = survivors.as_ref().unwrap_or(universe);
                    let next = self.candidates(
                        source,
                        &children[position],
                        input,
                        allow_scan,
                        cap,
                        cancellation,
                    )?;
                    let empty = next.is_empty();
                    survivors = Some(next);
                    if empty {
                        break;
                    }
                }
                Ok(survivors.unwrap_or_else(|| universe.clone()))
            }
            Node::Or(children) => {
                let mut candidates = IdSet::new();
                for child in children {
                    for id in
                        self.candidates(source, child, universe, allow_scan, cap, cancellation)?
                    {
                        cancellation.check()?;
                        candidates.insert(id);
                    }
                    check_size(candidates.len(), cap)?;
                }
                Ok(candidates)
            }
            Node::Not(child) => {
                check_size(universe.len(), cap)?;
                let excluded =
                    self.candidates(source, child, universe, allow_scan, cap, cancellation)?;
                Ok(complement(universe, &excluded, cancellation)?)
            }
            Node::Leaf { path, test } => {
                let kind = self.field_kind(path, allow_scan)?;
                match self.fields.get(*path) {
                    Some(index) => Ok(index.candidates(
                        test,
                        universe,
                        universe.ptr_eq(&self.ids),
                        cap,
                        cancellation,
                    )?),
                    None => {
                        check_size(universe.len(), cap)?;
                        let mut selected = IdSet::new();
                        for id in universe {
                            let matched = document_source::with_live(
                                source,
                                id,
                                None,
                                cancellation,
                                |document| {
                                    evaluate(
                                        test,
                                        crate::allocation::pointer(&document.body, path),
                                        kind,
                                        cancellation,
                                    )
                                },
                            )?;
                            if matched {
                                selected.insert(id.clone());
                            }
                        }
                        Ok(selected)
                    }
                }
            }
        }
    }
}

/// `universe` without `excluded` (a subset of it). A small exclusion shares
/// the universe's persistent nodes instead of copying every surviving ID.
fn complement(
    universe: &IdSet,
    excluded: &IdSet,
    cancellation: &QueryCancellation,
) -> Result<IdSet> {
    if excluded.len() <= universe.len() / 2 {
        let mut candidates = universe.clone();
        for id in excluded {
            cancellation.check()?;
            candidates.remove(id);
        }
        return Ok(candidates);
    }
    let mut candidates = IdSet::new();
    for id in universe {
        cancellation.check()?;
        if !excluded.contains(id) {
            candidates.insert(id.clone());
        }
    }
    Ok(candidates)
}

impl FieldIndex {
    /// `whole` means `universe` is the collection's complete ID set, so every
    /// index entry is already a subset of it and can be shared in O(1).
    fn candidates(
        &self,
        test: &Test<'_>,
        universe: &IdSet,
        whole: bool,
        cap: usize,
        cancellation: &QueryCancellation,
    ) -> Result<IdSet> {
        let kind = Some(self.kind);
        let mut candidates = IdSet::new();
        let mut add = |ids: &IdSet| -> Result<()> {
            if whole {
                check_size(
                    candidates
                        .len()
                        .saturating_add(ids.len())
                        .min(universe.len()),
                    cap,
                )?;
                if candidates.len() < ids.len() {
                    let previous = std::mem::replace(&mut candidates, ids.clone());
                    for id in previous {
                        cancellation.check()?;
                        candidates.insert(id);
                    }
                } else {
                    for id in ids {
                        cancellation.check()?;
                        candidates.insert(id.clone());
                    }
                }
                return check_size(candidates.len(), cap);
            }
            let (shorter, longer) = if ids.len() <= universe.len() {
                (ids, universe)
            } else {
                (universe, ids)
            };
            for id in shorter {
                cancellation.check()?;
                if longer.contains(id) {
                    candidates.insert(id.clone());
                    check_size(candidates.len(), cap)?;
                }
            }
            Ok(())
        };
        match test {
            Test::Exists(true) => add(&self.present)?,
            Test::Exists(false) if whole => {
                candidates = complement(universe, &self.present, cancellation)?;
                check_size(candidates.len(), cap)?;
            }
            Test::Exists(false) => {
                for id in universe {
                    cancellation.check()?;
                    if !self.present.contains(id) {
                        candidates.insert(id.clone());
                        check_size(candidates.len(), cap)?;
                    }
                }
            }
            Test::Eq(value) | Test::Contains(value) => {
                if let Some(ids) = self.entries.get(&scalar(Some(value), kind)?) {
                    add(ids)?;
                }
            }
            Test::In(values) => {
                for value in *values {
                    cancellation.check()?;
                    if let Some(ids) = self.entries.get(&scalar(Some(value), kind)?) {
                        add(ids)?;
                    }
                }
            }
            Test::Range { lower, upper } => {
                let range = index_range(*lower, *upper, kind)?;
                if !empty_range(&range) {
                    for (visited, (key, ids)) in self.entries.range(range).enumerate() {
                        cancellation.check()?;
                        check_size(visited + 1, cap)?;
                        if !matches!(key, Scalar::Missing | Scalar::Null) {
                            add(ids)?;
                        }
                    }
                }
            }
        }
        Ok(candidates)
    }
}
