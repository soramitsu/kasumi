//! The Kasumi query language: closed JSON with an equivalent typed builder.
//!
//! ```json
//! {"collection": "invoices",
//!  "filter": {"/status": "open", "/amount": {"gte": 10, "lt": 100}},
//!  "sort": ["-/amount"], "select": ["/amount", "/customer/name"], "limit": 20}
//! ```
//!
//! Field paths are JSON Pointers. In a filter object, keys that start with `/`
//! name fields and every other key is a combinator (`and`, `or`, `not`), so a
//! document field can never be mistaken for an operator. Every entry of a
//! filter object must hold; `{}` matches every document.
use crate::Direction;
use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;

/// Conjunction of field conditions and combinators.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Filter {
    /// Conditions keyed by JSON Pointer.
    pub fields: BTreeMap<String, Condition>,
    /// Further filters that must all hold, such as a second condition on a
    /// field that already has one.
    pub and: Vec<Filter>,
    /// When nonempty, at least one of these filters must hold.
    pub or: Vec<Filter>,
    /// When present, this filter must not hold.
    pub not: Option<Box<Filter>>,
}

/// Operators applied to one field; all present operators must hold.
///
/// `ne` and `nin` are the negations of `eq` and `in`, so they also match
/// documents where the field is absent. Range operators never match absent,
/// null or differently typed values.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Condition {
    pub eq: Option<Value>,
    pub ne: Option<Value>,
    pub gt: Option<Value>,
    pub gte: Option<Value>,
    pub lt: Option<Value>,
    pub lte: Option<Value>,
    pub r#in: Option<Vec<Value>>,
    pub nin: Option<Vec<Value>>,
    pub exists: Option<bool>,
    pub contains: Option<Value>,
}

/// Values accepted by one `in` or `nin` list.
pub const MAX_FILTER_IN_VALUES: usize = 256;

/// Operator names accepted in a field condition object.
pub const FILTER_OPERATORS: [&str; 10] = [
    "eq", "ne", "gt", "gte", "lt", "lte", "in", "nin", "exists", "contains",
];

impl Filter {
    /// The empty filter, which matches every document.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_all(&self) -> bool {
        self.fields.is_empty() && self.and.is_empty() && self.or.is_empty() && self.not.is_none()
    }

    /// Matches when at least one of `filters` matches.
    pub fn or(filters: impl IntoIterator<Item = Filter>) -> Self {
        Self {
            or: filters.into_iter().collect(),
            ..Self::default()
        }
    }

    pub fn eq(self, path: impl Into<String>, value: impl Into<Value>) -> Self {
        let value = value.into();
        self.with(path.into(), |c| &mut c.eq, value)
    }
    pub fn ne(self, path: impl Into<String>, value: impl Into<Value>) -> Self {
        let value = value.into();
        self.with(path.into(), |c| &mut c.ne, value)
    }
    pub fn gt(self, path: impl Into<String>, value: impl Into<Value>) -> Self {
        let value = value.into();
        self.with(path.into(), |c| &mut c.gt, value)
    }
    pub fn gte(self, path: impl Into<String>, value: impl Into<Value>) -> Self {
        let value = value.into();
        self.with(path.into(), |c| &mut c.gte, value)
    }
    pub fn lt(self, path: impl Into<String>, value: impl Into<Value>) -> Self {
        let value = value.into();
        self.with(path.into(), |c| &mut c.lt, value)
    }
    pub fn lte(self, path: impl Into<String>, value: impl Into<Value>) -> Self {
        let value = value.into();
        self.with(path.into(), |c| &mut c.lte, value)
    }
    /// `field` equals one of `values`.
    pub fn is_in<V: Into<Value>>(
        self,
        path: impl Into<String>,
        values: impl IntoIterator<Item = V>,
    ) -> Self {
        let values = values.into_iter().map(Into::into).collect();
        self.with(path.into(), |c| &mut c.r#in, values)
    }
    /// `field` is absent or equals none of `values`.
    pub fn not_in<V: Into<Value>>(
        self,
        path: impl Into<String>,
        values: impl IntoIterator<Item = V>,
    ) -> Self {
        let values = values.into_iter().map(Into::into).collect();
        self.with(path.into(), |c| &mut c.nin, values)
    }
    pub fn exists(self, path: impl Into<String>) -> Self {
        self.with(path.into(), |c| &mut c.exists, true)
    }
    pub fn missing(self, path: impl Into<String>) -> Self {
        self.with(path.into(), |c| &mut c.exists, false)
    }
    /// An array field contains `value`.
    pub fn contains(self, path: impl Into<String>, value: impl Into<Value>) -> Self {
        let value = value.into();
        self.with(path.into(), |c| &mut c.contains, value)
    }

    /// Require `other` as well. Conditions on a field merge unless they repeat
    /// an operator; anything that cannot merge is kept as a separate conjunct.
    pub fn and(mut self, other: Filter) -> Self {
        if self.is_all() {
            return other;
        }
        let Filter {
            fields,
            and,
            or,
            not,
        } = other;
        for (path, condition) in fields {
            match self.fields.get_mut(&path) {
                None => {
                    self.fields.insert(path, condition);
                }
                Some(existing) if existing.disjoint(&condition) => existing.merge(condition),
                Some(_) => self.and.push(Filter {
                    fields: BTreeMap::from([(path, condition)]),
                    ..Filter::default()
                }),
            }
        }
        self.and.extend(and);
        if !or.is_empty() {
            if self.or.is_empty() {
                self.or = or;
            } else {
                self.and.push(Filter::or(or));
            }
        }
        if let Some(not) = not {
            if self.not.is_none() {
                self.not = Some(not);
            } else {
                self.and.push(Filter {
                    not: Some(not),
                    ..Filter::default()
                });
            }
        }
        self
    }

    fn with<T>(
        mut self,
        path: String,
        slot: impl Fn(&mut Condition) -> &mut Option<T>,
        value: T,
    ) -> Self {
        let condition = self.fields.entry(path.clone()).or_default();
        if slot(condition).is_none() {
            *slot(condition) = Some(value);
            return self;
        }
        let mut repeated = Condition::default();
        *slot(&mut repeated) = Some(value);
        self.and.push(Filter {
            fields: BTreeMap::from([(path, repeated)]),
            ..Filter::default()
        });
        self
    }
}

/// `!filter` matches when `filter` does not.
impl std::ops::Not for Filter {
    type Output = Filter;
    fn not(self) -> Filter {
        Filter {
            not: Some(Box::new(self)),
            ..Filter::default()
        }
    }
}

impl Condition {
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }

    /// The equality value when this condition is exactly a scalar equality.
    fn shorthand(&self) -> Option<&Value> {
        let eq = self.eq.as_ref()?;
        let only_eq = self.ne.is_none()
            && self.gt.is_none()
            && self.gte.is_none()
            && self.lt.is_none()
            && self.lte.is_none()
            && self.r#in.is_none()
            && self.nin.is_none()
            && self.exists.is_none()
            && self.contains.is_none();
        (only_eq && !eq.is_object() && !eq.is_array()).then_some(eq)
    }

    fn disjoint(&self, other: &Condition) -> bool {
        (self.eq.is_none() || other.eq.is_none())
            && (self.ne.is_none() || other.ne.is_none())
            && (self.gt.is_none() || other.gt.is_none())
            && (self.gte.is_none() || other.gte.is_none())
            && (self.lt.is_none() || other.lt.is_none())
            && (self.lte.is_none() || other.lte.is_none())
            && (self.r#in.is_none() || other.r#in.is_none())
            && (self.nin.is_none() || other.nin.is_none())
            && (self.exists.is_none() || other.exists.is_none())
            && (self.contains.is_none() || other.contains.is_none())
    }

    fn merge(&mut self, other: Condition) {
        fn take<T>(slot: &mut Option<T>, value: Option<T>) {
            if value.is_some() {
                *slot = value;
            }
        }
        take(&mut self.eq, other.eq);
        take(&mut self.ne, other.ne);
        take(&mut self.gt, other.gt);
        take(&mut self.gte, other.gte);
        take(&mut self.lt, other.lt);
        take(&mut self.lte, other.lte);
        take(&mut self.r#in, other.r#in);
        take(&mut self.nin, other.nin);
        take(&mut self.exists, other.exists);
        take(&mut self.contains, other.contains);
    }
}

impl Serialize for Filter {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let entries = self.fields.len()
            + usize::from(!self.and.is_empty())
            + usize::from(self.not.is_some())
            + usize::from(!self.or.is_empty());
        let mut map = serializer.serialize_map(Some(entries))?;
        for (path, condition) in &self.fields {
            map.serialize_entry(path, condition)?;
        }
        if !self.and.is_empty() {
            map.serialize_entry("and", &self.and)?;
        }
        if let Some(not) = &self.not {
            map.serialize_entry("not", not)?;
        }
        if !self.or.is_empty() {
            map.serialize_entry("or", &self.or)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for Filter {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Entries;
        impl<'de> Visitor<'de> for Entries {
            type Value = Filter;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a filter object such as {\"/status\": \"open\"}")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut input: A) -> Result<Filter, A::Error> {
                let mut filter = Filter::default();
                let mut combinators = [false; 3];
                while let Some(key) = input.next_key::<String>()? {
                    if key.starts_with('/') {
                        if filter.fields.contains_key(&key) {
                            return Err(de::Error::custom(format!(
                                "duplicate filter field `{key}`"
                            )));
                        }
                        let condition = input.next_value()?;
                        filter.fields.insert(key, condition);
                        continue;
                    }
                    let slot = match key.as_str() {
                        "and" => 0,
                        "or" => 1,
                        "not" => 2,
                        _ => return Err(de::Error::custom(unknown_filter_key(&key))),
                    };
                    if std::mem::replace(&mut combinators[slot], true) {
                        return Err(de::Error::custom(format!("duplicate filter key `{key}`")));
                    }
                    match slot {
                        2 => filter.not = Some(Box::new(input.next_value()?)),
                        _ => {
                            let filters: Vec<Filter> = input.next_value()?;
                            if filters.is_empty() {
                                return Err(de::Error::custom(format!(
                                    "`{key}` requires at least one filter"
                                )));
                            }
                            if slot == 0 {
                                filter.and = filters;
                            } else {
                                filter.or = filters;
                            }
                        }
                    }
                }
                Ok(filter)
            }
        }
        deserializer.deserialize_map(Entries)
    }
}

fn unknown_filter_key(key: &str) -> String {
    let bare = key.trim_start_matches('$');
    if bare != key && matches!(bare, "and" | "or" | "not") {
        return format!(
            "unknown filter key `{key}`; combinators are written without `$`: `{bare}`"
        );
    }
    if FILTER_OPERATORS.contains(&bare) {
        return format!(
            "unknown filter key `{key}`; operators belong inside a field condition, e.g. {{\"/amount\": {{\"{bare}\": 10}}}}"
        );
    }
    format!(
        "unknown filter key `{key}`; field paths are JSON Pointers that start with '/', e.g. `/{bare}`, and combinators are `and`, `or` and `not`"
    )
}

impl Serialize for Condition {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if let Some(value) = self.shorthand() {
            return value.serialize(serializer);
        }
        let mut map = serializer.serialize_map(None)?;
        let scalars = [
            ("eq", &self.eq),
            ("ne", &self.ne),
            ("gt", &self.gt),
            ("gte", &self.gte),
            ("lt", &self.lt),
            ("lte", &self.lte),
        ];
        for (name, value) in scalars {
            if let Some(value) = value {
                map.serialize_entry(name, value)?;
            }
        }
        if let Some(values) = &self.r#in {
            map.serialize_entry("in", values)?;
        }
        if let Some(values) = &self.nin {
            map.serialize_entry("nin", values)?;
        }
        if let Some(exists) = &self.exists {
            map.serialize_entry("exists", exists)?;
        }
        if let Some(value) = &self.contains {
            map.serialize_entry("contains", value)?;
        }
        map.end()
    }
}

/// `null` is a value here, not an omitted operator.
fn present<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(deserializer).map(Some)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Operators {
    #[serde(default, deserialize_with = "present")]
    eq: Option<Value>,
    #[serde(default, deserialize_with = "present")]
    ne: Option<Value>,
    #[serde(default, deserialize_with = "present")]
    gt: Option<Value>,
    #[serde(default, deserialize_with = "present")]
    gte: Option<Value>,
    #[serde(default, deserialize_with = "present")]
    lt: Option<Value>,
    #[serde(default, deserialize_with = "present")]
    lte: Option<Value>,
    #[serde(default, rename = "in")]
    any_of: Option<Vec<Value>>,
    #[serde(default)]
    nin: Option<Vec<Value>>,
    #[serde(default)]
    exists: Option<bool>,
    #[serde(default, deserialize_with = "present")]
    contains: Option<Value>,
}

/// Derived structs also accept sequences positionally; operators are objects only.
struct OperatorObject(Operators);
impl<'de> Deserialize<'de> for OperatorObject {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Object;
        impl<'de> Visitor<'de> for Object {
            type Value = OperatorObject;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an operator object")
            }
            fn visit_map<A: MapAccess<'de>>(self, input: A) -> Result<OperatorObject, A::Error> {
                Operators::deserialize(de::value::MapAccessDeserializer::new(input))
                    .map(OperatorObject)
            }
        }
        deserializer.deserialize_map(Object)
    }
}

// Buffered alternatives keep exact numbers: the vendored serde_json replays its
// private number token through enum buffering.
#[derive(Deserialize)]
#[serde(untagged)]
enum ConditionInput {
    Operators(Box<OperatorObject>),
    Value(Value),
}

impl<'de> Deserialize<'de> for Condition {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let operators = match ConditionInput::deserialize(deserializer)? {
            ConditionInput::Operators(operators) => operators.0,
            ConditionInput::Value(Value::Object(object)) => {
                return Err(de::Error::custom(explain_condition(&object)));
            }
            ConditionInput::Value(Value::Array(_)) => {
                return Err(de::Error::custom(
                    "a filter value cannot be an array; use {\"in\": [...]} to match one of several values or {\"contains\": value} for array fields",
                ));
            }
            ConditionInput::Value(value) => {
                return Ok(Condition {
                    eq: Some(value),
                    ..Condition::default()
                });
            }
        };
        let condition = Condition {
            eq: operators.eq,
            ne: operators.ne,
            gt: operators.gt,
            gte: operators.gte,
            lt: operators.lt,
            lte: operators.lte,
            r#in: operators.any_of,
            nin: operators.nin,
            exists: operators.exists,
            contains: operators.contains,
        };
        if condition.is_empty() {
            return Err(de::Error::custom(
                "a field condition requires at least one operator",
            ));
        }
        Ok(condition)
    }
}

fn explain_condition(object: &serde_json::Map<String, Value>) -> String {
    for (key, value) in object {
        if !FILTER_OPERATORS.contains(&key.as_str()) {
            return format!(
                "unknown filter operator `{key}`; use one of {}",
                FILTER_OPERATORS.join(", ")
            );
        }
        match key.as_str() {
            "in" | "nin" if !value.is_array() => {
                return format!("`{key}` requires an array of values");
            }
            "exists" if !value.is_boolean() => return "`exists` requires true or false".into(),
            _ => {}
        }
    }
    "each filter operator may appear only once per field".into()
}

/// One sort key: a JSON Pointer, prefixed with `-` for descending order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sort {
    pub field: String,
    pub direction: Direction,
}

impl Sort {
    pub fn asc(field: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            direction: Direction::Asc,
        }
    }
    pub fn desc(field: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            direction: Direction::Desc,
        }
    }
}

impl Serialize for Sort {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.direction {
            Direction::Asc => serializer.serialize_str(&self.field),
            Direction::Desc => serializer.collect_str(&format_args!("-{}", self.field)),
        }
    }
}

impl<'de> Deserialize<'de> for Sort {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let key = String::deserialize(deserializer)?;
        let (field, direction) = match key.strip_prefix('-') {
            Some(field) => (field, Direction::Desc),
            None => (key.as_str(), Direction::Asc),
        };
        if !field.starts_with('/') {
            return Err(de::Error::custom(format!(
                "invalid sort key `{key}`; use a JSON Pointer such as \"/amount\", or \"-/amount\" for descending order"
            )));
        }
        Ok(Self {
            field: field.to_owned(),
            direction,
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AggregateFunction {
    Count,
    Sum,
    Min,
    Max,
    Avg,
}

/// `{"count": "*"}`, `{"count": "/field"}`, `{"sum": "/field"}`, or
/// `{"avg": "/field", "scale": 2}`. Counting a field counts non-null values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aggregation {
    pub function: AggregateFunction,
    /// None only for `count` of matching documents.
    pub field: Option<String>,
    /// Required by `avg`: decimal places of its half-even rounded result.
    pub scale: Option<i64>,
}

impl Aggregation {
    /// Count matching documents.
    pub fn count() -> Self {
        Self::of(AggregateFunction::Count, None)
    }
    /// Count documents where `field` is present and not null.
    pub fn count_of(field: impl Into<String>) -> Self {
        Self::of(AggregateFunction::Count, Some(field.into()))
    }
    pub fn sum(field: impl Into<String>) -> Self {
        Self::of(AggregateFunction::Sum, Some(field.into()))
    }
    pub fn min(field: impl Into<String>) -> Self {
        Self::of(AggregateFunction::Min, Some(field.into()))
    }
    pub fn max(field: impl Into<String>) -> Self {
        Self::of(AggregateFunction::Max, Some(field.into()))
    }
    pub fn avg(field: impl Into<String>, scale: i64) -> Self {
        Self {
            scale: Some(scale),
            ..Self::of(AggregateFunction::Avg, Some(field.into()))
        }
    }
    fn of(function: AggregateFunction, field: Option<String>) -> Self {
        Self {
            function,
            field,
            scale: None,
        }
    }
}

impl Serialize for Aggregation {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry(&self.function, self.field.as_deref().unwrap_or("*"))?;
        if let Some(scale) = self.scale {
            map.serialize_entry("scale", &scale)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for Aggregation {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Input {
            count: Option<String>,
            sum: Option<String>,
            min: Option<String>,
            max: Option<String>,
            avg: Option<String>,
            scale: Option<i64>,
        }
        let input = Input::deserialize(deserializer)?;
        let mut functions = [
            (AggregateFunction::Count, input.count),
            (AggregateFunction::Sum, input.sum),
            (AggregateFunction::Min, input.min),
            (AggregateFunction::Max, input.max),
            (AggregateFunction::Avg, input.avg),
        ]
        .into_iter()
        .filter_map(|(function, field)| field.map(|field| (function, field)));
        let (Some((function, field)), None) = (functions.next(), functions.next()) else {
            return Err(de::Error::custom(
                "an aggregate names exactly one of count, sum, min, max or avg, e.g. {\"sum\": \"/amount\"}",
            ));
        };
        let field = match (function, field.as_str()) {
            (AggregateFunction::Count, "*") => None,
            (_, "*") => {
                return Err(de::Error::custom(
                    "only count accepts \"*\"; other aggregates name a numeric field",
                ));
            }
            _ => Some(field),
        };
        Ok(Self {
            function,
            field,
            scale: input.scale,
        })
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TextMode {
    /// Every term must match, in any order.
    #[default]
    Terms,
    Phrase,
    /// The final term matches as a prefix.
    Prefix,
    /// Terms match within an edit distance (default 1, at most 2).
    Fuzzy,
}
impl TextMode {
    fn is_terms(&self) -> bool {
        *self == Self::Terms
    }
}

/// Full-text search over a declared text index.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TextSearch {
    pub index: String,
    pub query: String,
    #[serde(default, skip_serializing_if = "TextMode::is_terms")]
    pub mode: TextMode,
    /// Fuzzy edit distance; only valid with `mode: fuzzy`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub distance: Option<u8>,
}

impl TextSearch {
    pub const DEFAULT_FUZZY_DISTANCE: u8 = 1;

    pub fn new(index: impl Into<String>, query: impl Into<String>) -> Self {
        Self {
            index: index.into(),
            query: query.into(),
            mode: TextMode::Terms,
            distance: None,
        }
    }
    pub fn mode(mut self, mode: TextMode) -> Self {
        self.mode = mode;
        self
    }
    pub fn fuzzy(mut self, distance: u8) -> Self {
        self.mode = TextMode::Fuzzy;
        self.distance = Some(distance);
        self
    }
    pub fn fuzzy_distance(&self) -> u8 {
        self.distance.unwrap_or(Self::DEFAULT_FUZZY_DISTANCE)
    }
}

/// One query. Row queries return documents in pages; aggregate queries
/// return only their groups.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct QueryRequest {
    pub collection: String,
    #[serde(default, skip_serializing_if = "Filter::is_all")]
    pub filter: Filter,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub search: Option<TextSearch>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sort: Vec<Sort>,
    /// Returned fields, keeping their nesting. Empty returns whole documents.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub select: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub group_by: Vec<String>,
    #[serde(
        default,
        skip_serializing_if = "BTreeMap::is_empty",
        deserialize_with = "unique_aggregates"
    )]
    pub aggregate: BTreeMap<String, Aggregation>,
    /// Maximum rows per page; defaults to `DEFAULT_LIMIT`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Paging::is_snapshot")]
    pub paging: Paging,
    /// Permit filtering, sorting or grouping on fields without a declared index.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_scan: bool,
}

/// How a row query continues after its first page.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Paging {
    /// Every page reads the first page's snapshot. The rows after the first
    /// page stay pinned for the cursor, within the tenant's `max_cursor_bytes`,
    /// until `cursor_ttl_ms` passes.
    #[default]
    Snapshot,
    /// Each page is read straight from a unique index, continuing after the
    /// previous page's last row: no server state, no size or time limit. The
    /// filter fixes leading index fields by equality and may bound the next
    /// one; `sort` lists the remaining fields. Continuing after the collection
    /// changed reports `CURSOR_EXPIRED`.
    Seek,
}
impl Paging {
    pub fn is_snapshot(&self) -> bool {
        *self == Self::Snapshot
    }
}

fn unique_aggregates<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, Aggregation>, D::Error> {
    struct Aliases;
    impl<'de> Visitor<'de> for Aliases {
        type Value = BTreeMap<String, Aggregation>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("named aggregates such as {\"total\": {\"sum\": \"/amount\"}}")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut input: A) -> Result<Self::Value, A::Error> {
            let mut aggregates = BTreeMap::new();
            while let Some(alias) = input.next_key::<String>()? {
                let aggregate = input.next_value()?;
                if aggregates.contains_key(&alias) {
                    return Err(de::Error::custom(format!("duplicate aggregate `{alias}`")));
                }
                aggregates.insert(alias, aggregate);
            }
            Ok(aggregates)
        }
    }
    deserializer.deserialize_map(Aliases)
}

impl QueryRequest {
    pub const DEFAULT_LIMIT: usize = 100;

    pub fn new(collection: impl Into<String>) -> Self {
        Self {
            collection: collection.into(),
            filter: Filter::default(),
            search: None,
            sort: Vec::new(),
            select: Vec::new(),
            group_by: Vec::new(),
            aggregate: BTreeMap::new(),
            limit: None,
            cursor: None,
            paging: Paging::Snapshot,
            allow_scan: false,
        }
    }
    /// Require `filter` in addition to any existing filter.
    pub fn filter(mut self, filter: Filter) -> Self {
        self.filter = std::mem::take(&mut self.filter).and(filter);
        self
    }
    pub fn search(mut self, search: TextSearch) -> Self {
        self.search = Some(search);
        self
    }
    pub fn sort_asc(mut self, field: impl Into<String>) -> Self {
        self.sort.push(Sort::asc(field));
        self
    }
    pub fn sort_desc(mut self, field: impl Into<String>) -> Self {
        self.sort.push(Sort::desc(field));
        self
    }
    pub fn select<S: Into<String>>(mut self, fields: impl IntoIterator<Item = S>) -> Self {
        self.select.extend(fields.into_iter().map(Into::into));
        self
    }
    pub fn group_by<S: Into<String>>(mut self, fields: impl IntoIterator<Item = S>) -> Self {
        self.group_by.extend(fields.into_iter().map(Into::into));
        self
    }
    pub fn aggregate(mut self, alias: impl Into<String>, aggregation: Aggregation) -> Self {
        self.aggregate.insert(alias.into(), aggregation);
        self
    }
    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }
    /// Continue a previous page of this identical query.
    pub fn cursor(mut self, cursor: impl Into<String>) -> Self {
        self.cursor = Some(cursor.into());
        self
    }
    pub fn paging(mut self, paging: Paging) -> Self {
        self.paging = paging;
        self
    }
    pub fn allow_scan(mut self) -> Self {
        self.allow_scan = true;
        self
    }

    pub fn page_size(&self) -> usize {
        self.limit.unwrap_or(Self::DEFAULT_LIMIT)
    }
    pub fn is_aggregate(&self) -> bool {
        !self.aggregate.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QueryRow {
    pub id: String,
    pub version: u64,
    pub body: Value,
    pub score: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QueryResponse {
    pub revision: u64,
    pub rows: Vec<QueryRow>,
    /// Aggregate queries only: `{"group": {...}, "values": {alias: value}}`.
    pub aggregates: Vec<Value>,
    pub cursor: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parse(value: Value) -> Result<QueryRequest, String> {
        serde_json::from_value(value).map_err(|error| error.to_string())
    }

    #[test]
    fn concise_filters_round_trip_through_the_typed_form() {
        let query = parse(json!({
            "collection": "invoices",
            "filter": {
                "/status": "open",
                "/amount": {"gte": 10, "lt": 100},
                "/deleted_at": null,
                "or": [{"/region": {"in": ["eu", "jp"]}}, {"/vip": true}],
                "not": {"/tags": {"contains": "test"}}
            },
            "sort": ["-/amount", "/id"],
            "select": ["/amount"],
            "limit": 20
        }))
        .unwrap();
        let built = QueryRequest::new("invoices")
            .filter(
                Filter::new()
                    .eq("/status", "open")
                    .gte("/amount", 10)
                    .lt("/amount", 100)
                    .eq("/deleted_at", Value::Null)
                    .and(Filter::or([
                        Filter::new().is_in("/region", ["eu", "jp"]),
                        Filter::new().eq("/vip", true),
                    ]))
                    .and(!Filter::new().contains("/tags", "test")),
            )
            .sort_desc("/amount")
            .sort_asc("/id")
            .select(["/amount"])
            .limit(20);
        assert_eq!(query, built);
        let encoded = serde_json::to_value(&query).unwrap();
        assert_eq!(encoded["filter"]["/status"], json!("open"));
        assert_eq!(encoded["filter"]["/amount"], json!({"gte": 10, "lt": 100}));
        assert_eq!(encoded["sort"], json!(["-/amount", "/id"]));
        assert_eq!(parse(encoded).unwrap(), query);
        assert_eq!(
            serde_json::to_value(QueryRequest::new("docs")).unwrap(),
            json!({"collection": "docs"})
        );
    }

    #[test]
    fn exact_numbers_survive_shorthand_and_operator_buffering() {
        let text = r#"{"collection":"docs","filter":{"/a":900719925474099312345.000000001,"/b":{"gt":1e-900}},"aggregate":{"avg":{"avg":"/a","scale":2}}}"#;
        let query: QueryRequest = serde_json::from_str(text).unwrap();
        assert_eq!(serde_json::to_string(&query).unwrap(), text);
        let condition = &query.filter.fields["/b"];
        assert_eq!(condition.gt.as_ref().unwrap().to_string(), "1e-900");
    }

    #[test]
    fn mistakes_are_rejected_with_actionable_messages() {
        for (filter, message) in [
            (json!({"status": "open"}), "`/status`"),
            (json!({"$or": []}), "without `$`"),
            (json!({"gte": 1}), "inside a field condition"),
            (json!({"/a": {"gtt": 1}}), "unknown filter operator `gtt`"),
            (json!({"/a": {"in": 1}}), "`in` requires an array"),
            (
                json!({"/a": {"exists": "yes"}}),
                "`exists` requires true or false",
            ),
            (json!({"/a": [1, 2]}), "cannot be an array"),
            (json!({"/a": {}}), "at least one operator"),
            (json!({"or": []}), "at least one filter"),
        ] {
            let error = parse(json!({"collection": "docs", "filter": filter})).unwrap_err();
            assert!(error.contains(message), "{error}");
        }
        let duplicate = r#"{"collection":"docs","filter":{"/a":1,"/a":2}}"#;
        assert!(serde_json::from_str::<QueryRequest>(duplicate).is_err());
        let duplicate = r#"{"collection":"docs","filter":{"/a":{"gt":1,"gt":2}}}"#;
        let error = serde_json::from_str::<QueryRequest>(duplicate).unwrap_err();
        assert!(error.to_string().contains("only once"), "{error}");
        let duplicate =
            r#"{"collection":"docs","aggregate":{"n":{"count":"*"},"n":{"count":"*"}}}"#;
        assert!(serde_json::from_str::<QueryRequest>(duplicate).is_err());
        for sort in ["amount", "-amount", ""] {
            let error = parse(json!({"collection": "docs", "sort": [sort]})).unwrap_err();
            assert!(error.contains("-/amount"), "{error}");
        }
        for aggregate in [
            json!({}),
            json!({"sum": "/a", "max": "/a"}),
            json!({"sum": "*"}),
            json!({"total": "/a"}),
        ] {
            assert!(
                parse(json!({"collection": "docs", "aggregate": {"x": aggregate}})).is_err(),
                "{aggregate}"
            );
        }
        assert!(parse(json!({"collection": "docs", "projection": ["/a"]})).is_err());
    }

    #[test]
    fn builder_keeps_repeated_operators_as_separate_conjuncts() {
        let filter = Filter::new().contains("/tags", "a").contains("/tags", "b");
        assert_eq!(
            serde_json::to_value(&filter).unwrap(),
            json!({"/tags": {"contains": "a"}, "and": [{"/tags": {"contains": "b"}}]})
        );
        let merged = Filter::new().gte("/n", 1).and(Filter::new().lt("/n", 5));
        assert_eq!(
            serde_json::to_value(&merged).unwrap(),
            json!({"/n": {"gte": 1, "lt": 5}})
        );
        assert!(Filter::new().and(Filter::new()).is_all());
    }

    #[test]
    fn aggregates_and_search_use_compact_forms() {
        let query = QueryRequest::new("docs")
            .search(TextSearch::new("body", "tokyo").fuzzy(2))
            .group_by(["/status"])
            .aggregate("n", Aggregation::count())
            .aggregate("paid", Aggregation::count_of("/paid_at"))
            .aggregate("mean", Aggregation::avg("/amount", 2));
        let encoded = serde_json::to_value(&query).unwrap();
        assert_eq!(
            encoded,
            json!({
                "collection": "docs",
                "search": {"index": "body", "query": "tokyo", "mode": "fuzzy", "distance": 2},
                "group_by": ["/status"],
                "aggregate": {
                    "mean": {"avg": "/amount", "scale": 2},
                    "n": {"count": "*"},
                    "paid": {"count": "/paid_at"}
                }
            })
        );
        assert_eq!(parse(encoded).unwrap(), query);
        let search: TextSearch =
            serde_json::from_value(json!({"index": "body", "query": "tokyo"})).unwrap();
        assert_eq!((search.mode, search.fuzzy_distance()), (TextMode::Terms, 1));
    }
}
