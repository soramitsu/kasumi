use super::resources::{Call, exhausted, invalid};
use crate::ClientError;
use kasumi_types::{DocumentKey, ReadSnapshotRequest, SnapshotLease};
use serde::{
    Deserialize,
    de::{DeserializeSeed, SeqAccess, Visitor},
};
use serde_json::value::RawValue;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

pub(crate) enum Expected {
    Open {
        ttl_ms: u64,
    },
    Read {
        points: Vec<DocumentKey>,
        queries: Vec<QueryBound>,
        lease: Option<SnapshotLease>,
    },
    Scan {
        lease: SnapshotLease,
        collection: String,
        after: Option<String>,
        limit: usize,
    },
}
pub(crate) struct QueryBound {
    collection: String,
    limit: usize,
    aggregates: bool,
}
impl Expected {
    pub(super) fn read(request: &ReadSnapshotRequest, call: &Call) -> Result<Self, ClientError> {
        if request
            .documents
            .len()
            .checked_add(request.queries.len())
            .ok_or_else(exhausted)?
            > call.limits.max_rows
            || request
                .queries
                .iter()
                .any(|query| query.limit > call.limits.max_rows || query.cursor.is_some())
        {
            return Err(exhausted());
        }
        if request.documents.iter().collect::<BTreeSet<_>>().len() != request.documents.len() {
            return Err(invalid("duplicate requested snapshot point"));
        }
        Ok(Self::Read {
            points: request.documents.clone(),
            queries: request
                .queries
                .iter()
                .map(|query| QueryBound {
                    collection: query.collection.clone(),
                    limit: query.limit,
                    aggregates: !query.aggregates.is_empty(),
                })
                .collect(),
            lease: None,
        })
    }
    pub(super) fn validate(&self, bytes: &[u8], call: &Call) -> Result<(), ClientError> {
        match self {
            Self::Open { ttl_ms } => {
                let lease: SnapshotLease = serde_json::from_slice(bytes)?;
                if lease.ttl_ms == 0
                    || lease.ttl_ms != *ttl_ms
                    || !canonical_non_nil(&lease.lease_id)
                    || !expected_incarnation(&lease.incarnation, call)
                {
                    return Err(invalid("invalid snapshot lease response"));
                }
            }
            Self::Read {
                points,
                queries,
                lease,
            } => {
                let outer: ReadOuter<'_> = serde_json::from_slice(bytes)?;
                if !expected_incarnation(&outer.incarnation, call) {
                    return Err(invalid("invalid snapshot incarnation"));
                }
                if let Some(lease) = lease
                    && (outer.revision != lease.revision
                        || outer.incarnation != lease.incarnation
                        || outer.policy_epoch != lease.policy_epoch
                        || outer.schema_epoch != lease.schema_epoch)
                {
                    return Err(invalid("snapshot page changed its original generation"));
                }
                let documents = array(outer.documents, points.len())?;
                if documents.len() != points.len() {
                    return Err(invalid("snapshot response point count differs"));
                }
                // All point headers are checked before any document Value exists.
                for (raw, expected) in documents.iter().zip(points) {
                    call.check()?;
                    let point: Point<'_> = serde_json::from_str(raw.get())?;
                    if &point.key != expected {
                        return Err(invalid("snapshot response contains a different point"));
                    }
                    if let Some(document) = point.document {
                        let document: Document<'_> = serde_json::from_str(document.get())?;
                        if document.id != expected.id
                            || document.version == 0
                            || document.version > outer.revision
                        {
                            return Err(invalid("snapshot point body identity differs"));
                        }
                    }
                }
                let results = array(outer.queries, queries.len())?;
                if results.len() != queries.len() {
                    return Err(invalid("snapshot query count differs"));
                }
                let epochs: BTreeMap<String, u64> =
                    serde_json::from_str(outer.collection_epochs.get())?;
                let expected_collections: BTreeSet<_> =
                    queries.iter().map(|query| &query.collection).collect();
                if epochs.values().any(|epoch| *epoch > outer.revision)
                    || epochs.keys().collect::<BTreeSet<_>>() != expected_collections
                {
                    return Err(invalid("snapshot collection epochs differ"));
                }
                for (raw, expected) in results.iter().zip(queries) {
                    call.check()?;
                    let query: Query<'_> = serde_json::from_str(raw.get())?;
                    if query.revision != outer.revision || query.cursor.is_some() {
                        return Err(invalid(
                            "snapshot query is incomplete or from another generation",
                        ));
                    }
                    let data_epoch = epochs
                        .get(&expected.collection)
                        .copied()
                        .ok_or_else(|| invalid("snapshot query collection epoch is missing"))?;
                    let rows = array(query.rows, expected.limit)?;
                    let aggregates = array(query.aggregates, call.limits.max_rows)?;
                    if !expected.aggregates && !aggregates.is_empty() {
                        return Err(invalid("unexpected snapshot aggregates"));
                    }
                    let mut ids = BTreeSet::new();
                    for raw in rows {
                        let row: Row<'_> = serde_json::from_str(raw.get())?;
                        if row.id.is_empty()
                            || row.version == 0
                            || row.version > outer.revision
                            || row.version > data_epoch
                            || !ids.insert(row.id)
                        {
                            return Err(invalid("invalid or duplicate snapshot query row"));
                        }
                    }
                }
            }
            Self::Scan {
                lease,
                collection,
                after,
                limit,
            } => {
                let outer: ScanOuter<'_> = serde_json::from_slice(bytes)?;
                if !same_lease(&outer.snapshot, lease)
                    || !expected_incarnation(&outer.snapshot.incarnation, call)
                    || outer.data_epoch > lease.revision
                    || &outer.collection != collection
                {
                    return Err(invalid("snapshot scan changed its original scope"));
                }
                let rows = array(outer.documents, *limit)?;
                let mut previous = after.as_deref().unwrap_or("").to_owned();
                for raw in &rows {
                    call.check()?;
                    let document: Document<'_> = serde_json::from_str(raw.get())?;
                    if document.version == 0
                        || document.version > outer.data_epoch
                        || document.id <= previous
                    {
                        return Err(invalid("snapshot scan IDs are not strictly increasing"));
                    }
                    previous = document.id;
                }
                if let Some(next) = outer.next_after_id
                    && (rows.is_empty() || next != previous)
                {
                    return Err(invalid(
                        "snapshot scan continuation is not its last returned ID",
                    ));
                }
            }
        }
        call.check()
    }
}
pub(crate) enum Decoded {
    Lease(SnapshotLease),
    Read(kasumi_types::SnapshotReadResponse),
    Scan(kasumi_types::SnapshotScanPage),
}
impl Expected {
    pub(super) fn decode(&self, bytes: &[u8], call: &Call) -> Result<Decoded, ClientError> {
        // Inspect all identities, counts and revisions before constructing any
        // document or aggregate Value. The underlying admitted bytes are immutable.
        self.validate(bytes, call)?;
        match self {
            Self::Open { .. } => Ok(Decoded::Lease(serde_json::from_slice(bytes)?)),
            Self::Read {
                points, queries, ..
            } => {
                let outer: ReadOuter<'_> = serde_json::from_slice(bytes)?;
                let mut documents = Vec::new();
                for raw in array(outer.documents, points.len())? {
                    call.check()?;
                    let point: Point<'_> = serde_json::from_str(raw.get())?;
                    documents.push(kasumi_types::SnapshotDocument {
                        key: point.key,
                        document: point
                            .document
                            .map(|raw| decode_document(raw, call))
                            .transpose()?,
                    });
                }
                let mut results = Vec::new();
                for (raw, bound) in array(outer.queries, queries.len())?
                    .into_iter()
                    .zip(queries)
                {
                    let query: Query<'_> = serde_json::from_str(raw.get())?;
                    let mut rows = Vec::new();
                    for raw in array(query.rows, bound.limit)? {
                        call.check()?;
                        let row: Row<'_> = serde_json::from_str(raw.get())?;
                        rows.push(kasumi_types::QueryRow {
                            id: row.id,
                            version: row.version,
                            body: super::tokens::literal(row.body.get().as_bytes(), call)?,
                            score: row.score,
                        });
                    }
                    let mut aggregates = Vec::new();
                    for raw in array(query.aggregates, call.limits.max_rows)? {
                        aggregates.push(super::tokens::literal(raw.get().as_bytes(), call)?);
                    }
                    results.push(kasumi_types::QueryResponse {
                        revision: query.revision,
                        rows,
                        aggregates,
                        cursor: query.cursor,
                    });
                }
                Ok(Decoded::Read(kasumi_types::SnapshotReadResponse {
                    revision: outer.revision,
                    incarnation: outer.incarnation,
                    policy_epoch: outer.policy_epoch,
                    schema_epoch: outer.schema_epoch,
                    collection_epochs: serde_json::from_str(outer.collection_epochs.get())?,
                    documents,
                    queries: results,
                }))
            }
            Self::Scan { limit, .. } => {
                let outer: ScanOuter<'_> = serde_json::from_slice(bytes)?;
                let mut documents = Vec::new();
                for raw in array(outer.documents, *limit)? {
                    call.check()?;
                    documents.push(decode_document(raw, call)?);
                }
                Ok(Decoded::Scan(kasumi_types::SnapshotScanPage {
                    snapshot: outer.snapshot,
                    collection: outer.collection,
                    data_epoch: outer.data_epoch,
                    documents,
                    next_after_id: outer.next_after_id,
                }))
            }
        }
    }
}
fn decode_document(raw: &RawValue, call: &Call) -> Result<kasumi_types::Document, ClientError> {
    let document: Document<'_> = serde_json::from_str(raw.get())?;
    Ok(kasumi_types::Document {
        id: document.id,
        version: document.version,
        body: super::tokens::literal(document.body.get().as_bytes(), call)?,
    })
}

fn canonical_non_nil(text: &str) -> bool {
    uuid::Uuid::parse_str(text).is_ok_and(|id| !id.is_nil() && id.to_string() == text)
}
fn expected_incarnation(text: &str, call: &Call) -> bool {
    canonical_non_nil(text) && uuid::Uuid::parse_str(text).ok() == call.expected_incarnation
}
fn same_lease(left: &SnapshotLease, right: &SnapshotLease) -> bool {
    left.lease_id == right.lease_id
        && left.revision == right.revision
        && left.incarnation == right.incarnation
        && left.policy_epoch == right.policy_epoch
        && left.schema_epoch == right.schema_epoch
        && left.ttl_ms == right.ttl_ms
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadOuter<'a> {
    revision: u64,
    incarnation: String,
    policy_epoch: u64,
    schema_epoch: u64,
    #[serde(borrow)]
    collection_epochs: &'a RawValue,
    #[serde(borrow)]
    documents: &'a RawValue,
    #[serde(borrow)]
    queries: &'a RawValue,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Point<'a> {
    key: DocumentKey,
    #[serde(borrow)]
    document: Option<&'a RawValue>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document<'a> {
    id: String,
    version: u64,
    #[serde(borrow)]
    body: &'a RawValue,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Row<'a> {
    id: String,
    version: u64,
    #[serde(borrow)]
    body: &'a RawValue,
    score: Option<f32>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Query<'a> {
    revision: u64,
    #[serde(borrow)]
    rows: &'a RawValue,
    #[serde(borrow)]
    aggregates: &'a RawValue,
    cursor: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScanOuter<'a> {
    snapshot: SnapshotLease,
    collection: String,
    data_epoch: u64,
    #[serde(borrow)]
    documents: &'a RawValue,
    next_after_id: Option<String>,
}

// Check the bound before next_element invokes a row's Deserialize implementation.
fn array(raw: &RawValue, maximum: usize) -> Result<Vec<&RawValue>, ClientError> {
    struct Array(usize);
    struct Element(bool);
    impl<'de> DeserializeSeed<'de> for Element {
        type Value = &'de RawValue;
        fn deserialize<D: serde::Deserializer<'de>>(
            self,
            deserializer: D,
        ) -> Result<Self::Value, D::Error> {
            if !self.0 {
                return Err(serde::de::Error::custom(
                    "snapshot array exceeds expected count",
                ));
            }
            Deserialize::deserialize(deserializer)
        }
    }
    impl<'de> Visitor<'de> for Array {
        type Value = Vec<&'de RawValue>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a bounded snapshot array")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            let mut result = Vec::new();
            while let Some(value) = sequence.next_element_seed(Element(result.len() < self.0))? {
                result.push(value);
            }
            Ok(result)
        }
    }
    let mut decoder = serde_json::Deserializer::from_str(raw.get());
    let result = serde::Deserializer::deserialize_seq(&mut decoder, Array(maximum))?;
    decoder.end()?;
    Ok(result)
}
