//! Bounded traversal of the maintained unique tuple map, without candidate sets.
use crate::{
    QueryCancellation, QueryIndexes, ResultBudget,
    scalar::{Scalar, invalid, scalar},
};
use kasumi_types::*;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, ops::Bound};

pub struct OrderedSeekPage {
    pub rows: Vec<QueryRow>,
    pub after_key: Option<Vec<Value>>,
    pub index_entries_visited: u64,
}
pub fn ordered_seek_request_sha256(request: &OrderedSeekRequest) -> Result<String> {
    request_shape(request)?;
    let normalized = OrderedSeekRequest {
        continuation: None,
        ..request.clone()
    };
    let encoded =
        serde_json::to_vec(&normalized).map_err(|_| invalid("ordered seek encoding failed"))?;
    Ok(Sha256::digest(encoded)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}
fn request_shape(request: &OrderedSeekRequest) -> Result<()> {
    validate_name(&request.collection)?;
    validate_name(&request.index)?;
    let scalar_key = |values: &[Value]| -> Result<()> {
        if values.len() > 8 {
            return Err(invalid("ordered seek key field bound"));
        }
        for value in values {
            match value {
                Value::Null | Value::Bool(_) => {}
                Value::String(value) if value.len() <= 1024 => {}
                Value::Number(value) if value.to_string().len() <= 256 => {}
                _ => return Err(invalid("ordered seek key scalar byte bound")),
            }
        }
        Ok(())
    };
    scalar_key(&request.prefix)?;
    if let Some(bound) = &request.lower {
        scalar_key(&bound.key)?;
    }
    if let Some(bound) = &request.upper {
        scalar_key(&bound.key)?;
    }
    if let Some(cursor) = &request.continuation {
        scalar_key(&cursor.after_key)?;
        if cursor.tenant.is_empty()
            || cursor.tenant.len() > 256
            || cursor.incarnation.is_empty()
            || cursor.incarnation.len() > 256
            || [&cursor.index_sha256, &cursor.request_sha256]
                .into_iter()
                .any(|hash| {
                    hash.len() != 64
                        || !hash
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                })
        {
            return Err(invalid("ordered seek continuation identity bound"));
        }
    }
    Ok(())
}
fn values(values: &[Value], fields: &[IndexField], complete: bool) -> Result<Vec<Scalar>> {
    if values.len() > fields.len() || (complete && values.len() != fields.len()) {
        return Err(invalid("ordered seek tuple arity differs from index"));
    }
    values
        .iter()
        .zip(fields)
        .map(|(value, field)| {
            if matches!(
                field.kind,
                ScalarType::StringArray | ScalarType::NumberArray
            ) || serde_json::to_vec(value)
                .map_err(|_| invalid("ordered seek key encoding"))?
                .len()
                > 1024
            {
                return Err(invalid("ordered seek scalar key bound"));
            }
            scalar(Some(value), Some(field.kind))
        })
        .collect()
}
fn key(bound: &Bound<Vec<Scalar>>) -> &Vec<Scalar> {
    match bound {
        Bound::Included(key) | Bound::Excluded(key) => key,
        Bound::Unbounded => unreachable!("prefix bounds always finite"),
    }
}
fn lower_stricter(a: Bound<Vec<Scalar>>, b: Bound<Vec<Scalar>>) -> Bound<Vec<Scalar>> {
    match key(&a).cmp(key(&b)) {
        std::cmp::Ordering::Less => b,
        std::cmp::Ordering::Greater => a,
        std::cmp::Ordering::Equal => {
            if matches!(a, Bound::Excluded(_)) {
                a
            } else {
                b
            }
        }
    }
}
fn upper_stricter(a: Bound<Vec<Scalar>>, b: Bound<Vec<Scalar>>) -> Bound<Vec<Scalar>> {
    match key(&a).cmp(key(&b)) {
        std::cmp::Ordering::Greater => b,
        std::cmp::Ordering::Less => a,
        std::cmp::Ordering::Equal => {
            if matches!(a, Bound::Excluded(_)) {
                a
            } else {
                b
            }
        }
    }
}
impl QueryIndexes {
    pub fn ordered_seek_with_cancellation(
        &self,
        collections: &BTreeMap<String, CollectionState>,
        request: &OrderedSeekRequest,
        limits: &Limits,
        cancellation: &QueryCancellation,
    ) -> Result<OrderedSeekPage> {
        cancellation.check()?;
        request_shape(request)?;
        validate_name(&request.collection)?;
        validate_name(&request.index)?;
        if request.limit == 0
            || request.limit > limits.max_page_size
            || request
                .limit
                .checked_add(1)
                .is_none_or(|count| count > limits.max_query_candidates)
        {
            return Err(invalid("ordered seek page outside allowed bound"));
        }
        let collection = collections
            .get(&request.collection)
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "ordered seek collection absent"))?;
        let indexes = self
            .collections
            .get(&request.collection)
            .ok_or_else(|| Error::new(ErrorCode::Unavailable, "ordered seek index not ready"))?;
        let index = indexes
            .structured
            .unique
            .get(&request.index)
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::IndexRequired,
                    "ordered seek requires a declared unique tuple index",
                )
            })?;
        if index.fields.is_empty() || index.fields.len() > 8 {
            return Err(invalid("ordered seek index field bound"));
        }
        let prefix = values(&request.prefix, &index.fields, false)?;
        let mut high = prefix.clone();
        high.push(Scalar::UpperBound);
        let mut lower = Bound::Included(prefix.clone());
        let mut upper = Bound::Excluded(high);
        if let Some(bound) = &request.lower {
            let key = values(&bound.key, &index.fields, true)?;
            if !key.starts_with(&prefix) {
                return Err(invalid("ordered seek lower key leaves prefix"));
            }
            lower = lower_stricter(
                lower,
                if bound.inclusive {
                    Bound::Included(key)
                } else {
                    Bound::Excluded(key)
                },
            );
        }
        if let Some(bound) = &request.upper {
            let key = values(&bound.key, &index.fields, true)?;
            if !key.starts_with(&prefix) {
                return Err(invalid("ordered seek upper key leaves prefix"));
            }
            upper = upper_stricter(
                upper,
                if bound.inclusive {
                    Bound::Included(key)
                } else {
                    Bound::Excluded(key)
                },
            );
        }
        if let Some(cursor) = &request.continuation {
            if cursor.revision == 0
                || cursor.request_sha256 != ordered_seek_request_sha256(request)?
            {
                return Err(invalid("ordered seek continuation request differs"));
            }
            let key = values(&cursor.after_key, &index.fields, true)?;
            if !key.starts_with(&prefix) {
                return Err(invalid("ordered seek continuation leaves prefix"));
            }
            match request.direction {
                Direction::Asc => lower = lower_stricter(lower, Bound::Excluded(key)),
                Direction::Desc => upper = upper_stricter(upper, Bound::Excluded(key)),
            }
        }
        if key(&lower) > key(&upper)
            || (key(&lower) == key(&upper)
                && (!matches!(lower, Bound::Included(_)) || !matches!(upper, Bound::Included(_))))
        {
            return Ok(OrderedSeekPage {
                rows: vec![],
                after_key: None,
                index_entries_visited: 0,
            });
        }
        let range = index.entries.range((lower, upper));
        let entries: Box<dyn Iterator<Item = (&Vec<Scalar>, &String)>> = match request.direction {
            Direction::Asc => Box::new(range),
            Direction::Desc => Box::new(range.rev()),
        };
        let mut rows = Vec::with_capacity(request.limit);
        let mut visited = 0u64;
        let mut more = false;
        let mut last = None;
        let mut budget = ResultBudget::new(limits.max_result_bytes);
        for (key, id) in entries.take(request.limit + 1) {
            cancellation.check()?;
            visited += 1;
            if rows.len() == request.limit {
                more = true;
                break;
            }
            let document = collection.documents.get(id).ok_or_else(|| {
                Error::new(
                    ErrorCode::Unavailable,
                    "ordered seek selected archived content requires bounded hydration",
                )
            })?;
            let mut raw_key = Vec::with_capacity(index.fields.len());
            for (field, expected) in index.fields.iter().zip(key) {
                let value = document.body.pointer(&field.path).ok_or_else(|| {
                    Error::new(ErrorCode::Corruption, "ordered seek indexed field absent")
                })?;
                if scalar(Some(value), Some(field.kind))? != *expected {
                    return Err(Error::new(
                        ErrorCode::Corruption,
                        "ordered seek index/body differs",
                    ));
                }
                raw_key.push(value.clone());
            }
            let row = QueryRow {
                id: document.id.clone(),
                version: document.version,
                body: document.body.clone(),
                score: None,
            };
            budget.account(&row)?;
            rows.push(row);
            last = Some(raw_key);
        }
        cancellation.check()?;
        Ok(OrderedSeekPage {
            rows,
            after_key: if more { last } else { None },
            index_entries_visited: visited,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Arc;
    fn setup() -> (BTreeMap<String, CollectionState>, OrderedSeekRequest) {
        let definition = CollectionDefinition {
            name: "ordered".into(),
            schema: json!({"type":"object"}),
            indexes: vec![IndexDefinition {
                name: "scope_time_id".into(),
                fields: ["/scope", "/at", "/literalId"]
                    .into_iter()
                    .map(|path| IndexField {
                        path: path.into(),
                        kind: ScalarType::String,
                    })
                    .collect(),
                unique: true,
                text: None,
            }],
            write_mode: CollectionWriteMode::Mutable,
            retention_class: CollectionRetentionClass::Operational,
            strict_read_audit: true,
        };
        let documents=(0..20_010).map(|n|{let id=format!("row-{n:05}");(id.clone(),Arc::new(Document{id,version:10,body:json!({"scope":if n<10005{"a"}else{"b"},"at":format!("{:020}",n%10005),"literalId":format!("literal-{n:05}")})}))}).collect();
        let collections = BTreeMap::from([(
            "ordered".into(),
            CollectionState {
                definition,
                documents,
                archived_documents: Default::default(),
                archived_document_bytes: 0,
                data_epoch: 20,
            },
        )]);
        let request = OrderedSeekRequest {
            collection: "ordered".into(),
            index: "scope_time_id".into(),
            prefix: vec![json!("a")],
            lower: None,
            upper: None,
            direction: Direction::Desc,
            limit: 2,
            continuation: None,
        };
        (collections, request)
    }
    fn continuation(
        request: &OrderedSeekRequest,
        after_key: Vec<Value>,
    ) -> OrderedSeekContinuation {
        OrderedSeekContinuation {
            revision: 10,
            tenant: "tenant".into(),
            incarnation: "incarnation".into(),
            collection_epoch: 20,
            policy_epoch: 1,
            schema_epoch: 1,
            index_sha256: "0".repeat(64),
            request_sha256: ordered_seek_request_sha256(request).unwrap(),
            after_key,
        }
    }
    #[test]
    fn bounded_named_tuple_seek_examines_only_page_and_lookahead_at_volume() {
        let (collections, mut request) = setup();
        let indexes = QueryIndexes::build(&collections).unwrap();
        let limits = Limits {
            max_query_candidates: 3,
            ..Limits::default()
        };
        let page = indexes
            .ordered_seek_with_cancellation(
                &collections,
                &request,
                &limits,
                &QueryCancellation::after_checks(8),
            )
            .unwrap();
        assert_eq!(page.index_entries_visited, 3);
        assert_eq!(page.rows.len(), 2);
        assert_eq!(
            page.rows
                .iter()
                .map(|row| row.body["at"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["00000000000000010004", "00000000000000010003"]
        );
        request.continuation = Some(continuation(&request, page.after_key.unwrap()));
        let next = indexes
            .ordered_seek_with_cancellation(
                &collections,
                &request,
                &limits,
                &QueryCancellation::after_checks(8),
            )
            .unwrap();
        assert_eq!(next.rows[0].body["at"], "00000000000000010002");
        assert_eq!(next.index_entries_visited, 3);
        request.direction = Direction::Asc;
        request.continuation = None;
        let first = indexes
            .ordered_seek_with_cancellation(
                &collections,
                &request,
                &limits,
                &QueryCancellation::after_checks(8),
            )
            .unwrap();
        assert_eq!(first.rows[0].body["at"], "00000000000000000000");
        request.lower = Some(OrderedSeekBound {
            key: vec![
                json!("a"),
                json!("00000000000000010004"),
                json!("literal-10004"),
            ],
            inclusive: true,
        });
        let last = indexes
            .ordered_seek_with_cancellation(
                &collections,
                &request,
                &limits,
                &QueryCancellation::after_checks(8),
            )
            .unwrap();
        assert_eq!(last.rows.len(), 1);
        assert_eq!(last.index_entries_visited, 1);
        assert!(last.after_key.is_none());
    }
    #[test]
    fn boundaries_request_replay_and_index_requirements_fail_without_scanning() {
        let (collections, mut request) = setup();
        let indexes = QueryIndexes::build(&collections).unwrap();
        request.prefix = vec![json!("absent")];
        let empty = indexes
            .ordered_seek_with_cancellation(
                &collections,
                &request,
                &Limits::default(),
                &QueryCancellation::after_checks(4),
            )
            .unwrap();
        assert!(empty.rows.is_empty());
        assert_eq!(empty.index_entries_visited, 0);
        request.lower = Some(OrderedSeekBound {
            key: vec![json!("other"), json!("0"), json!("id")],
            inclusive: true,
        });
        assert!(
            indexes
                .ordered_seek_with_cancellation(
                    &collections,
                    &request,
                    &Limits::default(),
                    &QueryCancellation::default()
                )
                .is_err()
        );
        request.lower = None;
        request.prefix = vec![json!(42)];
        assert!(
            indexes
                .ordered_seek_with_cancellation(
                    &collections,
                    &request,
                    &Limits::default(),
                    &QueryCancellation::default()
                )
                .is_err()
        );
        request.prefix = vec![json!("a")];
        request.index = "missing".into();
        assert_eq!(
            indexes
                .ordered_seek_with_cancellation(
                    &collections,
                    &request,
                    &Limits::default(),
                    &QueryCancellation::default()
                )
                .err()
                .unwrap()
                .code,
            ErrorCode::IndexRequired
        );
        request.index = "scope_time_id".into();
        request.continuation = Some(continuation(
            &request,
            vec![json!("a"), json!("0"), json!("id")],
        ));
        request.limit = 3;
        assert!(
            indexes
                .ordered_seek_with_cancellation(
                    &collections,
                    &request,
                    &Limits::default(),
                    &QueryCancellation::default()
                )
                .is_err()
        );
    }
}
