//! Bounded named-unique-index reads. Continuation never silently changes revision.
use crate::{Direction, QueryRow};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OrderedSeekBound {
    /// Full tuple in the named index's declared field order.
    pub key: Vec<Value>,
    pub inclusive: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OrderedSeekContinuation {
    /// Original global data revision; source epochs below establish continuity.
    pub revision: u64,
    pub tenant: String,
    pub incarnation: String,
    pub collection_epoch: u64,
    pub policy_epoch: u64,
    pub schema_epoch: u64,
    pub index_sha256: String,
    pub request_sha256: String,
    pub after_key: Vec<Value>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OrderedSeekRequest {
    pub collection: String,
    pub index: String,
    pub prefix: Vec<Value>,
    pub lower: Option<OrderedSeekBound>,
    pub upper: Option<OrderedSeekBound>,
    pub direction: Direction,
    pub limit: usize,
    pub continuation: Option<OrderedSeekContinuation>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OrderedSeekResponse {
    /// Original data revision, retained across unchanged-source continuations.
    pub revision: u64,
    /// Current actual immutable generation inspected for this request.
    pub observed_revision: u64,
    pub tenant: String,
    pub collection_epoch: u64,
    pub index_sha256: String,
    pub incarnation: String,
    pub policy_epoch: u64,
    pub schema_epoch: u64,
    pub request_sha256: String,
    pub rows: Vec<QueryRow>,
    pub continuation: Option<OrderedSeekContinuation>,
    /// Actual ordered index entries inspected, including at most one lookahead.
    pub index_entries_visited: u64,
}
