//! Concrete local approval decoding. No generic caller-provided decoder/quote.
//! Source residency, destination DTO/scratch and the retained digest have
//! separate ownership. Optional anyhow backtraces remain diagnostic overhead.
use super::Proposal;
use anyhow::{Result, ensure};
use kasumi_engine::admission::{NodeAdmission, Reservation};
use kasumi_query::QueryCancellation;
use kasumi_types::{Action, Error, ErrorCode, Grant, SharedDocument};
use serde::Deserialize;
use serde_json::Value;
use std::{mem::size_of, sync::Arc};

pub(in crate::administration) struct ApprovedEnrollment {
    digest: String,
    _reservation: Reservation,
}
impl ApprovedEnrollment {
    pub(in crate::administration) fn digest(&self) -> &str {
        &self.digest
    }
}

// No original error extraction or mutable access. Downcasting an anyhow error
// moves this whole owner; source()/classification only lend the original.
pub(super) struct Failure {
    original: anyhow::Error,
    _reservation: Reservation,
}
impl Failure {
    pub(super) fn validation_error(&self) -> Option<&Error> {
        self.original.downcast_ref()
    }
}
impl std::fmt::Debug for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ApprovalFailure")
            .field(&self.original)
            .finish()
    }
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.original, f)
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.original.as_ref())
    }
}
fn overflow() -> Error {
    Error::new(
        ErrorCode::ResourceExhausted,
        "enrollment decode workspace size overflow",
    )
}
fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).ok_or_else(|| overflow().into())
}
fn mul(a: u64, b: u64) -> Result<u64> {
    a.checked_mul(b).ok_or_else(|| overflow().into())
}
fn backing(bytes: usize) -> Result<u64> {
    if bytes == 0 {
        return Ok(0);
    }
    if bytes > isize::MAX as usize {
        return Err(overflow().into());
    }
    bytes
        .checked_next_power_of_two()
        .and_then(|n| n.checked_add(64))
        .and_then(|n| u64::try_from(n).ok())
        .ok_or_else(|| overflow().into())
}
fn tree<K, V>(n: usize) -> Result<u64> {
    let bytes = size_of::<K>()
        .checked_add(size_of::<V>())
        .and_then(|n| n.checked_mul(11))
        .and_then(|n| n.checked_add(16 * size_of::<usize>()))
        .ok_or_else(overflow)?;
    mul(u64::try_from(n)?, backing(bytes)?)
}
fn vector<T>(n: usize) -> Result<u64> {
    // Serde's capped size hint and RawVec growth can reserve more than the
    // final length; include the minimum four slots and old/new growth overlap.
    // The quote also funds Policy::clone's exact-size destination.
    if n == 0 {
        return Ok(0);
    }
    mul(
        backing(
            size_of::<T>()
                .checked_mul(n.max(4))
                .and_then(|v| v.checked_mul(2))
                .ok_or_else(overflow)?,
        )?,
        2,
    )
}
fn field<'a>(value: &'a Value, name: &str, index: usize) -> Option<&'a Value> {
    match value {
        Value::Object(map) => map.get(name),
        Value::Array(values) => values.get(index),
        _ => None,
    }
}
fn longest(value: &Value) -> usize {
    match value {
        Value::String(s) => s.len(),
        Value::Number(n) => n.as_str().len(),
        Value::Array(a) => a.iter().map(longest).max().unwrap_or(0),
        Value::Object(o) => o
            .iter()
            .map(|(k, v)| k.len().max(longest(v)))
            .max()
            .unwrap_or(0),
        _ => 0,
    }
}
fn decoded_array_workspace(value: &Value) -> Result<u64> {
    // Value::deserialize uses Vec::new + push rather than Value::clone's
    // exact-size allocation. Account this for arbitrary nested key descriptors,
    // including minimum capacity and old/new RawVec growth overlap.
    match value {
        Value::Array(values) => values
            .iter()
            .try_fold(vector::<Value>(values.len())?, |bytes, value| {
                add(bytes, decoded_array_workspace(value)?)
            }),
        Value::Object(values) => values.values().try_fold(0, |bytes, value| {
            add(bytes, decoded_array_workspace(value)?)
        }),
        _ => Ok(0),
    }
}
fn policy_backing(value: Option<&Value>) -> Result<u64> {
    let Some(value) = value else {
        return Ok(0);
    };
    // The complete JSON clone is an intentionally conservative String/Value
    // allowance; typed Vec<Grant> and sparse action nodes are additional.
    let mut bytes = kasumi_query::document_parts_clone_bytes("", value)?;
    if let Some(grants) = field(value, "grants", 0).and_then(Value::as_array) {
        bytes = add(bytes, vector::<Grant>(grants.len())?)?;
        for grant in grants {
            if let Some(actions) = field(grant, "actions", 2).and_then(Value::as_array) {
                bytes = add(bytes, tree::<Action, ()>(actions.len())?)?;
            }
        }
    }
    Ok(bytes)
}
#[derive(Clone, Copy)]
struct Quote {
    peak: u64,
    digest: u64,
}
fn quote(value: &Value) -> Result<Quote> {
    use kasumi_engine::control::{ControlNode, ControlTopology};
    // JSON destination backing covers all cloned strings/keys and nested key descriptors.
    // Add concrete typed containers whose slots can exceed the JSON variant.
    let mut destination = add(
        kasumi_query::document_parts_clone_bytes("", value)?,
        decoded_array_workspace(value)?,
    )?;
    let policy = policy_backing(field(value, "initial_policy", 4))?;
    destination = add(destination, policy)?;
    let mut pins = 0usize;
    let mut url = 0;
    let mut key_scratch = 0;
    if let Some(nodes) = field(value, "nodes", 3).and_then(Value::as_object) {
        destination = add(destination, tree::<u64, ControlNode>(nodes.len())?)?;
        for (key, node) in nodes {
            key_scratch = key_scratch.max(add(backing(key.len())?, backing(20)?)?);
            if let Some(endpoint) = field(node, "endpoint", 0).and_then(Value::as_str) {
                url = url.max(ControlTopology::endpoint_workspace_bytes(endpoint)?);
            }
            if let Some(values) = field(node, "certificate_pins", 2).and_then(Value::as_array) {
                destination = add(destination, tree::<String, ()>(values.len())?)?;
                pins = pins.checked_add(values.len()).ok_or_else(overflow)?;
            }
        }
    }
    let voters = field(value, "route", 2)
        .and_then(|v| field(v, "voters", 2))
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    destination = add(destination, tree::<u64, ()>(voters)?)?;
    // Decode diagnostics format one input text with Debug escaping; cover both
    // growing String reallocations, boxed-str shrink and serde ErrorImpl.
    let diagnostic = longest(value)
        .checked_mul(8)
        .and_then(|n| n.checked_add(1024))
        .ok_or_else(overflow)?;
    let errors = add(
        add(
            mul(backing(diagnostic.checked_mul(2).ok_or_else(overflow)?)?, 2)?,
            backing(diagnostic)?,
        )?,
        backing(size_of::<[usize; 8]>())?,
    )?;
    let validate = add(
        tree::<&String, ()>(pins)?,
        url.max(add(tree::<&String, ()>(voters)?, backing(36)?)?),
    )?;
    // validate_genesis_inputs overlaps two compact Policy clones. Its empty
    // metadata is independently bounded below; no source TenantState is cloned.
    let genesis = add(mul(policy, 2)?, genesis_fixed_workspace()?)?;
    let digest = backing(78)?; // "enrollment-v1-" +64 lowercase hex digits (78bytes).
    let hash_strings = mul(backing(128)?, 4)?; // hex, final string, old/new format growth.
    let scratch = add(errors, key_scratch)?
        .max(add(validate, backing(Error::MAX_MESSAGE_BYTES)?)?)
        .max(genesis)
        .max(hash_strings);
    let cancellation = backing(
        QueryCancellation::shared_state_bytes()
            .checked_add(2 * size_of::<usize>())
            .ok_or_else(overflow)?,
    )?;
    let owners = mul(
        backing(
            size_of::<Failure>()
                .checked_add(size_of::<Option<std::backtrace::Backtrace>>())
                .and_then(|n| n.checked_add(size_of::<[usize; 8]>()))
                .ok_or_else(overflow)?,
        )?,
        2,
    )?;
    Ok(Quote {
        peak: add(add(add(destination, scratch)?, cancellation)?, owners)?,
        digest,
    })
}
fn genesis_fixed_workspace() -> Result<u64> {
    // Pinned imbl7 new OrdMap has root=None and new Vector uses InlineArray;
    // empty genesis containers allocate no backing. The validator keeps the
    // genesis state and one boxed metadata header, hence two Policy clones and
    // twenty identity/root strings (tenant,incarnation,4*(origin,digest) each).
    // Names have already passed the256-byte limit. staged_digest streams its
    // input; only its growing64-byte hex String needs old/new backing.
    let shells = mul(backing(size_of::<kasumi_types::TenantState>())?, 2)?;
    let identities = mul(backing(256)?, 20)?;
    let hex_growth = mul(backing(128)?, 3)?;
    // audit stream UUID alone uses to_vec of(tag,tenant,incarnation): each name
    // can expand sixfold under JSON escaping, plus64 bytes of tag/framing.
    // RawVec doubling and simultaneous old/new reallocations are both included.
    let audit_requested = 2 * 256 * 6 + 64;
    let audit = mul(backing(2 * audit_requested)?, 2)?;
    // fits() formats one u64 revision; a fixed canonical Error may coexist with
    // both state/header on a quota failure. Optional anyhow backtraces excluded.
    let diagnostics = add(backing(20)?, backing(Error::MAX_MESSAGE_BYTES)?)?;
    add(
        add(shells, identities)?,
        add(hex_growth.max(audit), diagnostics)?,
    )
}

pub(super) struct Work {
    source: SharedDocument,
    proposal: Option<Proposal>,
    digest: Option<String>,
    token: QueryCancellation,
    reservation: Reservation,
    quote: Quote,
}
impl Work {
    pub(super) fn new(node: &Arc<NodeAdmission>, source: SharedDocument) -> Result<Self> {
        let quote = quote(&source.body)?;
        let reservation = node.reserve(quote.peak, None)?;
        Ok(Self {
            source,
            proposal: None,
            digest: None,
            token: QueryCancellation::default(),
            reservation,
            quote,
        })
    }
    pub(super) fn evaluate(&mut self, node: &NodeAdmission, tenant: Option<&str>) -> Result<()> {
        node.check_release(&self.token)?;
        self.proposal = Some(Proposal::deserialize(&self.source.body)?);
        node.check_release(&self.token)?;
        let proposal = self.proposal.as_ref().expect("decoded approval");
        if let Some(tenant) = tenant {
            ensure!(
                proposal.tenant == tenant,
                "Control enrollment identity differs"
            );
        }
        self.digest = Some(proposal.digest()?);
        node.check_release(&self.token)?;
        Ok(())
    }
    pub(super) fn fail(self, error: anyhow::Error) -> anyhow::Error {
        let Self {
            source,
            proposal,
            digest,
            token,
            mut reservation,
            quote,
        } = self;
        drop(source);
        drop(proposal);
        drop(digest);
        drop(token);
        reservation.retain(quote.peak);
        anyhow::Error::new(Failure {
            original: error,
            _reservation: reservation,
        })
    }
    pub(super) fn finish(self) -> ApprovedEnrollment {
        let Self {
            source,
            proposal,
            digest,
            token,
            mut reservation,
            quote,
        } = self;
        drop(source);
        drop(proposal);
        drop(token);
        let digest = digest.expect("validated approval digest");
        reservation.retain(quote.digest);
        ApprovedEnrollment {
            digest,
            _reservation: reservation,
        }
    }
}

#[cfg(test)]
#[path = "approved_enrollment_tests.rs"]
mod tests;

#[cfg(test)]
pub(super) fn measure_topology<T>(work: impl FnOnce() -> T) -> (T, usize, usize, bool, usize) {
    tests::measure_topology(work)
}
