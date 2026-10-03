//! Local Control decode ownership. No barrier, audit or retained Generation.
use crate::admission::{NodeAdmission, Reservation};
use crate::output::{AdmittedOutput, OUTPUT_CHARGE_BYTES};
use kasumi_query::QueryCancellation;
use kasumi_types::control_topology::{ControlTopology, TopologyMemory, VersionedTopology};
use kasumi_types::{Error, ErrorCode, Result};
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;

fn overflow() -> Error {
    Error::new(
        ErrorCode::ResourceExhausted,
        "local topology ownership size overflow",
    )
}
fn add(left: u64, right: u64) -> Result<u64> {
    left.checked_add(right).ok_or_else(overflow)
}
fn token_bytes() -> Result<u64> {
    let size = QueryCancellation::shared_state_bytes()
        .checked_add(2 * std::mem::size_of::<usize>())
        .and_then(usize::checked_next_power_of_two)
        .and_then(|n| n.checked_add(64))
        .ok_or_else(overflow)?;
    u64::try_from(size).map_err(|_| overflow())
}

// Pinned anyhow1.0.104 uses repr(C) ErrorImpl { vtable, Option<Backtrace>,
// object }. Quote its fixed allocation for the private failure owner;
// optional captured Backtrace heap is explicitly NOT bounded by this DTO policy.
#[repr(C)]
struct ErrorHeader<T> {
    _vtable: usize,
    _backtrace: Option<std::backtrace::Backtrace>,
    _object: T,
}
fn allocation_bytes<T>() -> Result<u64> {
    let bytes = std::mem::size_of::<T>()
        .checked_next_power_of_two()
        .and_then(|n| n.checked_add(64))
        .ok_or_else(overflow)?;
    u64::try_from(bytes).map_err(|_| overflow())
}
fn failure_owner_bytes() -> Result<u64> {
    allocation_bytes::<ErrorHeader<LocalTopologyFailure>>()
}

#[derive(Debug)]
enum Failure {
    Decode(serde_json::Error),
    Validation(Error),
}
impl From<serde_json::Error> for Failure {
    fn from(error: serde_json::Error) -> Self {
        Self::Decode(error)
    }
}
impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        Self::Validation(error)
    }
}
/// Original local decode/validation failure and its retained operation grant.
/// The payload is immutable and private: consuming an anyhow downcast moves
/// this whole owner, and a mutable downcast cannot separate its original error.
/// Formatting or cloning a borrowed classification is a separate allocation.
/// Anyhow's optional backtrace/outer diagnostic boxes are not a DTO heap bound.
pub struct LocalTopologyFailure {
    failure: Failure,
    _reservation: Reservation,
}
impl LocalTopologyFailure {
    /// Preserve canonical validation/pressure classification without extraction.
    pub fn validation_error(&self) -> Option<&Error> {
        match &self.failure {
            Failure::Validation(error) => Some(error),
            Failure::Decode(_) => None,
        }
    }
}
impl std::fmt::Debug for LocalTopologyFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("LocalTopologyFailure")
            .field(&self.failure)
            .finish()
    }
}
impl std::fmt::Display for LocalTopologyFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.failure {
            Failure::Decode(error) => std::fmt::Display::fmt(error, f),
            Failure::Validation(error) => std::fmt::Display::fmt(error, f),
        }
    }
}
impl std::error::Error for LocalTopologyFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match &self.failure {
            Failure::Decode(error) => error,
            Failure::Validation(error) => error,
        })
    }
}
fn owned_failure(error: Failure, mut reservation: Reservation) -> anyhow::Error {
    reservation.retain_workspace();
    anyhow::Error::new(LocalTopologyFailure {
        failure: error,
        _reservation: reservation,
    })
}

// All payload and cancellation backing retire before the grant, including
// failure/unwind. The operation is synchronous; node pressure is checked before
// and after each noninterruptible serde/validator call, not by a detached task.
struct Decode {
    value: Option<VersionedTopology>,
    cancellation: QueryCancellation,
    reservation: Reservation,
    quote: TopologyMemory,
}
impl Decode {
    fn new(node: &Arc<NodeAdmission>, body: &Value) -> Result<Self> {
        Self::with_extra(node, body, 0)
    }
    fn with_extra(node: &Arc<NodeAdmission>, body: &Value, extra: u64) -> Result<Self> {
        let quote = ControlTopology::memory_from_value(body)?;
        let bytes = add(
            add(
                add(add(quote.peak_bytes, OUTPUT_CHARGE_BYTES)?, token_bytes()?)?,
                extra,
            )?,
            failure_owner_bytes()?,
        )?;
        // Reserve before constructing even the cancellation Arc. A synchronous
        // read has no external child/caller token; check_release observes actual
        // node pressure at each boundary and cancels this admitted token.
        let reservation = node.reserve(bytes, None)?;
        Ok(Self {
            value: None,
            cancellation: QueryCancellation::default(),
            reservation,
            quote,
        })
    }
    fn decode(
        &mut self,
        node: &Arc<NodeAdmission>,
        version: u64,
        body: &Value,
    ) -> std::result::Result<(), Failure> {
        self.decode_with_validation(node, version, body, true, false)
    }
    fn decode_with_validation(
        &mut self,
        node: &Arc<NodeAdmission>,
        version: u64,
        body: &Value,
        validate: bool,
        installed: bool,
    ) -> std::result::Result<(), Failure> {
        node.check_release(&self.cancellation)?;
        let topology = ControlTopology::deserialize(body).map_err(|error| {
            if installed {
                Failure::Validation(Error::new(
                    ErrorCode::Corruption,
                    "installed Control topology is invalid",
                ))
            } else {
                Failure::Decode(error)
            }
        })?;
        self.value = Some(VersionedTopology { version, topology });
        node.check_release(&self.cancellation)?;
        if validate {
            self.value
                .as_ref()
                .expect("decoded topology")
                .topology
                .validate()?;
        }
        node.check_release(&self.cancellation)?;
        Ok(())
    }
    fn fail(self, error: Failure) -> anyhow::Error {
        let Self {
            value,
            cancellation,
            reservation,
            ..
        } = self;
        drop(value);
        drop(cancellation);
        owned_failure(error, reservation)
    }
    fn finish(self) -> Result<AdmittedOutput<VersionedTopology>> {
        let retained = add(self.quote.retained_bytes, OUTPUT_CHARGE_BYTES)?;
        let Self {
            value,
            cancellation,
            mut reservation,
            ..
        } = self;
        let value = value.expect("validated topology");
        drop(cancellation);
        // Decode/URL/error scratch is gone. Retire the completed operation slot
        // before publishing output, preserving the DTO and charge-Arc backing.
        reservation.retain(retained);
        Ok(AdmittedOutput::new(value, Arc::new(reservation)))
    }
}

pub(super) fn local_topology(
    database: &crate::Database,
) -> anyhow::Result<AdmittedOutput<VersionedTopology>> {
    use anyhow::Context;
    // Keep the established local-management corridor and its exact missing/
    // decode/validation error ordering. This is not a current-quorum proof.
    database.raft_group().check_access()?;
    let generation = database.engine().generation()?;
    if generation.tenant() != super::CONTROL_TENANT {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "control metadata needs its dedicated group",
        )
        .into());
    }
    let document = generation
        .state
        .collections
        .get("topology")
        .and_then(|collection| collection.documents.get("current"))
        .context("control topology unavailable")?;
    let mut decode = Decode::new(database.admission(), &document.body)?;
    if let Err(error) = decode.decode(database.admission(), document.version, &document.body) {
        drop(generation);
        return Err(decode.fail(error));
    }
    // Current key/serving access is a release check; selecting it does not
    // replace any captured semantic data or introduce an audit/revision.
    if let Err(error) = database.raft_group().check_access() {
        // This opaque storage error retains its own original owner/backtrace.
        // It does not borrow DTO data; retire that data before its unrelated
        // workspace, then return the original error without reboxing it.
        drop(decode);
        drop(generation);
        return Err(error);
    }
    // generation() is also the Engine's installed serving-authority check.
    // Discard this access-only Arc immediately; no field from it participates
    // in the selected topology, version or accounting.
    if let Err(error) = database.engine().generation() {
        drop(decode);
        drop(generation);
        return Err(error.into());
    }
    drop(generation);
    Ok(decode.finish()?)
}

// The two fixed schema constructors create fewer than32 map entries/strings.
// Count full BTree nodes and256 requested bytes per string before construction;
// each allocation uses the same rounded backing policy as typed DTO quotes.
fn reserved_schema_workspace() -> Result<u64> {
    let node = 11 * (std::mem::size_of::<String>() + std::mem::size_of::<Value>())
        + 16 * std::mem::size_of::<usize>();
    let backing = |n: usize| {
        n.checked_next_power_of_two()
            .and_then(|n| n.checked_add(64))
            .and_then(|n| u64::try_from(n).ok())
            .ok_or_else(overflow)
    };
    add(backing(node)?, backing(256)?)?
        .checked_mul(32)
        .ok_or_else(overflow)
}
pub(super) fn selected_topology(
    database: &crate::Database,
    generation: &crate::Generation,
    validate: bool,
    installed: bool,
) -> anyhow::Result<Option<AdmittedOutput<VersionedTopology>>> {
    database.raft_group().check_access()?;
    drop(database.engine().generation()?);
    let document = generation
        .state
        .collections
        .get("topology")
        .and_then(|collection| collection.documents.get("current"));
    if !installed && document.is_none() {
        database.raft_group().check_access()?;
        drop(database.engine().generation()?);
        return Ok(None);
    }
    let body = document.map_or(&Value::Null, |document| &document.body);
    let mut decode = Decode::with_extra(
        database.admission(),
        body,
        if installed {
            reserved_schema_workspace()?
        } else {
            0
        },
    )?;
    let prepared = (|| -> std::result::Result<(), Failure> {
        database.admission().check_release(&decode.cancellation)?;
        if installed {
            let corrupt = |message| Failure::Validation(Error::new(ErrorCode::Corruption, message));
            if generation.tenant() != super::CONTROL_TENANT {
                return Err(corrupt("Control state has the wrong namespace"));
            }
            let collection = generation
                .state
                .collections
                .get("topology")
                .ok_or_else(|| corrupt("installed Control topology schema is missing"))?;
            if collection.definition != super::ControlPlane::topology_definition() {
                return Err(corrupt("installed Control topology schema differs"));
            }
            if generation.lifecycle_installation().is_some()
                && generation
                    .state
                    .collections
                    .get("tenant_enrollments")
                    .is_none_or(|collection| {
                        collection.definition != super::ControlPlane::enrollment_definition()
                    })
            {
                return Err(corrupt(
                    "installed Control enrollment schema is missing or differs",
                ));
            }
        }
        let document = document.ok_or_else(|| {
            Failure::Validation(Error::new(
                ErrorCode::Corruption,
                "installed Control topology is missing",
            ))
        })?;
        decode.decode_with_validation(
            database.admission(),
            document.version,
            &document.body,
            validate,
            installed,
        )
    })();
    if let Err(error) = prepared {
        return Err(decode.fail(error));
    }
    database.raft_group().check_access()?;
    drop(database.engine().generation()?);
    Ok(Some(decode.finish()?))
}

#[cfg(test)]
#[path = "control_topology_memory_tests.rs"]
mod tests;
