//! Dormant first-release format for the first Start(Quorum) custody binding.
//! A serialized Control phase is history, not authority to call the writer.
//! Runtime admission must verify it through installed Control and reserve the
//! exact dispatch in the independent journal before using this format.
#![allow(dead_code)]

use anyhow::{Context, Result, ensure};
use kasumi_store::TenantStore;
use kasumi_types::{
    ControlSigningRoot, LifecycleIntent, LifecyclePhase, RecoveryDispatch, RecoveryEffect,
    RecoveryPhase, RecoveryPhaseRecord, TargetOrigin, TargetQuorumInput, TargetReplicaInput,
    TargetRuntimeRequest, TargetRuntimeStep, staged_digest,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const NAMESPACE: &str = "target.lifecycle";
const KEY: &[u8] = b"initialize";
const MAX_RECORD: usize = 256 << 10;

/// Exact historical Start identity. It is not a dispatch ticket or an issuer
/// grant; constructing one from a decoded phase does not authenticate Control.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StartOwner {
    control_root: ControlSigningRoot,
    operation_id: Uuid,
    phase_id: Uuid,
    attempt_id: Uuid,
    node_id: u64,
    principal: String,
    command_id: Uuid,
    not_after_ms: u64,
    input_sha256: String,
}

impl StartOwner {
    fn validate(&self) -> Result<()> {
        self.control_root.validate()?;
        kasumi_types::validate_name(&self.principal)?;
        kasumi_types::validate_sha256(&self.input_sha256)?;
        ensure!(
            !self.operation_id.is_nil()
                && !self.phase_id.is_nil()
                && !self.attempt_id.is_nil()
                && !self.command_id.is_nil()
                && self.node_id != 0
                && self.not_after_ms != 0,
            "target Start owner identity is incomplete"
        );
        Ok(())
    }

    pub(crate) fn from_marked_phase(
        root: &ControlSigningRoot,
        phase: &RecoveryPhaseRecord,
    ) -> Result<Self> {
        root.validate()?;
        phase.validate()?;
        let RecoveryDispatch::Target { node_id, request } = &phase.input else {
            anyhow::bail!("Start owner requires a target dispatch");
        };
        ensure!(
            phase.phase == RecoveryPhase::Initialize
                && matches!(
                    request.step,
                    TargetRuntimeStep::Start(TargetReplicaInput::Quorum(_))
                ),
            "Start owner requires Initialize-phase Start(Quorum)"
        );
        let attempt = phase
            .effect_attempts
            .get(&RecoveryEffect::TargetCommand)
            .context("Start owner requires committed TargetCommand marker")?;
        ensure!(
            attempt.input_sha256 == phase.input_sha256
                && attempt.begun_revision > phase.prepared_revision,
            "Start owner marker differs from frozen input"
        );
        let owner = Self {
            control_root: root.clone(),
            operation_id: phase.operation_id,
            phase_id: phase.phase_id,
            attempt_id: attempt.attempt_id,
            node_id: *node_id,
            principal: phase.principal.clone(),
            command_id: request.command_id,
            not_after_ms: request.not_after_ms,
            input_sha256: phase.input_sha256.clone(),
        };
        owner.validate()?;
        Ok(owner)
    }
}

/// Exact historical Initialize identity. Parsing a marked phase is structural
/// only; the caller must first authenticate fresh Control readback and reserve
/// the same packet in the independent receiver journal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InitializeOwner {
    control_root: ControlSigningRoot,
    operation_id: Uuid,
    phase_id: Uuid,
    previous_phase_id: Uuid,
    sequence: u64,
    attempt_id: Uuid,
    node_id: u64,
    principal: String,
    command_id: Uuid,
    not_after_ms: u64,
    input_sha256: String,
}

impl InitializeOwner {
    fn validate(&self) -> Result<()> {
        self.control_root.validate()?;
        kasumi_types::validate_name(&self.principal)?;
        kasumi_types::validate_sha256(&self.input_sha256)?;
        ensure!(
            !self.operation_id.is_nil()
                && !self.phase_id.is_nil()
                && !self.previous_phase_id.is_nil()
                && self.previous_phase_id != self.phase_id
                && self.sequence > 1
                && !self.attempt_id.is_nil()
                && !self.command_id.is_nil()
                && self.node_id != 0
                && self.not_after_ms != 0,
            "target Initialize owner identity is incomplete"
        );
        Ok(())
    }

    pub(crate) fn from_marked_phase(
        root: &ControlSigningRoot,
        phase: &RecoveryPhaseRecord,
    ) -> Result<Self> {
        root.validate()?;
        phase.validate()?;
        let RecoveryDispatch::Target { node_id, request } = &phase.input else {
            anyhow::bail!("Initialize owner requires a target dispatch");
        };
        ensure!(
            phase.phase == RecoveryPhase::Initialize
                && matches!(request.step, TargetRuntimeStep::Initialize(_))
                && phase.outcome.is_none()
                && request.not_after_ms <= phase.original_credential_expires_at_ms,
            "Initialize owner requires unresolved Initialize dispatch"
        );
        let attempt = phase
            .effect_attempts
            .get(&RecoveryEffect::TargetCommand)
            .context("Initialize owner requires committed TargetCommand marker")?;
        let previous_phase_id = phase
            .previous_phase
            .context("Initialize owner requires a Control predecessor")?;
        ensure!(
            attempt.input_sha256 == phase.input_sha256
                && attempt.begun_revision > phase.prepared_revision,
            "Initialize owner marker differs from frozen input"
        );
        let owner = Self {
            control_root: root.clone(),
            operation_id: phase.operation_id,
            phase_id: phase.phase_id,
            previous_phase_id,
            sequence: phase.sequence,
            attempt_id: attempt.attempt_id,
            node_id: *node_id,
            principal: phase.principal.clone(),
            command_id: request.command_id,
            not_after_ms: request.not_after_ms,
            input_sha256: phase.input_sha256.clone(),
        };
        owner.validate()?;
        Ok(owner)
    }
}

/// Required first-release state. The former four-field Start row and a row
/// with a missing Initialize ownership state cannot be decoded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum InitializeOwnership {
    Prepared,
    Owned(InitializeOwner),
}

/// Required-owner replacement format for the pre-Raft intent row. No legacy
/// three-field value or missing owner can deserialize into this record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InitialTargetIntent {
    origin: TargetOrigin,
    intent: LifecycleIntent,
    input: TargetQuorumInput,
    start_owner: StartOwner,
    initialize_ownership: InitializeOwnership,
}

impl InitialTargetIntent {
    pub(crate) fn prepared(
        origin: TargetOrigin,
        intent: LifecycleIntent,
        input: TargetQuorumInput,
        root: &ControlSigningRoot,
        installed_root: &ControlSigningRoot,
        phase: &RecoveryPhaseRecord,
    ) -> Result<Self> {
        installed_root.validate()?;
        ensure!(
            root == installed_root,
            "target Start owner differs from installed Control root"
        );
        let start_owner = StartOwner::from_marked_phase(root, phase)?;
        let row = Self {
            origin,
            intent,
            input,
            start_owner,
            initialize_ownership: InitializeOwnership::Prepared,
        };
        row.validate()?;
        Ok(row)
    }

    fn validate(&self) -> Result<()> {
        self.start_owner.validate()?;
        self.origin
            .accepts_phase(&self.intent, LifecyclePhase::Initialize)?;
        ensure!(
            self.start_owner.control_root.control_incarnation == self.intent.control_incarnation
                && self.start_owner.command_id == self.intent.request.command_id
                && self.start_owner.principal == self.intent.original_principal
                && self.start_owner.node_id != 0
                && self
                    .intent
                    .request
                    .target_nodes
                    .contains_key(&self.start_owner.node_id)
                && self.input.origin_sha256 == self.origin.digest()?
                && self.intent.request.phase_input_sha256 == self.input.digest()?,
            "target Start owner differs from original initialization intent"
        );
        kasumi_serving::verify_target_materializations(&self.origin, &self.input.materialized)?;
        let request = TargetRuntimeRequest {
            tenant: self.intent.request.tenant.clone(),
            command_id: self.start_owner.command_id,
            not_after_ms: self.start_owner.not_after_ms,
            step: TargetRuntimeStep::Start(TargetReplicaInput::Quorum(self.input.clone())),
        };
        request.validate()?;
        ensure!(
            self.start_owner.input_sha256
                == staged_digest(&RecoveryDispatch::Target {
                    node_id: self.start_owner.node_id,
                    request: Box::new(request),
                })?
                .0,
            "target Start owner changed frozen dispatch"
        );
        if let InitializeOwnership::Owned(owner) = &self.initialize_ownership {
            owner.validate()?;
            ensure!(
                owner.control_root == self.start_owner.control_root
                    && owner.operation_id == self.start_owner.operation_id
                    && owner.phase_id != self.start_owner.phase_id
                    && owner.attempt_id != self.start_owner.attempt_id
                    && owner.node_id == self.start_owner.node_id
                    && Some(&owner.node_id) == self.origin.input.voters.keys().next()
                    && owner.principal == self.intent.original_principal
                    && owner.command_id == self.intent.request.command_id,
                "target Initialize owner differs from Start, installed placement, or lifecycle intent"
            );
            let request = TargetRuntimeRequest {
                tenant: self.intent.request.tenant.clone(),
                command_id: owner.command_id,
                not_after_ms: owner.not_after_ms,
                step: TargetRuntimeStep::Initialize(self.input.clone()),
            };
            request.validate()?;
            ensure!(
                owner.input_sha256
                    == staged_digest(&RecoveryDispatch::Target {
                        node_id: owner.node_id,
                        request: Box::new(request),
                    })?
                    .0,
                "target Initialize owner changed frozen dispatch"
            );
        }
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_RECORD,
            "target initial intent exceeds custody record bound"
        );
        Ok(())
    }

    pub(crate) fn encoded(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(serde_json::to_vec(self)?)
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_RECORD,
            "target initial intent exceeds bound"
        );
        let row: Self = serde_json::from_slice(bytes)?;
        row.validate()?;
        ensure!(
            serde_json::to_vec(&row)? == bytes,
            "noncanonical target initial intent"
        );
        Ok(row)
    }
}

/// Local observation only. Neither variant proves a failed Start, a live
/// worker after restart, or absence/presence of committed Raft membership.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum StartIntentStatus {
    NoLocalIntent,
    PreparedIntentOnly,
    OwnedWithoutAppliedProof,
}

/// These are local custody observations only; neither an owner nor a prepared
/// row establishes committed and locally applied membership.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum InitializeIntentStatus {
    NoLocalIntent,
    PreparedIntentOnly,
    OwnedWithoutAppliedProof,
}

/// Pure decision to be used only inside the custody writer's atomic mutation
/// owner. `AlreadyBound` is historical equality, never another child grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PreparedBinding {
    Write(Vec<u8>),
    AlreadyBound,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum InitializeBinding {
    Write(Vec<u8>),
    AlreadyBound,
}

pub(crate) fn decide_prepared_binding(
    existing: Option<&[u8]>,
    proposed: &InitialTargetIntent,
    installed_root: &ControlSigningRoot,
) -> Result<PreparedBinding> {
    installed_root.validate()?;
    ensure!(
        &proposed.start_owner.control_root == installed_root,
        "target Start owner differs from installed Control root"
    );
    ensure!(
        proposed.initialize_ownership == InitializeOwnership::Prepared,
        "Start cannot select the Initialize owner"
    );
    let encoded = proposed.encoded()?;
    match existing {
        None => Ok(PreparedBinding::Write(encoded)),
        Some(bytes) if InitialTargetIntent::decode(bytes)? == *proposed => {
            Ok(PreparedBinding::AlreadyBound)
        }
        Some(_) => {
            anyhow::bail!("target Start intent belongs to a different exact recovery attempt")
        }
    }
}

/// Pure compare-and-set decision. The future target custody writer must read
/// and commit this transition under its mutation owner before any Raft
/// initialize call. Equality is historical status, never a second grant.
pub(crate) fn decide_initialize_binding(
    existing: Option<&[u8]>,
    owner: &InitializeOwner,
    installed_root: &ControlSigningRoot,
) -> Result<InitializeBinding> {
    installed_root.validate()?;
    owner.validate()?;
    ensure!(
        &owner.control_root == installed_root,
        "Initialize owner differs from installed Control root"
    );
    let bytes = existing.context("Start intent must precede Initialize owner")?;
    let mut row = InitialTargetIntent::decode(bytes)?;
    ensure!(
        &row.start_owner.control_root == installed_root,
        "Start owner differs from installed Control root"
    );
    match row.initialize_ownership.clone() {
        InitializeOwnership::Owned(existing) if existing == *owner => {
            Ok(InitializeBinding::AlreadyBound)
        }
        InitializeOwnership::Owned(_) => {
            anyhow::bail!("target Initialize is owned by a different exact recovery attempt")
        }
        InitializeOwnership::Prepared => {
            row.initialize_ownership = InitializeOwnership::Owned(owner.clone());
            Ok(InitializeBinding::Write(row.encoded()?))
        }
    }
}

fn inspect_bytes(
    bytes: Option<&[u8]>,
    expected: &StartOwner,
    installed_root: &ControlSigningRoot,
) -> Result<StartIntentStatus> {
    installed_root.validate()?;
    expected.validate()?;
    ensure!(
        &expected.control_root == installed_root,
        "target Start status differs from installed Control root"
    );
    let Some(bytes) = bytes else {
        return Ok(StartIntentStatus::NoLocalIntent);
    };
    let row = InitialTargetIntent::decode(bytes)?;
    ensure!(
        &row.start_owner == expected,
        "target Start intent belongs to a different exact recovery attempt"
    );
    Ok(match row.initialize_ownership {
        InitializeOwnership::Prepared => StartIntentStatus::PreparedIntentOnly,
        InitializeOwnership::Owned(_) => StartIntentStatus::OwnedWithoutAppliedProof,
    })
}

fn inspect_initialize_bytes(
    bytes: Option<&[u8]>,
    expected: &InitializeOwner,
    installed_root: &ControlSigningRoot,
) -> Result<InitializeIntentStatus> {
    installed_root.validate()?;
    expected.validate()?;
    ensure!(
        &expected.control_root == installed_root,
        "Initialize status differs from installed Control root"
    );
    let Some(bytes) = bytes else {
        return Ok(InitializeIntentStatus::NoLocalIntent);
    };
    let row = InitialTargetIntent::decode(bytes)?;
    ensure!(
        &row.start_owner.control_root == installed_root,
        "Start owner differs from installed Control root"
    );
    let mut proposed = row.clone();
    proposed.initialize_ownership = InitializeOwnership::Owned(expected.clone());
    proposed.validate()?;
    match row.initialize_ownership {
        InitializeOwnership::Prepared => Ok(InitializeIntentStatus::PreparedIntentOnly),
        InitializeOwnership::Owned(owner) if owner == *expected => {
            Ok(InitializeIntentStatus::OwnedWithoutAppliedProof)
        }
        InitializeOwnership::Owned(_) => {
            anyhow::bail!("target Initialize status belongs to a different exact recovery attempt")
        }
    }
}

/// Read only the independently encrypted custody row. The caller must first
/// authenticate the requested historical Control phase and installed node;
/// this function never opens a generation or returns `Started`/`Initialized`.
pub(crate) fn read_start_intent_status(
    custody: &TenantStore,
    expected: &StartOwner,
    installed_root: &ControlSigningRoot,
) -> Result<StartIntentStatus> {
    let bytes = custody.get_bounded(NAMESPACE, KEY, MAX_RECORD)?;
    inspect_bytes(bytes.as_deref(), expected, installed_root)
}

/// Read-only local owner status. Historical Control and journal authentication
/// must precede this call; every returned variant remains unresolved.
pub(crate) fn read_initialize_intent_status(
    custody: &TenantStore,
    expected: &InitializeOwner,
    installed_root: &ControlSigningRoot,
) -> Result<InitializeIntentStatus> {
    let bytes = custody.get_bounded(NAMESPACE, KEY, MAX_RECORD)?;
    inspect_initialize_bytes(bytes.as_deref(), expected, installed_root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target_completion_machine::tests as fixture;
    use kasumi_types::{RecoveryEffectAttempt, TargetCompletionAttempt};
    use std::collections::BTreeMap;

    fn marked_start() -> (
        TargetOrigin,
        LifecycleIntent,
        TargetQuorumInput,
        ControlSigningRoot,
        RecoveryPhaseRecord,
    ) {
        let origin = fixture::origin();
        let attempt: TargetCompletionAttempt = fixture::attempt(&origin, None, 12, 1, 200, 500);
        let input = attempt.input.quorum;
        let intent = fixture::intent(
            &origin,
            LifecyclePhase::Initialize,
            input.digest().unwrap(),
            9,
            150,
            1_000,
        );
        let root = ControlSigningRoot {
            control_incarnation: intent.control_incarnation,
            public_key: "aa".repeat(32),
        };
        let dispatch = RecoveryDispatch::Target {
            node_id: 1,
            request: Box::new(TargetRuntimeRequest {
                tenant: intent.request.tenant.clone(),
                command_id: intent.request.command_id,
                not_after_ms: 500,
                step: TargetRuntimeStep::Start(TargetReplicaInput::Quorum(input.clone())),
            }),
        };
        let input_sha256 = staged_digest(&dispatch).unwrap().0;
        let phase = RecoveryPhaseRecord {
            operation_id: Uuid::from_u128(700),
            phase_id: Uuid::from_u128(701),
            sequence: 1,
            phase: RecoveryPhase::Initialize,
            completion_scope: None,
            previous_phase: None,
            input: dispatch,
            input_sha256: input_sha256.clone(),
            principal: "operator".into(),
            admitted_at_ms: 150,
            original_credential_expires_at_ms: 1_000,
            prepared_revision: 1,
            effect_attempts: BTreeMap::from([(
                RecoveryEffect::TargetCommand,
                RecoveryEffectAttempt {
                    attempt_id: Uuid::from_u128(702),
                    input_sha256,
                    admitted_at_ms: 151,
                    begun_revision: 2,
                },
            )]),
            activation_acceptance: None,
            outcome: None,
            resolved_revision: None,
        };
        phase.validate().unwrap();
        (origin, intent, input, root, phase)
    }

    fn marked_initialize(start: &RecoveryPhaseRecord) -> RecoveryPhaseRecord {
        let mut phase = start.clone();
        phase.phase_id = Uuid::from_u128(703);
        // Real Control prepares Start on voters 1, 2 and 3 before designated
        // Initialize on voter 1. The local Start is an ancestor, not the
        // Initialize phase's direct predecessor.
        phase.sequence += 3;
        phase.previous_phase = Some(Uuid::from_u128(706));
        phase.prepared_revision = 7;
        let RecoveryDispatch::Target { request, .. } = &mut phase.input else {
            unreachable!()
        };
        let TargetRuntimeStep::Start(TargetReplicaInput::Quorum(input)) = &request.step else {
            unreachable!()
        };
        let input = input.clone();
        request.step = TargetRuntimeStep::Initialize(input);
        request.not_after_ms += 1;
        phase.input_sha256 = staged_digest(&phase.input).unwrap().0;
        let marker = phase
            .effect_attempts
            .get_mut(&RecoveryEffect::TargetCommand)
            .unwrap();
        marker.attempt_id = Uuid::from_u128(704);
        marker.input_sha256 = phase.input_sha256.clone();
        marker.begun_revision = 8;
        phase.validate().unwrap();
        phase
    }

    #[test]
    fn initialize_owner_is_single_winner_and_never_a_membership_proof() {
        let (origin, intent, input, root, start) = marked_start();
        let prepared =
            InitialTargetIntent::prepared(origin, intent, input, &root, &root, &start).unwrap();
        let start_bytes = prepared.encoded().unwrap();
        let initialize = marked_initialize(&start);
        let owner = InitializeOwner::from_marked_phase(&root, &initialize).unwrap();
        assert_ne!(owner.previous_phase_id, prepared.start_owner.phase_id);
        assert_eq!(owner.sequence, start.sequence + 3);
        assert_eq!(
            inspect_initialize_bytes(None, &owner, &root).unwrap(),
            InitializeIntentStatus::NoLocalIntent
        );
        assert_eq!(
            inspect_initialize_bytes(Some(&start_bytes), &owner, &root).unwrap(),
            InitializeIntentStatus::PreparedIntentOnly
        );
        assert!(decide_initialize_binding(None, &owner, &root).is_err());
        let InitializeBinding::Write(owned_bytes) =
            decide_initialize_binding(Some(&start_bytes), &owner, &root).unwrap()
        else {
            panic!("first Initialize owner must be a custody write")
        };
        assert_eq!(
            inspect_initialize_bytes(Some(&owned_bytes), &owner, &root).unwrap(),
            InitializeIntentStatus::OwnedWithoutAppliedProof
        );
        assert_eq!(
            inspect_bytes(Some(&owned_bytes), &prepared.start_owner, &root).unwrap(),
            StartIntentStatus::OwnedWithoutAppliedProof
        );
        assert_eq!(
            decide_initialize_binding(Some(&owned_bytes), &owner, &root).unwrap(),
            InitializeBinding::AlreadyBound
        );
        assert!(decide_prepared_binding(Some(&owned_bytes), &prepared, &root).is_err());
        let mut other = owner.clone();
        other.attempt_id = Uuid::from_u128(705);
        assert!(decide_initialize_binding(Some(&owned_bytes), &other, &root).is_err());
        assert!(inspect_initialize_bytes(Some(&owned_bytes), &other, &root).is_err());
        let mut different_predecessor = owner.clone();
        different_predecessor.previous_phase_id = Uuid::from_u128(707);
        assert!(
            decide_initialize_binding(Some(&owned_bytes), &different_predecessor, &root).is_err()
        );
        let mut old_format: serde_json::Value = serde_json::from_slice(&start_bytes).unwrap();
        old_format
            .as_object_mut()
            .unwrap()
            .remove("initialize_ownership");
        assert!(InitialTargetIntent::decode(&serde_json::to_vec(&old_format).unwrap()).is_err());
    }

    #[test]
    fn initialize_owner_requires_marked_designated_exact_dispatch() {
        let (origin, intent, input, root, start) = marked_start();
        let prepared =
            InitialTargetIntent::prepared(origin, intent, input, &root, &root, &start).unwrap();
        let bytes = prepared.encoded().unwrap();
        let initialize = marked_initialize(&start);
        let owner = InitializeOwner::from_marked_phase(&root, &initialize).unwrap();
        let mut unmarked = initialize.clone();
        unmarked.effect_attempts.clear();
        assert!(InitializeOwner::from_marked_phase(&root, &unmarked).is_err());
        let mut orphan = initialize.clone();
        orphan.previous_phase = None;
        assert!(InitializeOwner::from_marked_phase(&root, &orphan).is_err());
        let mut changed = initialize.clone();
        if let RecoveryDispatch::Target { request, .. } = &mut changed.input {
            request.not_after_ms += 1;
        }
        assert!(InitializeOwner::from_marked_phase(&root, &changed).is_err());
        let mut follower = owner.clone();
        follower.node_id = 2;
        assert!(decide_initialize_binding(Some(&bytes), &follower, &root).is_err());
        let mut changed_phase = owner.clone();
        changed_phase.phase_id = start.phase_id;
        assert!(decide_initialize_binding(Some(&bytes), &changed_phase, &root).is_err());
        let mut changed_root = root.clone();
        changed_root.public_key = "bb".repeat(32);
        assert!(decide_initialize_binding(Some(&bytes), &owner, &changed_root).is_err());
    }

    #[test]
    fn start_owner_is_exact_and_intent_only_is_not_membership() {
        let (origin, intent, input, root, phase) = marked_start();
        let row =
            InitialTargetIntent::prepared(origin, intent, input, &root, &root, &phase).unwrap();
        let owner = row.start_owner.clone();
        let bytes = row.encoded().unwrap();
        assert_eq!(
            decide_prepared_binding(None, &row, &root).unwrap(),
            PreparedBinding::Write(bytes.clone())
        );
        assert_eq!(
            decide_prepared_binding(Some(&bytes), &row, &root).unwrap(),
            PreparedBinding::AlreadyBound
        );
        assert_eq!(
            inspect_bytes(None, &owner, &root).unwrap(),
            StartIntentStatus::NoLocalIntent
        );
        assert_eq!(
            inspect_bytes(Some(&bytes), &owner, &root).unwrap(),
            StartIntentStatus::PreparedIntentOnly
        );
        let mut other = owner.clone();
        other.phase_id = Uuid::from_u128(703);
        assert!(inspect_bytes(Some(&bytes), &other, &root).is_err());
        let mut another_phase = row.clone();
        another_phase.start_owner.phase_id = other.phase_id;
        assert!(decide_prepared_binding(Some(&bytes), &another_phase, &root).is_err());
        other = owner.clone();
        other.attempt_id = Uuid::from_u128(704);
        assert!(inspect_bytes(Some(&bytes), &other, &root).is_err());
        other = owner.clone();
        other.principal = "other-operator".into();
        assert!(inspect_bytes(Some(&bytes), &other, &root).is_err());
        let mut old: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        old.as_object_mut().unwrap().remove("start_owner");
        assert!(inspect_bytes(Some(&serde_json::to_vec(&old).unwrap()), &owner, &root).is_err());
        let mut changed_deadline = row.clone();
        changed_deadline.start_owner.not_after_ms += 1;
        assert!(changed_deadline.encoded().is_err());
        let mut changed_root = row.clone();
        changed_root.start_owner.control_root.control_incarnation = Uuid::from_u128(705);
        assert!(changed_root.encoded().is_err());
        let mut changed_key = row.clone();
        changed_key.start_owner.control_root.public_key = "bb".repeat(32);
        assert!(changed_key.encoded().is_ok());
        assert!(decide_prepared_binding(None, &changed_key, &root).is_err());
        assert!(
            inspect_bytes(
                Some(&changed_key.encoded().unwrap()),
                &changed_key.start_owner,
                &root
            )
            .is_err()
        );
        let mut changed_quorum = row.clone();
        changed_quorum.input.origin_sha256 = "bb".repeat(32);
        assert!(changed_quorum.encoded().is_err());
        let mut forged_materialization = row.clone();
        forged_materialization
            .input
            .materialized
            .get_mut(&1)
            .unwrap()
            .signature = "00".repeat(64);
        forged_materialization.intent.request.phase_input_sha256 =
            forged_materialization.input.digest().unwrap();
        forged_materialization.intent.request_sha256 =
            staged_digest(&forged_materialization.intent.request)
                .unwrap()
                .0;
        forged_materialization.start_owner.input_sha256 =
            staged_digest(&RecoveryDispatch::Target {
                node_id: forged_materialization.start_owner.node_id,
                request: Box::new(TargetRuntimeRequest {
                    tenant: forged_materialization.intent.request.tenant.clone(),
                    command_id: forged_materialization.start_owner.command_id,
                    not_after_ms: forged_materialization.start_owner.not_after_ms,
                    step: TargetRuntimeStep::Start(TargetReplicaInput::Quorum(
                        forged_materialization.input.clone(),
                    )),
                }),
            })
            .unwrap()
            .0;
        forged_materialization
            .origin
            .accepts_phase(&forged_materialization.intent, LifecyclePhase::Initialize)
            .unwrap();
        assert_eq!(
            forged_materialization.intent.request.phase_input_sha256,
            forged_materialization.input.digest().unwrap()
        );
        assert!(
            kasumi_serving::verify_target_materializations(
                &forged_materialization.origin,
                &forged_materialization.input.materialized
            )
            .is_err()
        );
        assert!(forged_materialization.encoded().is_err());
    }

    #[test]
    fn marker_and_frozen_request_are_required() {
        let (origin, intent, input, root, phase) = marked_start();
        let mut unmarked = phase.clone();
        unmarked.effect_attempts.clear();
        assert!(
            InitialTargetIntent::prepared(
                origin.clone(),
                intent.clone(),
                input.clone(),
                &root,
                &root,
                &unmarked
            )
            .is_err()
        );
        let mut changed = phase.clone();
        if let RecoveryDispatch::Target { request, .. } = &mut changed.input {
            request.not_after_ms += 1;
        }
        assert!(
            InitialTargetIntent::prepared(
                origin.clone(),
                intent.clone(),
                input.clone(),
                &root,
                &root,
                &changed
            )
            .is_err()
        );
        let mut substituted = root.clone();
        substituted.public_key = "bb".repeat(32);
        assert!(
            InitialTargetIntent::prepared(
                origin.clone(),
                intent.clone(),
                input.clone(),
                &substituted,
                &root,
                &phase
            )
            .is_err()
        );
        let row =
            InitialTargetIntent::prepared(origin, intent, input, &root, &root, &phase).unwrap();
        let mut noncanonical = row.encoded().unwrap();
        noncanonical.push(b' ');
        assert!(inspect_bytes(Some(&noncanonical), &row.start_owner, &root).is_err());
    }
}
