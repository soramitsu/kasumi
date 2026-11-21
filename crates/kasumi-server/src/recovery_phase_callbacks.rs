//! A target's credential is bound to its own return TLS connection. Only the
//! dispatching Control member can associate that reader with a live invocation.
use kasumi_engine::{Database, ResponseFence, TargetSigner};
use kasumi_types::{
    Action, Error, ErrorCode, LifecycleNode, RequestContext, Result, SignedTargetWriterChallenge,
    TargetReplicaInput, TargetRuntimeRequest, TargetRuntimeStep,
};
use std::{
    collections::{BTreeMap, btree_map::Entry},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::time::Instant;
use uuid::Uuid;

#[derive(Clone, Copy)]
pub(crate) enum Observation {
    Intent(Uuid),
    Phase { operation: Uuid, phase: Uuid },
    Writer(Uuid),
}

#[derive(Default)]
pub(crate) struct PhaseCallbacks(Mutex<BTreeMap<(u64, Uuid), Arc<PhaseCallback>>>);

pub(crate) struct PhaseCallback {
    node: LifecycleNode,
    command: Uuid,
    historical_intent: Option<Uuid>,
    phases: Vec<(Uuid, Uuid)>,
    original: RequestContext,
    fence: ResponseFence<'static>,
    deadline: Instant,
    active: AtomicBool,
}
pub(crate) struct OpenPhase<'a> {
    callbacks: &'a PhaseCallbacks,
    callback: Arc<PhaseCallback>,
}
impl Drop for OpenPhase<'_> {
    fn drop(&mut self) {
        self.callback.active.store(false, Ordering::Release);
        self.callbacks
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&(self.callback.node.node_id, self.callback.command));
    }
}
impl PhaseCallbacks {
    pub(crate) fn open(
        &self,
        database: &Arc<Database>,
        original: &RequestContext,
        node: &LifecycleNode,
        request: &TargetRuntimeRequest,
        phase: (Uuid, Uuid),
        deadline: Instant,
    ) -> Result<OpenPhase<'_>> {
        let mut fence = database.admitted_response_fence(original)?;
        fence.retain_response_bytes(8192)?;
        let mut phases = vec![phase];
        let mut historical_intent = None;
        if let TargetRuntimeStep::Start(TargetReplicaInput::InitialMembershipStatus(input))
        | TargetRuntimeStep::InspectInitialMembership(input) = &request.step
        {
            historical_intent = Some(input.original_intent.request.command_id);
            for record in input
                .starts
                .values()
                .chain(std::iter::once(&input.initialize))
            {
                if record.operation_id != phase.0 {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "foreign historical recovery phase",
                    ));
                }
                phases.push((record.operation_id, record.phase_id));
            }
        }
        let mut live = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if live.len() >= 64 {
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                "target observation concurrency limit",
            ));
        }
        let Entry::Vacant(slot) = live.entry((node.node_id, request.command_id)) else {
            return Err(Error::new(
                ErrorCode::Unavailable,
                "target dispatch is already active",
            ));
        };
        let callback = Arc::new(PhaseCallback {
            node: node.clone(),
            command: request.command_id,
            historical_intent,
            phases,
            original: original.clone(),
            fence,
            deadline,
            active: AtomicBool::new(true),
        });
        slot.insert(callback.clone());
        Ok(OpenPhase {
            callbacks: self,
            callback,
        })
    }

    pub(crate) fn find(
        &self,
        reader: &RequestContext,
        peer: &[u8; 32],
        observation: Observation,
        database: &Database,
    ) -> Result<Option<Arc<PhaseCallback>>> {
        let certificate = hex::encode(peer);
        let live = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let mut matches = live.values().filter(|c| {
            c.node.principal == reader.principal
                && c.node.certificate_sha256 == certificate
                && match observation {
                    Observation::Intent(id) => c.command == id || c.historical_intent == Some(id),
                    Observation::Phase { operation, phase } => {
                        c.phases.contains(&(operation, phase))
                    }
                    Observation::Writer(id) => c.command == id,
                }
        });
        let Some(callback) = matches.next().cloned() else {
            return Ok(None);
        };
        if matches.next().is_some() {
            return Err(Error::new(
                ErrorCode::Conflict,
                "ambiguous target observation",
            ));
        }
        drop(live);
        callback.check(reader, database)?;
        Ok(Some(callback))
    }
}
impl PhaseCallback {
    pub(crate) fn original(&self) -> &RequestContext {
        &self.original
    }
    pub(crate) fn check(&self, reader: &RequestContext, database: &Database) -> Result<()> {
        if !self.active.load(Ordering::Acquire) || Instant::now() >= self.deadline {
            return Err(Error::new(ErrorCode::Unavailable, "target dispatch closed"));
        }
        if reader.scopes.len() != 1 || !reader.scopes.contains(&Action::Read) {
            return Err(Error::new(
                ErrorCode::Forbidden,
                "target observation requires read scope",
            ));
        }
        database
            .engine()
            .authorize(reader, Some("target_recovery_observations"), Action::Read)?;
        database
            .engine()
            .authorize(&self.original, None, Action::Admin)?;
        self.fence.check()
    }
    pub(crate) fn verify_writer(&self, challenge: &SignedTargetWriterChallenge) -> Result<()> {
        if challenge.challenge.lifecycle_command != Some(self.command)
            || challenge.challenge.verifier != self.node.verifier
        {
            return Err(Error::new(
                ErrorCode::Forbidden,
                "writer differs from active target phase",
            ));
        }
        TargetSigner::verify_writer_challenge(challenge, &self.node).map_err(|cause| {
            Error::new(
                ErrorCode::Forbidden,
                "invalid target phase writer attestation",
            )
            .with_physical_source(cause)
        })
    }
}
