//! Temporary failure-only telemetry for the existing resolution timeout.
//! It grants no read authority and performs no retry, effect or credential work.
use super::*;

#[derive(Clone, Copy, Debug, Default)]
pub(super) enum Stage {
    #[default]
    Leader,
    PhaseRead,
    SyntheticEffect,
    ResolveWrite,
    StatusRead,
}

#[derive(Default)]
pub(super) struct Progress {
    stage: Stage,
    attempts: [u32; 5],
    selected: Option<(u64, u64)>,
    last_resolved: Option<bool>,
    resolved_reads: u32,
    // The first actual returned wire error is moved here, without cloning or
    // formatting. It owns no Database, generation, ticket or request context.
    first_uncertain: Option<(Stage, Error)>,
}
impl Progress {
    pub(super) fn enter(&mut self, stage: Stage) {
        self.stage = stage;
        let index = match stage {
            Stage::Leader => 0,
            Stage::PhaseRead => 1,
            Stage::SyntheticEffect => 2,
            Stage::ResolveWrite => 3,
            Stage::StatusRead => 4,
        };
        self.attempts[index] = self.attempts[index].saturating_add(1);
    }
    pub(super) fn selected(&mut self, db: &Database) {
        let metrics = db.raft_group().raft().metrics();
        let metrics = metrics.borrow();
        self.selected = Some((metrics.id, metrics.current_term));
    }
    pub(super) fn observed(&mut self, resolved: bool) {
        self.last_resolved = Some(resolved);
        self.resolved_reads = self.resolved_reads.saturating_add(u32::from(resolved));
    }
    pub(super) fn uncertain(&mut self, error: Error) {
        if self.first_uncertain.is_none() {
            self.first_uncertain = Some((self.stage, error));
        }
    }

    #[cold]
    #[inline(never)]
    pub(super) fn fail(
        &self,
        fixture: &Fixture,
        operation: Uuid,
        phase_id: Uuid,
        expected: &RecoveryDispatchOutcome,
        elapsed: tokio::time::error::Elapsed,
    ) -> ! {
        eprintln!(
            "recovery resolution timeout: operation={operation}, phase={phase_id}, stage={:?}, selected_node_term={:?}, attempts[leader,phase,synthetic,resolve,status]={:?}, last_observed_resolved={:?}, resolved_observations={}, first_uncertain={:#?}",
            self.stage,
            self.selected,
            self.attempts,
            self.last_resolved,
            self.resolved_reads,
            self.first_uncertain,
        );
        eprintln!(
            "recovery timeout all-node metrics:\n{}\nvote_transport={}",
            fixture.diagnostics(),
            fixture.vote_probe.diagnostic(),
        );
        // Current phase_key stores the globally unique phase UUID; require its
        // embedded operation and phase as well. These local, unverified views
        // are diagnostic only and cannot resolve the failed quorum operation.
        let key = phase_id.to_string();
        for (node, db) in &fixture.nodes {
            // Atomic diagnostic getters only: do not refresh a key lease or
            // call check_access(), whose failure path may seal the store.
            let stores = db.raft_group().storage_domains();
            eprintln!(
                "recovery timeout key lease: node={node}, application={:?}, custody={:?}",
                stores.application().key_lease_failure_class(),
                stores.custody().store().key_lease_failure_class(),
            );
            match db.engine().generation() {
                Ok(generation) => {
                    let phase =
                        generation
                            .state
                            .recovery_control
                            .phases
                            .get(&key)
                            .filter(|phase| {
                                phase.operation_id == operation && phase.phase_id == phase_id
                            });
                    eprintln!(
                        "recovery timeout LOCAL UNVERIFIED phase: node={node}, revision={}, present={}, outcome_present={}, exact_outcome={:?}, resolved_revision={:?}",
                        generation.state.revision,
                        phase.is_some(),
                        phase.is_some_and(|phase| phase.outcome.is_some()),
                        phase.and_then(|phase| phase
                            .outcome
                            .as_ref()
                            .map(|actual| actual == expected)),
                        phase.and_then(|phase| phase.resolved_revision),
                    );
                }
                Err(error) => eprintln!(
                    "recovery timeout LOCAL UNVERIFIED phase unavailable: node={node}, original={error:#?}"
                ),
            }
        }
        panic!("original recovery phase outcome did not resolve: {elapsed:?}");
    }
}
