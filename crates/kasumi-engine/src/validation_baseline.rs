//! Closed continuity inputs. A failed current acquisition is never absence.
//! Serialized callers borrow their real apply owner; concurrent validation owns
//! one ordinary public capture until its entire unpublished result is retired.
use super::*;

pub(super) struct ValidationBaseline<'owner> {
    engine: &'owner TenantEngine,
    previous: Option<&'owner Generation>,
}

impl<'owner> ValidationBaseline<'owner> {
    pub(super) fn from_apply(owner: &'owner ApplyOwner<'_>) -> Self {
        Self {
            engine: owner.engine(),
            previous: Some(owner.current()),
        }
    }

    pub(super) fn current_for(&self, engine: &TenantEngine) -> Result<Option<&Generation>> {
        if !std::ptr::eq(self.engine, engine) {
            return Err(Error::new(
                ErrorCode::Corruption,
                "snapshot validation baseline belongs to another engine",
            ));
        }
        Ok(self.previous)
    }
}

pub(super) struct CapturedValidation<'engine> {
    previous: Arc<Generation>,
    engine: &'engine TenantEngine,
}

impl<'engine> CapturedValidation<'engine> {
    pub(super) fn capture(engine: &'engine TenantEngine) -> Result<Self> {
        Ok(Self {
            previous: engine.generation()?,
            engine,
        })
    }

    pub(super) fn baseline(&self) -> ValidationBaseline<'_> {
        ValidationBaseline {
            engine: self.engine,
            previous: Some(&self.previous),
        }
    }
}

// This owner, not the waiting async future, accompanies the blocking worker.
// The old generation retires before the actual engine alias.
pub(super) struct OwnedValidation {
    previous: Arc<Generation>,
    engine: Arc<TenantEngine>,
}

impl OwnedValidation {
    pub(super) fn capture(engine: Arc<TenantEngine>) -> Result<Self> {
        Ok(Self {
            previous: engine.generation()?,
            engine,
        })
    }

    pub(super) fn engine(&self) -> &TenantEngine {
        &self.engine
    }

    pub(super) fn baseline(&self) -> ValidationBaseline<'_> {
        ValidationBaseline {
            engine: &self.engine,
            previous: Some(&self.previous),
        }
    }
}

// Only this constructor can create the absence baseline. It constructs the
// actual engine; it cannot reinterpret a sealed or inaccessible existing engine.
pub(super) struct UninitializedEngine {
    engine: TenantEngine,
}

impl UninitializedEngine {
    pub(super) fn new(state: &TenantState) -> Result<Self> {
        Ok(Self {
            engine: TenantEngine {
                access: std::sync::OnceLock::new(),
                snapshot_store: std::sync::OnceLock::new(),
                audit_maintenance: Mutex::new(None),
                leases: lease_retention::LeaseManager::default(),
                tenant: state.tenant.clone(),
                incarnation: state.incarnation.clone(),
                revision_base: state.revision_base,
                restoration_identity: staged_digest(&(
                    &state.restored_from,
                    &state.restore_lineage,
                ))?
                .0,
                bootstrap_sha256: std::sync::OnceLock::new(),
                application_sources: std::sync::OnceLock::new(),
                apply_lock: Mutex::new(()),
                #[cfg(any(test, feature = "test-utils"))]
                sealed_restore_observation: Mutex::new(None),
                current: ArcSwapOption::empty(),
            },
        })
    }

    pub(super) fn engine(&self) -> &TenantEngine {
        &self.engine
    }

    pub(super) fn baseline(&self) -> ValidationBaseline<'_> {
        ValidationBaseline {
            engine: &self.engine,
            previous: None,
        }
    }

    pub(super) fn finish(self, generation: Generation) -> TenantEngine {
        self.engine.publish_generation(Some(Arc::new(generation)));
        self.engine
    }
}
