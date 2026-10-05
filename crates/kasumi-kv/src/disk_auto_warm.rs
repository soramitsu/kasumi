//! Idempotent local scheduling for the existing bounded warm-up traversal.
//!
//! Completed parked polls compare only admitted inline state, cache accounting
//! and the bounded pin registry without scratch admission or data reads.
//! Provider refusal keeps an incomplete cursor for bounded retries under the
//! lifecycle driver's backoff, including pressure released inside a prior step.

use super::*;
use crate::core::{CacheWarmupState, CacheWarmupStatus};

pub(super) struct AutoWarm {
    state: CacheWarmupState,
    complete: bool,
    provider_limited: bool,
    cumulative_work: u64,
    attempt_generation: Option<u64>,
    byte_limit: u64,
    pinned_bytes: u64,
    evictions: u64,
    // Fixed owner-local scheduling metadata, included in DiskState admission.
    // These copies are never used for data reads or physical reclamation.
    roots: Vec<Option<DirectoryRoot>>,
}

impl AutoWarm {
    pub(super) const fn backing_bytes() -> usize {
        std::mem::size_of::<[Option<DirectoryRoot>; MAX_PINNED_ROOTS]>()
            + (std::mem::align_of::<Option<DirectoryRoot>>() - 1)
            + ALLOCATION_ALLOWANCE
    }

    // The caller's original fixed grant already covers this exact backing.
    pub(super) fn new(_original: &NativeResidentLease) -> Result<Self, CoreError> {
        let mut roots = Vec::new();
        roots
            .try_reserve_exact(MAX_PINNED_ROOTS)
            .map_err(|_| CoreError::new(crate::CoreErrorCause::CapacityDenied))?;
        if roots.capacity() != MAX_PINNED_ROOTS {
            return Err(CoreError::new(crate::CoreErrorCause::CapacityDenied));
        }
        for _ in 0..MAX_PINNED_ROOTS {
            roots.push(None);
        }
        Ok(Self {
            state: CacheWarmupState::Pending,
            complete: false,
            provider_limited: false,
            cumulative_work: 0,
            attempt_generation: None,
            byte_limit: 0,
            pinned_bytes: 0,
            evictions: 0,
            roots,
        })
    }
}

impl DiskState {
    pub(super) fn reset_auto_warm(&mut self) {
        self.warmup = Warmup::default();
        self.auto_warm.state = CacheWarmupState::Pending;
        self.auto_warm.complete = false;
        self.auto_warm.provider_limited = false;
        self.auto_warm.attempt_generation = None;
    }

    pub(crate) fn request_warm_retry(&mut self) -> Result<(), CoreError> {
        self.run(|state| {
            state.reset_auto_warm();
            Ok(())
        })
    }

    /// Before capturing publication pins, include a current root that may
    /// become historical. Later acquisitions are excluded by the owner lock;
    /// concurrent drops remain visible even if they happen during publication.
    pub(super) fn observe_warm_publication_start(&mut self) -> Result<(), CoreError> {
        if self.auto_warm.state == CacheWarmupState::CapacityLimited
            && self
                .pins
                .refresh_baseline(&mut self.auto_warm.roots, self.selected)?
        {
            self.reset_auto_warm();
        }
        Ok(())
    }

    /// Called after temporary candidate aliases and their proof scope drop.
    pub(super) fn observe_warm_publication(&mut self, shrank: bool) -> Result<(), CoreError> {
        if shrank || self.auto_warm.state != CacheWarmupState::CapacityLimited {
            self.reset_auto_warm();
        } else {
            // Do not let pure growth restart an already oversized scan. A
            // newly historical pin or output guard still gets a future retry.
            self.auto_warm.pinned_bytes = self
                .auto_warm
                .pinned_bytes
                .max(self.cache_stats()?.pinned_bytes);
        }
        Ok(())
    }

    fn observe_auto_eligibility(&mut self) -> Result<(), CoreError> {
        self.owner.check()?;
        let (config, stats) = {
            let cache = self
                .cache
                .lock()
                .map_err(|_| CoreError::new(crate::CoreErrorCause::OwnerFailed))?;
            (cache.config(), cache.stats())
        };
        if config.byte_limit == 0 {
            self.warmup = Warmup::default();
            self.auto_warm.state = CacheWarmupState::Disabled;
            self.auto_warm.complete = true;
            self.auto_warm.provider_limited = false;
            self.auto_warm.byte_limit = 0;
            return Ok(());
        }
        if matches!(
            self.auto_warm.state,
            CacheWarmupState::Resident | CacheWarmupState::CapacityLimited
        ) {
            let retired = self
                .pins
                .baseline_retired(&self.auto_warm.roots, self.selected)?;
            if retired
                || stats.pinned_bytes < self.auto_warm.pinned_bytes
                || (self.auto_warm.state == CacheWarmupState::Resident
                    && stats.evictions != self.auto_warm.evictions)
                || config.byte_limit != self.auto_warm.byte_limit
            {
                self.reset_auto_warm();
            }
        } else if self.auto_warm.state == CacheWarmupState::Disabled {
            self.reset_auto_warm();
        }
        self.owner.check()
    }

    fn begin_auto_attempt(&mut self) -> Result<(), CoreError> {
        self.pins
            .refresh_baseline(&mut self.auto_warm.roots, self.selected)?;
        let cache = self
            .cache
            .lock()
            .map_err(|_| CoreError::new(crate::CoreErrorCause::OwnerFailed))?;
        self.auto_warm.state = CacheWarmupState::Running;
        self.auto_warm.complete = false;
        self.auto_warm.provider_limited = false;
        self.auto_warm.attempt_generation = Some(self.selected.generation);
        self.auto_warm.byte_limit = cache.config().byte_limit;
        self.auto_warm.pinned_bytes = cache.stats().pinned_bytes;
        self.auto_warm.evictions = cache.stats().evictions;
        Ok(())
    }

    /// Sample at serialized step/item entrances, before cache candidate/proof
    /// guards exist. An output may become uncached between steps or during a
    /// previous prune item, then retire before the pass completes. Keep that
    /// real pressure signal until a fully resident pass; completion must not
    /// erase a release that can make an earlier refused item fit.
    pub(super) fn observe_warm_step_pins(&mut self) -> Result<(), CoreError> {
        self.auto_warm.pinned_bytes = self
            .auto_warm
            .pinned_bytes
            .max(self.cache_stats()?.pinned_bytes);
        Ok(())
    }

    pub(super) fn begin_manual_warm(&mut self) -> Result<(), CoreError> {
        // A manual call may resume an automatically refused item. Its native
        // cursor still belongs to the incomplete pass, including earlier skips.
        let continuing = self.auto_warm.state == CacheWarmupState::Running
            || (self.auto_warm.state == CacheWarmupState::CapacityLimited
                && !self.auto_warm.complete);
        if !continuing {
            self.begin_auto_attempt()?;
        }
        Ok(())
    }

    pub(super) fn record_auto_warm(
        &mut self,
        progress: &warming::WarmProgress,
    ) -> Result<(), CoreError> {
        self.auto_warm.cumulative_work = self
            .auto_warm
            .cumulative_work
            .saturating_add(progress.work as u64);
        self.auto_warm.provider_limited = progress.provider_limited;
        self.auto_warm.complete = progress.complete;
        if progress.complete {
            self.auto_warm.state = if progress.fully_resident {
                self.auto_warm.provider_limited = false;
                CacheWarmupState::Resident
            } else {
                CacheWarmupState::CapacityLimited
            };
            // Step-local proof Arcs are gone; only real retained outputs count.
            let stats = self.cache_stats()?;
            self.auto_warm.pinned_bytes = if progress.fully_resident {
                stats.pinned_bytes
            } else {
                self.auto_warm.pinned_bytes.max(stats.pinned_bytes)
            };
            self.auto_warm.evictions = stats.evictions;
        } else {
            self.auto_warm.state = if progress.provider_limited {
                CacheWarmupState::CapacityLimited
            } else {
                CacheWarmupState::Running
            };
        }
        Ok(())
    }

    pub(crate) fn warm_if_needed(&mut self, work_limit: usize) -> Result<CacheWarmup, CoreError> {
        self.run(|state| {
            state.observe_auto_eligibility()?;
            if matches!(
                state.auto_warm.state,
                CacheWarmupState::Resident | CacheWarmupState::Disabled
            ) || (state.auto_warm.state == CacheWarmupState::CapacityLimited
                && state.auto_warm.complete)
            {
                return Ok(state.parked_progress());
            }
            if state.auto_warm.state == CacheWarmupState::Pending {
                state.warmup = Warmup::default();
                state.begin_auto_attempt()?;
            }
            match state.warm_inner(work_limit, false) {
                Ok(progress) => {
                    state.record_auto_warm(&progress)?;
                    Ok(CacheWarmup {
                        work: progress.work,
                        complete: progress.complete,
                        fully_resident: progress.fully_resident,
                    })
                }
                Err(error) if error.is_capacity_denied() => {
                    // The exact refused cursor is retained. A lifecycle worker
                    // applies backoff before retrying this bounded item, so an
                    // in-step external pressure release cannot be missed.
                    state.auto_warm.state = CacheWarmupState::CapacityLimited;
                    state.auto_warm.complete = false;
                    state.auto_warm.provider_limited = true;
                    state.auto_warm.pinned_bytes = state
                        .auto_warm
                        .pinned_bytes
                        .max(state.cache_stats()?.pinned_bytes);
                    let work = state.warmup.last_work;
                    state.auto_warm.cumulative_work =
                        state.auto_warm.cumulative_work.saturating_add(work as u64);
                    Ok(CacheWarmup {
                        work,
                        complete: false,
                        fully_resident: false,
                    })
                }
                Err(error) => Err(error),
            }
        })
    }

    fn parked_progress(&self) -> CacheWarmup {
        CacheWarmup {
            work: 0,
            complete: self.auto_warm.complete,
            fully_resident: self.auto_warm.state == CacheWarmupState::Resident,
        }
    }

    pub(crate) fn warm_status(&mut self) -> Result<CacheWarmupStatus, CoreError> {
        self.run(|state| {
            state.observe_auto_eligibility()?;
            let byte_limit = state
                .cache
                .lock()
                .map_err(|_| CoreError::new(crate::CoreErrorCause::OwnerFailed))?
                .config()
                .byte_limit;
            Ok(CacheWarmupStatus {
                state: state.auto_warm.state,
                complete: state.auto_warm.complete,
                provider_limited: state.auto_warm.provider_limited,
                cumulative_work: state.auto_warm.cumulative_work,
                attempt_generation: state.auto_warm.attempt_generation,
                byte_limit,
            })
        })
    }
}
