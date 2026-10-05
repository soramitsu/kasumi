//! Original lower construction resources stay outside the opening catch.
use super::*;
use crate::arena::ArenaOpening;
use crate::native_backend::{DisposalObservation, OriginalBackend, dispose_slot};
use crate::snapshot_pins::SnapshotPinsOpening;

#[cfg(test)]
#[path = "disk_opening_tests.rs"]
mod tests;

struct DiskTail {
    _writer: SegmentWriter,
    _reclaim: Reclamation,
    _compact: Compaction,
    _warmup: Warmup,
    _auto_warm: AutoWarm,
}

pub(crate) struct DiskOpening {
    original_backend: Option<OriginalBackend>,
    backend: Option<BackendRef>,
    admission: Option<Arc<dyn StorageAdmission>>,
    fixed: Option<NativeResidentLease>,
    replay: Option<NativeResidentLease>,
    root_lease: Option<NativeResidentLease>,
    root_value: Option<Superblock>,
    root_mutex: Option<Mutex<Superblock>>,
    root_backend: Option<BackendRef>,
    root_admission: Option<Arc<dyn StorageAdmission>>,
    owner: Option<NativeOwnedArc<RootOwner>>,
    arena: Option<NativeOwnedArc<DirectoryArenaBackend>>,
    arena_opening: ArenaOpening<NativeOwnedArc<RootOwner>>,
    pins: SnapshotPinsOpening,
    cache: Option<NativeSharedCache>,
    pages: Option<CachedDirectoryBackend<NativeOwnedArc<DirectoryArenaBackend>>>,
    tail: Option<DiskTail>,
    auto_warm: Option<AutoWarm>,
    completed: Option<DiskState>,
    disposal: [DisposalObservation; 16],
}
impl Default for DiskOpening {
    fn default() -> Self {
        Self {
            original_backend: None,
            backend: None,
            admission: None,
            fixed: None,
            replay: None,
            root_lease: None,
            root_value: None,
            root_mutex: None,
            root_backend: None,
            root_admission: None,
            owner: None,
            arena: None,
            arena_opening: ArenaOpening::default(),
            pins: SnapshotPinsOpening::default(),
            cache: None,
            pages: None,
            tail: None,
            auto_warm: None,
            completed: None,
            disposal: std::array::from_fn(|_| DisposalObservation::default()),
        }
    }
}
impl DiskOpening {
    pub(crate) fn create(
        &mut self,
        backend: OriginalBackend,
        admission: Arc<dyn StorageAdmission>,
        group_id: [u8; 16],
        config: CacheConfig,
    ) -> Result<(), CoreError> {
        self.initialize(backend, admission, group_id)?;
        if !matches!(
            select_root(self.backend.as_ref().unwrap().as_ref())?,
            RootSelection::Empty
        ) {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "group already contains a root",
            )));
        }
        let genesis = Superblock::genesis(group_id);
        genesis.visit_census(self.backend.as_ref().unwrap().as_ref(), |_| Ok(()))?;
        let root = genesis.initialized()?;
        self.assemble(
            root.clone(),
            SegmentWriter::new(group_id),
            empty_root(group_id),
            config,
        )?;
        publish_root(self.backend.as_ref().unwrap().as_ref(), &genesis, &root)?;
        self.completed.as_ref().unwrap().owner.check()?;
        Ok(())
    }
    pub(crate) fn open(
        &mut self,
        backend: OriginalBackend,
        admission: Arc<dyn StorageAdmission>,
        group_id: [u8; 16],
        config: CacheConfig,
    ) -> Result<(), CoreError> {
        self.initialize(backend, admission, group_id)?;
        let RootSelection::Selected {
            mut superblock,
            slot,
            mirrored,
        } = select_root(self.backend.as_ref().unwrap().as_ref())?
        else {
            return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
                "group has no initialized root",
            )));
        };
        if superblock.group_id() != &group_id {
            return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
                "group incarnation differs from owner",
            )));
        }
        if superblock.checkpoint().is_some() {
            return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
                "checkpoint-only root is retired",
            )));
        }
        let mut selected = superblock
            .directory()
            .map_or(empty_root(group_id), |commit| commit.root);
        self.assemble(
            superblock.clone(),
            SegmentWriter::new(group_id),
            selected,
            config,
        )?;
        let backend = self.backend.as_ref().unwrap();
        let admission = self.admission.as_ref().unwrap();
        superblock.visit_census(backend.as_ref(), |_| Ok(()))?;
        if !mirrored {
            repair_mirror(backend.as_ref(), &superblock, slot)?;
        }
        if let Some(id) = superblock.pending_directory() {
            recover_directory_intent(backend.as_ref(), admission, group_id, id)?;
            let next = superblock.confirm_directory(id)?;
            publish_root(backend.as_ref(), &superblock, &next)?;
            superblock = next;
        }
        let start = superblock
            .directory()
            .map_or(ReplayStart::GENESIS, |commit| commit.start);
        validate_directory_anchor(backend.as_ref(), group_id, selected, &start)?;
        self.replay = Some(
            admission
                .reserve_workspace(segment::root_replay_workspace_bytes() + LEASE_ALLOWANCE as u64)
                .map(NativeResidentLease::new)?,
        );
        let end = replay_roots(
            backend.as_ref(),
            group_id,
            &start,
            &superblock.log_bounds(),
            |batch| {
                selected = batch.directory_root;
                Ok(())
            },
        )?;
        end.discard_tail(backend.as_ref())?;
        if selected.generation != start.batch_seq {
            let position =
                end.directory_end
                    .ok_or(CoreError::new(crate::CoreErrorCause::Corrupt(
                        "replayed directory has no log position",
                    )))?;
            let commit = DirectoryCommit {
                root: selected,
                start: ReplayStart {
                    position,
                    batch_seq: end.batch_seq,
                    chain: end.chain,
                },
            };
            validate_directory_anchor(backend.as_ref(), group_id, selected, &commit.start)?;
            let next = superblock.install_directory(commit)?;
            publish_root(backend.as_ref(), &superblock, &next)?;
            superblock = next;
        }
        let state = self.completed.as_mut().unwrap();
        state.writer = SegmentWriter::resume(group_id, &end);
        state.selected = selected;
        *state.owner.lock()? = superblock;
        state.finish_recorded_garbage()?;
        let _ = DirectoryReader::new(state.arena.as_ref(), state.owner.admission.clone()).next(
            selected,
            DirectoryKey::table("\0"),
            false,
        )?;
        state.owner.check()?;
        // The original replay grant stays in this preowned stage. Its actual
        // retirement is independent of this returned opening result.
        Ok(())
    }
    fn initialize(
        &mut self,
        backend: OriginalBackend,
        admission: Arc<dyn StorageAdmission>,
        _group_id: [u8; 16],
    ) -> Result<(), CoreError> {
        assert!(self.admission.is_none());
        self.original_backend = Some(backend);
        self.admission = Some(admission);
        self.fixed = Some(fixed_admission(self.admission.as_ref().unwrap())?);
        self.backend = Some(BackendRef::Checked(NativeOwnedArc::new(CheckedGroup::new(
            self.original_backend.take().unwrap(),
            self.admission.as_ref().unwrap().clone(),
        ))));
        Ok(())
    }
    fn assemble(
        &mut self,
        root: Superblock,
        writer: SegmentWriter,
        selected: DirectoryRoot,
        config: CacheConfig,
    ) -> Result<(), CoreError> {
        self.root_value = Some(root);
        let admission = self.admission.as_ref().unwrap();
        self.root_lease = Some(
            admission
                .reserve_workspace(
                    (std::mem::size_of::<RootOwner>()
                        + 2 * std::mem::size_of::<usize>()
                        + 2 * MAX_GARBAGE * std::mem::size_of::<GroupFile>()
                        + LEASE_ALLOWANCE
                        + 2 * ALLOCATION_ALLOWANCE
                        + crate::native_sync::mutex_backing_bytes()) as u64,
                )
                .map(NativeResidentLease::new)?,
        );
        let group_id = *self.root_value.as_ref().unwrap().group_id();
        self.root_mutex = Some(crate::native_sync::mutex(
            self.root_value.take().unwrap(),
            self.root_lease.as_ref().unwrap(),
        ));
        self.owner = Some(NativeOwnedArc::new(RootOwner {
            backend: self.backend.as_ref().unwrap().clone(),
            admission: admission.clone(),
            root: self.root_mutex.take().unwrap(),
            group_id,
            failed: AtomicBool::new(false),
            _lease: self.root_lease.take(),
        }));
        self.arena_opening.build(
            self.backend.as_ref().unwrap().clone(),
            self.owner.as_ref().unwrap().clone(),
            admission.clone(),
            group_id,
        )?;
        self.arena = Some(NativeOwnedArc::new(
            self.arena_opening.take_completed().unwrap(),
        ));
        self.cache = Some(Arc::new(crate::native_sync::mutex(
            NativeCache::new(config, admission.clone()),
            self.fixed.as_ref().unwrap(),
        )));
        self.pins
            .build(admission.clone(), group_id, MAX_PINNED_ROOTS)?;
        self.pages = Some(CachedDirectoryBackend::with_shared_cache(
            self.arena.as_ref().unwrap().clone(),
            admission.clone(),
            group_id,
            self.cache.as_ref().unwrap().clone(),
        ));
        self.auto_warm = Some(AutoWarm::new(self.fixed.as_ref().unwrap())?);
        self.owner.as_ref().unwrap().check()?;
        self.completed = Some(DiskState {
            owner: self.owner.take().unwrap(),
            arena: self.arena.take().unwrap(),
            pages: self.pages.take().unwrap(),
            cache: self.cache.take().unwrap(),
            writer,
            selected,
            pins: self.pins.take_completed().unwrap(),
            reclaim: Reclamation::default(),
            compact: Compaction::default(),
            warmup: Warmup::default(),
            auto_warm: self.auto_warm.take().unwrap(),
            _lease: self.fixed.take(),
        });
        Ok(())
    }
    pub(crate) fn completed(&self) -> Option<&DiskState> {
        self.completed.as_ref()
    }
    pub(crate) fn retire_transients(&mut self) -> bool {
        dispose_slot(&mut self.replay, &mut self.disposal[0])
    }
    pub(crate) fn take_completed(&mut self) -> Option<DiskState> {
        if self.replay.is_some()
            || matches!(
                self.disposal[0],
                DisposalObservation::Entered | DisposalObservation::Panicked(_)
            )
        {
            return None;
        }
        if self.completed.is_some() {
            // These extra aliases cannot destroy their allocation while the
            // completed original owners remain staged here.
            drop(self.backend.take());
            drop(self.admission.take());
        }
        self.completed.take()
    }
    pub(crate) fn adopt(&mut self, state: DiskState) {
        assert!(self.completed.is_none());
        self.completed = Some(state);
    }
    pub(crate) fn observation_count(&self) -> usize {
        16 + ArenaOpening::<NativeOwnedArc<RootOwner>>::OBSERVATIONS
            + SnapshotPinsOpening::OBSERVATIONS
    }
    pub(crate) fn complete(&self) -> bool {
        self.original_backend.is_none()
            && self.backend.is_none()
            && self.admission.is_none()
            && self.fixed.is_none()
            && self.replay.is_none()
            && self.root_lease.is_none()
            && self.root_value.is_none()
            && self.root_mutex.is_none()
            && self.root_backend.is_none()
            && self.root_admission.is_none()
            && self.owner.is_none()
            && self.arena.is_none()
            && self.cache.is_none()
            && self.pages.is_none()
            && self.tail.is_none()
            && self.auto_warm.is_none()
            && self.completed.is_none()
            && self.arena_opening.complete()
            && self.pins.complete()
            && self.disposal.iter().all(|outcome| {
                matches!(
                    outcome,
                    DisposalObservation::NotEntered | DisposalObservation::Returned
                )
            })
    }
    pub(crate) fn with_observation<T>(
        &self,
        index: usize,
        inspect: impl FnOnce(crate::retained::TerminalObservation<'_, std::convert::Infallible>) -> T,
    ) -> T {
        if index < 16 {
            return self.disposal[index].with_observation(inspect);
        }
        let index = index - 16;
        if index < ArenaOpening::<NativeOwnedArc<RootOwner>>::OBSERVATIONS {
            self.arena_opening.with_observation(index, inspect)
        } else {
            self.pins.with_observation(
                index - ArenaOpening::<NativeOwnedArc<RootOwner>>::OBSERVATIONS,
                inspect,
            )
        }
    }
    pub(crate) fn dispose(&mut self) -> bool {
        if let Some(state) = self.completed.take() {
            let DiskState {
                owner,
                arena,
                pages,
                cache,
                writer,
                pins,
                reclaim,
                compact,
                warmup,
                auto_warm,
                _lease,
                ..
            } = state;
            self.owner = Some(owner);
            self.arena = Some(arena);
            self.pages = Some(pages);
            self.cache = Some(cache);
            self.pins.adopt(pins);
            self.fixed = _lease;
            self.tail = Some(DiskTail {
                _writer: writer,
                _reclaim: reclaim,
                _compact: compact,
                _warmup: warmup,
                _auto_warm: auto_warm,
            });
        }
        if !self.retire_transients()
            || !dispose_slot(&mut self.tail, &mut self.disposal[1])
            || !dispose_slot(&mut self.auto_warm, &mut self.disposal[15])
            || !dispose_slot(&mut self.pages, &mut self.disposal[2])
            || !dispose_slot(&mut self.cache, &mut self.disposal[3])
            || !self.pins.dispose()
        {
            return false;
        }
        if let Some(arena) = self.arena.as_mut()
            && arena.get_mut().is_none()
        {
            return false;
        }
        if let Some(arena) = self.arena.take() {
            self.disposal[4].run(|| {
                let body = arena
                    .try_unwrap()
                    .ok()
                    .expect("exclusive original arena control");
                self.arena_opening.adopt(body);
            });
        }
        if matches!(
            self.disposal[4],
            DisposalObservation::Entered | DisposalObservation::Panicked(_)
        ) || !self.arena_opening.dispose()
        {
            return false;
        }
        if let Some(owner) = self.owner.as_mut() {
            let Some(body) = owner.get_mut() else {
                return false;
            };
            self.root_lease = body._lease.take();
        }
        if let Some(owner) = self.owner.take() {
            self.disposal[5].run(|| {
                let RootOwner {
                    backend,
                    admission,
                    root,
                    ..
                } = owner
                    .try_unwrap()
                    .ok()
                    .expect("exclusive original root control");
                self.root_backend = Some(backend);
                self.root_admission = Some(admission);
                self.root_mutex = Some(root);
            });
        }
        if matches!(
            self.disposal[5],
            DisposalObservation::Entered | DisposalObservation::Panicked(_)
        ) {
            return false;
        }
        dispose_slot(&mut self.root_value, &mut self.disposal[6])
            && dispose_slot(&mut self.root_mutex, &mut self.disposal[7])
            && dispose_slot(&mut self.root_backend, &mut self.disposal[8])
            && dispose_slot(&mut self.root_admission, &mut self.disposal[9])
            && dispose_slot(&mut self.root_lease, &mut self.disposal[10])
            && dispose_slot(&mut self.backend, &mut self.disposal[11])
            && dispose_slot(&mut self.original_backend, &mut self.disposal[14])
            && dispose_slot(&mut self.admission, &mut self.disposal[12])
            && dispose_slot(&mut self.fixed, &mut self.disposal[13])
    }
}
impl Drop for DiskOpening {
    fn drop(&mut self) {
        macro_rules! retain { ($($field:ident),*) => { $(
            if let Some(value) = self.$field.take() { std::mem::forget(value); }
        )* }; }
        retain!(
            original_backend,
            backend,
            admission,
            fixed,
            replay,
            root_lease,
            root_value,
            root_mutex,
            root_backend,
            root_admission,
            owner,
            arena,
            cache,
            pages,
            tail,
            auto_warm,
            completed
        );
        std::mem::forget(std::mem::replace(
            &mut self.disposal,
            std::array::from_fn(|_| DisposalObservation::default()),
        ));
        // Component stages independently preserve their exact remaining slots.
    }
}

#[cfg(test)]
pub(crate) struct DiskOpeningFailure {
    original: Result<(), CoreError>,
    pub(crate) stage: DiskOpening,
}
#[cfg(test)]
impl DiskOpeningFailure {
    pub(crate) fn original_error(&self) -> Option<&CoreError> {
        self.original.as_ref().err()
    }
}
#[cfg(test)]
impl std::fmt::Debug for DiskOpeningFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiskOpeningFailure")
            .field("original", &self.original)
            .field("disposal_complete", &self.stage.complete())
            .finish_non_exhaustive()
    }
}
#[cfg(test)]
#[allow(
    clippy::result_large_err,
    reason = "The fixture retains the actual opening and cleanup inline until observed disposal."
)]
pub(super) fn fixture(
    backend: Arc<dyn SegmentGroupBackend>,
    admission: Arc<dyn StorageAdmission>,
    group_id: [u8; 16],
    config: CacheConfig,
    create: bool,
) -> Result<DiskState, DiskOpeningFailure> {
    let mut stage = DiskOpening::default();
    let backend = OriginalBackend::component_fixture(backend);
    let result = catch_unwind(AssertUnwindSafe(|| {
        if create {
            stage.create(backend, admission, group_id, config)
        } else {
            stage.open(backend, admission, group_id, config)
        }
    }))
    .unwrap_or_else(|original| Err(CoreError::panicked(CorePanic::new(original))));
    match result {
        Ok(()) => {
            if stage.retire_transients() {
                Ok(stage.take_completed().unwrap())
            } else {
                Err(DiskOpeningFailure {
                    original: Ok(()),
                    stage,
                })
            }
        }
        Err(original) => {
            let _ = stage.dispose();
            Err(DiskOpeningFailure {
                original: Err(original),
                stage,
            })
        }
    }
}
