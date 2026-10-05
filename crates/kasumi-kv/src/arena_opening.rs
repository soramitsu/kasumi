//! Fixed construction custody; the caller records failure before disposal.
use super::*;
use crate::native_backend::{DisposalObservation, dispose_slot};
#[cfg(test)]
use std::panic::{AssertUnwindSafe, catch_unwind};

pub(crate) struct ArenaOpening<R> {
    backend: Option<BackendRef>,
    roll: Option<R>,
    boxed_roll: Option<Box<dyn DirectoryArenaRoll>>,
    admission: Option<Arc<dyn StorageAdmission>>,
    writer: Option<Mutex<Writer>>,
    header: Option<Mutex<[u8; HEADER_BYTES]>>,
    lease: Option<NativeResidentLease>,
    completed: Option<DirectoryArenaBackend>,
    disposal: [DisposalObservation; 7],
}
impl<R> Default for ArenaOpening<R> {
    fn default() -> Self {
        Self {
            backend: None,
            roll: None,
            boxed_roll: None,
            admission: None,
            writer: None,
            header: None,
            lease: None,
            completed: None,
            disposal: std::array::from_fn(|_| DisposalObservation::default()),
        }
    }
}
impl<R: DirectoryArenaRoll + 'static> ArenaOpening<R> {
    pub(crate) const OBSERVATIONS: usize = 7;
    pub(crate) fn build(
        &mut self,
        backend: BackendRef,
        roll: R,
        admission: Arc<dyn StorageAdmission>,
        group_id: [u8; 16],
    ) -> Result<(), CoreError> {
        assert!(self.backend.is_none() && self.completed.is_none());
        self.backend = Some(backend);
        self.roll = Some(roll);
        self.admission = Some(admission);
        let admission = self.admission.as_ref().unwrap();
        check_owner(admission)?;
        self.lease = Some(
            admission
                .reserve_workspace(DirectoryArenaBackend::request_bytes::<R>())
                .map(NativeResidentLease::new)?,
        );
        check_owner(admission)?;
        self.boxed_roll = Some(Box::new(self.roll.take().unwrap()));
        self.writer = Some(crate::native_sync::mutex(
            Writer::default(),
            self.lease.as_ref().unwrap(),
        ));
        self.header = Some(crate::native_sync::mutex(
            [0; HEADER_BYTES],
            self.lease.as_ref().unwrap(),
        ));
        self.completed = Some(DirectoryArenaBackend {
            backend: self.backend.take().unwrap(),
            roll: self.boxed_roll.take().unwrap(),
            admission: self.admission.take().unwrap(),
            group_id,
            writer: self.writer.take().unwrap(),
            read_header: self.header.take().unwrap(),
            max_pages: MAX_PAGES,
            pages_read: AtomicU64::new(0),
            pages_written: AtomicU64::new(0),
            syncs: AtomicU64::new(0),
            _lease: self.lease.take(),
        });
        Ok(())
    }
    pub(crate) fn take_completed(&mut self) -> Option<DirectoryArenaBackend> {
        self.completed.take()
    }
    pub(crate) fn complete(&self) -> bool {
        self.backend.is_none()
            && self.roll.is_none()
            && self.boxed_roll.is_none()
            && self.admission.is_none()
            && self.writer.is_none()
            && self.header.is_none()
            && self.lease.is_none()
            && self.completed.is_none()
            && self.disposal.iter().all(|outcome| {
                matches!(
                    outcome,
                    DisposalObservation::NotEntered | DisposalObservation::Returned
                )
            })
    }
    pub(crate) fn adopt(&mut self, body: DirectoryArenaBackend) {
        assert!(self.completed.is_none() && self.backend.is_none());
        self.completed = Some(body);
    }
    pub(crate) fn dispose(&mut self) -> bool {
        if let Some(body) = self.completed.take() {
            let DirectoryArenaBackend {
                backend,
                roll,
                admission,
                writer,
                read_header,
                _lease,
                ..
            } = body;
            self.backend = Some(backend);
            self.boxed_roll = Some(roll);
            self.admission = Some(admission);
            self.writer = Some(writer);
            self.header = Some(read_header);
            self.lease = _lease;
        }
        // Each operation consumes only its own original slot. In particular
        // the original grant is outside every arbitrary roll destructor.
        dispose_slot(&mut self.roll, &mut self.disposal[0])
            && dispose_slot(&mut self.boxed_roll, &mut self.disposal[1])
            && dispose_slot(&mut self.writer, &mut self.disposal[2])
            && dispose_slot(&mut self.header, &mut self.disposal[3])
            && dispose_slot(&mut self.backend, &mut self.disposal[4])
            && dispose_slot(&mut self.admission, &mut self.disposal[5])
            && dispose_slot(&mut self.lease, &mut self.disposal[6])
    }
    pub(crate) fn with_observation<T>(
        &self,
        index: usize,
        inspect: impl FnOnce(crate::retained::TerminalObservation<'_, std::convert::Infallible>) -> T,
    ) -> T {
        self.disposal[index].with_observation(inspect)
    }
}
impl<R> Drop for ArenaOpening<R> {
    fn drop(&mut self) {
        // An abandoned stage has no authority to declare actual disposal.
        // Preserve its exact remaining objects and original paid diagnostics.
        macro_rules! retain { ($($field:ident),*) => { $(
            if let Some(value) = self.$field.take() { std::mem::forget(value); }
        )* }; }
        retain!(
            backend, roll, boxed_roll, admission, writer, header, lease, completed
        );
        std::mem::forget(std::mem::replace(
            &mut self.disposal,
            std::array::from_fn(|_| DisposalObservation::default()),
        ));
    }
}

#[cfg(test)]
pub(crate) struct ArenaOpeningFailure<R> {
    original: CoreError,
    pub(crate) stage: ArenaOpening<R>,
}
#[cfg(test)]
impl<R> ArenaOpeningFailure<R> {
    pub(crate) fn original_error(&self) -> &CoreError {
        &self.original
    }
}
#[cfg(test)]
impl<R: DirectoryArenaRoll + 'static> std::fmt::Debug for ArenaOpeningFailure<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArenaOpeningFailure")
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
pub(super) fn fixture_new<R: DirectoryArenaRoll + 'static>(
    backend: Arc<dyn SegmentGroupBackend>,
    roll: R,
    admission: Arc<dyn StorageAdmission>,
    group_id: [u8; 16],
) -> Result<DirectoryArenaBackend, ArenaOpeningFailure<R>> {
    let mut stage = ArenaOpening::default();
    let result = catch_unwind(AssertUnwindSafe(|| {
        stage.build(
            BackendRef::Original(crate::native_backend::OriginalBackend::component_fixture(
                backend,
            )),
            roll,
            admission,
            group_id,
        )
    }))
    .unwrap_or_else(|original| Err(CoreError::panicked(crate::core::CorePanic::new(original))));
    match result {
        Ok(()) => Ok(stage.take_completed().unwrap()),
        Err(original) => {
            let _ = stage.dispose();
            Err(ArenaOpeningFailure { original, stage })
        }
    }
}
