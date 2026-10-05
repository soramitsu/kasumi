//! The original registry grant survives each independently observed teardown.
use super::*;
use crate::native_backend::{DisposalObservation, dispose_slot};

pub(crate) struct SnapshotPinsOpening {
    admission: Option<Arc<dyn StorageAdmission>>,
    lease: Option<NativeResidentLease>,
    slots: Option<Vec<Entry>>,
    backing: Option<Box<[Entry]>>,
    registry: Option<SnapshotPins>,
    payload: Option<RegistryInner>,
    disposal: [DisposalObservation; 6],
}
impl Default for SnapshotPinsOpening {
    fn default() -> Self {
        Self {
            admission: None,
            lease: None,
            slots: None,
            backing: None,
            registry: None,
            payload: None,
            disposal: std::array::from_fn(|_| DisposalObservation::default()),
        }
    }
}
impl SnapshotPinsOpening {
    pub(crate) const OBSERVATIONS: usize = 6;
    pub(crate) fn build(
        &mut self,
        admission: Arc<dyn StorageAdmission>,
        group_id: [u8; 16],
        max_pins: usize,
    ) -> Result<(), CoreError> {
        assert!(self.admission.is_none() && self.registry.is_none());
        self.admission = Some(admission);
        let admission = self.admission.as_ref().unwrap();
        admission
            .check_owner()
            .map_err(|_| CoreError::new(crate::CoreErrorCause::OwnerFailed))?;
        if max_pins == 0 {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "snapshot pin limit must be positive",
            )));
        }
        let charge = backing_charge::<Entry>(
            max_pins,
            std::mem::size_of::<RegistryInner>()
                + std::mem::size_of::<SnapshotPins>()
                + ARC_HEADER_BYTES
                + 2 * ALLOCATION_ALLOWANCE
                + LEASE_ALLOWANCE
                + crate::native_sync::mutex_backing_bytes(),
        )?;
        self.lease = Some(
            admission
                .reserve_workspace(charge)
                .map(NativeResidentLease::new)?,
        );
        admission
            .check_owner()
            .map_err(|_| CoreError::new(crate::CoreErrorCause::OwnerFailed))?;
        self.slots = Some(bounded_vec(max_pins)?);
        self.slots.as_mut().unwrap().resize(max_pins, Entry::Empty);
        self.backing = Some(self.slots.take().unwrap().into_boxed_slice());
        self.registry = Some(SnapshotPins {
            inner: RetiredArc::new(RegistryInner {
                admission: admission.clone(),
                group_id,
                max_pins,
                state: crate::native_sync::mutex(
                    RegistryState {
                        slots: self.backing.take().unwrap(),
                        epoch: 0,
                        serial: 0,
                    },
                    self.lease.as_ref().unwrap(),
                ),
                failed: AtomicBool::new(false),
                _lease: LeaseCharge(None),
            }),
        });
        self.registry.as_ref().unwrap().inner.check()?;
        // All fallible work returned. Move this same original grant into the
        // completed registry without replacing its backing or control.
        self.registry
            .as_mut()
            .unwrap()
            .inner
            .get_mut()
            .unwrap()
            ._lease
            .0 = self.lease.take();
        Ok(())
    }
    pub(crate) fn take_completed(&mut self) -> Option<SnapshotPins> {
        // The completed registry still holds this same provider allocation.
        // Release only the extra construction alias before promotion.
        if self.registry.is_some() {
            drop(self.admission.take());
        }
        self.registry.take()
    }
    pub(crate) fn complete(&self) -> bool {
        self.admission.is_none()
            && self.lease.is_none()
            && self.slots.is_none()
            && self.backing.is_none()
            && self.registry.is_none()
            && self.payload.is_none()
            && self.disposal.iter().all(|outcome| {
                matches!(
                    outcome,
                    DisposalObservation::NotEntered | DisposalObservation::Returned
                )
            })
    }
    pub(crate) fn adopt(&mut self, pins: SnapshotPins) {
        assert!(self.registry.is_none());
        self.registry = Some(pins);
    }
    pub(crate) fn dispose(&mut self) -> bool {
        if let Some(registry) = self.registry.as_mut() {
            // A remaining real pin prevents actual registry disposal.
            let Some(payload) = registry.inner.get_mut() else {
                return false;
            };
            if self.lease.is_none() {
                self.lease = payload._lease.0.take();
            }
        }
        if let Some(registry) = self.registry.take() {
            self.disposal[0].run(|| {
                self.payload = Some(
                    registry
                        .inner
                        .into_payload()
                        .expect("exclusive original registry"),
                );
            });
        }
        if matches!(
            self.disposal[0],
            DisposalObservation::Entered | DisposalObservation::Panicked(_)
        ) {
            return false;
        }
        dispose_slot(&mut self.payload, &mut self.disposal[1])
            && dispose_slot(&mut self.slots, &mut self.disposal[2])
            && dispose_slot(&mut self.backing, &mut self.disposal[3])
            && dispose_slot(&mut self.lease, &mut self.disposal[4])
            && dispose_slot(&mut self.admission, &mut self.disposal[5])
    }
    pub(crate) fn with_observation<T>(
        &self,
        index: usize,
        inspect: impl FnOnce(crate::retained::TerminalObservation<'_, std::convert::Infallible>) -> T,
    ) -> T {
        self.disposal[index].with_observation(inspect)
    }
}
impl Drop for SnapshotPinsOpening {
    fn drop(&mut self) {
        macro_rules! retain { ($($field:ident),*) => { $(
            if let Some(value) = self.$field.take() { std::mem::forget(value); }
        )* }; }
        retain!(admission, lease, slots, backing, registry, payload);
        std::mem::forget(std::mem::replace(
            &mut self.disposal,
            std::array::from_fn(|_| DisposalObservation::default()),
        ));
    }
}
#[cfg(test)]
pub(crate) struct SnapshotPinsOpeningFailure {
    original: CoreError,
    pub(crate) stage: SnapshotPinsOpening,
}
#[cfg(test)]
impl SnapshotPinsOpeningFailure {
    pub(crate) fn original_error(&self) -> &CoreError {
        &self.original
    }
}
#[cfg(test)]
impl std::fmt::Debug for SnapshotPinsOpeningFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnapshotPinsOpeningFailure")
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
pub(super) fn fixture_new(
    admission: Arc<dyn StorageAdmission>,
    group_id: [u8; 16],
    max_pins: usize,
) -> Result<SnapshotPins, SnapshotPinsOpeningFailure> {
    let mut stage = SnapshotPinsOpening::default();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        stage.build(admission, group_id, max_pins)
    }))
    .unwrap_or_else(|original| Err(CoreError::panicked(crate::core::CorePanic::new(original))));
    match result {
        Ok(()) => {
            let pins = stage.take_completed().unwrap();
            let _ = stage.dispose();
            Ok(pins)
        }
        Err(original) => {
            let _ = stage.dispose();
            Err(SnapshotPinsOpeningFailure { original, stage })
        }
    }
}
