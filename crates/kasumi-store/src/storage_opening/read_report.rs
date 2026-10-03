//! Shared original reader observations. This allocation has no database parent
//! registration; after positive native disposal diagnostics can outlive census.
use super::*;

pub(crate) struct AdmittedReadReport {
    state: Option<Arc<Mutex<ReaderState>>>,
    charge: ReportCharge,
}
// This field's own Drop preserves allocation-before-credit ordering even if
// an original diagnostic payload panics while the report Arc is destroyed.
#[derive(Clone)]
struct ReportCharge(Option<Arc<crate::DiskMemoryLease>>);
impl Drop for ReportCharge {
    fn drop(&mut self) {
        if let Some(charge) = self.0.take() {
            drop(Arc::into_inner(charge));
        }
    }
}
impl AdmittedReadReport {
    pub(super) fn request_bytes() -> io::Result<u64> {
        crate::disk_memory::add(
            crate::disk_memory::arc::<Mutex<ReaderState>>()?,
            crate::disk_memory::arc::<crate::DiskMemoryLease>()?,
        )
    }
    pub(super) fn new(
        provider: &Arc<dyn NodeDiskMemoryAdmission>,
        state: ReaderState,
    ) -> io::Result<Self> {
        let bytes = Self::request_bytes()?;
        // Reserve before either Arc, while this reader has not begun native
        // work. Routine cleanup never needs a fresh allocation or admission.
        let charge = provider.clone().reserve_installed(bytes)?;
        Ok(Self {
            state: Some(Arc::new(Mutex::new(state))),
            charge: ReportCharge(Some(Arc::new(charge))),
        })
    }
    pub(super) fn new_source(
        provider: &Arc<dyn NodeDiskMemoryAdmission>,
        grant: &mut Option<crate::source_metadata::SourceReportGrant>,
        state: &mut Option<ReaderState>,
    ) -> io::Result<Self> {
        if state.is_none() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        grant
            .as_ref()
            .ok_or(io::ErrorKind::InvalidInput)?
            .require(provider, Self::request_bytes()?)?;
        let charge = grant
            .take()
            .expect("validated source report grant")
            .into_lease();
        Ok(Self {
            state: Some(Arc::new(Mutex::new(
                state.take().expect("retained source state"),
            ))),
            charge: ReportCharge(Some(Arc::new(charge))),
        })
    }
    #[cfg(any(test, feature = "test-utils"))]
    pub(super) fn allocation_addresses(&self) -> [usize; 2] {
        [
            std::ptr::from_ref(self.state.as_deref().unwrap()) as usize,
            std::ptr::from_ref(self.charge.0.as_deref().unwrap()) as usize,
        ]
    }
    pub(crate) fn report(&self) -> NodeReadReport<'_> {
        NodeReadReport { state: self.lock() }
    }
    pub(crate) fn phase(&self) -> NodeReadPhase {
        self.lock().phase
    }
    pub(crate) fn try_routine_diagnostic(&self) -> bool {
        self.try_lock()
            .is_some_and(|state| state.routine_diagnostic_detachable())
    }
    pub(super) fn lock(&self) -> MutexGuard<'_, ReaderState> {
        self.state.as_ref().expect("admitted reader report").lock()
    }
    pub(super) fn try_lock(&self) -> Option<MutexGuard<'_, ReaderState>> {
        self.state
            .as_ref()
            .expect("admitted reader report")
            .try_lock()
    }
}
impl Clone for AdmittedReadReport {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            charge: self.charge.clone(),
        }
    }
}
impl Drop for AdmittedReadReport {
    fn drop(&mut self) {
        // Every clone follows this exact path; no Weak/raw Arc is exposed.
        // Arc::into_inner guarantees one concurrent final drop receives the
        // lease after the charge Arc allocation has actually been deallocated.
        // First retire the report Arc and original payload backing.
        drop(self.state.take());
        // ReportCharge then retires the charge Arc even on unwind.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestDiskMemory;
    fn state() -> ReaderState {
        ReaderState {
            phase: NodeReadPhase::Queued,
            transaction: None,
            source: None,
            begin: Observation::NotEntered,
            tables: Observation::NotEntered,
            outer: Observation::NotEntered,
            output_admission: Observation::NotEntered,
            read_failure: Observation::NotEntered,
            body_panic: Observation::NotEntered,
            finish_outer: Observation::NotEntered,
            outcomes_released: false,
        }
    }
    fn bytes() -> u64 {
        crate::disk_memory::add(
            crate::disk_memory::arc::<Mutex<ReaderState>>().unwrap(),
            crate::disk_memory::arc::<crate::DiskMemoryLease>().unwrap(),
        )
        .unwrap()
    }
    #[test]
    fn routine_report_one_byte_admission_boundary_funds_both_actual_arcs() {
        let slots = 4;
        let baseline = TestDiskMemory::required_bookkeeping_bytes(slots).unwrap();
        let cost = TestDiskMemory::required_reservation_bytes(bytes()).unwrap();
        let too_small = TestDiskMemory::new(baseline + cost - 1, slots);
        let provider: Arc<dyn NodeDiskMemoryAdmission> = too_small.clone();
        assert!(
            matches!(AdmittedReadReport::new(&provider, state()), Err(error)
            if error.kind() == io::ErrorKind::OutOfMemory)
        );
        assert_eq!(too_small.snapshot().used_bytes, 0);
        assert_eq!(too_small.snapshot().live_reservations, 0);
        let exact = TestDiskMemory::new(baseline + cost, slots);
        let provider: Arc<dyn NodeDiskMemoryAdmission> = exact.clone();
        let report = AdmittedReadReport::new(&provider, state()).unwrap();
        assert_eq!(exact.snapshot().used_bytes, cost);
        drop(report);
        assert_eq!(exact.snapshot().used_bytes, 0);
    }
    #[test]
    fn routine_report_concurrent_last_drop_releases_original_payload_before_credit() {
        struct Original {
            memory: Arc<TestDiskMemory>,
            destroyed: Arc<AtomicUsize>,
            expected: u64,
        }
        impl Drop for Original {
            fn drop(&mut self) {
                assert_eq!(self.memory.snapshot().used_bytes, self.expected);
                self.destroyed.fetch_add(1, Ordering::SeqCst);
            }
        }
        let memory = TestDiskMemory::new(1 << 20, 4);
        let provider: Arc<dyn NodeDiskMemoryAdmission> = memory.clone();
        let report = AdmittedReadReport::new(&provider, state()).unwrap();
        let cost = TestDiskMemory::required_reservation_bytes(bytes()).unwrap();
        let destroyed = Arc::new(AtomicUsize::new(0));
        report.lock().body_panic = Observation::Panicked(Box::new(Original {
            memory: memory.clone(),
            destroyed: destroyed.clone(),
            expected: cost,
        }));
        let copies: Vec<_> = (0..8).map(|_| report.clone()).collect();
        drop(report);
        assert_eq!(memory.snapshot().used_bytes, cost);
        let gate = Arc::new(std::sync::Barrier::new(copies.len()));
        std::thread::scope(|scope| {
            for report in copies {
                let gate = gate.clone();
                scope.spawn(move || {
                    gate.wait();
                    drop(report);
                });
            }
        });
        assert_eq!(destroyed.load(Ordering::SeqCst), 1);
        assert_eq!(memory.snapshot().used_bytes, 0);
        assert_eq!(memory.snapshot().live_reservations, 0);
    }
}
