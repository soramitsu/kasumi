//! Admission checks around every native group operation.
//!
//! Root and segment codecs receive this owner-bound adapter, so cached or
//! already-open native descriptors cannot bypass the current owner check.
//! Its retained holder is admitted by the enclosing disk state before use.

use std::ffi::OsStr;
use std::io;
use std::sync::Arc;

use crate::core::{BackendCloseOutcome, OwnerFailed, StorageAdmission};
use crate::group::{GroupFile, SegmentGroupBackend};
use crate::root::{ROOT_SLOT_BYTES, RootSlot};

pub(crate) struct CheckedGroup {
    backend: crate::native_backend::OriginalBackend,
    admission: Arc<dyn StorageAdmission>,
}

impl CheckedGroup {
    pub(crate) fn new(
        backend: crate::native_backend::OriginalBackend,
        admission: Arc<dyn StorageAdmission>,
    ) -> Self {
        Self { backend, admission }
    }

    fn check(&self) -> io::Result<()> {
        self.admission
            .check_owner()
            .map_err(|_| io::Error::other(OwnerFailed))
    }

    fn checked<T>(&self, operation: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
        self.check()?;
        let result = operation();
        // Check even after backend failure, preserving its original error.
        let current = self.check();
        match result {
            Err(error) => Err(error),
            Ok(value) => current.map(|()| value),
        }
    }
}

impl SegmentGroupBackend for CheckedGroup {
    fn reserve_transaction(
        &self,
        plan: &crate::TransactionSpacePlan,
    ) -> std::result::Result<(), crate::TransactionReserveError> {
        self.check()
            .map_err(crate::TransactionReserveError::Failed)?;
        let result = self.backend.as_ref().reserve_transaction(plan);
        let current = self.check();
        match result {
            Err(error) => Err(error),
            Ok(()) => current.map_err(crate::TransactionReserveError::Failed),
        }
    }
    fn finish_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
        self.backend
            .as_ref()
            .finish_transaction(group_id, batch_seq)
    }
    fn cancel_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
        self.backend
            .as_ref()
            .cancel_transaction(group_id, batch_seq)
    }

    fn read_root(&self, slot: RootSlot, out: &mut [u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        self.checked(|| self.backend.as_ref().read_root(slot, out))
    }

    fn write_root(&self, slot: RootSlot, bytes: &[u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        self.checked(|| self.backend.as_ref().write_root(slot, bytes))
    }

    fn sync_root(&self) -> io::Result<()> {
        self.checked(|| self.backend.as_ref().sync_root())
    }

    fn visit_entries(&self, visitor: &mut dyn FnMut(&OsStr) -> io::Result<()>) -> io::Result<()> {
        self.checked(|| {
            self.backend
                .as_ref()
                .visit_entries(&mut |name| self.checked(|| visitor(name)))
        })
    }

    fn exists(&self, file: GroupFile) -> io::Result<bool> {
        self.checked(|| self.backend.as_ref().exists(file))
    }

    fn create(&self, file: GroupFile) -> io::Result<()> {
        self.checked(|| self.backend.as_ref().create(file))
    }

    fn len(&self, file: GroupFile) -> io::Result<u64> {
        self.checked(|| self.backend.as_ref().len(file))
    }

    fn read(&self, file: GroupFile, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.checked(|| self.backend.as_ref().read(file, at, out))
    }

    fn write(&self, file: GroupFile, at: u64, bytes: &[u8]) -> io::Result<()> {
        self.checked(|| self.backend.as_ref().write(file, at, bytes))
    }

    fn set_len(&self, file: GroupFile, length: u64) -> io::Result<()> {
        self.checked(|| self.backend.as_ref().set_len(file, length))
    }

    fn sync(&self, file: GroupFile) -> io::Result<()> {
        self.checked(|| self.backend.as_ref().sync(file))
    }

    fn unlink(&self, file: GroupFile) -> io::Result<()> {
        self.checked(|| self.backend.as_ref().unlink(file))
    }

    fn sync_names(&self) -> io::Result<()> {
        self.checked(|| self.backend.as_ref().sync_names())
    }

    /// Expiration never prevents the exact owner from draining its resources.
    fn close(&self) -> BackendCloseOutcome {
        self.backend.as_ref().close()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{AdmissionError, BackendNativeDisposition, ResidentLease};
    use crate::group::InMemoryGroup;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[derive(Default)]
    struct Admission {
        expired: AtomicBool,
        checks: AtomicUsize,
    }
    struct Lease;
    impl StorageAdmission for Admission {
        fn check_owner(&self) -> Result<(), OwnerFailed> {
            self.checks.fetch_add(1, Ordering::Relaxed);
            if self.expired.load(Ordering::Acquire) {
                Err(OwnerFailed)
            } else {
                Ok(())
            }
        }
        fn reserve_workspace(&self, _: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
            self.check_owner()
                .map_err(|_| AdmissionError::OwnerFailed)?;
            Ok(Box::new(Lease))
        }
        fn reserve_growth(&self, _: u64, _: u64) -> Result<(), AdmissionError> {
            self.check_owner().map_err(|_| AdmissionError::OwnerFailed)
        }
        fn settle_growth(&self, _: u64) -> Result<(), OwnerFailed> {
            self.check_owner()
        }
        fn owner_failed(&self) {
            self.expired.store(true, Ordering::Release);
        }

        fn quote_cache_memory(
            &self,
            bytes: u64,
        ) -> Result<crate::CacheMemoryQuote, crate::AdmissionError> {
            crate::cache_test::quote::<Self>(bytes)
        }
        fn reserve_cache_memory(
            self: std::sync::Arc<Self>,
            bytes: u64,
        ) -> Result<crate::CacheMemoryLease, crate::AdmissionError> {
            crate::cache_test::reserve(self, bytes)
        }
    }
    impl crate::cache_test::Provider for Admission {
        fn acquire_cache(&self, bytes: u64, first: bool) -> Result<(), crate::AdmissionError> {
            let _ = first;
            let _ = bytes;
            Ok(())
        }
        fn release_cache(&self, bytes: u64, last: bool) {
            let _ = (bytes, last);
        }
    }

    struct Probe {
        inner: InMemoryGroup,
        admission: Arc<Admission>,
        calls: AtomicUsize,
        expire_after: AtomicBool,
        expire_before_visit: AtomicBool,
        fail_after: AtomicBool,
    }
    impl Probe {
        fn run<T>(&self, operation: impl FnOnce(&InMemoryGroup) -> io::Result<T>) -> io::Result<T> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let result = operation(&self.inner);
            if self.expire_after.load(Ordering::Acquire) {
                self.admission.expired.store(true, Ordering::Release);
            }
            if self.fail_after.load(Ordering::Acquire) {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "original backend failure",
                ));
            }
            result
        }
    }
    impl SegmentGroupBackend for Probe {
        fn reserve_transaction(
            &self,
            plan: &crate::TransactionSpacePlan,
        ) -> std::result::Result<(), crate::TransactionReserveError> {
            self.inner.reserve_transaction(plan)
        }
        fn finish_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
            self.inner.finish_transaction(group_id, batch_seq)
        }
        fn cancel_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
            self.inner.cancel_transaction(group_id, batch_seq)
        }

        fn read_root(&self, slot: RootSlot, out: &mut [u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
            self.run(|b| b.read_root(slot, out))
        }
        fn write_root(&self, slot: RootSlot, bytes: &[u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
            self.run(|b| b.write_root(slot, bytes))
        }
        fn sync_root(&self) -> io::Result<()> {
            self.run(SegmentGroupBackend::sync_root)
        }
        fn visit_entries(
            &self,
            visitor: &mut dyn FnMut(&OsStr) -> io::Result<()>,
        ) -> io::Result<()> {
            self.run(|b| {
                if self.expire_before_visit.load(Ordering::Acquire) {
                    self.admission.expired.store(true, Ordering::Release);
                }
                b.visit_entries(visitor)
            })
        }
        fn exists(&self, file: GroupFile) -> io::Result<bool> {
            self.run(|b| b.exists(file))
        }
        fn create(&self, file: GroupFile) -> io::Result<()> {
            self.run(|b| b.create(file))
        }
        fn len(&self, file: GroupFile) -> io::Result<u64> {
            self.run(|b| b.len(file))
        }
        fn read(&self, file: GroupFile, at: u64, out: &mut [u8]) -> io::Result<()> {
            self.run(|b| b.read(file, at, out))
        }
        fn write(&self, file: GroupFile, at: u64, bytes: &[u8]) -> io::Result<()> {
            self.run(|b| b.write(file, at, bytes))
        }
        fn set_len(&self, file: GroupFile, length: u64) -> io::Result<()> {
            self.run(|b| b.set_len(file, length))
        }
        fn sync(&self, file: GroupFile) -> io::Result<()> {
            self.run(|b| b.sync(file))
        }
        fn unlink(&self, file: GroupFile) -> io::Result<()> {
            self.run(|b| b.unlink(file))
        }
        fn sync_names(&self) -> io::Result<()> {
            self.run(SegmentGroupBackend::sync_names)
        }
        fn close(&self) -> BackendCloseOutcome {
            self.inner.close()
        }
    }

    fn fixture() -> (CheckedGroup, Arc<Probe>, Arc<Admission>) {
        let admission = Arc::new(Admission::default());
        let inner = InMemoryGroup::new();
        inner.create(GroupFile::segment(1)).unwrap();
        inner.write(GroupFile::segment(1), 0, b"data").unwrap();
        let probe = Arc::new(Probe {
            inner,
            admission: admission.clone(),
            calls: AtomicUsize::new(0),
            expire_after: AtomicBool::new(false),
            expire_before_visit: AtomicBool::new(false),
            fail_after: AtomicBool::new(false),
        });
        (
            CheckedGroup::new(
                crate::native_backend::OriginalBackend::component_fixture(probe.clone()),
                admission.clone(),
            ),
            probe,
            admission,
        )
    }

    type Operation = fn(&dyn SegmentGroupBackend) -> io::Result<()>;
    fn operations() -> [Operation; 13] {
        [
            |b| b.read_root(RootSlot::A, &mut [0; ROOT_SLOT_BYTES]),
            |b| b.write_root(RootSlot::A, &[1; ROOT_SLOT_BYTES]),
            |b| b.sync_root(),
            |b| b.visit_entries(&mut |_| Ok(())),
            |b| b.exists(GroupFile::segment(1)).map(|_| ()),
            |b| b.create(GroupFile::directory(1)),
            |b| b.len(GroupFile::segment(1)).map(|_| ()),
            |b| b.read(GroupFile::segment(1), 0, &mut [0; 4]),
            |b| b.write(GroupFile::segment(1), 0, b"next"),
            |b| b.set_len(GroupFile::segment(1), 3),
            |b| b.sync(GroupFile::segment(1)),
            |b| b.unlink(GroupFile::segment(1)),
            |b| b.sync_names(),
        ]
    }

    #[test]
    fn expired_owner_never_enters_any_backend_call() {
        for operation in operations() {
            let (checked, backend, admission) = fixture();
            admission.expired.store(true, Ordering::Release);
            let error = operation(&checked).unwrap_err();
            assert!(error.get_ref().unwrap().is::<OwnerFailed>());
            assert_eq!(backend.calls.load(Ordering::Relaxed), 0);
            assert_eq!(backend.inner.len(GroupFile::segment(1)).unwrap(), 4);
            let closed = checked.close();
            assert_eq!(
                closed.native_disposition(),
                BackendNativeDisposition::Drained
            );
            closed.into_result().unwrap();
        }
    }

    #[test]
    fn expiry_during_any_successful_backend_call_rejects_its_result() {
        for operation in operations() {
            let (checked, backend, _) = fixture();
            backend.expire_after.store(true, Ordering::Release);
            let error = operation(&checked).unwrap_err();
            assert!(error.get_ref().unwrap().is::<OwnerFailed>());
            assert_eq!(backend.calls.load(Ordering::Relaxed), 1);
            assert!(checked.sync_root().is_err());
            assert_eq!(backend.calls.load(Ordering::Relaxed), 1);
            checked.close().into_result().unwrap();
        }
    }

    #[test]
    fn backend_failure_is_preserved_even_when_its_owner_expires() {
        let (checked, backend, admission) = fixture();
        backend.expire_after.store(true, Ordering::Release);
        backend.fail_after.store(true, Ordering::Release);
        let error = checked
            .write(GroupFile::segment(1), 0, b"next")
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WriteZero);
        assert_eq!(error.to_string(), "original backend failure");
        assert_eq!(admission.checks.load(Ordering::Relaxed), 2);
        checked.close().into_result().unwrap();
    }

    #[test]
    fn expiry_before_a_streamed_entry_prevents_its_callback() {
        let (checked, backend, _) = fixture();
        backend.expire_before_visit.store(true, Ordering::Release);
        let mut calls = 0;
        let error = checked
            .visit_entries(&mut |_| {
                calls += 1;
                Ok(())
            })
            .unwrap_err();
        assert!(error.get_ref().unwrap().is::<OwnerFailed>());
        assert_eq!(calls, 0);
        checked.close().into_result().unwrap();
    }

    #[test]
    fn visitor_expiry_stops_before_another_callback() {
        let (checked, _, admission) = fixture();
        let mut calls = 0;
        let error = checked
            .visit_entries(&mut |_| {
                calls += 1;
                admission.expired.store(true, Ordering::Release);
                Ok(())
            })
            .unwrap_err();
        assert!(error.get_ref().unwrap().is::<OwnerFailed>());
        assert_eq!(calls, 1);
        checked.close().into_result().unwrap();
    }
}
