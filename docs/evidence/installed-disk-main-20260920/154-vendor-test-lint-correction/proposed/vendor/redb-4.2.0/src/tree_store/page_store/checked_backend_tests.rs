use super::CheckedBackend;
use crate::{AdmissionError, OwnerFailed, StorageAdmission, StorageBackend, StorageError};
use std::{
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Method {
    Len,
    Read,
    SetLen,
    Write,
    Sync,
    Close,
}
const METHODS: [Method; 6] = [
    Method::Len,
    Method::Read,
    Method::SetLen,
    Method::Write,
    Method::Sync,
    Method::Close,
];

#[derive(Debug)]
struct OriginalIoFailure(u64);
impl core::fmt::Display for OriginalIoFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "original checked backend failure {}", self.0)
    }
}
impl std::error::Error for OriginalIoFailure {}

#[derive(Debug)]
struct Fault {
    method: Method,
    original: Mutex<Option<io::Error>>,
    calls: [AtomicUsize; METHODS.len()],
}
impl Fault {
    fn enter(&self, method: Method) -> io::Result<()> {
        self.calls[method as usize].fetch_add(1, Ordering::SeqCst);
        if method == self.method {
            return Err(self
                .original
                .lock()
                .unwrap()
                .take()
                .expect("failed physical operation must never be replayed"));
        }
        Ok(())
    }
    fn counts(&self) -> [usize; METHODS.len()] {
        std::array::from_fn(|index| self.calls[index].load(Ordering::SeqCst))
    }
}

#[derive(Debug, Default)]
struct Owner {
    failed: AtomicBool,
    failures: AtomicUsize,
}
impl StorageAdmission for Owner {
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        if self.failed.load(Ordering::Acquire) {
            Err(OwnerFailed)
        } else {
            Ok(())
        }
    }
    fn reserve_growth(&self, _: u64, _: u64) -> Result<(), AdmissionError> {
        self.check_owner().map_err(|_| AdmissionError::OwnerFailed)
    }
    fn settle_growth(&self, _: u64) -> Result<(), OwnerFailed> {
        self.check_owner()
    }
    fn owner_failed(&self) {
        self.failed.store(true, Ordering::Release);
        self.failures.fetch_add(1, Ordering::SeqCst);
    }
}

#[derive(Debug)]
struct Backend {
    inner: crate::backends::InMemoryBackend,
    fault: Arc<Fault>,
}
impl StorageBackend for Backend {
    fn len(&self) -> io::Result<u64> {
        self.fault.enter(Method::Len)?;
        self.inner.len()
    }
    fn read(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.fault.enter(Method::Read)?;
        self.inner.read(offset, out)
    }
    fn set_len(&self, len: u64) -> io::Result<()> {
        self.fault.enter(Method::SetLen)?;
        self.inner.set_len(len)
    }
    fn write(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        self.fault.enter(Method::Write)?;
        self.inner.write(offset, data)
    }
    fn sync_data(&self) -> io::Result<()> {
        self.fault.enter(Method::Sync)?;
        self.inner.sync_data()
    }
    fn close(&self) -> io::Result<()> {
        self.fault.enter(Method::Close)?;
        self.inner.close()
    }
}

fn invoke(backend: &CheckedBackend, method: Method) -> crate::Result<()> {
    match method {
        Method::Len => backend.len().map(|_| ()),
        Method::Read => backend.read(0, &mut [0]),
        Method::SetLen => backend.set_len(128),
        Method::Write => backend.write(0, &[1]),
        Method::Sync => backend.sync_data(),
        Method::Close => backend.close(),
    }
}

#[test]
fn every_backend_io_failure_preserves_original_object_and_fences_later_access() {
    for method in METHODS {
        let original = io::Error::new(
            io::ErrorKind::BrokenPipe,
            OriginalIoFailure(method as u64 + 1),
        );
        let identity = std::ptr::from_ref(
            original
                .get_ref()
                .unwrap()
                .downcast_ref::<OriginalIoFailure>()
                .unwrap(),
        );
        let fault = Arc::new(Fault {
            method,
            original: Mutex::new(Some(original)),
            calls: std::array::from_fn(|_| AtomicUsize::new(0)),
        });
        let owner = Arc::new(Owner::default());
        let inner = crate::backends::InMemoryBackend::new();
        inner.set_len(64).unwrap();
        let backend = CheckedBackend::new(
            Box::new(Backend {
                inner,
                fault: fault.clone(),
            }),
            owner.clone(),
        );
        let StorageError::Io(original) = invoke(&backend, method).unwrap_err() else {
            panic!("{method:?} replaced its actual backend I/O error");
        };
        assert_eq!(original.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(
            std::ptr::from_ref(
                original
                    .get_ref()
                    .unwrap()
                    .downcast_ref::<OriginalIoFailure>()
                    .unwrap()
            ),
            identity,
        );
        assert!(owner.failed.load(Ordering::Acquire));
        assert_eq!(owner.failures.load(Ordering::SeqCst), 1);
        let calls = fault.counts();
        assert_eq!(calls[method as usize], 1);
        for retry in &METHODS[..5] {
            let error = invoke(&backend, *retry).unwrap_err();
            assert!(match method {
                Method::Close => matches!(error, StorageError::DatabaseClosed),
                _ => matches!(error, StorageError::OwnerFailed),
            });
        }
        assert_eq!(fault.counts(), calls, "fenced retries touched the backend");
        // Explicit close must still drain the physical backend after a data I/O
        // failure. An already attempted close is observed without replay.
        backend.close().unwrap();
        backend.close().unwrap();
        assert_eq!(
            fault.calls[Method::Close as usize].load(Ordering::SeqCst),
            1
        );
        assert!(matches!(backend.len(), Err(StorageError::DatabaseClosed)));
        drop(backend);
        assert_eq!(
            fault.calls[Method::Close as usize].load(Ordering::SeqCst),
            1
        );
        assert_eq!(owner.failures.load(Ordering::SeqCst), 1);
        assert_eq!(
            std::ptr::from_ref(
                original
                    .get_ref()
                    .unwrap()
                    .downcast_ref::<OriginalIoFailure>()
                    .unwrap()
            ),
            identity,
            "later fencing/close replaced the original error object",
        );
    }
}
