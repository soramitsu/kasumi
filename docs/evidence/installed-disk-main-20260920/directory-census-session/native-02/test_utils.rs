use std::time::Duration;
/// A fixture installation starts private; production constructors never repair
/// permissions on a supplied directory.
pub fn private_tempdir() -> std::io::Result<tempfile::TempDir> {
    use std::os::unix::fs::PermissionsExt;
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
}

/// Explicit fixture setup retry. Production and isolated single-attempt disk
/// constructors never retry; only their typed registry-contention result may
/// be retried here. Provider errors and filesystem ownership failures remain
/// visible even when their underlying OS kind is WouldBlock.
pub fn retry_disk_registry<T>(
    mut open: impl FnMut() -> std::result::Result<T, crate::DiskOpenError>,
) -> std::result::Result<T, crate::DiskOpenError> {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match open() {
            Err(crate::DiskOpenError::RegistryBusy) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(1));
            }
            result => return result,
        }
    }
}

/// Explicit bounded memory owner for physical-disk fixtures. It performs the
/// same mandatory resident acquisition and owns every accepted lease until Drop;
/// no production constructor selects this governor implicitly.
pub struct TestDiskMemory {
    max_bytes: u64,
    max_reservations: usize,
    state: std::sync::Mutex<TestDiskMemorySnapshot>,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TestDiskMemorySnapshot {
    pub used_bytes: u64,
    pub live_reservations: usize,
    pub attempts: u64,
}
struct TestDiskLease {
    owner: std::sync::Arc<TestDiskMemory>,
    bytes: u64,
}
impl TestDiskMemory {
    pub fn new(max_bytes: u64, max_reservations: usize) -> std::sync::Arc<Self> {
        assert!(max_bytes > 0 && max_reservations > 0);
        let owner = std::sync::Arc::new(Self {
            max_bytes,
            max_reservations,
            state: Default::default(),
        });
        drop(owner.state.lock().unwrap());
        owner
    }
    pub fn required_reservation_bytes(bytes: u64) -> std::io::Result<u64> {
        crate::disk_memory::add(bytes, crate::disk_memory::allocation::<TestDiskLease>(1)?)
    }
    pub fn snapshot(&self) -> TestDiskMemorySnapshot {
        *self.state.lock().unwrap()
    }
}
impl crate::NodeDiskMemoryAdmission for TestDiskMemory {
    fn reserve_installed(
        self: std::sync::Arc<Self>,
        bytes: u64,
    ) -> std::io::Result<crate::DiskMemoryLease> {
        let bytes = Self::required_reservation_bytes(bytes)?;
        let mut state = self.state.lock().map_err(|_| std::io::ErrorKind::Other)?;
        state.attempts = state
            .attempts
            .checked_add(1)
            .ok_or(std::io::ErrorKind::Other)?;
        let next = state
            .used_bytes
            .checked_add(bytes)
            .ok_or(std::io::ErrorKind::OutOfMemory)?;
        if next > self.max_bytes || state.live_reservations >= self.max_reservations {
            return Err(std::io::ErrorKind::OutOfMemory.into());
        }
        state.used_bytes = next;
        state.live_reservations += 1;
        drop(state);
        Ok(crate::DiskMemoryLease::new(TestDiskLease {
            owner: self,
            bytes,
        }))
    }
}
impl Drop for TestDiskLease {
    fn drop(&mut self) {
        let mut state = self.owner.state.lock().unwrap();
        state.used_bytes = state
            .used_bytes
            .checked_sub(self.bytes)
            .expect("owned fixture bytes");
        state.live_reservations = state
            .live_reservations
            .checked_sub(1)
            .expect("owned fixture slot");
    }
}
