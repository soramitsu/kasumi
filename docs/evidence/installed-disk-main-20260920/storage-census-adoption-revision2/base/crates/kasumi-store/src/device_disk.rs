//! One charged reservation boundary for every managed writer on a filesystem.
use crate::DiskOpenError;
use crate::disk_memory::{self, Lease, List, NodeDiskMemoryAdmission};
use std::{
    ops::Deref,
    sync::{Arc, Mutex, MutexGuard},
};

struct State {
    pending: u64,
    owners: List<Owner>,
    poisoned: bool,
}
impl Default for State {
    fn default() -> Self {
        Self {
            pending: 0,
            owners: List::new(),
            poisoned: false,
        }
    }
}
struct Owner {
    id: uuid::Uuid,
    minimum_free_bytes: u64,
    uncertain: bool,
    pending: u64,
    // Removal deallocates the actual list node before this lease is dropped.
    _charge: Lease,
}
struct Device {
    state: Mutex<State>,
    memory: Arc<dyn NodeDiskMemoryAdmission>,
    _charge: Lease,
}
struct RegisteredDevice {
    id: u64,
    device: Arc<Device>,
}
type Registry = parking_lot::Mutex<List<RegisteredDevice>>;

/// The registration and shared device each retain their actual resident lease.
/// A persistent disk keeps its registration through runtime replacement.
pub(crate) struct DeviceDisk {
    device: Arc<Device>,
    id: uuid::Uuid,
}
pub(crate) enum DeviceSelection {
    Installed,
    #[cfg(any(test, feature = "test-utils"))]
    Isolated,
    #[cfg(test)]
    Existing(DeviceDisk),
}
impl DeviceSelection {
    pub(crate) fn open(
        self,
        id: u64,
        minimum: u64,
        memory: Arc<dyn NodeDiskMemoryAdmission>,
    ) -> Result<DeviceDisk, DiskOpenError> {
        match self {
            Self::Installed => DeviceDisk::open(id, minimum, memory),
            #[cfg(any(test, feature = "test-utils"))]
            Self::Isolated => DeviceDisk::isolated(minimum, memory).map_err(Into::into),
            #[cfg(test)]
            Self::Existing(owner) => {
                if !Arc::ptr_eq(owner.memory(), &memory) {
                    return Err(std::io::ErrorKind::InvalidInput.into());
                }
                Ok(owner)
            }
        }
    }
}
impl DeviceDisk {
    pub(crate) fn metadata_requirements() -> std::io::Result<(u64, u64)> {
        let device = disk_memory::add(
            disk_memory::arc::<Device>()?,
            disk_memory::allocation::<disk_memory::Entry<RegisteredDevice>>(1)?,
        )?;
        let owner = disk_memory::allocation::<disk_memory::Entry<Owner>>(1)?;
        Ok((device, owner))
    }
    #[cfg(test)]
    pub(crate) fn memory(&self) -> &Arc<dyn NodeDiskMemoryAdmission> {
        &self.device.memory
    }
    pub(crate) fn open(
        device_id: u64,
        minimum_free_bytes: u64,
        memory: Arc<dyn NodeDiskMemoryAdmission>,
    ) -> Result<Self, DiskOpenError> {
        static DEVICES: Registry = parking_lot::Mutex::new(List::new());
        Self::open_registered(&DEVICES, device_id, minimum_free_bytes, memory)
    }
    fn open_registered(
        registry: &Registry,
        device_id: u64,
        minimum_free_bytes: u64,
        memory: Arc<dyn NodeDiskMemoryAdmission>,
    ) -> Result<Self, DiskOpenError> {
        // A contended constructor fails before allocating a parking waiter or
        // an uncharged provisional registry collection. Callers may retry.
        let mut devices = registry.try_lock().ok_or(DiskOpenError::RegistryBusy)?;
        if let Some(existing) = devices.find(|entry| entry.id == device_id) {
            if !Arc::ptr_eq(&existing.device.memory, &memory) {
                return Err(std::io::ErrorKind::InvalidInput.into());
            }
            return Self::register(existing.device.clone(), minimum_free_bytes).map_err(Into::into);
        }
        let device = Self::new_device(memory)?;
        let entry = List::prepare(RegisteredDevice {
            id: device_id,
            device: device.clone(),
        });
        let owner = Self::register(device, minimum_free_bytes)?;
        devices.insert(entry);
        Ok(owner)
    }
    fn new_device(memory: Arc<dyn NodeDiskMemoryAdmission>) -> std::io::Result<Arc<Device>> {
        let charge = memory
            .clone()
            .reserve_installed(Self::metadata_requirements()?.0)?;
        let device = Arc::new(Device {
            state: Mutex::new(State::default()),
            memory,
            _charge: charge,
        });
        drop(device.state.lock().expect("unpublished device state"));
        Ok(device)
    }
    fn register(device: Arc<Device>, minimum_free_bytes: u64) -> std::io::Result<Self> {
        let charge = device
            .memory
            .clone()
            .reserve_installed(Self::metadata_requirements()?.1)?;
        let id = uuid::Uuid::new_v4();
        let entry = List::prepare(Owner {
            id,
            minimum_free_bytes,
            uncertain: false,
            pending: 0,
            _charge: charge,
        });
        let mut state = device.state.lock().unwrap_or_else(|p| {
            let mut state = p.into_inner();
            state.poisoned = true;
            state
        });
        state.owners.insert(entry);
        drop(state);
        Ok(Self { device, id })
    }
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn isolated(
        minimum_free_bytes: u64,
        memory: Arc<dyn NodeDiskMemoryAdmission>,
    ) -> std::io::Result<Self> {
        Self::register(Self::new_device(memory)?, minimum_free_bytes)
    }
    #[cfg(test)]
    pub(crate) fn share(&self, minimum_free_bytes: u64) -> Self {
        Self::register(self.device.clone(), minimum_free_bytes).unwrap()
    }
    #[cfg(test)]
    pub(crate) fn poison(&self) {
        let _result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _state = self.device.state.lock().unwrap();
            panic!("injected shared promise mutation panic");
        }));
    }
    pub(crate) fn lock(&self) -> DevicePromises<'_> {
        let state = self.device.state.lock().unwrap_or_else(|p| {
            let mut state = p.into_inner();
            state.poisoned = true;
            state
        });
        DevicePromises {
            state,
            owner: self.id,
        }
    }
}
impl Drop for DeviceDisk {
    fn drop(&mut self) {
        let mut state = self.device.state.lock().unwrap_or_else(|p| {
            let mut state = p.into_inner();
            state.poisoned = true;
            state
        });
        let owner = state.owners.remove(|owner| owner.id == self.id);
        if owner
            .as_ref()
            .is_some_and(|owner| owner.uncertain || owner.pending != 0)
        {
            state.poisoned = true;
        }
        drop(state);
        drop(owner);
    }
}

pub(crate) struct DevicePromises<'a> {
    state: MutexGuard<'a, State>,
    owner: uuid::Uuid,
}

impl DevicePromises<'_> {
    pub(crate) fn minimum_free_bytes(&self) -> u64 {
        self.state
            .owners
            .iter()
            .map(|owner| owner.minimum_free_bytes)
            .max()
            .unwrap_or(0)
    }

    pub(crate) fn admission_ready(&self) -> bool {
        !self.state.poisoned && !self.state.owners.iter().any(|owner| owner.uncertain)
    }

    pub(crate) fn fail_owner(&mut self) {
        self.state
            .owners
            .find_mut(|owner| owner.id == self.owner)
            .expect("registered device owner")
            .uncertain = true;
    }

    pub(crate) fn reconcile_owner(&mut self) {
        self.state
            .owners
            .find_mut(|owner| owner.id == self.owner)
            .expect("registered device owner")
            .uncertain = false;
    }

    /// Publish a precomputed aggregate transition while retaining the exact
    /// contribution of this registration. Failure leaves all counters unchanged.
    pub(crate) fn set_pending(&mut self, next: u64) -> std::io::Result<()> {
        let previous = self.state.pending;
        let owned = self
            .state
            .owners
            .find(|owner| owner.id == self.owner)
            .expect("registered owner")
            .pending;
        let owned_next = if next >= previous {
            owned.checked_add(next - previous)
        } else {
            owned.checked_sub(previous - next)
        };
        let Some(owned_next) = owned_next else {
            self.state.poisoned = true;
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
        };
        self.state
            .owners
            .find_mut(|owner| owner.id == self.owner)
            .expect("registered owner")
            .pending = owned_next;
        self.state.pending = next;
        Ok(())
    }
}

impl Deref for DevicePromises<'_> {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.state.pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poisoned_device_stays_closed_after_all_registration_handles_drop() {
        let memory = crate::test_utils::TestDiskMemory::new(1 << 20, 32);
        let registry = Registry::new(List::new());
        let owner = DeviceDisk::open_registered(&registry, 11, 0, memory.clone()).unwrap();
        owner.poison();
        drop(owner);
        let reopened = DeviceDisk::open_registered(&registry, 11, 0, memory.clone()).unwrap();
        assert!(!reopened.lock().admission_ready());
        reopened.lock().reconcile_owner();
        assert!(!reopened.lock().admission_ready());
    }

    #[test]
    fn abandoned_uncertainty_or_pending_bytes_cannot_be_released_by_drop() {
        for pending in [false, true] {
            let memory = crate::test_utils::TestDiskMemory::new(1 << 20, 32);
            let registry = Registry::new(List::new());
            let owner = DeviceDisk::open_registered(&registry, 12, 4096, memory.clone()).unwrap();
            if pending {
                owner.lock().set_pending(8192).unwrap();
            } else {
                owner.lock().fail_owner();
            }
            drop(owner);
            let reopened = DeviceDisk::open_registered(&registry, 12, 0, memory.clone()).unwrap();
            assert!(!reopened.lock().admission_ready());
            assert_eq!(*reopened.lock(), if pending { 8192 } else { 0 });
            reopened.lock().reconcile_owner();
            assert!(!reopened.lock().admission_ready());
        }
    }
}

#[cfg(test)]
mod memory_tests {
    use super::*;
    use crate::test_utils::TestDiskMemory;

    #[test]
    fn device_registry_and_registration_have_exact_independent_lifetime_charges() {
        let (device_bytes, registration_bytes) = DeviceDisk::metadata_requirements().unwrap();
        let device_bytes = TestDiskMemory::required_reservation_bytes(device_bytes).unwrap();
        let registration_bytes =
            TestDiskMemory::required_reservation_bytes(registration_bytes).unwrap();
        let memory = TestDiskMemory::new(device_bytes + 2 * registration_bytes, 3);
        let registry = Registry::new(List::new());
        let first = DeviceDisk::open_registered(&registry, 73, 0, memory.clone()).unwrap();
        assert_eq!(
            memory.snapshot().used_bytes,
            device_bytes + registration_bytes
        );
        let second = DeviceDisk::open_registered(&registry, 73, 4096, memory.clone()).unwrap();
        assert_eq!(
            memory.snapshot().used_bytes,
            device_bytes + 2 * registration_bytes
        );
        assert_eq!(first.lock().minimum_free_bytes(), 4096);
        drop(second);
        assert_eq!(
            memory.snapshot().used_bytes,
            device_bytes + registration_bytes
        );
        assert_eq!(first.lock().minimum_free_bytes(), 0);
        drop(first);
        assert_eq!(memory.snapshot().used_bytes, device_bytes);
        assert_eq!(memory.snapshot().live_reservations, 1);
        drop(registry);
        assert_eq!(memory.snapshot().used_bytes, 0);
        assert_eq!(memory.snapshot().live_reservations, 0);
    }

    #[test]
    fn failed_registration_and_foreign_core_do_not_grow_retained_device_metadata() {
        let (device_bytes, registration_bytes) = DeviceDisk::metadata_requirements().unwrap();
        let device_bytes = TestDiskMemory::required_reservation_bytes(device_bytes).unwrap();
        let registration_bytes =
            TestDiskMemory::required_reservation_bytes(registration_bytes).unwrap();
        let registry = Registry::new(List::new());
        let too_small = TestDiskMemory::new(device_bytes + registration_bytes, 1);
        assert!(DeviceDisk::open_registered(&registry, 74, 0, too_small.clone()).is_err());
        assert_eq!(too_small.snapshot().used_bytes, 0);
        assert_eq!(too_small.snapshot().live_reservations, 0);
        assert_eq!(registry.lock().iter().count(), 0);
        let memory = TestDiskMemory::new(device_bytes + registration_bytes, 2);
        let owner = DeviceDisk::open_registered(&registry, 74, 0, memory.clone()).unwrap();
        let before = memory.snapshot();
        assert!(DeviceDisk::open_registered(&registry, 74, 0, too_small.clone()).is_err());
        assert_eq!(too_small.snapshot().attempts, 2);
        assert_eq!(memory.snapshot(), before);
        assert_eq!(registry.lock().iter().count(), 1);
        drop(owner);
        drop(registry);
        assert_eq!(memory.snapshot().used_bytes, 0);
    }
}

#[cfg(test)]
mod registry_busy_tests {
    use super::*;
    #[test]
    fn busy_device_registry_does_not_allocate_or_touch_memory_admission() {
        let memory = crate::test_utils::TestDiskMemory::new(1, 1);
        let registry = Registry::new(List::new());
        let guard = registry.lock();
        let (result, allocations) = crate::allocation_tests::measure(|| {
            DeviceDisk::open_registered(&registry, 31, 0, memory.clone())
        });
        assert!(matches!(result, Err(DiskOpenError::RegistryBusy)));
        assert_eq!(allocations, 0);
        assert_eq!(memory.snapshot().attempts, 0);
        drop(guard);
    }
}
