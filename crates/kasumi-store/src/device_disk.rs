//! One reservation boundary for every managed writer on a filesystem.
use std::{
    collections::HashMap,
    ops::Deref,
    sync::{Arc, Mutex, MutexGuard, OnceLock},
};

#[derive(Default)]
struct State {
    pending: u64,
    owners: HashMap<uuid::Uuid, Owner>,
    poisoned: bool,
}

struct Owner {
    minimum_free_bytes: u64,
    uncertain: bool,
    pending: u64,
}

#[derive(Default)]
struct Device {
    state: Mutex<State>,
}

/// Keeps this installed owner's floor active until its accounting owner closes.
/// Persistent owners retain this registration across service/handle shutdown.
pub(crate) struct DeviceDisk {
    device: Arc<Device>,
    id: uuid::Uuid,
}

impl DeviceDisk {
    pub(crate) fn open(device_id: u64, minimum_free_bytes: u64) -> std::io::Result<Self> {
        static DEVICES: OnceLock<Mutex<HashMap<u64, Arc<Device>>>> = OnceLock::new();
        Self::open_registered(
            DEVICES.get_or_init(Default::default),
            device_id,
            minimum_free_bytes,
        )
    }

    fn open_registered(
        registry: &Mutex<HashMap<u64, Arc<Device>>>,
        device_id: u64,
        minimum_free_bytes: u64,
    ) -> std::io::Result<Self> {
        let mut devices = registry
            .lock()
            .map_err(|_| std::io::Error::other("filesystem identity registry is poisoned"))?;
        let device = devices.entry(device_id).or_default().clone();
        Ok(Self::register(device, minimum_free_bytes))
    }

    fn register(device: Arc<Device>, minimum_free_bytes: u64) -> Self {
        let id = uuid::Uuid::new_v4();
        let mut state = device.state.lock().unwrap_or_else(|p| {
            let mut state = p.into_inner();
            state.poisoned = true;
            state
        });
        state.owners.insert(
            id,
            Owner {
                minimum_free_bytes,
                uncertain: false,
                pending: 0,
            },
        );
        drop(state);
        Self { device, id }
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn isolated(minimum_free_bytes: u64) -> Self {
        Self::register(Arc::new(Device::default()), minimum_free_bytes)
    }

    #[cfg(test)]
    pub(crate) fn share(&self, minimum_free_bytes: u64) -> Self {
        Self::register(self.device.clone(), minimum_free_bytes)
    }

    #[cfg(test)]
    pub(crate) fn poison(&self) {
        let _result = std::panic::catch_unwind(|| {
            let _state = self.device.state.lock().unwrap();
            panic!("injected shared promise mutation panic");
        });
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
        if let Some(owner) = state.owners.remove(&self.id)
            && (owner.uncertain || owner.pending != 0)
        {
            // Do not orphan a promise or forget uncertainty merely because its
            // last handle closed. A new registration cannot repair this state.
            state.poisoned = true;
        }
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
            .values()
            .map(|owner| owner.minimum_free_bytes)
            .max()
            .unwrap_or(0)
    }

    pub(crate) fn admission_ready(&self) -> bool {
        !self.state.poisoned && !self.state.owners.values().any(|owner| owner.uncertain)
    }

    pub(crate) fn fail_owner(&mut self) {
        self.state
            .owners
            .get_mut(&self.owner)
            .expect("registered device owner")
            .uncertain = true;
    }

    pub(crate) fn reconcile_owner(&mut self) {
        self.state
            .owners
            .get_mut(&self.owner)
            .expect("registered device owner")
            .uncertain = false;
    }

    /// Publish a precomputed aggregate transition while retaining the exact
    /// contribution of this registration. Failure leaves all counters unchanged.
    pub(crate) fn set_pending(&mut self, next: u64) -> std::io::Result<()> {
        let previous = self.state.pending;
        let owned = self.state.owners[&self.owner].pending;
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
            .get_mut(&self.owner)
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
        let registry = Mutex::new(HashMap::new());
        let owner = DeviceDisk::open_registered(&registry, 11, 0).unwrap();
        owner.poison();
        drop(owner);
        let reopened = DeviceDisk::open_registered(&registry, 11, 0).unwrap();
        assert!(!reopened.lock().admission_ready());
        reopened.lock().reconcile_owner();
        assert!(!reopened.lock().admission_ready());
    }

    #[test]
    fn abandoned_uncertainty_or_pending_bytes_cannot_be_released_by_drop() {
        for pending in [false, true] {
            let registry = Mutex::new(HashMap::new());
            let owner = DeviceDisk::open_registered(&registry, 12, 4096).unwrap();
            if pending {
                owner.lock().set_pending(8192).unwrap();
            } else {
                owner.lock().fail_owner();
            }
            drop(owner);
            let reopened = DeviceDisk::open_registered(&registry, 12, 0).unwrap();
            assert!(!reopened.lock().admission_ready());
            assert_eq!(*reopened.lock(), if pending { 8192 } else { 0 });
            reopened.lock().reconcile_owner();
            assert!(!reopened.lock().admission_ready());
        }
    }
}
