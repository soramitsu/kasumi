//! OpenRaft joins its core before its state-machine, snapshot, and replication
//! workers necessarily finish. Track their actual storage ownership separately.

use kasumi_store::{PlaintextValue, RetainedPlaintextValue, TenantStore};
use std::{ops::Deref, sync::Arc};
use tokio::sync::watch;

#[derive(Clone)]
pub(crate) struct StorageDrain(watch::Receiver<bool>);

pub(crate) struct StorageLease(watch::Sender<bool>);

impl StorageDrain {
    pub(crate) fn new() -> (Self, Arc<StorageLease>) {
        let (sender, receiver) = watch::channel(false);
        (Self(receiver), Arc::new(StorageLease(sender)))
    }

    pub(crate) async fn wait(&self) {
        let mut receiver = self.0.clone();
        // The final lease publishes completion before closing the sender. A
        // closed channel therefore also means that every tracked owner dropped.
        let _ = receiver.wait_for(|drained| *drained).await;
    }
}

impl Drop for StorageLease {
    fn drop(&mut self) {
        self.0.send_replace(true);
    }
}

/// Clone storage ownership and its shutdown lease together, including when a
/// blocking job outlives the future that was awaiting it. Deref exposes only &T,
/// so a caller cannot accidentally clone an untracked Arc out of this handle.
pub(crate) struct StorageHandle<T: ?Sized>(Arc<StorageOwner<T>>);

struct StorageOwner<T: ?Sized> {
    // Field drop order is significant: release the store/backend before the
    // last lease can wake shutdown and permit reopening its durable files.
    value: Arc<T>,
    _lease: Option<Arc<StorageLease>>,
}

impl<T: ?Sized> StorageHandle<T> {
    pub(crate) fn new(value: Arc<T>, lease: Option<Arc<StorageLease>>) -> Self {
        Self(Arc::new(StorageOwner {
            value,
            _lease: lease,
        }))
    }
}

/// An escaped plaintext result keeps the exact storage owner and shutdown
/// lease. Both fields are move-only; plaintext and its resident charge retire
/// before the final custody handle can announce storage drain.
pub(crate) struct StoragePlaintext {
    value: PlaintextValue,
    _custody: PlaintextCustody,
}

#[derive(Clone)]
enum PlaintextCustody {
    Store {
        _owner: StorageHandle<TenantStore>,
    },
    Domains {
        _owner: StorageHandle<crate::domains::Domains>,
    },
}

impl StoragePlaintext {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.value.as_bytes()
    }
}

impl Deref for StoragePlaintext {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// The immutable point control is paid by its original Store point lease.
/// Cloning this inline wrapper retains the SAME plaintext and existing storage
/// handle; it allocates neither a second byte Vec nor another control/grant.
#[derive(Clone)]
pub(crate) struct RetainedStoragePlaintext {
    value: RetainedPlaintextValue,
    _custody: PlaintextCustody,
}
impl RetainedStoragePlaintext {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.value.as_bytes()
    }
    pub(crate) fn is_from_memory(
        &self,
        memory: &Arc<dyn kasumi_store::NodeDiskMemoryAdmission>,
    ) -> bool {
        self.value.is_from_memory(memory)
    }
}

impl StorageHandle<TenantStore> {
    #[cfg(test)]
    pub(crate) fn get_retained(
        &self,
        namespace: &str,
        key: &[u8],
    ) -> anyhow::Result<Option<RetainedStoragePlaintext>> {
        self.0.value.get_retained(namespace, key).map(|value| {
            value.map(|value| RetainedStoragePlaintext {
                value,
                _custody: PlaintextCustody::Store {
                    _owner: self.clone(),
                },
            })
        })
    }
    pub(crate) fn get(
        &self,
        namespace: &str,
        key: &[u8],
    ) -> anyhow::Result<Option<StoragePlaintext>> {
        self.0.value.get(namespace, key).map(|value| {
            value.map(|value| StoragePlaintext {
                value,
                _custody: PlaintextCustody::Store {
                    _owner: self.clone(),
                },
            })
        })
    }
}

impl StorageHandle<crate::domains::Domains> {
    pub(crate) fn application_get_retained(
        &self,
        namespace: &str,
        key: &[u8],
    ) -> anyhow::Result<Option<RetainedStoragePlaintext>> {
        self.0
            .value
            .application()?
            .get_retained(namespace, key)
            .map(|value| {
                value.map(|value| RetainedStoragePlaintext {
                    value,
                    _custody: PlaintextCustody::Domains {
                        _owner: self.clone(),
                    },
                })
            })
    }

    pub(crate) fn application_get(
        &self,
        namespace: &str,
        key: &[u8],
    ) -> anyhow::Result<Option<StoragePlaintext>> {
        self.0
            .value
            .application()?
            .get(namespace, key)
            .map(|value| {
                value.map(|value| StoragePlaintext {
                    value,
                    _custody: PlaintextCustody::Domains {
                        _owner: self.clone(),
                    },
                })
            })
    }
}

impl<T: ?Sized> Clone for StorageHandle<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: ?Sized> Deref for StorageHandle<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0.value
    }
}

#[cfg(test)]
#[path = "lifetime_plaintext_tests.rs"]
mod plaintext_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[tokio::test]
    async fn drain_is_not_released_until_the_last_resource_is_dropped() {
        struct Resource(Arc<AtomicBool>);
        impl Drop for Resource {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let (drain, lease) = StorageDrain::new();
        let first = StorageHandle::new(Arc::new(Resource(dropped.clone())), Some(lease));
        let last = first.clone();
        drop(first);
        assert!(!*drain.0.borrow());
        assert!(!dropped.load(Ordering::Acquire));
        drop(last);
        drain.wait().await;
        assert!(dropped.load(Ordering::Acquire));
    }
}
