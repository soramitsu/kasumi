//! OpenRaft joins its core before its state-machine, snapshot, and replication
//! workers necessarily finish. Track their actual storage ownership separately.

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
