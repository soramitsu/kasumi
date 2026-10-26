//! Exact invalidation for callers that keep decoded rows in memory.
//!
//! A cache owner watches the few namespaces it caches. Every write of this
//! store that names a watched namespace holds a fence across its synchronous
//! commit attempt: the namespace epoch is odd from before the write begins
//! until its commit attempt has returned, successful or not, and then becomes
//! even again. A row read between two equal even samples of the epoch is
//! therefore exactly the committed row until the epoch next changes. Epochs
//! cover only this in-process owner, never another process or a reopened store.
//!
//! Write-once identities cannot change once present (`write_domain` refuses a
//! different value or a delete, and namespace replacement refuses them), so a
//! present value is retained after its first authenticated read.
use super::*;

/// One fence word records every watched namespace of a write.
const MAX_WATCHED_NAMESPACES: usize = 64;
/// The largest retained write-once identity value; larger values are re-read.
const MAX_RETAINED_IDENTITY_BYTES: usize = 4096;

type Watched = Vec<(Box<str>, Arc<AtomicU64>)>;
type RetainedIdentity = (String, Vec<u8>, Zeroizing<Vec<u8>>);

#[derive(Default)]
pub(crate) struct CachedRows {
    watched: RwLock<Watched>,
    identities: Mutex<Vec<RetainedIdentity>>,
}

/// The write epoch of one watched namespace of one store.
#[derive(Clone)]
pub struct NamespaceEpoch(Arc<AtomicU64>);

impl NamespaceEpoch {
    /// Odd while a write of the namespace is in flight.
    pub fn current(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// Held by one write from before it begins until its commit attempt returns.
pub(crate) struct NamespaceWriteFence<'a> {
    watched: parking_lot::RwLockReadGuard<'a, Watched>,
    fenced: u64,
}

impl NamespaceWriteFence<'_> {
    fn advance(&self) {
        let mut fenced = self.fenced;
        while fenced != 0 {
            self.watched[fenced.trailing_zeros() as usize]
                .1
                .fetch_add(1, Ordering::SeqCst);
            fenced &= fenced - 1;
        }
    }
}

impl Drop for NamespaceWriteFence<'_> {
    fn drop(&mut self) {
        self.advance();
    }
}

impl CachedRows {
    /// Fence every watched namespace among `namespaces` for one write.
    pub(crate) fn fence<'n>(
        &self,
        namespaces: impl IntoIterator<Item = &'n str>,
    ) -> NamespaceWriteFence<'_> {
        // Recursive acquisition never waits behind a pending registration, so
        // a thread already holding this store's fence cannot deadlock on it.
        let watched = self.watched.read_recursive();
        let mut fenced = 0;
        if !watched.is_empty() {
            for namespace in namespaces {
                if let Some(index) = watched.iter().position(|(name, _)| **name == *namespace) {
                    fenced |= 1 << index;
                }
            }
        }
        let fence = NamespaceWriteFence { watched, fenced };
        fence.advance();
        fence
    }

    pub(crate) fn fence_operations(&self, operations: &[WriteOp]) -> NamespaceWriteFence<'_> {
        self.fence_replacing(&[], operations)
    }

    pub(crate) fn fence_replacing(
        &self,
        replacements: &[NamespaceReplacement<'_>],
        operations: &[WriteOp],
    ) -> NamespaceWriteFence<'_> {
        self.fence(
            replacements
                .iter()
                .map(NamespaceReplacement::namespace)
                .chain(operations.iter().map(|operation| match operation {
                    WriteOp::Put { namespace, .. } | WriteOp::Delete { namespace, .. } => {
                        namespace.as_str()
                    }
                })),
        )
    }
}

impl TenantStore {
    /// Watch `namespace` for an in-process cache of its decoded rows. A cached
    /// row read after an even epoch sample stays exact while a later sample is
    /// equal. Registration waits for in-flight writes, so a new epoch never
    /// misses a commit attempt that began before it.
    pub fn namespace_epoch(&self, namespace: &str) -> Result<NamespaceEpoch> {
        let mut watched = self.cached_rows.watched.write();
        if let Some((_, epoch)) = watched.iter().find(|(name, _)| **name == *namespace) {
            return Ok(NamespaceEpoch(epoch.clone()));
        }
        ensure!(
            watched.len() < MAX_WATCHED_NAMESPACES,
            "too many watched namespaces"
        );
        let epoch = Arc::new(AtomicU64::new(0));
        watched.push((namespace.into(), epoch.clone()));
        Ok(NamespaceEpoch(epoch))
    }

    /// Read a write-once identity, retaining a present value after its first
    /// authenticated read. Every call still requires current key access.
    pub fn get_write_once_identity(
        &self,
        namespace: &str,
        key: &[u8],
        max_value_bytes: usize,
    ) -> Result<Option<Zeroizing<Vec<u8>>>> {
        ensure!(
            is_paired_identity(namespace, key),
            "not a retained write-once identity"
        );
        let retained = self
            .cached_rows
            .identities
            .lock()
            .iter()
            .find(|(name, row, _)| name == namespace && row == key)
            .map(|(_, _, value)| value.clone());
        if let Some(value) = retained {
            self.check_access()?;
            ensure!(
                value.len() <= max_value_bytes,
                "record exceeds caller read budget"
            );
            return Ok(Some(value));
        }
        let Some(value) = self.get_bounded(namespace, key, max_value_bytes)? else {
            return Ok(None);
        };
        let value = Zeroizing::new(value.to_vec());
        if value.len() <= MAX_RETAINED_IDENTITY_BYTES {
            let mut identities = self.cached_rows.identities.lock();
            if !identities
                .iter()
                .any(|(name, row, _)| name == namespace && row == key)
            {
                identities.push((namespace.to_owned(), key.to_vec(), value.clone()));
            }
        }
        Ok(Some(value))
    }
}

#[cfg(test)]
#[path = "cached_rows_tests.rs"]
mod tests;
