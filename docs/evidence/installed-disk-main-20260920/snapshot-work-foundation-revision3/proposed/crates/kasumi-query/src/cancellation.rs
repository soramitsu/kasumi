use kasumi_types::{Error, ErrorCode, Result};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

/// Cooperative cancellation for query evaluation only. Never use this to change
/// the outcome of a committed state-machine operation.
#[derive(Clone, Debug, Default)]
pub struct QueryCancellation(Arc<CancellationState>);
#[derive(Debug, Default)]
struct CancellationState {
    cancelled: AtomicBool,
    #[cfg(test)]
    checks_left: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    limit_checks: AtomicBool,
}

impl QueryCancellation {
    /// Concrete shared-state storage, including this crate's active cfg layout.
    /// Admission planners must additionally cover Arc and allocator bookkeeping;
    /// the inline QueryCancellation value contains only the shared owner handle.
    pub const fn shared_state_bytes() -> usize {
        std::mem::size_of::<CancellationState>()
    }

    pub fn cancel(&self) {
        self.0.cancelled.store(true, Ordering::Release);
    }
    pub fn is_cancelled(&self) -> bool {
        self.0.cancelled.load(Ordering::Acquire)
    }
    pub fn check(&self) -> Result<()> {
        #[cfg(test)]
        if self.0.limit_checks.load(Ordering::Relaxed)
            && self
                .0
                .checks_left
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |left| {
                    left.checked_sub(1)
                })
                .is_err()
        {
            self.cancel();
        }
        if self.is_cancelled() {
            Err(Error::new(
                ErrorCode::ResourceExhausted,
                "query work cancelled",
            ))
        } else {
            Ok(())
        }
    }
    #[cfg(test)]
    pub(crate) fn after_checks(checks: usize) -> Self {
        let token = Self::default();
        token.0.checks_left.store(checks, Ordering::Relaxed);
        token.0.limit_checks.store(true, Ordering::Relaxed);
        token
    }
}

/// In-place heapsort with cancellation at every comparison. Returning an error
/// discards this private result; the comparator never changes ordering mid-sort.
pub(crate) fn sort<T>(
    items: &mut [T],
    token: &QueryCancellation,
    compare: impl Fn(&T, &T) -> std::cmp::Ordering,
) -> Result<()> {
    fn sift<T>(
        items: &mut [T],
        mut root: usize,
        end: usize,
        token: &QueryCancellation,
        compare: &impl Fn(&T, &T) -> std::cmp::Ordering,
    ) -> Result<()> {
        while let Some(left) = root
            .checked_mul(2)
            .and_then(|x| x.checked_add(1))
            .filter(|x| *x < end)
        {
            token.check()?;
            let right = left + 1;
            let child = if right < end && compare(&items[left], &items[right]).is_lt() {
                right
            } else {
                left
            };
            if !compare(&items[root], &items[child]).is_lt() {
                break;
            }
            items.swap(root, child);
            root = child;
        }
        Ok(())
    }
    token.check()?;
    for root in (0..items.len() / 2).rev() {
        sift(items, root, items.len(), token, &compare)?;
    }
    for end in (1..items.len()).rev() {
        token.check()?;
        items.swap(0, end);
        sift(items, 0, end, token, &compare)?;
    }
    token.check()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancellation_during_sort_stops_comparisons() {
        let token = QueryCancellation::default();
        let count = std::cell::Cell::new(0);
        let mut data: Vec<_> = (0..10_000).rev().collect();
        let error = sort(&mut data, &token, |a, b| {
            count.set(count.get() + 1);
            if count.get() == 100 {
                token.cancel();
            }
            a.cmp(b)
        })
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::ResourceExhausted);
        assert!(count.get() <= 102);
    }
    #[test]
    fn sort_matches_reference_with_duplicates() {
        let mut data: Vec<_> = (0..10_000).map(|x| (x * 7919) % 233).collect();
        let mut reference = data.clone();
        reference.sort();
        sort(&mut data, &QueryCancellation::default(), Ord::cmp).unwrap();
        assert_eq!(data, reference);
    }
}
