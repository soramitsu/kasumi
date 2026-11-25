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

/// In-place bottom-up heapsort with cancellation before every comparison.
/// Each sift follows the larger child down to a leaf, one comparison per
/// level, then climbs back to where the sifted item belongs, which is nearly
/// always close to the bottom. That takes about half the comparisons of
/// testing the item against both children at every level, with no workspace.
/// `compare` must be a total order: the result is then the sorted order,
/// whatever the algorithm. Returning an error discards this private result;
/// the comparator never changes ordering mid-sort.
pub(crate) fn sort<T>(
    items: &mut [T],
    token: &QueryCancellation,
    compare: impl Fn(&T, &T) -> std::cmp::Ordering,
) -> Result<()> {
    fn sift<T>(
        items: &mut [T],
        root: usize,
        end: usize,
        token: &QueryCancellation,
        compare: &impl Fn(&T, &T) -> std::cmp::Ordering,
    ) -> Result<()> {
        let mut node = root;
        while let Some(left) = node
            .checked_mul(2)
            .and_then(|x| x.checked_add(1))
            .filter(|x| *x < end)
        {
            let right = left + 1;
            node = if right < end {
                token.check()?;
                if compare(&items[left], &items[right]).is_lt() {
                    right
                } else {
                    left
                }
            } else {
                left
            };
        }
        // The deepest node on that path whose item is greater than the
        // root's: sifting down would stop there, as no item below it is.
        while node > root {
            token.check()?;
            if compare(&items[root], &items[node]).is_lt() {
                break;
            }
            node = (node - 1) / 2;
        }
        // The root's item moves to that node, and each item on the path
        // above it moves up one level.
        while node > root {
            items.swap(root, node);
            node = (node - 1) / 2;
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

    /// Deterministic pseudo-random values in `0..range`.
    fn values(len: usize, range: u64, mut state: u64) -> Vec<u64> {
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state % range
            })
            .collect()
    }

    #[test]
    fn sort_matches_reference_for_every_small_length_and_shape() {
        let token = QueryCancellation::default();
        for len in 0..=130 {
            let shapes = [
                (0..len as u64).collect::<Vec<_>>(),
                (0..len as u64).rev().collect(),
                vec![7; len],
                values(len, 3, 0x2545_f491_4f6c_dd1d + len as u64),
                values(len, u64::MAX, 0x9e37_79b9_7f4a_7c15 ^ len as u64),
            ];
            for mut data in shapes {
                let mut reference = data.clone();
                reference.sort();
                sort(&mut data, &token, Ord::cmp).unwrap();
                assert_eq!(data, reference, "length {len}");
            }
        }
    }

    #[test]
    fn sort_orders_distinct_keys_with_about_one_comparison_per_level() {
        let len = 50_000;
        // Distinct (key, tie-breaker) pairs, as query rows order with their ID.
        let mut data: Vec<_> = values(len, 10_000, 0x5851_f42d_4c95_7f2d)
            .into_iter()
            .zip(0..)
            .collect::<Vec<(u64, u32)>>();
        let mut reference = data.clone();
        reference.sort();
        let count = std::cell::Cell::new(0u64);
        sort(&mut data, &QueryCancellation::default(), |a, b| {
            count.set(count.get() + 1);
            a.cmp(b)
        })
        .unwrap();
        assert_eq!(data, reference);
        // Sifting with two comparisons per level takes about 2 n log2 n.
        let levels = (len as f64).log2();
        assert!(
            (count.get() as f64) < 1.15 * len as f64 * levels,
            "{} comparisons",
            count.get()
        );
    }
}
