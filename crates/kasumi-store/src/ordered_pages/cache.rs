//! Decrypted-page residency charged as optional cache credit.
//!
//! Every retained page is charged through the node's aggregate cache admission,
//! the same optional-cache origin the native ciphertext cache uses, so their
//! combined charges obey one ceiling. A page that does not fit is served
//! through the reader's bounded operation workspace and not retained. The
//! cache never funds committed work and never authorizes a read.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct CacheKey {
    domain: [u8; 16],
    id: PageId,
    sha256: [u8; 32],
}

struct Slot {
    page: Arc<Page>,
    charge: u64,
    tick: u64,
}

struct State {
    budget: u64,
    charged: u64,
    lease: Option<kasumi_kv::CacheMemoryLease>,
    pages: HashMap<CacheKey, Slot>,
    recency: BTreeMap<u64, CacheKey>,
    tick: u64,
    hits: u64,
    misses: u64,
    refusals: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PageCacheStats {
    pub budget: u64,
    pub charged: u64,
    /// Credit held from the admission provider; never above the budget.
    pub leased: u64,
    pub pages: usize,
    pub hits: u64,
    pub misses: u64,
    /// Insertions the provider refused under memory pressure.
    pub refusals: u64,
}

/// Least-recently-used decrypted pages up to `budget` charged bytes.
pub struct PageCache {
    memory: Arc<dyn NodeDiskMemoryAdmission>,
    state: Mutex<State>,
}

impl PageCache {
    pub fn new(memory: Arc<dyn NodeDiskMemoryAdmission>, budget: u64) -> Arc<Self> {
        Arc::new(Self {
            memory,
            state: Mutex::new(State {
                budget,
                charged: 0,
                lease: None,
                pages: HashMap::new(),
                recency: BTreeMap::new(),
                tick: 0,
                hits: 0,
                misses: 0,
                refusals: 0,
            }),
        })
    }

    pub fn stats(&self) -> PageCacheStats {
        let state = self.state.lock();
        PageCacheStats {
            budget: state.budget,
            charged: state.charged,
            leased: state
                .lease
                .as_ref()
                .map_or(0, |lease| lease.quote().credit_bytes()),
            pages: state.pages.len(),
            hits: state.hits,
            misses: state.misses,
            refusals: state.refusals,
        }
    }

    /// Shrinking evicts least recently used pages and returns their credit.
    pub fn set_budget(&self, budget: u64) {
        let mut state = self.state.lock();
        state.budget = budget;
        Self::evict_to(&mut state, budget);
    }

    pub(super) fn key(domain: &str, space: &str, tree: &[u8; 16], page: &PageRef) -> CacheKey {
        let mut digest = Sha256::new();
        digest.update((domain.len() as u64).to_be_bytes());
        digest.update(domain);
        digest.update(space);
        digest.update(tree);
        let domain: [u8; 32] = digest.finalize().into();
        CacheKey {
            domain: domain[..16].try_into().expect("digest prefix"),
            id: page.id,
            sha256: page.sha256,
        }
    }

    pub(super) fn get(&self, key: &CacheKey) -> Option<Arc<Page>> {
        let mut guard = self.state.lock();
        let state = &mut *guard;
        state.tick += 1;
        let tick = state.tick;
        let Some(slot) = state.pages.get_mut(key) else {
            state.misses += 1;
            return None;
        };
        state.recency.remove(&slot.tick);
        slot.tick = tick;
        state.recency.insert(tick, *key);
        state.hits += 1;
        Some(slot.page.clone())
    }

    /// Retain `page` if it fits. With `evict`, older pages make room; a
    /// preload never evicts what it already warmed. Returns whether the page
    /// is resident afterwards.
    pub(super) fn insert(&self, key: CacheKey, page: &Arc<Page>, evict: bool) -> bool {
        let charge = page.charge();
        let mut guard = self.state.lock();
        let state = &mut *guard;
        if state.pages.contains_key(&key) {
            return true;
        }
        if charge > state.budget {
            return false;
        }
        if state.charged + charge > state.budget {
            if !evict {
                return false;
            }
            let target = state.budget - charge;
            Self::evict_to(state, target);
        }
        let credit = state.charged + charge;
        let granted = match state.lease.as_mut() {
            Some(lease) => lease.try_grow_to(credit).is_ok(),
            None => match self.memory.clone().reserve_cache_memory(credit) {
                Ok(lease) => {
                    state.lease = Some(lease);
                    true
                }
                Err(_) => false,
            },
        };
        if !granted {
            // Node-wide pressure: keep serving through bounded reads.
            state.refusals += 1;
            return false;
        }
        state.tick += 1;
        let tick = state.tick;
        state.charged = credit;
        state.recency.insert(tick, key);
        state.pages.insert(
            key,
            Slot {
                page: page.clone(),
                charge,
                tick,
            },
        );
        true
    }

    fn evict_to(state: &mut State, target: u64) {
        while state.charged > target {
            let Some((_, key)) = state.recency.pop_first() else {
                break;
            };
            if let Some(slot) = state.pages.remove(&key) {
                state.charged -= slot.charge;
            }
        }
        if let Some(lease) = state.lease.as_mut() {
            lease.shrink_to(state.charged);
        }
    }
}
