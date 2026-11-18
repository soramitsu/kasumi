//! Fixed admission and ownership census for startup lifecycles.
//!
//! Each seat holds one prepaid typed startup terminal. The census is allocated
//! with the core, so seat reservation itself never allocates.
use super::{MemoryCore, allocation_bytes};
use kasumi_types::{Error, ErrorCode, Result};

#[path = "prepaid_startup.rs"]
pub mod prepaid;
pub use prepaid::{
    PrepaidStartup, PreparedStartup, StartupBacking, StartupTerminal, StartupTerminalId,
    StartupTerminalLoan, StartupWorkerReport,
};

fn next_generation() -> Result<u64> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_update(
        std::sync::atomic::Ordering::SeqCst,
        std::sync::atomic::Ordering::SeqCst,
        |value| value.checked_add(1),
    )
    .map_err(|_| Error::new(ErrorCode::Unavailable, "startup identity exhausted"))
}

struct CensusSlot {
    generation: u64,
    reserved: bool,
    owner: Option<prepaid::ErasedTerminal>,
}
pub(super) struct Census {
    slots: Box<[CensusSlot]>,
}
impl Census {
    pub(super) fn required_bytes(capacity: usize) -> anyhow::Result<u64> {
        allocation_bytes::<CensusSlot>(capacity)
    }
    pub(super) fn allocate(capacity: usize) -> anyhow::Result<Self> {
        let mut slots = Vec::new();
        slots.try_reserve_exact(capacity)?;
        slots.resize_with(capacity, || CensusSlot {
            generation: 0,
            reserved: false,
            owner: None,
        });
        Ok(Self {
            slots: slots.into_boxed_slice(),
        })
    }
}

impl MemoryCore {
    /// Seats in the census, as configured by `max_startup_scopes`; bounds an
    /// admitted traversal of `prepaid_startup_at`.
    pub fn startup_scope_capacity(&self) -> usize {
        self.data.config.max_startup_scopes
    }
}
