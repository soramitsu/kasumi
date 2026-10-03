//! Operation-owned query admission. These counters describe explicitly admitted
//! allocations, not process RSS or a complete census of third-party libraries.
use kasumi_types::{Error, ErrorCode, Limits, QueryRequest, Result};

/// Keep at least this absolute allowance with the actual work and its output.
/// Successful growth must remain owned until this provider is dropped; a failed
/// request must leave its previous allowance intact. Implementations must not
/// acquire a new operation slot for every increase.
pub trait QueryWorkspace {
    fn ensure_peak(&mut self, total_bytes: u64) -> Result<()>;
}

/// One ledger travels through planning, evaluation and retained output. Its
/// provider can have a larger pre-admitted floor than the logical live bytes.
/// It must outlive the allocations it accounts for, including an uncollected
/// worker result. Source-owned decode loans have their own admission.
pub struct QueryMemory<W: QueryWorkspace> {
    workspace: W,
    live: u64,
    peak: u64,
    floor: u64,
}

impl<W: QueryWorkspace> QueryMemory<W> {
    /// Take custody without admitting any new bytes or inspecting the provider.
    /// When live inputs already exist, place them before this ledger in their
    /// owning struct, then call `reserve` through that owner. A denied initial
    /// claim must not drop the provider before those inputs are destroyed.
    pub fn empty(workspace: W) -> Self {
        Self {
            workspace,
            live: 0,
            peak: 0,
            floor: 0,
        }
    }

    /// `initial_live_bytes` accounts for inputs owned by this operation. Do not
    /// include independently admitted shared generation data or spare capacity
    /// in the provider's existing reservation. Failure drops the provider; use
    /// `empty` and an owning struct when pre-existing payloads depend on it.
    pub fn new(workspace: W, initial_live_bytes: u64) -> Result<Self> {
        let mut memory = Self::empty(workspace);
        memory.reserve(initial_live_bytes)?;
        memory.floor = initial_live_bytes;
        Ok(memory)
    }

    /// Admit growth before allocating, including any old/new capacity overlap.
    /// Arithmetic overflow and provider denial leave both counters unchanged.
    pub fn reserve(&mut self, additional_bytes: u64) -> Result<()> {
        let live = self
            .live
            .checked_add(additional_bytes)
            .ok_or_else(overflow)?;
        if live > self.peak {
            self.workspace.ensure_peak(live)?;
        }
        self.live = live;
        self.peak = self.peak.max(live);
        Ok(())
    }

    /// Forget bytes only after their allocation is destroyed or ownership has
    /// transferred to another admitted owner. This never reduces the provider's
    /// peak allowance and cannot release an enclosing scope's retained inputs.
    pub fn release(&mut self, bytes: u64) -> Result<()> {
        let live = self
            .live
            .checked_sub(bytes)
            .filter(|live| *live >= self.floor)
            .ok_or_else(inconsistent)?;
        self.live = live;
        Ok(())
    }

    /// Run scratch work above the current live baseline. A successful closure
    /// returns its value and the additional, already-admitted bytes retained by
    /// that value. The closure's other locals must own its scratch allocations,
    /// so they drop before this method restores the baseline. On error, query
    /// scratch must not escape in the error; independently owned source failures
    /// keep their separate custody. The peak remains charged on every outcome.
    pub fn scope<T, E: From<Error>>(
        &mut self,
        run: impl FnOnce(&mut Self) -> std::result::Result<(T, u64), E>,
    ) -> std::result::Result<T, E> {
        let baseline = self.live;
        let previous_floor = self.floor;
        self.floor = baseline;
        let mut scope = Scope {
            memory: self,
            baseline,
            previous_floor,
            retained: 0,
        };
        match run(&mut *scope.memory) {
            Ok((value, retained)) => {
                if retained > scope.memory.live - baseline {
                    // The output must be destroyed while its allowance is still
                    // live, before Scope::drop restores the enclosing baseline.
                    drop(value);
                    return Err(inconsistent().into());
                }
                scope.retained = retained;
                Ok(value)
            }
            Err(error) => Err(error),
        }
    }

    pub fn live_bytes(&self) -> u64 {
        self.live
    }

    /// Logical peak, which can be smaller than a provider's pre-admitted floor.
    pub fn peak_bytes(&self) -> u64 {
        self.peak
    }

    /// Inspect the retained provider without moving it or resetting this ledger.
    /// This is used to bind an existing operation grant to its actual worker
    /// owner. Admission growth still goes through this ledger; no mutable
    /// provider or ownership extraction is exposed by this borrow.
    pub fn workspace(&self) -> &W {
        &self.workspace
    }

    /// Transfer the unchanged peak allowance with its surviving output owner.
    pub fn into_workspace(self) -> W {
        self.workspace
    }
}

struct Scope<'a, W: QueryWorkspace> {
    memory: &'a mut QueryMemory<W>,
    baseline: u64,
    previous_floor: u64,
    retained: u64,
}
impl<W: QueryWorkspace> Drop for Scope<'_, W> {
    fn drop(&mut self) {
        // Success validated retained <= live - baseline; error and unwind keep
        // retained at zero. No arithmetic can fail while unwinding.
        self.memory.live = self.baseline + self.retained;
        self.memory.floor = self.previous_floor;
    }
}

fn overflow() -> Error {
    Error::new(
        ErrorCode::ResourceExhausted,
        "query workspace size overflow",
    )
}
fn inconsistent() -> Error {
    Error::new(ErrorCode::Unavailable, "query workspace accounting differs")
}

pub(crate) fn bytes(value: usize) -> Result<u64> {
    u64::try_from(value).map_err(|_| overflow())
}
pub(crate) fn product(left: u64, right: u64) -> Result<u64> {
    left.checked_mul(right).ok_or_else(overflow)
}
fn sum(left: u64, right: u64) -> Result<u64> {
    left.checked_add(right).ok_or_else(overflow)
}

/// Initial allowance for the still-provisional recursive planner, group and
/// search work. Selected rows, ID/string-sort copies and row JSON clones have
/// separate allocation claims; they must not be counted a second time here.
/// Aggregate output, decimal arithmetic, candidate-tree internals, Tantivy and
/// Lindera remain unqualified. A continuation's existing allowance remains
/// provisional until its caller admits the actual page clone.
pub fn query_workspace_estimate(limits: &Limits, request: &QueryRequest) -> Result<u64> {
    if request.cursor.is_some() {
        return product(bytes(limits.max_result_bytes)?, 2);
    }
    let candidates = product(bytes(limits.max_query_candidates)?, 128)?;
    if request.aggregates.is_empty() {
        return Ok(candidates);
    }
    let output = product(bytes(limits.max_result_bytes)?, 3)?;
    let groups = product(
        bytes(limits.max_query_groups)?,
        sum(128, product(bytes(request.aggregates.len())?, 96)?)?,
    )?;
    sum(sum(output, candidates)?, groups)
}

/// imbl 7's borrowed iterators own two traversal Vecs. Every branch has at
/// least two children, so addressable trees have fewer than usize::BITS levels.
/// This includes both cursors and allocator slack before iterator construction.
/// Recursive planner iterators remain covered only by its provisional term.
pub(crate) fn imbl_iterator_bytes() -> Result<u64> {
    product(
        crate::allocation::vec_bytes::<(usize, *const ())>(usize::BITS as usize)?,
        2,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    struct Bounded {
        limit: u64,
        charge: Rc<Cell<u64>>,
        calls: Rc<RefCell<Vec<u64>>>,
    }
    impl QueryWorkspace for Bounded {
        fn ensure_peak(&mut self, total: u64) -> Result<()> {
            self.calls.borrow_mut().push(total);
            if total > self.limit {
                return Err(Error::new(ErrorCode::ResourceExhausted, "fixture budget"));
            }
            self.charge.set(self.charge.get().max(total));
            Ok(())
        }
    }
    impl Drop for Bounded {
        fn drop(&mut self) {
            self.charge.set(0);
        }
    }
    fn bounded(limit: u64) -> Bounded {
        Bounded {
            limit,
            charge: Rc::new(Cell::new(0)),
            calls: Rc::default(),
        }
    }

    #[test]
    fn growth_denial_and_overflow_leave_the_previous_allowance_intact() {
        let provider = bounded(100);
        let charge = provider.charge.clone();
        let mut memory = QueryMemory::new(provider, 10).unwrap();
        memory.reserve(40).unwrap();
        assert_eq!(
            memory.reserve(51).unwrap_err().code,
            ErrorCode::ResourceExhausted
        );
        assert_eq!(
            (memory.live_bytes(), memory.peak_bytes(), charge.get()),
            (50, 50, 50)
        );
        assert_eq!(
            memory.reserve(u64::MAX).unwrap_err().code,
            ErrorCode::ResourceExhausted
        );
        assert_eq!(
            (memory.live_bytes(), memory.peak_bytes(), charge.get()),
            (50, 50, 50)
        );
        memory.release(20).unwrap();
        memory.reserve(15).unwrap();
        assert_eq!(&*memory.workspace.calls.borrow(), &[10, 50, 101]);
        drop(memory);
        assert_eq!(charge.get(), 0);
    }

    #[test]
    fn consecutive_scopes_admit_previous_output_as_live_baseline() {
        let mut memory = QueryMemory::new(bounded(100), 5).unwrap();
        memory
            .scope::<_, Error>(|memory| {
                memory.reserve(60)?;
                Ok(((), 30))
            })
            .unwrap();
        assert_eq!((memory.live_bytes(), memory.peak_bytes()), (35, 65));
        memory
            .scope::<_, Error>(|memory| {
                assert_eq!(memory.live_bytes(), 35);
                memory.reserve(60)?;
                Ok(((), 20))
            })
            .unwrap();
        assert_eq!((memory.live_bytes(), memory.peak_bytes()), (55, 95));
        assert_eq!(&*memory.workspace.calls.borrow(), &[5, 65, 95]);
    }

    #[test]
    fn nested_scopes_preserve_outer_inputs_and_restore_floors_on_error() {
        let mut memory = QueryMemory::new(bounded(200), 10).unwrap();
        memory
            .scope::<_, Error>(|memory| {
                memory.reserve(40)?;
                let error = memory
                    .scope::<(), Error>(|memory| {
                        memory.reserve(100)?;
                        memory.release(101)?;
                        Ok(((), 0))
                    })
                    .unwrap_err();
                assert_eq!(error.code, ErrorCode::Unavailable);
                assert_eq!(memory.live_bytes(), 50);
                memory.scope::<_, Error>(|memory| {
                    memory.reserve(30)?;
                    Ok(((), 20))
                })?;
                memory.release(20)?;
                Ok(((), 10))
            })
            .unwrap();
        assert_eq!((memory.live_bytes(), memory.peak_bytes()), (20, 150));
        assert!(memory.release(11).is_err());
        assert!(memory.release(u64::MAX).is_err());
        assert_eq!(memory.live_bytes(), 20);
    }

    struct Allocation {
        charge: Rc<Cell<u64>>,
        dropped: Rc<Cell<bool>>,
        minimum: u64,
    }
    impl Drop for Allocation {
        fn drop(&mut self) {
            assert!(self.charge.get() >= self.minimum);
            self.dropped.set(true);
        }
    }

    #[test]
    fn unwind_drops_scratch_before_restoring_nested_baseline() {
        let provider = bounded(200);
        let charge = provider.charge.clone();
        let dropped = Rc::new(Cell::new(false));
        let mut memory = QueryMemory::new(provider, 10).unwrap();
        memory
            .scope::<_, Error>(|memory| {
                memory.reserve(30)?;
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    memory.scope::<(), Error>(|memory| {
                        memory.reserve(80)?;
                        let _scratch = Allocation {
                            charge: charge.clone(),
                            dropped: dropped.clone(),
                            minimum: 120,
                        };
                        panic!("fixture interrupted");
                    })
                }));
                assert!(result.is_err());
                assert!(dropped.get());
                assert_eq!(memory.live_bytes(), 40);
                memory.release(20)?;
                Ok(((), 10))
            })
            .unwrap();
        assert_eq!(
            (memory.live_bytes(), memory.peak_bytes(), charge.get()),
            (20, 120, 120)
        );
    }

    #[test]
    fn invalid_output_accounting_destroys_output_without_releasing_peak() {
        let provider = bounded(100);
        let charge = provider.charge.clone();
        let dropped = Rc::new(Cell::new(false));
        let mut memory = QueryMemory::new(provider, 10).unwrap();
        let error = memory
            .scope::<_, Error>(|memory| {
                memory.reserve(30)?;
                Ok((
                    Allocation {
                        charge: charge.clone(),
                        dropped: dropped.clone(),
                        minimum: 40,
                    },
                    31,
                ))
            })
            .err()
            .unwrap();
        assert_eq!(error.code, ErrorCode::Unavailable);
        assert!(dropped.get());
        assert_eq!(
            (memory.live_bytes(), memory.peak_bytes(), charge.get()),
            (10, 40, 40)
        );
    }

    #[test]
    fn completed_output_keeps_provider_until_payload_drop_and_handoff() {
        struct Output {
            payload: Allocation,
            memory: QueryMemory<Bounded>,
        }
        let provider = bounded(100);
        let charge = provider.charge.clone();
        let dropped = Rc::new(Cell::new(false));
        let mut memory = QueryMemory::new(provider, 0).unwrap();
        let payload = memory
            .scope::<_, Error>(|memory| {
                memory.reserve(60)?;
                Ok((
                    Allocation {
                        charge: charge.clone(),
                        dropped: dropped.clone(),
                        minimum: 60,
                    },
                    20,
                ))
            })
            .unwrap();
        let output = Output { payload, memory };
        assert_eq!(output.memory.live_bytes(), 20);
        assert_eq!(charge.get(), 60);
        let Output { payload, memory } = output;
        let provider = memory.into_workspace();
        assert_eq!(charge.get(), 60);
        drop(payload);
        assert!(dropped.get());
        drop(provider);
        assert_eq!(charge.get(), 0);
    }

    #[test]
    fn empty_takes_custody_before_initial_admission_can_fail() {
        struct Input {
            _payload: Allocation,
            memory: QueryMemory<Bounded>,
        }
        let provider = bounded(10);
        let charge = provider.charge.clone();
        // The provider already owns this input's allowance before handoff.
        charge.set(10);
        let dropped = Rc::new(Cell::new(false));
        let mut input = Input {
            _payload: Allocation {
                charge: charge.clone(),
                dropped: dropped.clone(),
                minimum: 10,
            },
            memory: QueryMemory::empty(provider),
        };
        assert!(input.memory.workspace.calls.borrow().is_empty());
        assert_eq!(
            (input.memory.live_bytes(), input.memory.peak_bytes()),
            (0, 0)
        );
        assert!(input.memory.reserve(20).is_err());
        assert_eq!(charge.get(), 10);
        assert!(!dropped.get());
        drop(input);
        assert!(dropped.get());
        assert_eq!(charge.get(), 0);
    }

    #[test]
    fn initial_baseline_and_estimate_overflow_are_rejected() {
        assert!(QueryMemory::new(bounded(9), 10).is_err());
        let limits = Limits {
            max_query_candidates: usize::MAX,
            ..Limits::default()
        };
        let request: QueryRequest =
            serde_json::from_value(serde_json::json!({ "collection": "docs" })).unwrap();
        assert_eq!(
            query_workspace_estimate(&limits, &request)
                .unwrap_err()
                .code,
            ErrorCode::ResourceExhausted
        );
    }
}
