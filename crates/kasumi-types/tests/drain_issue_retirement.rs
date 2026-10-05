//! Observe the actual system deallocation boundary, including racing final
//! clones. Original error retirement must follow release of its issue Arc.
use kasumi_types::drain::{DrainIssue, DrainIssueRef, DrainReport};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::{
    Arc, Barrier,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

struct Observed;
#[global_allocator]
static ALLOCATOR: Observed = Observed;
static WATCHED: AtomicUsize = AtomicUsize::new(0);
static SHELL_FREED: AtomicBool = AtomicBool::new(false);
static ERROR_DROPS: AtomicUsize = AtomicUsize::new(0);
static EARLY_ERROR_DROP: AtomicBool = AtomicBool::new(false);

// SAFETY: pointer operations forward their original arguments unchanged to
// System. Observation compares addresses as integers, never dereferencing freed
// storage. The hook uses only atomics and cannot allocate.
unsafe impl GlobalAlloc for Observed {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        unsafe { System.realloc(ptr, layout, size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let target = WATCHED.load(Ordering::Acquire);
        let base = ptr as usize;
        let matches = target != 0 && target >= base && target - base < layout.size();
        let watched = matches
            && WATCHED
                .compare_exchange(target, 0, Ordering::AcqRel, Ordering::Acquire)
                .is_ok();
        unsafe { System.dealloc(ptr, layout) };
        if watched {
            SHELL_FREED.store(true, Ordering::Release);
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("original observation {0}")]
struct OriginalError(u64);
impl Drop for OriginalError {
    fn drop(&mut self) {
        if !SHELL_FREED.load(Ordering::Acquire) {
            EARLY_ERROR_DROP.store(true, Ordering::Release);
        }
        ERROR_DROPS.fetch_add(1, Ordering::AcqRel);
    }
}

#[test]
fn issue_shell_retires_before_original_error_with_concurrent_final_clones() {
    for handles in [1, 2, 8] {
        for attempt in 0..16 {
            SHELL_FREED.store(false, Ordering::Release);
            EARLY_ERROR_DROP.store(false, Ordering::Release);
            ERROR_DROPS.store(0, Ordering::Release);
            let mut report = DrainReport::default();
            let issue = report.record("worker", attempt, OriginalError(71).into());
            let original = issue.error().downcast_ref::<OriginalError>().unwrap();
            let error_address = original as *const OriginalError;
            let failure = report.complete().unwrap_err();
            let mut parent = DrainReport::default();
            parent.merge(&failure);
            assert!(DrainIssueRef::ptr_eq(&issue, &parent.issues()[0]));
            assert_eq!(
                parent.issues()[0]
                    .error()
                    .downcast_ref::<OriginalError>()
                    .unwrap() as *const OriginalError,
                error_address
            );
            let mut aliases = Vec::with_capacity(handles);
            for _ in 0..handles {
                aliases.push(issue.clone());
            }
            drop((report, failure, parent));
            WATCHED.store((&*issue as *const DrainIssue) as usize, Ordering::Release);
            drop(issue);
            assert!(!SHELL_FREED.load(Ordering::Acquire));
            assert_eq!(ERROR_DROPS.load(Ordering::Acquire), 0);
            let barrier = Arc::new(Barrier::new(handles + 1));
            let workers: Vec<_> = aliases
                .into_iter()
                .map(|alias| {
                    let barrier = barrier.clone();
                    std::thread::spawn(move || {
                        barrier.wait();
                        drop(alias);
                    })
                })
                .collect();
            barrier.wait();
            for worker in workers {
                worker.join().unwrap();
            }
            assert!(
                SHELL_FREED.load(Ordering::Acquire),
                "did not observe the issue allocation's actual release"
            );
            assert_eq!(WATCHED.load(Ordering::Acquire), 0);
            assert_eq!(ERROR_DROPS.load(Ordering::Acquire), 1);
            assert!(
                !EARLY_ERROR_DROP.load(Ordering::Acquire),
                "original error retired before its enclosing issue allocation"
            );
        }
    }
}
