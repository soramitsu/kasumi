//! The Tokio runtime each Kasumi binary runs its async main on.
//!
//! An unoptimized build copies large storage owners by value through deep
//! async poll frames: the native database owner alone is 33 KB, and a debug
//! `kasumid init --mode standalone` needs between 8 and 9 MiB of stack, more
//! than the usual 8 MiB main thread. With debug assertions on, the main future
//! is therefore polled on its own thread, and every runtime worker and
//! blocking thread runs, with a `DEBUG_STACK_BYTES` stack. That is reserved
//! address space; pages are committed only as frames reach them. A release
//! build is exactly `#[tokio::main]`: the process's main thread and Tokio's
//! default thread stacks.

use std::{future::Future, process::ExitCode};

/// Stack of every runtime thread in a build with debug assertions.
pub const DEBUG_STACK_BYTES: usize = 64 << 20;

/// Run `main` to completion on a multi-threaded runtime with every driver
/// enabled. A panic in `main` unwinds out of this call, as it would out of
/// `#[tokio::main]`.
pub fn block_on<F, Fut>(main: F) -> ExitCode
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = ExitCode>,
{
    if !cfg!(debug_assertions) {
        return runtime(None).block_on(main());
    }
    let polled = std::thread::Builder::new()
        .name("main".into())
        .stack_size(DEBUG_STACK_BYTES)
        .spawn(move || runtime(Some(DEBUG_STACK_BYTES)).block_on(main()))
        .expect("failed to start the main runtime thread");
    match polled.join() {
        Ok(status) => status,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

fn runtime(stack_bytes: Option<usize>) -> tokio::runtime::Runtime {
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all();
    if let Some(bytes) = stack_bytes {
        builder.thread_stack_size(bytes);
    }
    builder.build().expect("Failed building the Runtime")
}
