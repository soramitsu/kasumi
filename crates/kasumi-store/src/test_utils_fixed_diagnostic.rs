//! Fixture diagnostics use bounded stack storage and the existing descriptor.
//! Stdio mutex contention can initialize per-thread parking backing after a
//! refused grant. Logging must not introduce that unadmitted allocation.
use std::fmt::{self, Write};

pub(super) fn write(arguments: fmt::Arguments<'_>) {
    struct Buffer {
        bytes: [u8; 1024],
        len: usize,
    }
    impl fmt::Write for Buffer {
        fn write_str(&mut self, value: &str) -> fmt::Result {
            let end = self.len.checked_add(value.len()).ok_or(fmt::Error)?;
            let destination = self.bytes.get_mut(self.len..end).ok_or(fmt::Error)?;
            destination.copy_from_slice(value.as_bytes());
            self.len = end;
            Ok(())
        }
    }
    let mut buffer = Buffer {
        bytes: [0; 1024],
        len: 0,
    };
    if buffer.write_fmt(arguments).is_ok() {
        // SAFETY: the complete initialized stack slice lives through write.
        // Descriptor 2 is the same process stderr used by the previous logger;
        // this call neither owns/closes it nor acquires Rust's stdio mutex.
        // Diagnostics remain best effort, independently of admission outcome.
        let _ = unsafe {
            libc::write(
                libc::STDERR_FILENO,
                buffer.bytes.as_ptr().cast(),
                buffer.len,
            )
        };
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn refusal_diagnostic_does_not_acquire_stdio_lock_or_allocate() {
        let stderr = std::io::stderr();
        let guard = stderr.lock();
        let (_, allocations) = crate::allocation_tests::measure(|| {
            super::write(format_args!(
                "fixed refusal diagnostic: bytes={} kind={:?}\n",
                u64::MAX,
                std::io::ErrorKind::OutOfMemory
            ));
        });
        drop(guard);
        assert_eq!(allocations, 0);
    }
}
