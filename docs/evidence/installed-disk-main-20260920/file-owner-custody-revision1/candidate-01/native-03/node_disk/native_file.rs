//! Inline custody for native descriptors used by admitted file operations.
use std::{fs::File, io, os::fd::IntoRawFd};

/// The original native close result is retained, not reconstructed from errno.
/// The consumed descriptor number is diagnostic only and must never be retried.
pub(super) struct CloseOutcome {
    pub(super) descriptor: i32,
    pub(super) error: io::Error,
}

pub(super) fn projection(error: &io::Error) -> io::Error {
    error
        .raw_os_error()
        .map_or_else(|| error.kind().into(), io::Error::from_raw_os_error)
}

/// Close one exact owned descriptor once. An error consumes Rust ownership but
/// does not establish physical drain; the original outcome remains in its slot.
pub(super) fn close(file: &mut Option<File>, outcome: &mut Option<CloseOutcome>) -> io::Result<()> {
    if let Some(outcome) = outcome {
        return Err(projection(&outcome.error));
    }
    let Some(file) = file.take() else {
        return Ok(());
    };
    let descriptor = file.into_raw_fd();
    // SAFETY: ownership was consumed above. Neither File::drop nor any retry
    // will close this integer after the one native attempt below.
    let result = unsafe { libc::close(descriptor) };
    let error = (result != 0).then(io::Error::last_os_error);
    #[cfg(test)]
    let error = {
        CLOSE_ATTEMPTS.with(|count| count.set(count.get() + 1));
        let injected = CLOSE_FAILURE.with(|failure| failure.take());
        error.or_else(|| injected.map(io::Error::from_raw_os_error))
    };
    let Some(error) = error else {
        return Ok(());
    };
    let returned = projection(&error);
    *outcome = Some(CloseOutcome { descriptor, error });
    Err(returned)
}

/// Two bounded walk descriptors. Every new FD is installed before metadata or
/// identity checks. Failure leaves both descriptors and original result here.
#[derive(Default)]
pub(super) struct Walk {
    pub(super) current: Option<File>,
    pub(super) next: Option<File>,
    pub(super) failure: Option<io::Error>,
    current_close: Option<CloseOutcome>,
    next_close: Option<CloseOutcome>,
}

impl Walk {
    pub(super) fn ready(&self) -> io::Result<()> {
        if let Some(error) = &self.failure {
            return Err(projection(error));
        }
        if let Some(outcome) = self.current_close.as_ref().or(self.next_close.as_ref()) {
            return Err(projection(&outcome.error));
        }
        if self.current.is_some() || self.next.is_some() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(())
    }

    pub(super) fn record<T>(&mut self, result: io::Result<T>) -> io::Result<T> {
        match result {
            Ok(value) => Ok(value),
            Err(error) => {
                let returned = projection(&error);
                if self.failure.is_none() {
                    self.failure = Some(error);
                }
                Err(returned)
            }
        }
    }

    pub(super) fn advance(&mut self) -> io::Result<()> {
        close(&mut self.current, &mut self.current_close)?;
        self.current = self.next.take();
        Ok(())
    }

    pub(super) fn close_resources(&mut self) -> io::Result<()> {
        // Attempt both independent descriptors even if the first close fails.
        let first = close(&mut self.current, &mut self.current_close);
        let second = close(&mut self.next, &mut self.next_close);
        first.and(second)
    }

    pub(super) fn drained(&self) -> bool {
        self.current.is_none()
            && self.next.is_none()
            && self.current_close.is_none()
            && self.next_close.is_none()
    }

    pub(super) fn uncertain_close(&self) -> Option<&CloseOutcome> {
        self.current_close.as_ref().or(self.next_close.as_ref())
    }
}

#[cfg(test)]
std::thread_local! {
    static CLOSE_FAILURE: std::cell::Cell<Option<i32>> = const { std::cell::Cell::new(None) };
    static CLOSE_ATTEMPTS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}
#[cfg(test)]
pub(super) fn fail_next_close(errno: i32) {
    // Perform the real close, then model an uncertain native result. This
    // deliberately cannot prove that the descriptor survived the syscall.
    CLOSE_FAILURE.with(|failure| assert!(failure.replace(Some(errno)).is_none()));
}
#[cfg(test)]
pub(super) fn close_attempts() -> u64 {
    CLOSE_ATTEMPTS.with(std::cell::Cell::get)
}
