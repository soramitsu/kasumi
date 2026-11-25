//! Limits a Kasumi daemon places on its own process before it reads any key.

/// Stop the kernel writing this process's memory to a core file. A core holds
/// tenant data keys, wrapping keys, the token signer and plaintext documents.
/// The packaged units set the same limit; this covers a container or any
/// other way the binary is started. Swap stays a host and service setting.
pub fn disable_core_files() -> std::io::Result<()> {
    let none = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit only reads the valid limit it is given.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &none) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Descriptors outside the persistent budgets: listeners and connections,
/// the event loop, scratch spool files, logs and the configuration.
pub const DESCRIPTOR_MARGIN: u64 = 1024;

/// Descriptors the configured persistent budgets can hold open at once. A file
/// owner retains at most two descriptors and a directory owner can retain its
/// parent's, so both budgets count twice, plus `DESCRIPTOR_MARGIN`.
pub fn required_descriptors(max_open_files: u32, max_open_directories: u32) -> u64 {
    2 * u64::from(max_open_files) + 2 * u64::from(max_open_directories) + DESCRIPTOR_MARGIN
}

/// The open-file limit after `ensure_descriptors`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DescriptorLimit {
    pub soft: u64,
    pub hard: u64,
    pub required: u64,
    /// The soft limit before it was raised, when it was.
    pub raised_from: Option<u64>,
}

/// Process limits are below what the configured budgets need.
#[derive(Debug)]
pub struct DescriptorShortfall(pub DescriptorLimit);
impl std::fmt::Display for DescriptorShortfall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let limit = self.0;
        write!(
            f,
            "the open-file limit ({} soft, {} hard) is below the {} descriptors the persistent budgets need \
             (2 x persistent_disk.max_open_files + 2 x persistent_disk.max_open_directories + {}); \
             raise LimitNOFILE or lower those budgets",
            limit.soft, limit.hard, limit.required, DESCRIPTOR_MARGIN
        )
    }
}
impl std::error::Error for DescriptorShortfall {}

/// Raise the soft open-file limit to `required` when the hard limit allows
/// it, and refuse when it does not: a descriptor refused mid-write is an
/// uncertain storage outcome, not an admission refusal. The packaged units
/// set LimitNOFILE; a daemon started another way often has a soft 1,024.
pub fn ensure_descriptors(
    required: u64,
) -> std::io::Result<Result<DescriptorLimit, DescriptorShortfall>> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit fills the valid limit it is given.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let value = |raw: libc::rlim_t| {
        if raw == libc::RLIM_INFINITY {
            u64::MAX
        } else {
            raw
        }
    };
    let (soft, hard) = (value(limit.rlim_cur), value(limit.rlim_max));
    let mut raised_from = None;
    if soft < required {
        let target = required.min(hard);
        if target > soft {
            limit.rlim_cur = target;
            // SAFETY: setrlimit only reads the valid limit it is given.
            if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            raised_from = Some(soft);
        }
    }
    let result = DescriptorLimit {
        soft: value(limit.rlim_cur),
        hard,
        required,
        raised_from,
    };
    Ok(if result.soft < required {
        Err(DescriptorShortfall(result))
    } else {
        Ok(result)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn core_limit() -> (libc::rlim_t, libc::rlim_t) {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit fills the valid limit it is given.
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) }, 0);
        (limit.rlim_cur, limit.rlim_max)
    }

    /// The limit is process-wide and an unprivileged process cannot raise it
    /// again, so a child process lowers it instead of the shared test process.
    #[test]
    fn the_core_file_limit_becomes_zero_and_stays_zero() {
        const NAME: &str = "process_limits::tests::the_core_file_limit_becomes_zero_and_stays_zero";
        const MARKER: &str = "KASUMI_CORE_LIMIT_CHILD";
        if std::env::var(MARKER).as_deref() == Ok(NAME) {
            disable_core_files().unwrap();
            assert_eq!(core_limit(), (0, 0));
            // Repeating it is harmless.
            disable_core_files().unwrap();
            assert_eq!(core_limit(), (0, 0));
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", NAME, "--nocapture", "--test-threads=1"])
            .env(MARKER, NAME)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn descriptor_limit() -> (u64, u64) {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit fills the valid limit it is given.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
            0
        );
        (limit.rlim_cur, limit.rlim_max)
    }

    /// Lowered limits are process-wide, so a child process exercises them.
    #[test]
    fn the_descriptor_limit_is_raised_within_the_hard_limit_or_refused() {
        const NAME: &str = "process_limits::tests::the_descriptor_limit_is_raised_within_the_hard_limit_or_refused";
        const MARKER: &str = "KASUMI_DESCRIPTOR_LIMIT_CHILD";
        if std::env::var(MARKER).as_deref() == Ok(NAME) {
            assert_eq!(
                required_descriptors(1024, 1536),
                2048 + 3072 + DESCRIPTOR_MARGIN
            );
            let set = |soft: u64, hard: u64| {
                let limit = libc::rlimit {
                    rlim_cur: soft as libc::rlim_t,
                    rlim_max: hard as libc::rlim_t,
                };
                // SAFETY: setrlimit only reads the valid limit it is given.
                assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
            };
            set(256, 2048);
            // Already enough: nothing changes.
            let unchanged = ensure_descriptors(200).unwrap().unwrap();
            assert_eq!((unchanged.soft, unchanged.raised_from), (256, None));
            // Raised to exactly the requirement, never to the hard limit.
            let raised = ensure_descriptors(1500).unwrap().unwrap();
            assert_eq!(
                (raised.soft, raised.hard, raised.raised_from),
                (1500, 2048, Some(256))
            );
            assert_eq!(descriptor_limit(), (1500, 2048));
            // Beyond the hard limit: raised as far as allowed, then refused.
            let short = ensure_descriptors(4096).unwrap().unwrap_err();
            assert_eq!(
                (short.0.soft, short.0.hard, short.0.required),
                (2048, 2048, 4096)
            );
            assert!(short.to_string().contains("raise LimitNOFILE"), "{short}");
            assert_eq!(descriptor_limit(), (2048, 2048));
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", NAME, "--nocapture", "--test-threads=1"])
            .env(MARKER, NAME)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
