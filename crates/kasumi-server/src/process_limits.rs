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
}
