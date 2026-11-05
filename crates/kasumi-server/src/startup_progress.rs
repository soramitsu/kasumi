//! Visible daemon startup. A reopen can take many minutes (snapshot restore,
//! journal replay, cache warming), and no listener serves until it ends, so each
//! phase is logged with its elapsed time and published to systemd: with
//! `Type=notify`, `systemctl status` shows the current phase and `READY=1`
//! reaches dependent units only once the node serves.
use std::{sync::OnceLock, time::Instant};

fn started() -> Instant {
    static STARTED: OnceLock<Instant> = OnceLock::new();
    *STARTED.get_or_init(Instant::now)
}

/// Anchor elapsed times at daemon start.
pub fn begin() {
    let _ = started();
    systemd::notify(&format!(
        "STATUS=starting: opening the installed configuration\nEXTEND_TIMEOUT_USEC={}",
        PHASE_TIMEOUT.as_micros()
    ));
}

/// One startup phase was reached. `detail` names a tenant or a count; it never
/// carries document data or secrets.
pub(crate) fn phase(phase: &'static str, detail: &str) {
    let elapsed = started().elapsed();
    tracing::info!(
        event = "startup_phase",
        phase,
        detail,
        elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
        "startup: {phase}{}{detail} after {:.1}s",
        if detail.is_empty() { "" } else { " " },
        elapsed.as_secs_f64()
    );
    // Each phase restarts systemd's start timeout: a phase that makes no
    // progress for PHASE_TIMEOUT still fails the start, a long reopen does not.
    systemd::notify(&format!(
        "STATUS=starting: {phase}{}{detail} ({:.0}s)\nEXTEND_TIMEOUT_USEC={}",
        if detail.is_empty() { "" } else { " " },
        elapsed.as_secs_f64(),
        PHASE_TIMEOUT.as_micros()
    ));
}

/// The longest one startup phase may take before systemd fails the start.
const PHASE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// The memory admission budget this process enforces. Unset in configuration,
/// the high-water mark is half the detected host or cgroup memory (e.g. 8 GiB
/// under `MemoryMax=16G`): operators need to see the figure that refuses work.
pub(crate) fn effective_admission(
    snapshot: &kasumi_engine::admission::AdmissionSnapshot,
    configured: bool,
) {
    tracing::info!(
        event = "effective_admission",
        high_water_bytes = snapshot.high_water_bytes,
        low_water_bytes = snapshot.low_water_bytes,
        resident_bytes = snapshot.resident_bytes,
        high_water_source = if configured {
            "configured"
        } else {
            "half of detected memory"
        },
        "memory admission refuses new work above {} MiB resident ({}); set admission.high_water_bytes to change it",
        snapshot.high_water_bytes >> 20,
        if configured {
            "configured"
        } else {
            "half of detected host or cgroup memory"
        }
    );
}

/// Free space where the node writes, once both disks are open. Scratch spools
/// snapshot builds and restores, so on the persistent filesystem a large build
/// can consume the margin every durable write needs.
pub(crate) fn storage_placement(
    limits: &kasumi_store::NodeDiskConfig,
    persistent: &kasumi_store::NodeDiskSnapshot,
    scratch: &kasumi_store::ScratchDiskSnapshot,
    shared: Option<bool>,
) {
    let gib = |bytes: Option<u64>| bytes.map_or(-1.0, |bytes| bytes as f64 / (1u64 << 30) as f64);
    tracing::info!(
        event = "storage_placement",
        persistent_available_bytes = persistent.filesystem_available_bytes,
        persistent_min_free_bytes = persistent.filesystem_min_free_bytes,
        scratch_available_bytes = scratch.filesystem_available_bytes,
        scratch_min_free_bytes = scratch.min_free_bytes,
        scratch_shares_persistent_filesystem = shared,
        // The installed limits a StorageFull refusal can come from; they often
        // differ from the source defaults.
        persistent_max_bytes = limits.max_bytes,
        persistent_max_files = limits.max_persistent_files,
        persistent_max_open_files = limits.max_open_files,
        persistent_max_open_directories = limits.max_open_directories,
        "persistent filesystem {:.1} GiB free, scratch filesystem {:.1} GiB free",
        gib(persistent.filesystem_available_bytes),
        gib(scratch.filesystem_available_bytes)
    );
    if shared == Some(true) {
        tracing::warn!(
            event = "scratch_shares_persistent_filesystem",
            "scratch_disk.directory is on the persistent filesystem: snapshot builds and restores spool through scratch and can exhaust the space durable writes need; place it on another volume"
        );
    }
}

/// Every listener serves.
pub(crate) fn serving() {
    let elapsed = started().elapsed();
    tracing::info!(
        event = "daemon_serving",
        elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
        "serving after {:.1}s",
        elapsed.as_secs_f64()
    );
    systemd::notify(&format!(
        "READY=1\nSTATUS=serving (started in {:.0}s)",
        elapsed.as_secs_f64()
    ));
}

/// Shutdown began; draining can take a while.
pub(crate) fn stopping() {
    tracing::info!(event = "daemon_stopping", "draining before exit");
    systemd::notify("STOPPING=1\nSTATUS=draining");
}

/// A failed open, or a stopping daemon, can retain native owners and retry their
/// drain indefinitely (the library keeps exact ownership rather than guess). A
/// daemon process does not need to: exiting releases every owner, and the store
/// recovers on its next start exactly as after a crash. These signals let
/// `kasumid` stop waiting and exit instead of hanging as "active".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Retained {
    /// The open failed and its cleanup is retrying.
    Startup,
    /// The serving drain after shutdown is retrying.
    Drain,
}

impl Retained {
    fn name(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::Drain => "drain",
        }
    }
    fn signal(self) -> &'static tokio::sync::watch::Sender<bool> {
        static STARTUP: OnceLock<tokio::sync::watch::Sender<bool>> = OnceLock::new();
        static DRAIN: OnceLock<tokio::sync::watch::Sender<bool>> = OnceLock::new();
        match self {
            Self::Startup => &STARTUP,
            Self::Drain => &DRAIN,
        }
        .get_or_init(|| tokio::sync::watch::channel(false).0)
    }
}

pub(crate) fn owners_retained(during: Retained) {
    during.signal().send_replace(true);
}

/// Resolve `grace` after `during` first retained owners.
pub async fn retained_for(during: Retained, grace: std::time::Duration) -> Retained {
    let mut receiver = during.signal().subscribe();
    if receiver.wait_for(|retained| *retained).await.is_err() {
        std::future::pending::<()>().await;
    }
    tokio::time::sleep(grace).await;
    during
}

/// Exit now, logging why; used only by the daemon binary.
pub fn exit_with_retained_owners(during: Retained, grace: std::time::Duration) -> ! {
    let during = during.name();
    tracing::error!(
        event = "daemon_exit_with_retained_owners",
        during,
        grace_secs = grace.as_secs(),
        "{during} left native owners retained for {}s; exiting so the service manager can restart a fresh process (the store recovers as after a crash)",
        grace.as_secs()
    );
    systemd::notify("STATUS=exiting with retained owners");
    std::process::exit(1)
}

pub(crate) mod systemd {
    /// Send one `sd_notify` datagram to `$NOTIFY_SOCKET`. Without that variable,
    /// or on any error, this does nothing: notification is never load-bearing.
    pub(crate) fn notify(state: &str) {
        let Some(socket) = std::env::var_os("NOTIFY_SOCKET") else {
            return;
        };
        let _ = send(&socket, state.as_bytes());
    }

    fn send(socket: &std::ffi::OsStr, payload: &[u8]) -> std::io::Result<()> {
        use std::os::unix::net::UnixDatagram;
        let datagram = UnixDatagram::unbound()?;
        let address = socket.as_encoded_bytes();
        if let Some(_name) = address.strip_prefix(b"@") {
            #[cfg(target_os = "linux")]
            {
                use std::os::linux::net::SocketAddrExt;
                let address = std::os::unix::net::SocketAddr::from_abstract_name(_name)?;
                datagram.send_to_addr(payload, &address)?;
            }
            return Ok(());
        }
        datagram.send_to(payload, std::path::Path::new(socket))?;
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn notifications_reach_a_path_socket() {
            // Short parent: Unix socket paths are limited to ~100 bytes.
            let directory = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
            let path = directory.path().join("notify.sock");
            let receiver = std::os::unix::net::UnixDatagram::bind(&path).unwrap();
            super::send(path.as_os_str(), b"READY=1\nSTATUS=serving").unwrap();
            let mut buffer = [0; 64];
            let length = receiver.recv(&mut buffer).unwrap();
            assert_eq!(&buffer[..length], b"READY=1\nSTATUS=serving");
        }
    }
}
