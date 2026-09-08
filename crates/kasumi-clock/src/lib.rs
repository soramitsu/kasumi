//! Lease clocks include system suspend; wall-clock adjustments cannot extend access.

use std::time::Duration;

pub trait LeaseClock: Send + Sync {
    fn now(&self) -> Duration;
}

pub struct SystemLeaseClock;

impl LeaseClock for SystemLeaseClock {
    fn now(&self) -> Duration {
        #[cfg(target_os = "linux")]
        {
            let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
            // CLOCK_BOOTTIME includes suspend. Failure cannot produce a valid lease.
            let rc = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
            assert_eq!(rc, 0, "suspend-aware lease clock unavailable");
            Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
        }
        #[cfg(target_os = "macos")]
        {
            unsafe extern "C" {
                fn mach_continuous_time() -> u64;
                fn mach_timebase_info(info: *mut Timebase) -> i32;
            }
            #[repr(C)]
            struct Timebase {
                numer: u32,
                denom: u32,
            }
            static SCALE: std::sync::OnceLock<(u32, u32)> = std::sync::OnceLock::new();
            let (numer, denom) = *SCALE.get_or_init(|| {
                let mut info = Timebase { numer: 0, denom: 0 };
                let rc = unsafe { mach_timebase_info(&mut info) };
                assert!(rc == 0 && info.denom != 0, "lease clock unavailable");
                (info.numer, info.denom)
            });
            let ticks = unsafe { mach_continuous_time() };
            let ns = u128::from(ticks) * u128::from(numer) / u128::from(denom);
            Duration::from_nanos(u64::try_from(ns).expect("lease clock overflow"))
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        compile_error!("Kasumi needs a suspend-aware lease clock on this platform");
    }
}

/// UTC is used to establish a verified credential's absolute expiration once;
/// subsequent local validity uses the suspend-aware elapsed clock.
pub trait WallClock: Send + Sync {
    fn now_ms(&self) -> anyhow::Result<u64>;
}
pub struct SystemWallClock;
impl WallClock for SystemWallClock {
    fn now_ms(&self) -> anyhow::Result<u64> {
        Ok(u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_millis(),
        )?)
    }
}

/// A paired trusted UTC/elapsed observation. It cannot be deserialized or
/// re-anchored from caller-provided timestamps.
#[derive(Clone)]
pub struct ClockObservation {
    utc_ms: u64,
    elapsed_at: Duration,
    clock: std::sync::Arc<dyn LeaseClock>,
}
impl ClockObservation {
    pub fn utc_ms(&self) -> u64 {
        self.utc_ms
    }
    pub fn until(&self, expires_at_ms: u64) -> anyhow::Result<ElapsedDeadline> {
        let remaining = expires_at_ms
            .checked_sub(self.utc_ms)
            .filter(|value| *value > 0)
            .ok_or_else(|| anyhow::anyhow!("credential already expired"))?;
        let deadline = self
            .elapsed_at
            .checked_add(Duration::from_millis(remaining))
            .ok_or_else(|| anyhow::anyhow!("credential deadline overflow"))?;
        let proof = ElapsedDeadline {
            clock: self.clock.clone(),
            acquired: self.elapsed_at,
            last_seen: std::sync::Arc::new(std::sync::Mutex::new(Some(self.elapsed_at))),
            deadline,
        };
        proof.check()?;
        Ok(proof)
    }
}
/// Cloning preserves the original elapsed deadline, including time spent before
/// constructing a later owner. There is no deserializer or reset method.
#[derive(Clone)]
pub struct ElapsedDeadline {
    clock: std::sync::Arc<dyn LeaseClock>,
    acquired: Duration,
    last_seen: std::sync::Arc<std::sync::Mutex<Option<Duration>>>,
    deadline: Duration,
}
impl ElapsedDeadline {
    /// Shorten this proof without replacing its original elapsed anchor. The
    /// child has its own expiry state; reaching its earlier limit cannot seal
    /// a parent invocation that is still valid.
    pub fn shortened_by(&self, amount: Duration) -> anyhow::Result<Self> {
        self.check()?;
        let deadline = self
            .deadline
            .checked_sub(amount)
            .ok_or_else(|| anyhow::anyhow!("deadline reduction underflow"))?;
        let last_seen = *self
            .last_seen
            .lock()
            .map_err(|_| anyhow::anyhow!("elapsed deadline poisoned"))?;
        let child = Self {
            clock: self.clock.clone(),
            acquired: self.acquired,
            last_seen: std::sync::Arc::new(std::sync::Mutex::new(last_seen)),
            deadline,
        };
        child.check()?;
        Ok(child)
    }
    pub fn check(&self) -> anyhow::Result<()> {
        let mut last = self
            .last_seen
            .lock()
            .map_err(|_| anyhow::anyhow!("elapsed deadline poisoned"))?;
        let now = self.clock.now();
        if last.is_none_or(|last| now < last) || now < self.acquired || now >= self.deadline {
            *last = None;
            anyhow::bail!("elapsed deadline expired or clock regressed");
        }
        *last = Some(now);
        Ok(())
    }
}

struct EpochAnchor {
    last_seen: Duration,
    elapsed: Duration,
    utc_ms: u64,
}
/// A process-local trusted UTC floor. Backward wall-clock adjustments cannot
/// extend fresh or retained credentials after this clock has been established.
/// Correct time at a fresh process/authority boot remains a deployment premise.
pub struct EpochClock {
    elapsed: std::sync::Arc<dyn LeaseClock>,
    wall: std::sync::Arc<dyn WallClock>,
    anchor: std::sync::Mutex<EpochAnchor>,
}
impl EpochClock {
    /// All production authenticators and execution clocks in this process share
    /// one UTC floor. Constructing another listener must not reset that floor
    /// after wall-clock rollback.
    pub fn system() -> anyhow::Result<std::sync::Arc<Self>> {
        static CLOCK: std::sync::OnceLock<std::result::Result<std::sync::Arc<EpochClock>, String>> =
            std::sync::OnceLock::new();
        CLOCK
            .get_or_init(|| {
                Self::new(
                    std::sync::Arc::new(SystemLeaseClock),
                    std::sync::Arc::new(SystemWallClock),
                )
                .map(std::sync::Arc::new)
                .map_err(|error| error.to_string())
            })
            .as_ref()
            .cloned()
            .map_err(|error| anyhow::anyhow!(error))
    }
    pub fn new(
        elapsed: std::sync::Arc<dyn LeaseClock>,
        wall: std::sync::Arc<dyn WallClock>,
    ) -> anyhow::Result<Self> {
        let monotonic = elapsed.now();
        let utc_ms = wall.now_ms()?;
        Ok(Self {
            elapsed,
            wall,
            anchor: std::sync::Mutex::new(EpochAnchor {
                last_seen: monotonic,
                elapsed: monotonic,
                utc_ms,
            }),
        })
    }
    pub fn elapsed_clock(&self) -> std::sync::Arc<dyn LeaseClock> {
        self.elapsed.clone()
    }
    pub fn now_ms(&self) -> anyhow::Result<u64> {
        Ok(self.observe()?.utc_ms())
    }
    pub fn observe(&self) -> anyhow::Result<ClockObservation> {
        // Sample after acquiring the lock: an earlier delayed sample must never
        // look like elapsed-clock rollback relative to another caller's update.
        let mut anchor = self
            .anchor
            .lock()
            .map_err(|_| anyhow::anyhow!("credential clock poisoned"))?;
        let now = self.elapsed.now();
        anyhow::ensure!(
            now >= anchor.last_seen,
            "elapsed credential clock regressed"
        );
        anchor.last_seen = now;
        let elapsed_ms = u64::try_from((now - anchor.elapsed).as_millis())?;
        let projected = anchor
            .utc_ms
            .checked_add(elapsed_ms)
            .ok_or_else(|| anyhow::anyhow!("credential clock overflow"))?;
        let observed = self.wall.now_ms()?;
        if observed > projected {
            *anchor = EpochAnchor {
                last_seen: now,
                elapsed: now,
                utc_ms: observed,
            };
            return Ok(ClockObservation {
                utc_ms: observed,
                elapsed_at: now,
                clock: self.elapsed.clone(),
            });
        }
        // Keep the original anchor when projecting elapsed time. Resetting it
        // here would discard fractional milliseconds on high-frequency calls.
        Ok(ClockObservation {
            utc_ms: projected,
            elapsed_at: now,
            clock: self.elapsed.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };
    struct Mono(AtomicU64);
    impl LeaseClock for Mono {
        fn now(&self) -> Duration {
            Duration::from_nanos(self.0.load(Ordering::SeqCst))
        }
    }
    struct Wall(AtomicU64);
    impl WallClock for Wall {
        fn now_ms(&self) -> anyhow::Result<u64> {
            Ok(self.0.load(Ordering::SeqCst))
        }
    }
    #[test]
    fn wall_rollback_and_frequent_observation_cannot_stop_elapsed_expiry() {
        let mono = Arc::new(Mono(AtomicU64::new(0)));
        let wall = Arc::new(Wall(AtomicU64::new(10_000)));
        let clock = EpochClock::new(mono.clone(), wall.clone()).unwrap();
        wall.0.store(100, Ordering::SeqCst);
        for step in 1..=1000 {
            mono.0.store(step * 100_000, Ordering::SeqCst);
            assert_eq!(clock.now_ms().unwrap(), 10_000 + step / 10);
        }
        // A large suspend-like elapsed jump expires time immediately on resume.
        mono.0.store(3_600_000_000_000, Ordering::SeqCst);
        assert_eq!(clock.now_ms().unwrap(), 3_610_000);
        wall.0.store(5_000_000, Ordering::SeqCst);
        assert_eq!(clock.now_ms().unwrap(), 5_000_000);
        wall.0.store(0, Ordering::SeqCst);
        mono.0.store(3_600_001_000_000, Ordering::SeqCst);
        assert_eq!(clock.now_ms().unwrap(), 5_000_001);
    }
    #[test]
    fn delayed_use_of_a_paired_observation_never_reanchors_credential_expiry() {
        let mono = Arc::new(Mono(AtomicU64::new(0)));
        let clock = EpochClock::new(mono.clone(), Arc::new(Wall(AtomicU64::new(1000)))).unwrap();
        let observation = clock.observe().unwrap();
        mono.0.store(999_000_000, Ordering::SeqCst);
        let deadline = observation.until(2000).unwrap();
        mono.0.store(1_000_000_000, Ordering::SeqCst);
        assert!(deadline.check().is_err());
        assert!(observation.until(2000).is_err());
    }
    #[test]
    fn elapsed_regression_is_not_treated_as_renewed_time() {
        let mono = Arc::new(Mono(AtomicU64::new(1_000_000)));
        let clock = EpochClock::new(mono.clone(), Arc::new(Wall(AtomicU64::new(100)))).unwrap();
        mono.0.store(0, Ordering::SeqCst);
        assert!(clock.now_ms().is_err());
    }
    #[test]
    fn production_clock_acquisition_does_not_create_a_new_utc_anchor() {
        let first = EpochClock::system().unwrap();
        let original = first.observe().unwrap();
        let second = EpochClock::system().unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert!(second.now_ms().unwrap() >= original.utc_ms());
    }
}
