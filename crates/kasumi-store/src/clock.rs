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
