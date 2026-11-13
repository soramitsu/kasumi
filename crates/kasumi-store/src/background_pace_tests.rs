use super::*;

#[test]
fn a_paced_delay_is_the_foreground_share_of_the_time_held_within_its_bounds() {
    // Four parts pause to one part work: at most a fifth of the time.
    assert_eq!(FOREGROUND_SHARE, 4);
    for held in [2, 10, 62, 100, 250] {
        let held = Duration::from_millis(held);
        assert_eq!(paced_delay(held), held * FOREGROUND_SHARE);
    }
    // Never shorter than the floor, also for a unit that took no time.
    assert_eq!(paced_delay(Duration::ZERO), MIN_PACED_DELAY);
    assert_eq!(paced_delay(Duration::from_micros(100)), MIN_PACED_DELAY);
    assert_eq!(
        paced_delay(MIN_PACED_DELAY / FOREGROUND_SHARE),
        MIN_PACED_DELAY
    );
    // Never longer than the cap, also for a unit that took days.
    assert_eq!(
        paced_delay(MAX_PACED_DELAY / FOREGROUND_SHARE),
        MAX_PACED_DELAY
    );
    assert_eq!(paced_delay(Duration::from_secs(2)), MAX_PACED_DELAY);
    assert_eq!(paced_delay(Duration::MAX), MAX_PACED_DELAY);
    assert!(MIN_PACED_DELAY < MAX_PACED_DELAY);
}

#[test]
fn a_stream_owes_the_paced_delay_only_while_foreground_operations_are_active() {
    let held = Duration::from_millis(30);
    assert_eq!(owed_pause(held, false), MIN_PACED_DELAY);
    assert_eq!(owed_pause(held, true), held * FOREGROUND_SHARE);
    assert_eq!(owed_pause(Duration::from_secs(5), false), MIN_PACED_DELAY);
    assert_eq!(owed_pause(Duration::from_secs(5), true), MAX_PACED_DELAY);
    assert_eq!(owed_pause(Duration::ZERO, true), MIN_PACED_DELAY);
}

#[test]
fn background_write_counters_saturate_instead_of_wrapping() {
    assert_eq!(nanos(Duration::from_nanos(7)), 7);
    assert_eq!(nanos(Duration::MAX), u64::MAX);
    let writes = BackgroundWrites::default();
    assert_eq!(writes.status(), BackgroundWriteStatus::default());
    writes.units.store(3, Ordering::Relaxed);
    writes.database_nanos.store(2_000_000, Ordering::Relaxed);
    writes.longest_nanos.store(1_500_000, Ordering::Relaxed);
    writes.paced_nanos.store(8_000_000, Ordering::Relaxed);
    assert_eq!(
        writes.status(),
        BackgroundWriteStatus {
            units: 3,
            database_time: Duration::from_millis(2),
            longest_database_time: Duration::from_micros(1500),
            paced_delay: Duration::from_millis(8),
        }
    );
}
