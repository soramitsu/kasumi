//! Real installed funding and encrypted captured roots across precommit refusal.
use super::*;
use kasumi_kv::TerminalObservation;
use kasumi_store::{NodeDiskMemoryAdmission, SourceHistoryAbort, SourceHistoryRefusal};
use std::io;

fn metadata_history_bytes(fixture: &Fixture) -> Result<u64> {
    let requests = RegisteredSourceFundingFixture::memory_requests()?;
    Ok(fixture.core().quote_installed(requests[2])?)
}

fn native_history_refusal_pressure(fixture: &Fixture) -> Result<Reservation> {
    let (cache, _) = fixture
        .core()
        .data
        .config
        .cache_work_headroom(fixture.core().data.max_bytes);
    let ordinary = fixture.core().data.state.lock().unwrap().ordinary_protected;
    let available = fixture.core().data.max_bytes - fixture.core().snapshot().reserved_bytes;
    Ok(fixture
        .storage
        .admission
        .reserve_resident(available - cache - ordinary - metadata_history_bytes(fixture)?)?)
}

fn assert_metadata_history_accepted(reader: &RegisteredNodeRead) {
    assert!(matches!(
        reader.report().source_history_metadata_preparation(),
        Some(TerminalObservation::Returned(Ok(())))
    ));
}

#[tokio::test]
async fn actual_history_capacity_refusals_restore_encrypted_current_and_allow_retry() -> Result<()>
{
    for cause in ["metadata", "native-bytes", "native-pins"] {
        let fixture = Fixture::new(0).await?;
        fixture.write(b"unchanged-current")?;
        let backing = fixture.backing()?;
        let mut source = fixture.source()?;
        source.queue(0, 0)?;
        source.prepare(0);
        source.capture(0);
        let reader = fixture.reader(&source, 0);
        let id = reader.id();
        let selected = source
            .with_native_report(0, |read| read.selected_generation())
            .unwrap();
        let mut points = backing.bind_source(&fixture.stores, fixture.reader(&source, 0))?;
        let mut blockers = None;
        let pressure = match cause {
            "metadata" => Some(fixture.fill_all()?),
            "native-bytes" => Some(native_history_refusal_pressure(&fixture)?),
            "native-pins" => {
                let mut pins = fixture.opening.queue_native_slot_blockers_fixture()?;
                pins.begin();
                assert_eq!(pins.count(), 254);
                blockers = Some(pins);
                None
            }
            _ => unreachable!(),
        };
        let before = fixture.core().snapshot();
        source.prepare_history(0);
        if cause != "metadata" {
            assert_metadata_history_accepted(&reader);
        }
        assert!(!source.history_complete(0));
        assert!(points.application_get("payload", b"key", 128).is_err());
        let SourceHistoryAbort::Restored {
            refusal: Some(refusal),
        } = reader.abort_source_history()
        else {
            panic!("actual {cause} refusal did not positively restore current");
        };
        match (cause, &refusal) {
            ("metadata", SourceHistoryRefusal::Metadata(error)) => {
                assert_eq!(error.kind(), io::ErrorKind::OutOfMemory)
            }
            (
                "native-bytes",
                SourceHistoryRefusal::Native(kasumi_kv::SourceHistoryRefusal::Provider(error)),
            ) => assert_eq!(error.kind(), io::ErrorKind::OutOfMemory),
            (
                "native-pins",
                SourceHistoryRefusal::Native(kasumi_kv::SourceHistoryRefusal::Native(
                    kasumi_kv::StorageError::Core(original),
                )),
            ) if original.is_capacity_denied() => {}
            _ => panic!("lost actual capacity cause: {refusal:?}"),
        }
        assert_eq!(reader.phase(), NodeReadPhase::SourceCaptured);
        assert!(!reader.report().has_failures());
        assert_eq!(reader.id(), id);
        assert_eq!(
            source
                .with_native_report(0, |read| read.selected_generation())
                .unwrap(),
            selected
        );
        assert_eq!(
            fixture.core().snapshot().reserved_bytes,
            before.reserved_bytes
        );
        assert_eq!(
            fixture.core().snapshot().live_reservations,
            before.live_reservations
        );
        assert_eq!(
            fixture.core().storage_census.snapshot().source_replacements,
            0
        );
        assert_eq!(
            points.application_get("payload", b"key", 128)?,
            Some(b"unchanged-current".as_slice())
        );
        assert_eq!(
            points.custody_get("payload", b"key", 128)?,
            Some(b"unchanged-current".as_slice())
        );
        assert!(points.application_get("payload", b"absent", 128)?.is_none());
        drop(pressure);
        if let Some(mut pins) = blockers {
            assert!(pins.close());
        }

        // The same actual account and captured pin can prepare again.
        source.prepare_history(0);
        source.commit_history(0);
        assert!(source.history_complete(0));
        assert!(matches!(
            reader.abort_source_history(),
            SourceHistoryAbort::Retained
        ));
        assert!(source.history_complete(0));
        assert_eq!(
            points.application_get("payload", b"key", 128)?,
            Some(b"unchanged-current".as_slice())
        );
        drop(reader);
        source.release_read(0);
        points.close()?;
        fixture.finish_source(source);
        fixture.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn prepared_history_cancellation_keeps_current_then_retry_can_commit() -> Result<()> {
    let fixture = Fixture::new(0).await?;
    fixture.write(b"current")?;
    let backing = fixture.backing()?;
    let mut source = fixture.source()?;
    source.queue(0, 0)?;
    source.prepare(0);
    source.capture(0);
    let reader = fixture.reader(&source, 0);
    let mut points = backing.bind_source(&fixture.stores, fixture.reader(&source, 0))?;
    let before = fixture.core().snapshot();
    source.prepare_history(0);
    assert!(matches!(
        reader.abort_source_history(),
        SourceHistoryAbort::Restored { refusal: None }
    ));
    assert_eq!(
        fixture.core().snapshot().reserved_bytes,
        before.reserved_bytes
    );
    assert_eq!(
        fixture.core().snapshot().live_reservations,
        before.live_reservations
    );
    assert_eq!(
        points.application_get("payload", b"key", 128)?,
        Some(b"current".as_slice())
    );
    source.prepare_history(0);
    source.defer_next_committed_marker(0);
    source.commit_history(0);
    assert_eq!(source.history_progress(0), Some((1, true, false, false)));
    assert!(matches!(
        reader.abort_source_history(),
        SourceHistoryAbort::Retained
    ));
    assert!(points.application_get("payload", b"key", 128).is_err());
    source.commit_history(0);
    assert!(source.history_complete(0));
    assert_eq!(source.history_progress(0), Some((1, true, true, true)));
    drop(reader);
    source.release_read(0);
    points.close()?;
    fixture.finish_source(source);
    fixture.close().await
}

#[derive(Debug)]
struct ActualHistoryRetirementPanic(u64);

#[tokio::test]
async fn history_refusal_and_actual_replacement_drop_panic_keep_distinct_originals() -> Result<()> {
    let fixture = Fixture::new(0).await?;
    fixture.write(b"current")?;
    let mut source = fixture.source()?;
    source.queue(0, 0)?;
    source.prepare(0);
    source.capture(0);
    let reader = fixture.reader(&source, 0);
    let pressure = native_history_refusal_pressure(&fixture)?;
    let probe = crate::admission::installed_drop_probe::Probe::begin(fixture.core());
    source.prepare_history(0); // Actual metadata grant succeeds, native bytes refuse.
    assert_metadata_history_accepted(&reader);
    let panic = Box::new(ActualHistoryRetirementPanic(918));
    let original = std::ptr::from_ref(panic.as_ref()) as usize;
    probe.arm_last(panic);
    assert!(matches!(
        reader.abort_source_history(),
        SourceHistoryAbort::Retained
    ));
    assert!(probe.fired());
    {
        let report = reader.report();
        assert!(matches!(report.source_history_refusal(),
            Some(SourceHistoryRefusal::Native(kasumi_kv::SourceHistoryRefusal::Provider(error)))
            if error.kind() == io::ErrorKind::OutOfMemory));
        match report.source_history_metadata_cleanup().unwrap() {
            TerminalObservation::Panicked(payload) => {
                let payload = payload
                    .downcast_ref::<ActualHistoryRetirementPanic>()
                    .unwrap();
                assert_eq!(payload.0, 918);
                assert_eq!(std::ptr::from_ref(payload) as usize, original);
            }
            _ => panic!("actual replacement retirement panic disappeared"),
        }
        assert!(report.has_failures());
        assert_ne!(report.phase(), NodeReadPhase::SourceCaptured);
    }
    assert!(matches!(
        reader.abort_source_history(),
        SourceHistoryAbort::Retained
    ));
    assert!(!source.acknowledge_read(0));
    assert!(source.queue(1, 0).is_err());
    drop(probe);
    drop(pressure);
    // Unknown cleanup stays in the real registered owner even though the
    // injected actual lease dropped after returning its concrete byte charge.
    drop(reader);
    drop(source);
    drop(fixture);
    Ok(())
}

#[tokio::test]
async fn history_abort_keeps_exact_cause_while_census_cancel_is_pending() -> Result<()> {
    let fixture = Fixture::new(0).await?;
    fixture.write(b"current")?;
    let backing = fixture.backing()?;
    let mut source = fixture.source()?;
    source.queue(0, 0)?;
    source.prepare(0);
    source.capture(0);
    let reader = fixture.reader(&source, 0);
    let mut points = backing.bind_source(&fixture.stores, fixture.reader(&source, 0))?;
    let pressure = native_history_refusal_pressure(&fixture)?;
    source.prepare_history(0);
    assert_metadata_history_accepted(&reader);
    let entered = std::sync::Barrier::new(2);
    let release = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        let source = &source;
        let entered = &entered;
        let release = &release;
        scope.spawn(move || {
            source
                .with_reader_census_held(0, || {
                    entered.wait();
                    release.wait();
                })
                .unwrap();
        });
        entered.wait();
        let outcome = reader.abort_source_history();
        let retained_cause = matches!(reader.report().source_history_refusal(),
            Some(SourceHistoryRefusal::Native(kasumi_kv::SourceHistoryRefusal::Provider(error)))
                if error.kind() == io::ErrorKind::OutOfMemory);
        let unreadable = points.application_get("payload", b"key", 128).is_err();
        release.wait();
        assert!(matches!(outcome, SourceHistoryAbort::Pending));
        assert!(retained_cause);
        assert!(unreadable);
    });
    assert!(matches!(reader.abort_source_history(),
        SourceHistoryAbort::Restored { refusal: Some(SourceHistoryRefusal::Native(
            kasumi_kv::SourceHistoryRefusal::Provider(error))) }
            if error.kind() == io::ErrorKind::OutOfMemory));
    assert_eq!(reader.phase(), NodeReadPhase::SourceCaptured);
    assert_eq!(
        points.application_get("payload", b"key", 128)?,
        Some(b"current".as_slice())
    );
    drop(pressure);
    drop(reader);
    source.release_read(0);
    points.close()?;
    fixture.finish_source(source);
    fixture.close().await
}

#[tokio::test]
async fn history_census_admission_refusal_preserves_current_without_entering_native() -> Result<()>
{
    let fixture = Fixture::new(0).await?;
    fixture.write(b"current")?;
    let backing = fixture.backing()?;
    let mut source = fixture.source()?;
    source.queue(0, 0)?;
    source.prepare(0);
    source.capture(0);
    let reader = fixture.reader(&source, 0);
    let mut points = backing.bind_source(&fixture.stores, fixture.reader(&source, 0))?;
    let before = fixture.core().snapshot();
    let entered = std::sync::Barrier::new(2);
    let release = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        let source = &source;
        let entered = &entered;
        let release = &release;
        scope.spawn(move || {
            source
                .with_reader_census_held(0, || {
                    entered.wait();
                    release.wait();
                })
                .unwrap();
        });
        entered.wait();
        source.prepare_history(0);
        let outcome = reader.abort_source_history();
        release.wait();
        assert!(matches!(outcome, SourceHistoryAbort::Restored {
            refusal: Some(SourceHistoryRefusal::Census(error))
        } if error.kind() == io::ErrorKind::WouldBlock));
    });
    assert!(
        source
            .with_native_report(0, |read| read.history_report().is_none())
            .unwrap()
    );
    assert_eq!(
        fixture.core().snapshot().reserved_bytes,
        before.reserved_bytes
    );
    assert_eq!(
        fixture.core().snapshot().live_reservations,
        before.live_reservations
    );
    assert_eq!(
        points.application_get("payload", b"key", 128)?,
        Some(b"current".as_slice())
    );
    source.prepare_history(0);
    source.commit_history(0);
    assert!(source.history_complete(0));
    drop(reader);
    source.release_read(0);
    points.close()?;
    fixture.finish_source(source);
    fixture.close().await
}
