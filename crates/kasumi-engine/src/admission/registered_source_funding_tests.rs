//! Real MemoryCore -> registered Store -> protected native funding. These
//! tests intentionally prove lifecycle/metadata accounting, not encrypted I/O.
use super::*;
use kasumi_kv::{DatabaseOpenSettlement, TerminalObservation};
use kasumi_store::{
    NodeDiskMemoryAdmission, NodeReadPhase, RegisteredNodeRead, RegisteredSourceFundingFixture,
    SourcePoolPhase,
};

pub(super) fn metadata_quote(fixture: &tests::Fixture) -> anyhow::Result<[u64; 4]> {
    let mut charges = [0; 4];
    for (target, request) in charges
        .iter_mut()
        .zip(RegisteredSourceFundingFixture::memory_requests()?)
    {
        *target = fixture.core().quote_installed(request)?;
    }
    Ok(charges)
}
fn is_present(core: &MemoryCore, id: kasumi_store::StorageOwnerId) -> bool {
    (0..core.storage_census.snapshot().capacity)
        .any(|index| core.storage_census.owner_at(index) == Some(id))
}

#[test]
fn registered_source_funding_real_provider_counts_complete_layout_and_has_no_post_bank_reserve()
-> anyhow::Result<()> {
    let fixture = tests::Fixture::new()?;
    let before = fixture.core().snapshot();
    let metadata = metadata_quote(&fixture)?;
    let (result, live, peak, allocations) =
        crate::document_pool::allocation_tests::measure_topology_input(|| {
            let mut source = fixture.registered();
            source.install();
            source.queue(0, 0)?;
            source.queue(1, 1)?;
            source.prepare(0);
            source.prepare(1);
            Ok::<_, io::Error>(source)
        });
    let mut source = result?;
    assert_eq!(source.phase(), Some(SourcePoolPhase::Ready));
    let native = source.native_snapshot().unwrap();
    let charged = metadata.iter().sum::<u64>() + native.charged_bytes;
    let after = fixture.core().snapshot();
    assert!(live > 0 && allocations > 0);
    assert!(
        peak as u64 <= charged,
        "actual control/bank/two report/census/native owners exceeded their exact provider quote"
    );
    assert_eq!(after.reserved_bytes - before.reserved_bytes, charged);
    assert_eq!(after.live_reservations - before.live_reservations, 5);
    for slot in [0, 1] {
        let reader = source.reader(slot).unwrap();
        assert_eq!(reader.phase(), NodeReadPhase::SourcePrepared);
        let provider: Arc<dyn NodeDiskMemoryAdmission> = fixture.core().clone();
        let recovered = RegisteredNodeRead::retained(provider, reader.id()).unwrap();
        assert_eq!(recovered.begin(), NodeReadPhase::SourcePrepared);
        assert!(recovered.catalog_bytes([0; 32], 1).is_err());
        drop(recovered);
    }
    source.capture(0);
    let old = source
        .with_native_report(0, |r| r.selected_generation())
        .unwrap();
    source.publish_generation(91)?;
    let filler = fixture.fill_all()?;
    let saturated = fixture.core().snapshot();
    source.capture(1);
    assert_eq!(
        source.reader(1).unwrap().phase(),
        NodeReadPhase::SourceCaptured
    );
    assert!(
        source
            .with_native_report(1, |r| r.selected_generation())
            .unwrap()
            > old
    );
    assert_eq!(
        source
            .with_native_report(0, |r| r.selected_generation())
            .unwrap(),
        old
    );
    assert_eq!(
        fixture.core().snapshot().reserved_bytes,
        saturated.reserved_bytes
    );
    assert_eq!(
        fixture.core().snapshot().live_reservations,
        saturated.live_reservations
    );
    drop(filler);
    for slot in [0, 1] {
        assert_eq!(source.close_read(slot), Some(NodeReadPhase::Finished));
        source.release_read(slot);
    }
    source.seal();
    source.drain();
    assert_eq!(source.phase(), Some(SourcePoolPhase::Finished));
    let pool_id = source.id();
    drop(source);
    fixture.core().storage_census.drain_owner(pool_id);
    assert_eq!(
        fixture.core().snapshot().reserved_bytes,
        before.reserved_bytes
    );
    fixture.finish()
}

#[test]
fn registered_source_history_report_outlives_ordinary_cell_and_preserves_its_own_bytes()
-> anyhow::Result<()> {
    let fixture = tests::Fixture::new()?;
    let before = fixture.core().snapshot();
    let metadata = metadata_quote(&fixture)?;
    let mut source = fixture.registered();
    source.install();
    source.queue(0, 0)?;
    source.prepare(0);
    source.capture(0);
    let old_id = source.reader(0).unwrap().id();
    let old_generation = source
        .with_native_report(0, |r| r.selected_generation())
        .unwrap();
    source.prepare_history(0);
    source.commit_history(0);
    assert!(source.history_complete(0));
    assert_eq!(fixture.core().storage_census.snapshot().source_history, 1);
    assert_eq!(
        source
            .with_native_report(0, |r| r.selected_generation())
            .unwrap(),
        old_generation
    );
    // Same protected metadata/native right is now genuinely reusable.
    source.publish_generation(92)?;
    source.queue(1, 0)?;
    source.prepare(1);
    source.capture(1);
    assert!(
        source
            .with_native_report(1, |r| r.selected_generation())
            .unwrap()
            > old_generation
    );
    let diagnostic = source.retain_diagnostic(0).unwrap();
    assert_eq!(source.close_read(0), Some(NodeReadPhase::Finished));
    source.release_read(0);
    source.drain();
    assert!(
        !is_present(fixture.core(), old_id),
        "ordinary history cell waited for an unrelated report tail"
    );
    assert_eq!(fixture.core().storage_census.snapshot().source_history, 0);
    assert_eq!(diagnostic.phase(), NodeReadPhase::Finished);
    assert!(!diagnostic.has_failures());
    assert_eq!(source.close_read(1), Some(NodeReadPhase::Finished));
    source.release_read(1);
    source.seal();
    source.drain();
    assert_eq!(source.phase(), Some(SourcePoolPhase::Finished));
    let pool_id = source.id();
    drop(source);
    fixture.core().storage_census.drain_owner(pool_id);
    let history_tail = metadata[1] + metadata[2];
    assert_eq!(
        fixture.core().snapshot().reserved_bytes,
        before.reserved_bytes + history_tail
    );
    assert_eq!(
        fixture.core().snapshot().live_reservations,
        before.live_reservations + 2
    );
    assert_eq!(
        fixture.opening().close()?,
        DatabaseOpenSettlement::Closed,
        "detached diagnostic retained an actual database alias"
    );
    let before_tail = fixture.core().snapshot();
    drop(diagnostic);
    assert_eq!(
        fixture.core().snapshot().reserved_bytes,
        before_tail.reserved_bytes - history_tail
    );
    assert_eq!(
        fixture.core().snapshot().live_reservations,
        before_tail.live_reservations - 2
    );
    assert_eq!(fixture.core().storage_census.snapshot().source_pools, 0);
    assert_eq!(fixture.core().storage_census.snapshot().source_reserved, 0);
    fixture.finish()
}

#[test]
fn registered_source_no_facade_close_recovers_actual_pool_and_both_prepared_readers()
-> anyhow::Result<()> {
    let fixture = tests::Fixture::new()?;
    let mut source = fixture.registered();
    source.install();
    source.queue(0, 0)?;
    source.queue(1, 1)?;
    source.prepare(0);
    source.prepare(1);
    source.capture(0);
    assert_eq!(fixture.core().storage_census.snapshot().source_active, 2);
    drop(source);
    assert_eq!(fixture.opening().close()?, DatabaseOpenSettlement::Closed);
    let census = fixture.core().storage_census.snapshot();
    assert_eq!(census.source_pools, 0);
    assert_eq!(census.source_active, 0);
    assert_eq!(census.source_reserved, 0);
    fixture.finish()
}

#[test]
fn registered_source_history_native_slot_denial_cancels_whole_registered_request()
-> anyhow::Result<()> {
    let fixture = tests::Fixture::new()?;
    let mut source = fixture.registered();
    source.install();
    source.queue(0, 0)?;
    source.prepare(0);
    source.capture(0);
    let mut ordinary = fixture.opening().queue_native_slot_blockers_fixture()?;
    ordinary.begin();
    assert_eq!(ordinary.count(), 254);
    let before = fixture.core().snapshot();
    source.prepare_history(0);
    assert!(
        source
            .with_native_report(0, |read| matches!(&(read.history_report().unwrap().preparation()), TerminalObservation::Returned(Err(kasumi_kv::StorageError::Core(
                    native_error
                ))) if matches!(native_error.rejected_cause(), Some(kasumi_kv::CoreErrorCause::CapacityDenied))))
            .unwrap()
    );
    assert!(fixture.core().snapshot().reserved_bytes > before.reserved_bytes);
    source.commit_history(0);
    assert!(!source.history_complete(0));
    assert_eq!(source.close_read(0), Some(NodeReadPhase::Finished));
    assert!(source.reader(0).unwrap().report().has_failures());
    // The exact original remains while positive cleanup permits explicit ack.
    assert!(source.acknowledge_read(0));
    source.release_read(0);
    source.drain();
    assert_eq!(
        fixture.core().storage_census.snapshot().source_replacements,
        0
    );
    assert!(ordinary.close());
    drop(ordinary);
    source.seal();
    source.drain();
    assert_eq!(source.phase(), Some(SourcePoolPhase::Finished));
    let pool_id = source.id();
    drop(source);
    fixture.core().storage_census.drain_owner(pool_id);
    fixture.finish()
}

#[test]
fn registered_source_no_facade_recovers_precommit_and_native_committed_pending_local_exchange()
-> anyhow::Result<()> {
    for committed in [false, true] {
        let fixture = tests::Fixture::new()?;
        let mut source = fixture.registered();
        source.install();
        source.queue(0, 0)?;
        source.prepare(0);
        source.capture(0);
        source.prepare_history(0);
        if committed {
            source.defer_next_local_completion(0);
            source.commit_history(0);
            assert!(
                source
                    .with_native_report(0, |r| r.history_report().unwrap().exchange_committed())
                    .unwrap()
            );
            assert!(!source.history_complete(0));
        }
        assert_eq!(
            fixture.core().storage_census.snapshot().source_replacements,
            1
        );
        drop(source);
        assert_eq!(fixture.opening().close()?, DatabaseOpenSettlement::Closed);
        let census = fixture.core().storage_census.snapshot();
        assert_eq!(census.source_pools, 0);
        assert_eq!(census.source_replacements, 0);
        assert_eq!(census.source_active, 0);
        assert_eq!(census.source_history, 0);
        fixture.finish()?;
    }
    Ok(())
}

#[test]
fn registered_source_busy_census_cancel_retries_without_replaying_native_cleanup()
-> anyhow::Result<()> {
    let fixture = tests::Fixture::new()?;
    let mut source = fixture.registered();
    source.install();
    source.queue(0, 0)?;
    source.prepare(0);
    source.capture(0);
    source.prepare_history(0);
    let entered = std::sync::Barrier::new(2);
    let release = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        let source = &source;
        let entered_ref = &entered;
        let release_ref = &release;
        scope.spawn(move || {
            source
                .with_reader_census_held(0, || {
                    entered_ref.wait();
                    release_ref.wait();
                })
                .unwrap()
        });
        entered.wait();
        assert_eq!(source.close_read(0), Some(NodeReadPhase::WaitingForGuards));
        assert!(
            source
                .with_native_report(0, |read| read.is_closed())
                .unwrap()
        );
        release.wait();
    });
    assert_eq!(source.close_read(0), Some(NodeReadPhase::Finished));
    assert!(!source.reader(0).unwrap().report().has_failures());
    source.release_read(0);
    source.seal();
    source.drain();
    let pool_id = source.id();
    drop(source);
    fixture.core().storage_census.drain_owner(pool_id);
    fixture.finish()
}

#[test]
fn registered_source_both_local_suffix_panics_retain_original_and_fence_lane_reuse()
-> anyhow::Result<()> {
    use kasumi_store::SourceCompletionFault;
    for fault in [
        SourceCompletionFault::AfterMetadataApplied,
        SourceCompletionFault::BeforeCensusFinal,
    ] {
        let fixture = tests::Fixture::new()?;
        let mut source = fixture.registered();
        source.install();
        source.queue(0, 0)?;
        source.prepare(0);
        source.capture(0);
        source.prepare_history(0);
        let before = fixture.core().snapshot();
        source.inject_completion_fault(0, fault);
        source.commit_history(0);
        assert!(
            source
                .with_native_report(0, |read| read
                    .history_report()
                    .unwrap()
                    .exchange_committed())
                .unwrap()
        );
        assert!(!source.history_complete(0));
        let original = source
            .with_local_completion(0, |observation| match observation {
                TerminalObservation::Panicked(payload) => {
                    let payload = payload.downcast_ref::<SourceCompletionFault>().unwrap();
                    assert_eq!(*payload, fault);
                    std::ptr::from_ref(payload) as usize
                }
                _ => panic!("missing original completion panic"),
            })
            .unwrap();
        source.commit_history(0);
        assert_eq!(
            source.with_local_completion(0, |observation| match observation {
                TerminalObservation::Panicked(payload) =>
                    std::ptr::from_ref(payload.downcast_ref::<SourceCompletionFault>().unwrap())
                        as usize,
                _ => 0,
            }),
            Some(original)
        );
        assert!(source.queue(1, 0).is_err());
        assert_eq!(
            fixture.core().snapshot().reserved_bytes,
            before.reserved_bytes
        );
        assert_eq!(
            fixture.core().snapshot().live_reservations,
            before.live_reservations
        );
        assert!(fixture.core().storage_census.snapshot().fenced);
        assert_eq!(source.close_read(0), Some(NodeReadPhase::Retained));
        assert!(!source.acknowledge_read(0));
        assert_eq!(
            fixture.opening().close()?,
            DatabaseOpenSettlement::WaitingForTransactions
        );
        // Deliberately retained fixed failure custody. There is no test-only
        // acknowledgment or forced refund for a possible partial exchange.
        // These two bounded failed censuses remain until this test process exits.
        // Keep their actual filesystem owner too: removing its TempDir while
        // retained native custody is unresolved would falsify the fixture's
        // physical lifetime. This is limited to the two explicit panic cases.
        drop(source);
        std::mem::forget(fixture);
    }
    Ok(())
}

#[test]
fn registered_source_control_real_capacity_failure_survives_all_facades_until_explicit_ack()
-> anyhow::Result<()> {
    let fixture = tests::Fixture::new()?;
    let before = fixture.core().snapshot();
    let filler = fixture.fill_all()?;
    let source = fixture.registered();
    assert_eq!(source.phase(), None);
    let id = source.id();
    let original = source
        .with_control_observation(|observation, _, _| match observation {
            TerminalObservation::Returned(Err(error)) => {
                assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
                std::ptr::from_ref(error) as usize
            }
            _ => panic!("missing actual provider refusal"),
        })
        .unwrap();
    drop(source);
    drop(filler);
    assert_eq!(
        fixture.core().snapshot().reserved_bytes,
        before.reserved_bytes
    );
    assert_eq!(
        fixture.core().snapshot().live_reservations,
        before.live_reservations
    );
    assert_eq!(fixture.opening().close()?, DatabaseOpenSettlement::Closed);
    assert_eq!(fixture.core().storage_census.snapshot().source_pools, 1);
    assert_eq!(
        fixture
            .opening()
            .with_source_control_observation_fixture(id, |observation, _, cleanup| {
                assert!(matches!(cleanup, TerminalObservation::Returned(Ok(()))));
                match observation {
                    TerminalObservation::Returned(Err(error)) => std::ptr::from_ref(error) as usize,
                    _ => 0,
                }
            }),
        Some(original)
    );
    fixture.opening().acknowledge_source_control_fixture(id)?;
    fixture.core().storage_census.drain_owner(id);
    assert!(!is_present(fixture.core(), id));
    assert_eq!(fixture.core().storage_census.snapshot().source_pools, 0);
    fixture.finish()
}

#[test]
fn registered_source_native_success_survives_actual_committed_marker_contention_once()
-> anyhow::Result<()> {
    let fixture = tests::Fixture::new()?;
    let mut source = fixture.registered();
    source.install();
    source.queue(0, 0)?;
    source.prepare(0);
    source.capture(0);
    let selected = source
        .with_native_report(0, |read| read.selected_generation())
        .unwrap();
    assert!(selected.is_some());
    source.prepare_history(0);
    source.defer_next_committed_marker(0);
    source.commit_history(0);
    assert_eq!(source.history_progress(0), Some((1, true, false, false)));
    assert!(
        source
            .with_native_report(0, |read| {
                read.history_report().unwrap().exchange_committed()
                    && matches!(
                        read.history_exchange(),
                        Some(TerminalObservation::Returned(Ok(())))
                    )
            })
            .unwrap()
    );
    let paid = fixture.core().snapshot();
    let native = source.native_snapshot();
    let census = fixture.core().storage_census.snapshot();
    assert_eq!(census.source_replacements, 1);
    let entered = std::sync::Barrier::new(2);
    let release = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        let source = &source;
        let entered_ref = &entered;
        let release_ref = &release;
        scope.spawn(move || {
            source
                .with_reader_census_held(0, || {
                    entered_ref.wait();
                    release_ref.wait();
                })
                .unwrap();
        });
        entered.wait();
        // Native exchange has already succeeded. The real old-cell try_lock
        // now refuses only its local committed marker; no native call repeats.
        source.commit_history(0);
        let progress = source.history_progress(0);
        let snapshot = fixture.core().snapshot();
        let native_after = source.native_snapshot();
        let selected_after = source.with_native_report(0, |read| read.selected_generation());
        let positive = source.with_native_report(0, |read| {
            read.history_report().unwrap().exchange_committed()
                && matches!(
                    read.history_exchange(),
                    Some(TerminalObservation::Returned(Ok(())))
                )
        });
        // Release before assertions so a failing qualification cannot strand
        // the scoped lock holder at its barrier.
        release.wait();
        assert_eq!(progress, Some((1, true, false, false)));
        assert_eq!(snapshot.reserved_bytes, paid.reserved_bytes);
        assert_eq!(snapshot.live_reservations, paid.live_reservations);
        assert_eq!(native_after, native);
        assert_eq!(selected_after, Some(selected));
        assert_eq!(positive, Some(true));
    });
    source.commit_history(0);
    assert_eq!(source.history_progress(0), Some((1, true, true, true)));
    assert_eq!(source.native_snapshot(), native);
    assert_eq!(
        source.with_native_report(0, |read| read.selected_generation()),
        Some(selected)
    );
    let complete = fixture.core().storage_census.snapshot();
    assert_eq!(complete.source_replacements, 0);
    assert_eq!(complete.source_history, 1);
    assert!(!source.reader(0).unwrap().report().has_failures());
    assert_eq!(source.close_read(0), Some(NodeReadPhase::Finished));
    source.release_read(0);
    source.seal();
    source.drain();
    assert_eq!(source.phase(), Some(SourcePoolPhase::Finished));
    let pool_id = source.id();
    drop(source);
    fixture.core().storage_census.drain_owner(pool_id);
    fixture.finish()
}

#[test]
fn registered_source_partial_queue_actual_registration_contention_retains_report_and_original()
-> anyhow::Result<()> {
    let fixture = tests::Fixture::new()?;
    let baseline = fixture.core().snapshot();
    let metadata = metadata_quote(&fixture)?;
    let mut source = fixture.registered();
    source.install();
    assert_eq!(source.phase(), Some(SourcePoolPhase::Ready));
    let paid = fixture.core().snapshot();
    let before_census = fixture.core().storage_census.snapshot();
    let native_before = source.native_snapshot().unwrap();
    assert_eq!(native_before.assigned, 0);
    let (result, live, peak, allocations) =
        crate::document_pool::allocation_tests::measure_topology_input(|| {
            source.queue_with_registration_census_held(0, 0)
        });
    assert!(result.is_err());
    assert!(source.reader(0).is_none());
    assert!(
        live > 0 && allocations > 0,
        "actual partial report/account were not allocated"
    );
    assert!(
        peak as u64 <= metadata[2],
        "partial queue exceeded its paid metadata lane"
    );
    let original = source
        .with_pending_queue_observation(0, |observation, disposal, held| {
            assert!(matches!(disposal, TerminalObservation::NotEntered));
            // Native/account moved into the real report; report grant was consumed.
            // The payload grant has not entered a census ReaderRequest.
            assert_eq!(held, [false, false, false, true, false, true]);
            match observation {
                TerminalObservation::Returned(Err(error)) => {
                    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
                    std::ptr::from_ref(error) as usize
                }
                _ => panic!("actual register_source_child contention original absent"),
            }
        })
        .unwrap();
    let partial = fixture.core().snapshot();
    let partial_census = fixture.core().storage_census.snapshot();
    assert_eq!(partial.reserved_bytes, paid.reserved_bytes);
    assert_eq!(partial.live_reservations, paid.live_reservations);
    // queue_read only clones existing native owners into inline empty state.
    // Native account/backing/pin construction belongs to prepare, never entered.
    assert_eq!(source.native_snapshot(), Some(native_before));
    assert_eq!(partial_census.source_active, before_census.source_active);
    assert_eq!(
        partial_census.source_reserved,
        before_census.source_reserved
    );
    assert_eq!(partial_census.readers, before_census.readers);
    assert!(!partial_census.fenced);
    assert!(!source.acknowledge_pool());
    assert_eq!(
        source.queue(0, 0).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(
        source.with_pending_queue_observation(0, |observation, _, _| {
            match observation {
                TerminalObservation::Returned(Err(error)) => std::ptr::from_ref(error) as usize,
                _ => 0,
            }
        }),
        Some(original)
    );
    // The registered pool closes/disposes its real queued native owner, report,
    // account and both child tokens. It retains the first construction error.
    source.seal();
    source.drain();
    assert_eq!(source.phase(), Some(SourcePoolPhase::Finished));
    assert_eq!(
        source.with_pending_queue_observation(0, |observation, disposal, held| {
            assert!(matches!(disposal, TerminalObservation::Returned(Ok(()))));
            assert_eq!(held, [false; 6]);
            match observation {
                TerminalObservation::Returned(Err(error)) => std::ptr::from_ref(error) as usize,
                _ => 0,
            }
        }),
        Some(original)
    );
    let settled = fixture.core().snapshot();
    assert_eq!(
        settled.reserved_bytes,
        baseline.reserved_bytes + metadata[0]
    );
    assert_eq!(settled.live_reservations, baseline.live_reservations + 1);
    let settled_census = fixture.core().storage_census.snapshot();
    assert_eq!(settled_census.source_pools, 1);
    assert_eq!(settled_census.source_reserved, 0);
    assert_eq!(settled_census.source_active, 0);
    // Positive tail disposal permits explicit acknowledgement, never the
    // earlier failed queue or merely dropping its returned marker.
    assert!(source.acknowledge_pool());
    let pool_id = source.id();
    drop(source);
    fixture.core().storage_census.drain_owner(pool_id);
    assert_eq!(
        fixture.core().snapshot().reserved_bytes,
        baseline.reserved_bytes
    );
    assert_eq!(
        fixture.core().snapshot().live_reservations,
        baseline.live_reservations
    );
    assert!(!is_present(fixture.core(), pool_id));
    fixture.finish()
}
