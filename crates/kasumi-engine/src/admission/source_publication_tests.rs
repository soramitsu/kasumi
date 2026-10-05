use super::*;
use crate::admission::{AdmissionConfig, NodeAdmission};
use kasumi_kv::{
    DatabaseOpenSettlement, SourceReadSettlement, SourceRightsSettlement, TerminalObservation,
};
use kasumi_store::{
    NativeSourceFundingFixture, NodeOpeningMode, NodeOpeningPhase, NodeWriterPhase,
    RegisteredNodeOpening, StorageCensusDisposition,
};

pub(super) struct Fixture {
    _directory: tempfile::TempDir,
    storage: crate::test_utils::FixtureStorage,
    opening: RegisteredNodeOpening,
}
impl Fixture {
    pub(super) fn new() -> anyhow::Result<Self> {
        let directory = kasumi_store::test_utils::private_tempdir()?;
        let (mut persistent, mut scratch) =
            crate::test_utils::fixture_disk_configs(directory.path())?;
        persistent.native_storage.cache.byte_limit = 0;
        scratch.native_cache_bytes = 0;
        let config = crate::test_utils::isolated_disk_admission_config(
            AdmissionConfig {
                max_inflight_bytes: Some(256 << 20),
                ..Default::default()
            },
            &persistent,
            &scratch,
        )?;
        let admission = NodeAdmission::with_fixed_memory(config, 2 << 30, 0)?;
        let storage =
            crate::test_utils::FixtureStorage::with_admission(&persistent, &scratch, admission)?;
        let opening = RegisteredNodeOpening::prepare(
            &directory.path().join("persistent/funded.kv"),
            uuid::Uuid::from_u128(491),
            storage.persistent.clone(),
            NodeOpeningMode::Create,
            storage.persistent.native_storage_config(),
        )
        .unwrap_or_else(|original| std::panic::panic_any(original));
        assert_eq!(opening.open(), NodeOpeningPhase::Open);
        let tables = opening.queue_node_tables()?;
        assert_eq!(tables.run(), NodeWriterPhase::Finished);
        opening.publish_ready_after_tables(&tables)?;
        assert_eq!(tables.retire(), StorageCensusDisposition::Retired);
        Ok(Self {
            _directory: directory,
            storage,
            opening,
        })
    }
    pub(super) fn core(&self) -> &Arc<MemoryCore> {
        self.storage.admission.memory()
    }
    pub(super) fn registered(&self) -> kasumi_store::RegisteredSourceFundingFixture {
        self.opening
            .queue_registered_source_funding_fixture()
            .unwrap()
    }
    pub(super) fn opening(&self) -> &RegisteredNodeOpening {
        &self.opening
    }
    pub(super) fn fill_all(&self) -> anyhow::Result<Reservation> {
        let remaining = self.core().data.max_bytes - self.core().snapshot().reserved_bytes;
        Ok(self.storage.admission.reserve_resident(remaining)?)
    }
    pub(super) fn native(&self) -> NativeSourceFundingFixture {
        self.opening.queue_native_source_funding_fixture().unwrap()
    }
    pub(super) fn finish(self) -> anyhow::Result<()> {
        assert_eq!(self.opening.close()?, DatabaseOpenSettlement::Closed);
        assert_eq!(self.opening.retire(), StorageCensusDisposition::Retired);
        Ok(())
    }
}
fn ok<E>(observation: TerminalObservation<'_, E>) -> bool {
    matches!(observation, TerminalObservation::Returned(Ok(())))
}
pub(super) fn close(reads: &mut NativeSourceFundingFixture, slot: usize) {
    reads.close_read(slot).unwrap();
    assert!(reads.read(slot).unwrap().is_closed());
    assert!(ok(reads.read(slot).unwrap().account_controller_disposal()));
    // Clean account-admission denial creates no account and needs no ticket.
    assert!(
        ok(reads.read(slot).unwrap().account_retirement())
            || matches!(
                reads.read(slot).unwrap().account_retirement(),
                TerminalObservation::NotEntered
            )
    );
}

#[test]
fn native_source_bank_real_provider_two_lanes_capture_with_ordinary_bytes_full()
-> anyhow::Result<()> {
    let fixture = Fixture::new()?;
    let before = fixture.core().snapshot();
    let mut reads = fixture.native();
    let (result, live, peak, allocations) =
        crate::document_pool::allocation_tests::measure_topology_input(|| {
            reads.install()?;
            reads.prepare(0)?;
            reads.prepare(1)
        });
    result.unwrap();
    assert!(ok(reads.pool().installation()));
    assert_eq!(reads.rights().settlement(), SourceRightsSettlement::Ready);
    let bank = reads.pool().snapshot().unwrap();
    assert_eq!(bank.charged_bytes, bank.fixed_bytes + 2 * bank.lane_bytes);
    assert!(allocations > 0 && live > 0 && peak as u64 <= bank.charged_bytes);
    assert_eq!(
        fixture.core().snapshot().reserved_bytes - before.reserved_bytes,
        bank.charged_bytes
    );
    assert_eq!(
        fixture.core().snapshot().live_reservations - before.live_reservations,
        1
    );
    for slot in [0, 1] {
        assert_eq!(
            reads.read(slot).unwrap().native_report().settlement(),
            SourceReadSettlement::Prepared
        );
    }
    // No ordinary provider reserve is hidden in either funded constructor.
    assert_eq!(
        fixture.core().snapshot().reserved_bytes - before.reserved_bytes,
        bank.charged_bytes
    );
    assert_eq!(
        fixture.core().snapshot().live_reservations - before.live_reservations,
        1
    );
    reads.capture(0).unwrap();
    let old = reads.read(0).unwrap().selected_generation().unwrap();
    reads.publish_generation(73)?;
    let remaining = fixture.core().data.max_bytes - fixture.core().snapshot().reserved_bytes;
    let filler = fixture.storage.admission.reserve_resident(remaining)?;
    let saturated = fixture.core().snapshot();
    assert_eq!(saturated.reserved_bytes, fixture.core().data.max_bytes);
    reads.capture(1).unwrap();
    assert!(reads.read(1).unwrap().selected_generation().unwrap() > old);
    assert_eq!(reads.read(0).unwrap().selected_generation(), Some(old));
    assert_eq!(
        fixture.core().snapshot().reserved_bytes,
        saturated.reserved_bytes
    );
    assert_eq!(
        fixture.core().snapshot().live_reservations,
        saturated.live_reservations
    );
    reads.prepare(2).unwrap();
    assert!(
        matches!(reads.read(2).unwrap().account_installation(), TerminalObservation::Returned(Err(kasumi_kv::SourceFundingError::Provider(error))) if error.kind() == io::ErrorKind::OutOfMemory)
    );
    assert_eq!(reads.pool().snapshot().unwrap().assigned, 2);
    close(&mut reads, 2);
    drop(filler);
    close(&mut reads, 0);
    close(&mut reads, 1);
    reads.retire().unwrap();
    assert!(ok(reads.pool().sealing()));
    assert!(ok(reads.pool().disposal()));
    drop(reads);
    assert_eq!(
        fixture.core().snapshot().reserved_bytes,
        before.reserved_bytes
    );
    fixture.finish()
}

#[test]
fn native_source_history_transfers_actual_children_and_sealed_bank_keeps_only_fixed_credit()
-> anyhow::Result<()> {
    let fixture = Fixture::new()?;
    let before = fixture.core().snapshot();
    let mut reads = fixture.native();
    reads.install().unwrap();
    reads.prepare(0).unwrap();
    reads.capture(0).unwrap();
    let generation = reads.read(0).unwrap().selected_generation();
    let bank = reads.pool().snapshot().unwrap();
    reads.prepare_history(0).unwrap();
    assert!(ok(reads.read(0).unwrap().history_preparation().unwrap()));
    assert_eq!(
        reads
            .read(0)
            .unwrap()
            .history_report()
            .unwrap()
            .settlement(),
        kasumi_kv::SourceHistorySettlement::Prepared
    );
    let ordinary =
        fixture.core().snapshot().reserved_bytes - before.reserved_bytes - bank.charged_bytes;
    assert!(ordinary >= bank.lane_bytes);
    reads.commit_history(0).unwrap();
    assert!(ok(reads.read(0).unwrap().history_exchange().unwrap()));
    assert_eq!(reads.pool().snapshot().unwrap().assigned, 0);
    assert_eq!(reads.read(0).unwrap().selected_generation(), generation);
    assert_eq!(
        fixture.core().snapshot().reserved_bytes,
        before.reserved_bytes + bank.charged_bytes + ordinary
    );
    // Rights facade retires; the historical real PinInner still retains its
    // RightsInner allocation. The one-way bank shrink must preserve fixed B.
    reads.retire().unwrap();
    assert!(ok(reads.pool().sealing()));
    assert_eq!(
        fixture.core().snapshot().reserved_bytes,
        before.reserved_bytes + bank.fixed_bytes + ordinary
    );
    assert_eq!(reads.read(0).unwrap().selected_generation(), generation);
    close(&mut reads, 0);
    drop(reads);
    assert_eq!(
        fixture.core().snapshot().reserved_bytes,
        before.reserved_bytes
    );
    fixture.finish()
}

#[test]
fn native_source_busy_seal_resumes_only_after_positive_account_retirement() -> anyhow::Result<()> {
    let fixture = Fixture::new()?;
    let before = fixture.core().snapshot();
    let mut reads = fixture.native();
    reads.install().unwrap();
    reads.prepare(0).unwrap();
    let bank = reads.pool().snapshot().unwrap();
    reads.seal_pool();
    assert!(ok(reads.pool().seal_barrier()));
    assert!(matches!(
        reads.pool().sealing(),
        TerminalObservation::NotEntered
    ));
    assert!(!reads.pool().is_ready());
    assert!(reads.prepare(1).is_err());
    assert_eq!(
        reads.pool().snapshot().unwrap().charged_bytes,
        bank.charged_bytes
    );
    close(&mut reads, 0);
    reads.retire().unwrap();
    assert!(ok(reads.pool().sealing()));
    drop(reads);
    assert_eq!(
        fixture.core().snapshot().reserved_bytes,
        before.reserved_bytes
    );
    fixture.finish()
}

#[test]
fn native_source_history_byte_denial_preserves_original_then_cancels_unentered_native_hold()
-> anyhow::Result<()> {
    let fixture = Fixture::new()?;
    let mut reads = fixture.native();
    reads.install().unwrap();
    reads.prepare(0).unwrap();
    reads.capture(0).unwrap();
    let remaining = fixture.core().data.max_bytes - fixture.core().snapshot().reserved_bytes;
    let filler = fixture.storage.admission.reserve_resident(remaining)?;
    reads.prepare_history(0).unwrap();
    assert!(
        matches!(reads.read(0).unwrap().history_preparation().unwrap(), TerminalObservation::Returned(Err(kasumi_kv::SourceFundingError::Provider(error))) if error.kind() == io::ErrorKind::OutOfMemory)
    );
    assert!(matches!(
        reads
            .read(0)
            .unwrap()
            .history_report()
            .unwrap()
            .preparation(),
        TerminalObservation::NotEntered
    ));
    assert_eq!(reads.pool().snapshot().unwrap().assigned, 1);
    drop(filler);
    close(&mut reads, 0);
    // Cleanup did not rewrite the failed byte admission as successful prepare.
    assert!(matches!(
        reads.read(0).unwrap().history_preparation().unwrap(),
        TerminalObservation::Returned(Err(_))
    ));
    reads.retire().unwrap();
    drop(reads);
    fixture.finish()
}

#[test]
fn native_source_binding_rejects_same_policy_foreign_core_without_fallback() -> anyhow::Result<()> {
    let fixture = Fixture::new()?;
    let other = NodeAdmission::with_fixed_memory(AdmissionConfig::default(), 2 << 30, 0)?;
    let expected: Arc<dyn kasumi_store::NodeDiskMemoryAdmission> = other.memory().clone();
    let before = fixture.core().snapshot();
    let foreign_before = other.snapshot();
    let mut native = fixture
        .opening
        .queue_native_source_funding_with_provider_fixture(Some(expected))
        .unwrap();
    native.install().unwrap();
    assert!(!native.pool().is_ready());
    assert_eq!(
        native.pool().protocol_error(),
        Some(kasumi_kv::SourceFundingCallError::ForeignProvider)
    );
    assert!(native.pool().snapshot().is_none());
    assert_eq!(
        fixture.core().snapshot().reserved_bytes,
        before.reserved_bytes
    );
    assert_eq!(
        other.snapshot().reserved_bytes,
        foreign_before.reserved_bytes
    );
    native.dispose_unbound_pool().unwrap();
    assert!(ok(native.pool().disposal()));
    // The original provider mismatch remains available after positive cleanup.
    assert_eq!(
        native.pool().protocol_error(),
        Some(kasumi_kv::SourceFundingCallError::ForeignProvider)
    );
    drop(native);
    fixture.finish()
}

#[test]
fn native_source_prepared_rights_block_actual_opening_close_before_capture() -> anyhow::Result<()> {
    let fixture = Fixture::new()?;
    let mut reads = fixture.native();
    reads.install().unwrap();
    reads.prepare(0).unwrap();
    assert!(reads.read(0).unwrap().selected_generation().is_none());
    assert_eq!(
        fixture.opening.close()?,
        DatabaseOpenSettlement::WaitingForTransactions
    );
    close(&mut reads, 0);
    reads.retire().unwrap();
    drop(reads);
    fixture.finish()
}

#[test]
fn native_source_bank_exact_byte_boundary_preserves_cache_and_ordinary_headroom()
-> anyhow::Result<()> {
    let fixture = Fixture::new()?;
    let before = fixture.core().snapshot();
    let mut probe = fixture.native();
    probe.install().unwrap();
    let required = probe.pool().snapshot().unwrap().charged_bytes;
    probe.retire().unwrap();
    drop(probe);
    assert_eq!(
        fixture.core().snapshot().reserved_bytes,
        before.reserved_bytes
    );
    let protection = fixture.core().protect_ordinary(8192, 1)?;
    let (cache_headroom, _) = fixture
        .core()
        .data
        .config
        .cache_work_headroom(fixture.core().data.max_bytes);
    let ordinary = fixture.core().data.state.lock().unwrap().ordinary_protected;
    for short in [1, 0] {
        let baseline = fixture.core().snapshot();
        let filler_bytes = fixture.core().data.max_bytes
            - baseline.reserved_bytes
            - cache_headroom
            - ordinary
            - required
            + short;
        let filler = fixture.storage.admission.reserve_resident(filler_bytes)?;
        let filled = fixture.core().snapshot();
        let mut native = fixture.native();
        native.install().unwrap();
        if short == 1 {
            assert!(!native.pool().is_ready());
            assert!(
                matches!(native.pool().installation(), TerminalObservation::Returned(Err(kasumi_kv::SourceFundingError::Provider(error))) if error.kind() == io::ErrorKind::OutOfMemory)
            );
            assert!(native.pool().snapshot().is_none());
            assert_eq!(
                fixture.core().snapshot().reserved_bytes,
                filled.reserved_bytes
            );
            assert_eq!(
                fixture.core().snapshot().live_reservations,
                filled.live_reservations
            );
            native.dispose_unbound_pool().unwrap();
            assert!(ok(native.pool().disposal()));
            assert!(matches!(
                native.pool().installation(),
                TerminalObservation::Returned(Err(_))
            ));
        } else {
            assert!(native.pool().is_ready());
            assert_eq!(
                fixture.core().snapshot().reserved_bytes,
                filled.reserved_bytes + required
            );
            assert_eq!(
                fixture.core().snapshot().live_reservations,
                filled.live_reservations + 1
            );
            assert_eq!(
                fixture.core().snapshot().reserved_bytes + cache_headroom + ordinary,
                fixture.core().data.max_bytes
            );
            native.retire().unwrap();
        }
        drop(native);
        drop(filler);
        assert_eq!(
            fixture.core().snapshot().reserved_bytes,
            baseline.reserved_bytes
        );
    }
    drop(protection);
    fixture.finish()
}

#[test]
fn native_source_history_slot_denial_retains_byte_grant_until_positive_cancel() -> anyhow::Result<()>
{
    let fixture = Fixture::new()?;
    let before = fixture.core().snapshot();
    let mut native = fixture.native();
    native.install().unwrap();
    native.prepare(0).unwrap();
    native.capture(0).unwrap();
    // Exactly two source rights share the real fixed 256-slot native registry.
    // These are separately admitted ordinary native readers, confined to the test-only bridge.
    let mut ordinary = fixture.opening.queue_native_slot_blockers_fixture()?;
    ordinary.begin();
    assert!(ok(ordinary.acquisition()));
    assert_eq!(ordinary.count(), 254);
    let filled = fixture.core().snapshot();
    native.prepare_history(0).unwrap();
    let read = native.read(0).unwrap();
    assert!(ok(read.history_preparation().unwrap()));
    assert!(
        matches!(&(read.history_report().unwrap().preparation()), TerminalObservation::Returned(Err(kasumi_kv::StorageError::Core(
            native_error
        ))) if matches!(native_error.rejected_cause(), Some(kasumi_kv::CoreErrorCause::CapacityDenied)))
    );
    assert_eq!(native.pool().snapshot().unwrap().assigned, 1);
    assert!(
        fixture.core().snapshot().reserved_bytes > filled.reserved_bytes,
        "actual ordinary history byte grant was not retained after native slot denial"
    );
    assert!(native.commit_history(0).is_err());
    close(&mut native, 0);
    assert!(matches!(&(native
            .read(0)
            .unwrap()
            .history_report()
            .unwrap()
            .preparation()), TerminalObservation::Returned(Err(kasumi_kv::StorageError::Core(
            native_error
        ))) if matches!(native_error.rejected_cause(), Some(kasumi_kv::CoreErrorCause::CapacityDenied))));
    assert_eq!(
        fixture.core().snapshot().reserved_bytes,
        filled.reserved_bytes
    );
    assert!(ordinary.close());
    drop(ordinary);
    native.retire().unwrap();
    drop(native);
    assert_eq!(
        fixture.core().snapshot().reserved_bytes,
        before.reserved_bytes
    );
    fixture.finish()
}
