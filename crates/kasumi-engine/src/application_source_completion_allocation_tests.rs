//! Actual admitted completion allocations; the parent supplies the existing
//! before/after-System.dealloc observer and serialized retirement gates.
use super::*;
use crate::{
    application_sources::completion::OrdinarySourceCompletion,
    document_pool::allocation_tests::measure_topology_input,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordinary_completion_constructor_quote_covers_actual_three_allocations() -> Result<()> {
    let _serial = SERIAL.lock().await;
    let fixture = Fixture::new().await?;
    let before = fixture.storage.admission.snapshot();
    let quote = OrdinarySourceCompletion::required_bytes()?;
    let (result, live, peak, allocations) =
        measure_topology_input(|| OrdinarySourceCompletion::new(&fixture.roots));
    let (owner, binding) = result?;
    let after = fixture.storage.admission.snapshot();
    assert_eq!(
        allocations, 3,
        "cell Arc, credit Arc and erased binding Box"
    );
    assert!(live > 0 && peak >= live);
    assert!(u64::try_from(peak)? <= quote);
    assert_eq!(after.reserved_bytes - before.reserved_bytes, quote);
    assert_eq!(after.live_reservations - before.live_reservations, 1);
    drop(owner);
    assert_eq!(
        fixture.storage.admission.snapshot().reserved_bytes,
        after.reserved_bytes
    );
    drop(binding);
    assert_eq!(
        fixture.storage.admission.snapshot().reserved_bytes,
        before.reserved_bytes
    );
    assert_eq!(
        fixture.storage.admission.snapshot().live_reservations,
        before.live_reservations
    );
    fixture.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordinary_completion_cell_and_credit_remain_funded_through_actual_deallocation()
-> Result<()> {
    let _serial = SERIAL.lock().await;
    let fixture = Fixture::new().await?;
    for block_credit in [false, true] {
        let before = fixture.storage.admission.snapshot().reserved_bytes;
        let (owner, binding) = OrdinarySourceCompletion::new(&fixture.roots)?;
        drop(binding);
        let grant = fixture.storage.admission.snapshot().reserved_bytes - before;
        assert_eq!(grant, OrdinarySourceCompletion::required_bytes()?);
        let data = owner.allocation_address_for_test();
        let credit = owner.credit_address_for_test();
        let filler = fill(&fixture)?;
        let slots = fixture.storage.admission.snapshot().live_reservations;
        arm(data, credit, block_credit);
        let retiring = Retiring::one(owner);
        assert_held(&fixture, grant, slots, block_credit).await;
        retiring.finish();
        assert_retired(&fixture, grant, slots)?;
        drop(filler);
    }
    fixture.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordinary_completion_erased_binding_retires_before_its_actual_credit() -> Result<()> {
    let _serial = SERIAL.lock().await;
    let fixture = Fixture::new().await?;
    for block_credit in [false, true] {
        let before = fixture.storage.admission.snapshot().reserved_bytes;
        let (owner, binding) = OrdinarySourceCompletion::new(&fixture.roots)?;
        let data = binding.allocation_address();
        let credit = owner.credit_address_for_test();
        let grant = fixture.storage.admission.snapshot().reserved_bytes - before;
        drop(owner);
        let filler = fill(&fixture)?;
        let slots = fixture.storage.admission.snapshot().live_reservations;
        arm(data, credit, block_credit);
        let retiring = Retiring::one(binding);
        assert_held(&fixture, grant, slots, block_credit).await;
        retiring.finish();
        assert_retired(&fixture, grant, slots)?;
        drop(filler);
    }
    fixture.close().await
}
