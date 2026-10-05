//! Actual planner backing and registered-reader retirement preserve bare denial.
use super::*;

fn outer_is_access_denied(original: &anyhow::Error) -> bool {
    let outer: &(dyn std::error::Error + Send + Sync) = original.as_ref();
    outer.downcast_ref::<crate::KeyAccessDenied>().is_some()
}

fn original_address(original: &anyhow::Error) -> usize {
    let outer: &(dyn std::error::Error + Send + Sync) = original.as_ref();
    std::ptr::from_ref(outer) as *const () as usize
}

#[tokio::test]
async fn planner_access_denial_preserves_exact_original_after_positive_native_and_backing_retirement()
-> Result<()> {
    for transfer in [false, true] {
        let fixture = Fixture::new(0).await?;
        fixture.write(&[29; 64])?;
        let baseline = fixture.memory.snapshot();
        let mut session = fixture.session(64)?;
        let id = session.registered_reader_id().unwrap();
        assert_eq!(
            session.application_get("payload", b"key", 64)?,
            Some(&[29; 64][..])
        );
        assert!(fixture.memory.snapshot().used_bytes > baseline.used_bytes);
        fixture.stores.application().seal();
        let original = session.application_get("payload", b"key", 64).unwrap_err();
        assert!(outer_is_access_denied(&original));
        let address = original_address(&original);
        let original = if transfer {
            session
                .finish_with_workspace::<()>(Err(original))
                .err()
                .unwrap()
        } else {
            session.finish::<()>(Err(original)).unwrap_err()
        };
        assert!(outer_is_access_denied(&original));
        assert_eq!(original_address(&original), address);
        assert_eq!(
            original.to_string(),
            "tenant is sealed: key-access lease unavailable or expired"
        );
        assert_eq!(fixture.memory.storage_census().snapshot().readers, 0);
        assert!(RegisteredNodeRead::retained(fixture.memory.clone(), id).is_none());
        let retired = fixture.memory.snapshot();
        assert_eq!(retired.used_bytes, baseline.used_bytes);
        assert_eq!(retired.live_reservations, baseline.live_reservations);
        // Retaining this unchanged diagnostic does not keep native custody.
        fixture.close().await?;
        assert_eq!(original_address(&original), address);
    }
    Ok(())
}

#[tokio::test]
async fn planner_access_denial_inside_actual_backing_panic_keeps_outer_owner_and_both_originals()
-> Result<()> {
    for transfer in [false, true] {
        let fixture = Fixture::new(0).await?;
        fixture.write(&[31; 64])?;
        let mut session = fixture.session(64)?;
        let id = session.registered_reader_id().unwrap();
        fixture.stores.application().seal();
        let original = session.application_get("payload", b"key", 64).unwrap_err();
        let address = original_address(&original);
        fixture
            .memory
            .panic_on_last_point_lease_drop(Box::new(0x719_u64));
        let error = if transfer {
            session
                .finish_with_workspace::<()>(Err(original))
                .err()
                .unwrap()
        } else {
            session.finish::<()>(Err(original)).unwrap_err()
        };
        assert!(!outer_is_access_denied(&error));
        let failure = error
            .downcast_ref::<crate::NodeScopedReadFailure>()
            .unwrap();
        assert_eq!(failure.reader_id(), id);
        let body = failure.body_error().unwrap();
        assert!(outer_is_access_denied(body));
        assert_eq!(original_address(body), address);
        for _ in 0..2 {
            assert_eq!(
                failure.try_retire_routine(),
                StorageCensusDisposition::Retained
            );
            let report = failure.report();
            let kasumi_kv::TerminalObservation::Panicked(payload) = report.body_panic() else {
                panic!("exact original backing retirement panic absent");
            };
            assert_eq!(payload.downcast_ref::<u64>(), Some(&0x719));
        }
        drop(error);
        // Test-only acknowledgement after proving ordinary cleanup refuses
        // the injected unknown panic, matching the existing retirement control.
        assert_eq!(
            RegisteredNodeRead::retained(fixture.memory.clone(), id)
                .unwrap()
                .retire(),
            StorageCensusDisposition::Retired
        );
        fixture.close().await?;
    }
    Ok(())
}
