//! Ordinary protection must preserve the same floor as already admitted sources/cache.
use super::*;
use kasumi_store::NodeDiskMemoryAdmission;

fn protection(core: &MemoryCore) -> (u64, usize) {
    let state = core.data.state.lock().unwrap();
    (state.ordinary_protected, state.ordinary_protected_slots)
}

#[test]
fn ordinary_protection_refuses_byte_or_slot_overlap_without_mutating_existing_owners()
-> anyhow::Result<()> {
    for dimension in ["bytes", "slots"] {
        let node = NodeAdmission::with_fixed_memory(
            AdmissionConfig {
                max_inflight_bytes: Some(64 << 20),
                max_reservations: 128,
                cache_work_reserve_bytes: Some(1 << 20),
                cache_work_reserve_slots: Some(4),
                ..Default::default()
            },
            2 << 30,
            0,
        )?;
        let core = node.memory();
        let old = core.protect_ordinary(4096, 1)?;
        let source = node.reserve_document_source(4096)?;
        let cache = core.clone().reserve_cache_memory(4096)?;
        let baseline = core.snapshot();
        let before_protection = protection(core);
        let requested = (8192, 2);
        let mut pressure = Vec::new();
        if dimension == "bytes" {
            // Fits the old bytes+ordinary-only check exactly; the already
            // admitted source/cache still require the separate cache-work floor.
            pressure.push(node.reserve_resident(
                core.data.max_bytes - baseline.reserved_bytes - before_protection.0 - requested.0,
            )?);
        } else {
            let count = core.data.config.max_reservations
                - baseline.live_reservations
                - before_protection.1
                - requested.1;
            for _ in 0..count {
                pressure.push(node.reserve_resident(0)?);
            }
        }
        let full = core.snapshot();
        let error = core
            .protect_ordinary(requested.0, requested.1)
            .err()
            .expect("installation cannot spend already required cache-work room");
        assert_eq!(error.code, ErrorCode::ResourceExhausted);
        assert_eq!(protection(core), before_protection);
        assert_eq!(core.snapshot().reserved_bytes, full.reserved_bytes);
        assert_eq!(core.snapshot().live_reservations, full.live_reservations);
        {
            let state = core.data.state.lock().unwrap();
            let actual = state.charge(source.slot, source.id).unwrap();
            assert_eq!(actual.bytes, 4096);
            assert!(actual.origin == ChargeOrigin::DocumentSource);
            assert!(
                state
                    .slots
                    .iter()
                    .filter_map(|slot| slot.charge.as_ref())
                    .any(|charge| charge.origin == ChargeOrigin::NativeCache)
            );
        }
        drop(pressure);
        let accepted = core.protect_ordinary(requested.0, requested.1)?;
        assert_eq!(
            protection(core),
            (
                before_protection.0 + requested.0,
                before_protection.1 + requested.1
            )
        );
        // A precise successful installation counted the prior protection once.
        let (cache_bytes, _) = core.data.config.cache_work_headroom(core.data.max_bytes);
        let floor = protection(core).0 + cache_bytes;
        let headroom = core.data.max_bytes - core.snapshot().reserved_bytes - floor;
        let exact = node.reserve_document_source(headroom)?;
        assert!(node.reserve_document_source(1).is_err());
        drop(exact);
        drop(accepted);
        assert_eq!(protection(core), before_protection);
        drop(cache);
        drop(source);
        drop(old);
        assert_eq!(protection(core), (0, 0));
    }
    Ok(())
}
