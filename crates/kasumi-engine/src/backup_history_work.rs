//! External history bodies are independent of the logical snapshot's maximum
//! record. Keep both workspaces while their DTOs and point reads overlap.
use crate::admission::{NodeAdmission, Reservation};
use anyhow::{Result, ensure};
use kasumi_types::{HistoryArchiveChunk, MAX_ARCHIVE_CHUNK_BYTES};
use std::sync::Arc;

fn workspace(bytes: &[u8], retained: u64, check: &mut dyn FnMut() -> Result<()>) -> Result<u64> {
    ensure!(
        bytes.len() <= MAX_ARCHIVE_CHUNK_BYTES,
        "external history body exceeds its installed record limit"
    );
    let external = crate::snapshot_codec::inspect_external_json_work(bytes, check)?;
    retained
        .checked_add(external)
        .ok_or_else(|| anyhow::anyhow!("external history workspace overflow"))
}

pub(super) fn verify_body(
    bytes: Vec<u8>,
    reservation: &Reservation,
    admission: &Arc<NodeAdmission>,
    retained: u64,
    check: &mut dyn FnMut() -> Result<()>,
    verify: impl FnOnce(&HistoryArchiveChunk, &mut dyn FnMut() -> Result<()>) -> Result<()>,
) -> Result<()> {
    let peak = workspace(&bytes, retained, check)?;
    reservation.handoff_workspace(admission, peak)?;
    let result = (|| {
        check()?;
        let body: HistoryArchiveChunk = serde_json::from_slice(&bytes)?;
        verify(&body, check)?;
        check()?;
        Ok(())
    })();
    // The body, its validation temporaries and the external plaintext are gone
    // before returning to the retained logical index/point-read budget. On error
    // or panic the blocking worker keeps the expanded owner until actual drain.
    drop(bytes);
    if result.is_ok() {
        reservation.handoff_workspace(admission, retained)?;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::AdmissionConfig;

    fn body() -> Vec<u8> {
        let mut bytes = br#"{"kind":"history_subset","archive_id":"archive","source_incarnation":"source","collection":"rows","index":0,"documents":[{"id":"row","version":1,"body":{"dense":["#.to_vec();
        for i in 0..8192 {
            if i != 0 {
                bytes.push(b',');
            }
            bytes.push(b'0');
        }
        bytes.extend_from_slice(b"]}}]}");
        bytes
    }

    fn governor(maximum: u64) -> Arc<NodeAdmission> {
        NodeAdmission::with_fixed_memory(
            AdmissionConfig {
                max_inflight_bytes: Some(maximum),
                ..Default::default()
            },
            2 << 30,
            0,
        )
        .unwrap()
    }

    #[test]
    fn dense_external_body_requires_its_peak_in_addition_to_retained_point_work() {
        let bytes = body();
        let retained = (128 << 20) + (3 << 20);
        let peak = workspace(&bytes, retained, &mut || Ok(())).unwrap();
        assert!(bytes.len() < MAX_ARCHIVE_CHUNK_BYTES);
        assert!(peak - retained > bytes.len() as u64 * 32);
        let denied = governor(peak - 1);
        let reservation = denied.reserve(retained, None).unwrap();
        let mut entered = false;
        let error = verify_body(
            bytes.clone(),
            &reservation,
            &denied,
            retained,
            &mut || Ok(()),
            |_, _| {
                entered = true;
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<kasumi_types::Error>().unwrap().code,
            kasumi_types::ErrorCode::ResourceExhausted
        );
        assert!(!entered);
        assert_eq!(denied.snapshot().reserved_bytes, retained);
        drop(reservation);
        assert_eq!(denied.snapshot().reserved_bytes, 0);

        let admitted = governor(peak);
        let reservation = admitted.reserve(retained, None).unwrap();
        verify_body(
            bytes,
            &reservation,
            &admitted,
            retained,
            &mut || Ok(()),
            |body, check| {
                assert_eq!(admitted.snapshot().reserved_bytes, peak);
                assert_eq!(
                    body.documents[0].body["dense"].as_array().unwrap().len(),
                    8192
                );
                check()
            },
        )
        .unwrap();
        assert_eq!(admitted.snapshot().reserved_bytes, retained);
        drop(reservation);
        assert_eq!(admitted.snapshot().reserved_bytes, 0);
    }

    #[test]
    fn decode_failure_and_validation_panic_keep_the_expanded_charge_until_owner_drain() {
        let retained = 128 << 20;
        let malformed = br#"{"kind":"history_subset","documents":[0,0,0]}"#.to_vec();
        let peak = workspace(&malformed, retained, &mut || Ok(())).unwrap();
        let admission = governor(peak);
        let reservation = admission.reserve(retained, None).unwrap();
        assert!(
            verify_body(
                malformed,
                &reservation,
                &admission,
                retained,
                &mut || Ok(()),
                |_, _| panic!("malformed body reached semantic verification")
            )
            .is_err()
        );
        assert_eq!(admission.snapshot().reserved_bytes, peak);
        drop(reservation);
        assert_eq!(admission.snapshot().reserved_bytes, 0);

        let bytes = body();
        let peak = workspace(&bytes, retained, &mut || Ok(())).unwrap();
        let admission = governor(peak);
        let reservation = admission.reserve(retained, None).unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            verify_body(
                bytes,
                &reservation,
                &admission,
                retained,
                &mut || Ok(()),
                |_, _| panic!("injected verifier panic"),
            )
        }));
        assert!(result.is_err());
        assert_eq!(admission.snapshot().reserved_bytes, peak);
        drop(reservation);
        assert_eq!(admission.snapshot().reserved_bytes, 0);
    }

    #[tokio::test]
    async fn cancelled_waiter_keeps_external_body_and_point_work_until_the_worker_drains() {
        use crate::{
            admission::WorkFence,
            backup_verify::{VerificationDeadline, VerificationWork},
        };
        use std::time::Duration;

        let bytes = body();
        let retained = (128 << 20) + (3 << 20);
        let peak = workspace(&bytes, retained, &mut || Ok(())).unwrap();
        let admission = governor(peak);
        let reservation = Arc::new(admission.reserve(retained, None).unwrap());
        let worker_reservation = reservation.clone();
        let worker_admission = admission.clone();
        let fence = Arc::new(WorkFence::default());
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let registration = VerificationWork::new(
            fence.begin(Default::default()).unwrap(),
            slots.clone().try_acquire_owned().unwrap(),
        );
        let (entered, body_live) = tokio::sync::oneshot::channel();
        let (body_done, body_gone) = tokio::sync::oneshot::channel();
        let (release_body, body_release) = std::sync::mpsc::channel();
        let (release_worker, worker_release) = std::sync::mpsc::channel();
        let deadline = VerificationDeadline::new(10_000).unwrap();
        let task = tokio::spawn(async move {
            deadline
                .blocking(reservation, Some(registration), move || {
                    verify_body(
                        bytes,
                        &worker_reservation,
                        &worker_admission,
                        retained,
                        &mut || deadline.check(),
                        |body, check| {
                            assert_eq!(
                                body.documents[0].body["dense"].as_array().unwrap().len(),
                                8192
                            );
                            entered.send(()).unwrap();
                            body_release.recv_timeout(Duration::from_secs(5))?;
                            check()
                        },
                    )?;
                    body_done.send(()).unwrap();
                    worker_release.recv_timeout(Duration::from_secs(5))?;
                    Ok(())
                })
                .await
        });
        tokio::time::timeout(Duration::from_secs(5), body_live)
            .await
            .unwrap()
            .unwrap();
        task.abort();
        assert!(
            tokio::time::timeout(Duration::from_secs(5), task)
                .await
                .unwrap()
                .unwrap_err()
                .is_cancelled()
        );
        fence.seal();
        assert!(
            tokio::time::timeout(Duration::from_millis(25), fence.drain())
                .await
                .is_err()
        );
        assert_eq!(admission.snapshot().reserved_bytes, peak);
        assert_eq!(slots.available_permits(), 0);

        release_body.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), body_gone)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(admission.snapshot().reserved_bytes, retained);
        assert_eq!(slots.available_permits(), 0);
        assert!(
            tokio::time::timeout(Duration::from_millis(25), fence.drain())
                .await
                .is_err()
        );

        release_worker.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), fence.drain())
            .await
            .unwrap();
        assert_eq!(admission.snapshot().reserved_bytes, 0);
        assert_eq!(admission.snapshot().inflight_operations, 0);
        assert_eq!(slots.available_permits(), 1);
    }
}
