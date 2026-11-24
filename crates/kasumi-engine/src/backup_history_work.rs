//! Verify one external history document at a time alongside the retained snapshot index.
use crate::admission::{NodeAdmission, Reservation};
use anyhow::{Context, Result, ensure};
use kasumi_types::{
    Document, HistoryArchiveKind, HistoryArchiveManifest, MAX_ARCHIVE_CHUNK_BYTES,
    MAX_ARCHIVE_DOCUMENTS, staged_digest,
};
use serde::de::{Deserializer, SeqAccess, Visitor};
use serde_json::value::RawValue;
use std::{fmt, sync::Arc};
use zeroize::Zeroizing;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Chunk<'a> {
    #[serde(rename = "kind")]
    _kind: HistoryArchiveKind,
    archive_id: String,
    source_incarnation: String,
    collection: String,
    index: usize,
    #[serde(borrow)]
    documents: &'a RawValue,
}

impl Chunk<'_> {
    fn visit_raw(&self, mut visit: impl FnMut(&RawValue) -> Result<()>) -> Result<()> {
        struct Elements<'a, F> {
            visit: F,
            failure: &'a mut Option<anyhow::Error>,
        }
        impl<'de, F: FnMut(&'de RawValue) -> Result<()>> Visitor<'de> for Elements<'_, F> {
            type Value = ();
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an array of archived documents")
            }
            fn visit_seq<A: SeqAccess<'de>>(mut self, mut seq: A) -> Result<(), A::Error> {
                let mut count = 0;
                while let Some(raw) = seq.next_element::<&'de RawValue>()? {
                    if count == MAX_ARCHIVE_DOCUMENTS {
                        return Err(serde::de::Error::custom(
                            "external history document count exceeds its bound",
                        ));
                    }
                    count += 1;
                    if let Err(error) = (self.visit)(raw) {
                        // Propagate the original cancellation, capacity or source error.
                        *self.failure = Some(error);
                        return Err(serde::de::Error::custom("external history visit stopped"));
                    }
                }
                Ok(())
            }
        }
        let mut failure = None;
        let mut parser = serde_json::Deserializer::from_str(self.documents.get());
        let parsed = parser.deserialize_seq(Elements {
            visit: &mut visit,
            failure: &mut failure,
        });
        if let Some(error) = failure {
            return Err(error);
        }
        parsed?;
        parser.end()?;
        Ok(())
    }

    fn peak(&self, envelope: u64, check: &mut dyn FnMut() -> Result<()>) -> Result<u64> {
        let mut maximum = 0;
        self.visit_raw(|raw| {
            let work =
                crate::snapshot_codec::inspect_external_json_work(raw.get().as_bytes(), check)?;
            maximum = maximum.max(work);
            Ok(())
        })?;
        envelope
            .checked_add(maximum)
            .context("external history workspace overflow")
    }

    pub(super) fn verify_against(
        &self,
        state: &super::VerifiedState,
        manifest: &HistoryArchiveManifest,
        index: usize,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        let chunk = &manifest.chunks[index];
        ensure!(
            self.archive_id == manifest.archive_id
                && self.collection == manifest.collection
                && self.source_incarnation == manifest.source_incarnation
                && self.index == index,
            "full backup history chunk identity differs"
        );
        let collection = state.collection(&manifest.collection)?;
        let mut count = 0;
        let mut previous = String::new();
        self.visit_documents(check, |doc| {
            ensure!(
                count < chunk.document_count
                    && (count != 0 || doc.id == chunk.first_id)
                    && (count == 0 || previous < doc.id),
                "full backup history chunk identity differs"
            );
            let reference = state.archived(&manifest.collection, &doc.id)?;
            ensure!(
                reference.archive_id == manifest.archive_id
                    && reference.chunk_index == index
                    && reference.version == doc.version
                    && reference.document_sha256 == staged_digest(doc)?.0
                    && reference.document_bytes == crate::accounting::encoded_len(doc)?
                    && reference.indexed_fields
                        == crate::state::history::index_fields(&collection.definition, doc),
                "full backup archived document differs from retained metadata"
            );
            count += 1;
            previous.clone_from(&doc.id);
            Ok(())
        })?;
        ensure!(
            count != 0 && count == chunk.document_count && previous == chunk.last_id,
            "full backup history chunk identity differs"
        );
        Ok(())
    }

    fn visit_documents(
        &self,
        check: &mut dyn FnMut() -> Result<()>,
        mut visit: impl FnMut(&Document) -> Result<()>,
    ) -> Result<()> {
        self.visit_raw(|raw| {
            check()?;
            visit(&serde_json::from_str(raw.get())?)?;
            check()
        })
    }
}

fn envelope_workspace(bytes: &[u8], retained: u64) -> Result<u64> {
    ensure!(
        bytes.len() <= MAX_ARCHIVE_CHUNK_BYTES,
        "external history body exceeds its installed record limit"
    );
    // Plaintext, owned header strings and parser escape scratch, including
    // capacity growth. Both document passes borrow slices from this plaintext.
    retained
        .checked_add(4 * bytes.len() as u64 + (64 << 10))
        .context("external history workspace overflow")
}

pub(super) fn verify_body(
    bytes: Zeroizing<Vec<u8>>,
    reservation: &Reservation,
    admission: &Arc<NodeAdmission>,
    retained: u64,
    check: &mut dyn FnMut() -> Result<()>,
    verify: impl FnOnce(&Chunk<'_>, &mut dyn FnMut() -> Result<()>) -> Result<()>,
) -> Result<()> {
    let envelope = envelope_workspace(&bytes, retained)?;
    // Enforce the installed nesting bound and cancellation before parsing the
    // envelope. The structural meter uses a fixed stack.
    crate::snapshot_codec::inspect_external_json_work(&bytes, check)?;
    reservation.handoff_workspace(admission, envelope)?;
    let body: Chunk<'_> = serde_json::from_slice(&bytes)?;
    let peak = body.peak(envelope, check)?;
    if let Err(error) = reservation.handoff_workspace(admission, peak) {
        drop(body);
        drop(bytes);
        reservation.handoff_workspace(admission, retained)?;
        return Err(error.into());
    }
    let result = verify(&body, check).and_then(|()| check());
    drop(body);
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

    fn workspace(
        bytes: &[u8],
        retained: u64,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<u64> {
        serde_json::from_slice::<Chunk<'_>>(bytes)?
            .peak(envelope_workspace(bytes, retained)?, check)
    }

    fn body() -> Zeroizing<Vec<u8>> {
        let mut bytes = br#"{"kind":"history_subset","archive_id":"archive","source_incarnation":"source","collection":"rows","index":0,"documents":[{"id":"row","version":1,"body":{"dense":["#.to_vec();
        for i in 0..8192 {
            if i != 0 {
                bytes.push(b',');
            }
            bytes.push(b'0');
        }
        bytes.extend_from_slice(b"]}}]}");
        Zeroizing::new(bytes)
    }

    fn governor(maximum: u64) -> Arc<NodeAdmission> {
        NodeAdmission::with_fixed_memory(
            crate::test_utils::admission_config_with_bookkeeping(AdmissionConfig {
                max_inflight_bytes: Some(maximum),
                ..Default::default()
            })
            .unwrap(),
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
        assert_eq!(crate::test_utils::reserved_payload_bytes(&denied), retained);
        drop(reservation);
        assert_eq!(crate::test_utils::reserved_payload_bytes(&denied), 0);

        let admitted = governor(peak);
        let reservation = admitted.reserve(retained, None).unwrap();
        verify_body(
            bytes,
            &reservation,
            &admitted,
            retained,
            &mut || Ok(()),
            |body, check| {
                assert_eq!(crate::test_utils::reserved_payload_bytes(&admitted), peak);
                body.visit_documents(check, |doc| {
                    assert_eq!(doc.body["dense"].as_array().unwrap().len(), 8192);
                    Ok(())
                })?;
                check()
            },
        )
        .unwrap();
        assert_eq!(
            crate::test_utils::reserved_payload_bytes(&admitted),
            retained
        );
        drop(reservation);
        assert_eq!(crate::test_utils::reserved_payload_bytes(&admitted), 0);
    }

    #[test]
    fn multiple_documents_share_the_largest_decode_workspace() {
        let original = body();
        let value: serde_json::Value = serde_json::from_slice(&original).unwrap();
        let document = &value["documents"][0];
        let mut multiple = value.clone();
        multiple["documents"] = serde_json::json!([document, document, document]);
        let bytes = Zeroizing::new(serde_json::to_vec(&multiple).unwrap());
        let retained = 128 << 20;
        let peak = workspace(&bytes, retained, &mut || Ok(())).unwrap();
        let single = crate::snapshot_codec::inspect_typed_json_work(document).unwrap();
        assert_eq!(peak, envelope_workspace(&bytes, retained).unwrap() + single);
        let admission = governor(peak);
        let reservation = admission.reserve(retained, None).unwrap();
        let mut seen = 0;
        verify_body(
            bytes,
            &reservation,
            &admission,
            retained,
            &mut || Ok(()),
            |chunk, check| {
                chunk.visit_documents(check, |_| {
                    seen += 1;
                    Ok(())
                })
            },
        )
        .unwrap();
        assert_eq!(seen, 3);
        assert_eq!(
            crate::test_utils::reserved_payload_bytes(&admission),
            retained
        );
    }

    #[test]
    fn decode_failure_and_validation_panic_keep_the_expanded_charge_until_owner_drain() {
        let retained = 128 << 20;
        let malformed =
            Zeroizing::new(br#"{"kind":"history_subset","documents":[0,0,0]}"#.to_vec());
        let peak = envelope_workspace(&malformed, retained).unwrap();
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
        assert_eq!(crate::test_utils::reserved_payload_bytes(&admission), peak);
        drop(reservation);
        assert_eq!(crate::test_utils::reserved_payload_bytes(&admission), 0);

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
        assert_eq!(crate::test_utils::reserved_payload_bytes(&admission), peak);
        drop(reservation);
        assert_eq!(crate::test_utils::reserved_payload_bytes(&admission), 0);
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
        let task: tokio::task::JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
            deadline
                .blocking(reservation, Some(registration), move || {
                    verify_body(
                        bytes,
                        &worker_reservation,
                        &worker_admission,
                        retained,
                        &mut || deadline.check(),
                        |body, check| {
                            body.visit_documents(check, |doc| {
                                assert_eq!(doc.body["dense"].as_array().unwrap().len(), 8192);
                                Ok(())
                            })?;
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
        assert_eq!(crate::test_utils::reserved_payload_bytes(&admission), peak);
        assert_eq!(slots.available_permits(), 0);

        release_body.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), body_gone)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            crate::test_utils::reserved_payload_bytes(&admission),
            retained
        );
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
        assert_eq!(crate::test_utils::reserved_payload_bytes(&admission), 0);
        assert_eq!(admission.snapshot().inflight_operations, 0);
        assert_eq!(slots.available_permits(), 1);
    }
}
