use super::*;
use std::{future::Future, task::Poll};

async fn registered(authority: &IndependentAuthority, count: usize) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while authority.request_jobs.registered() != count {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

async fn close_after_unclaimed_release_outcome(
    fixture: Fixture,
    authority: &Arc<IndependentAuthority>,
) {
    use kasumi_types::drain::DrainCompletion;
    tokio::time::timeout(Duration::from_secs(10), async {
        while authority.request_jobs.completed_unclaimed_errors() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(authority.request_jobs.registered(), 1);
    assert_eq!(
        authority.requests.available_permits(),
        AUTHORITY_REQUEST_SLOTS
    );
    let failure = tokio::time::timeout(Duration::from_secs(10), authority.shutdown())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(failure.completion(), DrainCompletion::Complete);
    let issue = failure
        .issues()
        .iter()
        .find(|issue| issue.component() == "authority request outcome")
        .unwrap();
    let original = issue.error().downcast_ref::<Error>().unwrap();
    assert_eq!(original.code, ErrorCode::UnknownOutcome);
    assert_eq!(
        original.message,
        "authority acknowledgement unavailable; resolve the exact permanent command identity"
    );
    assert_eq!(authority.request_jobs.registered(), 0);
    assert_eq!(
        authority.requests.available_permits(),
        AUTHORITY_REQUEST_SLOTS
    );
    for service in &fixture.services {
        if !Arc::ptr_eq(service, authority) {
            service.shutdown().await.unwrap();
        }
    }
    for store in &fixture.stores {
        store.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn cancelled_public_command_waiter_keeps_actual_child_until_its_receipt_commits() {
    let fixture = Fixture::new().await;
    let authority = fixture.leader().await;
    let proposal = authority.proposal.lock().await;
    let command = fixture.command(AuthorityAction::ReplaceAdministrators {
        administrators: BTreeSet::from(["operator".into()]),
    });
    let retained_command = command.clone();
    let context = fixture.context("operator");
    let worker = authority.clone();
    let caller = tokio::spawn(async move { worker.execute(context, command).await });
    registered(&authority, 1).await;
    caller.abort();
    assert!(caller.await.err().unwrap().is_cancelled());
    assert_eq!(
        authority.requests.available_permits(),
        AUTHORITY_REQUEST_SLOTS - 1
    );
    assert_eq!(authority.request_jobs.registered(), 1);
    drop(proposal);
    tokio::time::timeout(Duration::from_secs(10), async {
        while authority
            .backend
            .receipt(&retained_command.tenant, retained_command.command_id)
            .unwrap()
            .is_none()
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    close_after_unclaimed_release_outcome(fixture, &authority).await;
}

#[tokio::test]
async fn acknowledgement_timeout_keeps_original_command_owner_and_actual_completion() {
    let fixture = Fixture::new().await;
    let authority = fixture.leader().await;
    let proposal = authority.proposal.lock().await;
    let permit = authority.permit().unwrap();
    let signer = authority.request_signer().unwrap();
    let context = fixture.context("operator");
    let command = fixture.command(AuthorityAction::ReplaceAdministrators {
        administrators: BTreeSet::from(["operator".into()]),
    });
    let retained_command = command.clone();
    let worker = authority.clone();
    let result = authority
        .accepted_request(
            tokio::time::Instant::now() + Duration::from_millis(20),
            async move { worker.execute_owned(permit, signer, context, command).await },
        )
        .await;
    assert_eq!(result.err().unwrap().code, ErrorCode::UnknownOutcome);
    assert_eq!(authority.request_jobs.registered(), 1);
    assert_eq!(
        authority.requests.available_permits(),
        AUTHORITY_REQUEST_SLOTS - 1
    );
    drop(proposal);
    tokio::time::timeout(Duration::from_secs(10), async {
        while authority
            .backend
            .receipt(&retained_command.tenant, retained_command.command_id)
            .unwrap()
            .is_none()
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    close_after_unclaimed_release_outcome(fixture, &authority).await;
}

#[tokio::test]
async fn timed_out_waiter_keeps_original_rejection_until_exact_shutdown_drain() {
    use kasumi_types::drain::DrainCompletion;
    let admission = kasumi_engine::admission::NodeAdmission::new(Default::default()).unwrap();
    let jobs = RequestJobs::new(request_budget(&admission)).unwrap();
    let requests = Arc::new(Semaphore::new(AUTHORITY_REQUEST_SLOTS));
    let (release, waiting) = tokio::sync::oneshot::channel::<()>();
    let (child, mut receive) = jobs
        .submit::<()>(requests.clone(), async move {
            waiting.await.unwrap();
            Err(Error::new(
                ErrorCode::Conflict,
                "original accepted authority rejection",
            ))
        })
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(10), &mut receive)
            .await
            .is_err()
    );
    drop(receive);
    release.send(()).unwrap();
    child.drain().await.unwrap();
    jobs.observe(&requests);
    assert_eq!(jobs.registered(), 1);
    assert!(!requests.is_closed());
    let failure = jobs.drain(&requests).await.unwrap_err();
    assert_eq!(failure.completion(), DrainCompletion::Complete);
    let issue = failure
        .issues()
        .iter()
        .find(|issue| issue.component() == "authority request outcome")
        .unwrap();
    let original = issue.error().downcast_ref::<Error>().unwrap();
    assert_eq!(original.code, ErrorCode::Conflict);
    assert_eq!(original.message, "original accepted authority rejection");
    assert_eq!(jobs.registered(), 0);
    let again = jobs.drain(&requests).await.unwrap_err();
    assert!(
        again
            .issues()
            .iter()
            .any(|candidate| Arc::ptr_eq(candidate, issue))
    );
}

#[tokio::test]
async fn ordinary_command_rejection_is_preserved_without_fencing_or_failed_drain() {
    let fixture = Fixture::new().await;
    let authority = fixture.leader().await;
    let mut command = fixture.command(AuthorityAction::ReplaceAdministrators {
        administrators: BTreeSet::from(["operator".into()]),
    });
    command.expected_policy_epoch += 1;
    let rejected = authority
        .execute(fixture.context("operator"), command)
        .await;
    assert_eq!(rejected.err().unwrap().code, ErrorCode::Conflict);
    assert!(!authority.requests.is_closed());
    authority.request_jobs.observe(&authority.requests);
    assert_eq!(authority.request_jobs.registered(), 0);
    assert!(!authority.requests.is_closed());
    fixture.close().await;
}

#[tokio::test]
async fn actual_child_panic_fences_admission_and_cancelled_drain_keeps_original_join_error() {
    use kasumi_types::drain::DrainCompletion;
    let fixture = Fixture::new().await;
    let authority = fixture.leader().await;
    let panic_permit = authority.permit().unwrap();
    let blocked_permit = authority.permit().unwrap();
    let (release, waiting) = tokio::sync::oneshot::channel::<()>();
    let (blocked, receive) = authority
        .request_jobs
        .submit(authority.requests.clone(), async move {
            let _permit = blocked_permit;
            waiting.await.unwrap();
            Ok(())
        })
        .unwrap();
    drop(receive);
    let (panicked, receive) = authority
        .request_jobs
        .submit::<()>(authority.requests.clone(), async move {
            let _permit = panic_permit;
            panic!("original accepted authority child panic");
        })
        .unwrap();
    assert!(receive.await.is_err());
    assert!(
        authority.requests.is_closed(),
        "actual unwind must fence before a later admission probe"
    );
    let original = panicked.drain().await.unwrap_err();
    assert!(
        original.issues()[0]
            .error()
            .downcast_ref::<tokio::task::JoinError>()
            .unwrap()
            .is_panic()
    );
    let mut cancelled = Box::pin(authority.shutdown());
    std::future::poll_fn(|cx| {
        assert!(cancelled.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(cancelled);
    assert!(blocked.observed().is_none());
    release.send(()).unwrap();
    let first = tokio::time::timeout(Duration::from_secs(10), authority.shutdown())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(first.completion(), DrainCompletion::Complete);
    assert!(
        first
            .issues()
            .iter()
            .any(|issue| Arc::ptr_eq(issue, &original.issues()[0]))
    );
    let again = authority.shutdown().await.unwrap_err();
    assert_eq!(again.completion(), DrainCompletion::Complete);
    assert!(
        again
            .issues()
            .iter()
            .any(|issue| Arc::ptr_eq(issue, &original.issues()[0]))
    );
    for service in &fixture.services {
        if !Arc::ptr_eq(service, &authority) {
            service.shutdown().await.unwrap();
        }
    }
    for store in &fixture.stores {
        store.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn request_registry_metadata_charge_outlives_cancelled_waiters_and_dropped_facade() {
    let admission = kasumi_engine::admission::NodeAdmission::new(Default::default()).unwrap();
    let bytes = authority_request_metadata_bytes().unwrap();
    let baseline = admission.snapshot().reserved_bytes;
    let charge = admission.memory().reserve_resident(bytes).unwrap();
    let jobs = RequestJobs::new(
        BackgroundWorkBudget::new(AUTHORITY_REQUEST_SLOTS, Arc::new(charge)).unwrap(),
    )
    .unwrap();
    let requests = Arc::new(tokio::sync::Semaphore::new(AUTHORITY_REQUEST_SLOTS));
    let (release, waiting) = tokio::sync::oneshot::channel::<()>();
    let (child, receive) = jobs
        .submit(requests, async move {
            waiting.await.unwrap();
            Ok(())
        })
        .unwrap();
    drop(receive);
    drop(jobs);
    assert_eq!(admission.snapshot().reserved_bytes, baseline + bytes);
    assert_eq!(admission.snapshot().inflight_operations, 0);
    let mut first = Box::pin(child.drain());
    std::future::poll_fn(|cx| {
        assert!(first.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(first);
    assert_eq!(admission.snapshot().reserved_bytes, baseline + bytes);
    release.send(()).unwrap();
    child.drain().await.unwrap();
    drop(child);
    assert_eq!(admission.snapshot().reserved_bytes, baseline);
}

#[tokio::test]
async fn request_child_inventory_is_bounded_and_capacity_denial_does_not_fence_owner() {
    let admission = kasumi_engine::admission::NodeAdmission::new(Default::default()).unwrap();
    let jobs = RequestJobs::new(request_budget(&admission)).unwrap();
    let requests = Arc::new(tokio::sync::Semaphore::new(AUTHORITY_REQUEST_SLOTS));
    let mut releases = Vec::new();
    for _ in 0..AUTHORITY_REQUEST_SLOTS {
        let (release, waiting) = tokio::sync::oneshot::channel::<()>();
        let (_, receive) = jobs
            .submit(requests.clone(), async move {
                waiting.await.unwrap();
                Ok(())
            })
            .unwrap();
        drop(receive);
        releases.push(release);
    }
    assert_eq!(jobs.registered(), AUTHORITY_REQUEST_SLOTS);
    assert_eq!(
        jobs.submit(requests.clone(), async { Ok(()) })
            .err()
            .unwrap()
            .code,
        ErrorCode::ResourceExhausted
    );
    assert!(!requests.is_closed());
    for release in releases {
        release.send(()).unwrap();
    }
    jobs.drain(&requests).await.unwrap();
    assert_eq!(jobs.registered(), 0);
}

#[tokio::test]
async fn authority_shutdown_retains_admitted_jobs_and_returned_fences_after_waiter_cancellation() {
    let fixture = Fixture::new().await;
    let authority = fixture.leader().await;
    let context = fixture.context("operator");
    let (_, fence) = authority
        .receipt(context.clone(), "acme", Uuid::new_v4())
        .await
        .unwrap();
    fence.release().await.unwrap();
    let admitted = authority.permit().unwrap();
    let signer = authority.request_signer().unwrap();
    let command = fixture.command(AuthorityAction::ReplaceAdministrators {
        administrators: BTreeSet::from(["operator".into()]),
    });
    let (resume, waiting) = tokio::sync::oneshot::channel::<()>();
    let worker = authority.clone();
    // This exact admitted owner is held before the real accepted worker reaches
    // its proposal mutex. The shutdown mutex cannot stand in for this lifetime.
    let job = tokio::spawn(async move {
        waiting.await.unwrap();
        worker
            .execute_owned(admitted, signer, context, command)
            .await
    });
    let mut first = Box::pin(authority.shutdown());
    std::future::poll_fn(|cx| {
        assert!(first.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    assert_eq!(
        authority.permit().err().unwrap().code,
        ErrorCode::Unavailable
    );
    assert!(authority.peer_allowed(authority.local_node_id).is_err());
    assert!(authority.initialize().await.is_err());
    assert!(fence.check().is_err());
    assert!(fence.release().await.is_err());
    drop(first);

    let mut retry = Box::pin(authority.shutdown());
    std::future::poll_fn(|cx| {
        assert!(retry.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    resume.send(()).unwrap();
    let outcome = tokio::time::timeout(Duration::from_secs(10), job)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(outcome.err().unwrap().code, ErrorCode::Unavailable);
    std::future::poll_fn(|cx| {
        assert!(
            retry.as_mut().poll(cx).is_pending(),
            "returned fence released its owner too soon"
        );
        Poll::Ready(())
    })
    .await;
    drop(fence);
    tokio::time::timeout(Duration::from_secs(10), retry)
        .await
        .unwrap()
        .unwrap();
    fixture.close().await;
}

#[tokio::test]
async fn original_signer_authorization_is_reused_when_all_native_slots_are_occupied() {
    let fixture = Fixture::new().await;
    let authority = fixture.leader().await;
    let authorization = authority
        .authorize_signer_maintenance(fixture.context("operator"))
        .await
        .unwrap();
    let held = (0..31)
        .map(|_| authority.permit().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        authority.permit().err().unwrap().code,
        ErrorCode::ResourceExhausted
    );
    // Pinned peer work has independent ownership and cannot be starved by full
    // native request capacity. The live signer sub-operation reuses its owner.
    authority.peer_allowed(authority.local_node_id).unwrap();
    let verifier = fixture.settings.installed_members[&authority.local_node_id]
        .verifier
        .clone();
    let domain = fixture
        .installation
        .manifest
        .signing_domain(0)
        .unwrap()
        .digest()
        .unwrap();
    assert!(
        authority
            .signer_directive(authorization.clone(), &verifier, &domain, Uuid::new_v4())
            .await
            .unwrap()
            .is_none()
    );
    use ring::signature::KeyPair;
    let key =
        ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let key = ring::signature::Ed25519KeyPair::from_pkcs8(key.as_ref()).unwrap();
    let certificate = fixture
        .signing_root
        .certify(2, hex::encode(key.public_key().as_ref()))
        .unwrap();
    let command = SignerTrustCommand {
        operation_id: Uuid::new_v4(),
        expected_revision: 0,
        not_after_ms: 1_050_000,
        action: SignerTrustAction::Stage { certificate },
    };
    // The missing global stage is the actual conflict, even at full capacity;
    // this sub-operation must not acquire a second native request permit.
    assert_eq!(
        authority
            .commit_signer_directive(authorization.clone(), &verifier, &domain, &command)
            .await
            .err()
            .unwrap()
            .code,
        ErrorCode::Conflict
    );
    let other = fixture
        .services
        .iter()
        .find(|candidate| !Arc::ptr_eq(candidate, &authority))
        .unwrap();
    assert_eq!(
        other
            .signer_directive(authorization.clone(), &verifier, &domain, Uuid::new_v4())
            .await
            .err()
            .unwrap()
            .code,
        ErrorCode::Forbidden
    );
    drop(held);
    drop(authorization);
    fixture.close().await;
}
