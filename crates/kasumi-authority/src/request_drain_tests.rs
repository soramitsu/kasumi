use super::*;
use std::{future::Future, task::Poll};

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
