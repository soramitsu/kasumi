#[tokio::test]
async fn permanent_target_stop_defeats_missing_and_prepared_generations_then_reopens_after_full_drain()
 {
    let mut fixture = Fixture::new().await;
    let service = fixture.leader().await;
    let source = fixture.enroll(&service).await;
    let trust = fixture.trust.clone();
    let replacement = target(source);
    let prepare = fixture.command(AuthorityAction::PrepareTarget {
        source_incarnation: source,
        source_epoch: 1,
        target: replacement.clone(),
    });
    service
        .execute(fixture.context("operator"), prepare)
        .await
        .unwrap();
    let prepared_boot = boot(&fixture, replacement.incarnation, 2).for_restore_preparation();
    let held = acquire(&fixture, &service, &prepared_boot).await;
    let command = fixture.command(AuthorityAction::StopTarget {
        source_incarnation: source,
        source_epoch: 1,
        target: replacement.clone(),
    });
    let receipt = service
        .execute(fixture.context("operator"), command.clone())
        .await
        .unwrap()
        .0;
    assert!(matches!(
        receipt.receipt.outcome,
        AuthorityOutcome::TargetStopped { .. }
    ));
    let reference = TargetStopReference {
        tenant: "city".into(),
        command_id: command.command_id,
        receipt_digest: receipt.receipt.digest().unwrap(),
    };
    let attempt = prepared_boot.begin_acquisition().unwrap();
    let caller = AuthenticatedNode::from_verified_transport(
        fixture.context("node-1"),
        nodes().first().unwrap().certificate_sha256.clone(),
    )
    .unwrap();
    assert!(
        service
            .acquire(caller, attempt.request().clone())
            .await
            .is_err()
    );
    held.check().unwrap();
    assert!(
        service
            .verify_target_stop(fixture.context("operator"), reference.clone())
            .await
            .is_err()
    );
    fixture.clock.0.store(1000, Ordering::SeqCst);
    assert!(held.check().is_err());
    let (signed, fence) = service
        .verify_target_stop(fixture.context("operator"), reference.clone())
        .await
        .unwrap();
    fence.release().await.unwrap();
    let proof = trust
        .verify_target_stop(signed.clone(), &reference)
        .unwrap();
    assert_eq!(proof.target(), &replacement);
    let mut substituted = signed;
    substituted.observation.drain_ms = 0;
    assert!(trust.verify_target_stop(substituted, &reference).is_err());
    let never_prepared = target(source);
    let stop = fixture.command(AuthorityAction::StopTarget {
        source_incarnation: source,
        source_epoch: 1,
        target: never_prepared.clone(),
    });
    let stopped = fixture.exact_administrative(stop).await;
    assert!(matches!(
        stopped.outcome,
        AuthorityOutcome::TargetStopped { .. }
    ));
    let delayed = fixture
        .exact_administrative(fixture.command(AuthorityAction::PrepareTarget {
            source_incarnation: source,
            source_epoch: 1,
            target: never_prepared.clone(),
        }))
        .await;
    assert!(matches!(
        delayed.outcome,
        AuthorityOutcome::Rejected { .. }
    ));
    let changed = fixture
        .exact_administrative(fixture.command(AuthorityAction::StopTarget {
            source_incarnation: source,
            source_epoch: 2,
            target: replacement.clone(),
        }))
        .await;
    assert!(matches!(
        changed.outcome,
        AuthorityOutcome::Rejected { .. }
    ));
    drop(service);
    let service = fixture.leader().await;
    use kasumi_raft::StateMachineBackend;
    let mut snapshot = Vec::new();
    service.backend.snapshot(&mut snapshot).unwrap();
    service.backend.validate_snapshot(&mut snapshot.as_slice()).unwrap();
    drop(fence);
    drop(service);
    fixture.reopen().await;
    let service = fixture.leader().await;
    assert!(
        service
            .verify_target_stop(fixture.context("operator"), reference.clone())
            .await
            .is_err(),
        "a restarted process cannot reuse an old elapsed witness"
    );
    fixture.clock.0.store(1999, Ordering::SeqCst);
    assert!(
        service
            .verify_target_stop(fixture.context("operator"), reference.clone())
            .await
            .is_err()
    );
    fixture.clock.0.store(2000, Ordering::SeqCst);
    let (signed, fence) = service
        .verify_target_stop(fixture.context("operator"), reference.clone())
        .await
        .unwrap();
    fence.release().await.unwrap();
    assert_eq!(
        trust
            .verify_target_stop(signed, &reference)
            .unwrap()
            .target(),
        &replacement
    );
    let fenced = fixture
        .exact_administrative(fixture.command(AuthorityAction::Fence {
            incarnation: source,
            authority_epoch: 1,
        }))
        .await;
    let activate = fixture.command(AuthorityAction::Activate {
        fence_id: fenced.command.command_id,
        fence_digest: fenced.digest().unwrap(),
        target: replacement,
    });
    let activation_context = fixture.context("operator");
    assert!(
        service
            .execute(activation_context.clone(), activate.clone())
            .await
            .is_err()
    );
    fixture.clock.0.store(3000, Ordering::SeqCst);
    let denied = exact_stopped_activation_after_current_drain(
        &fixture,
        activation_context,
        activate,
    )
    .await;
    assert!(matches!(
        denied.outcome,
        AuthorityOutcome::Rejected { .. }
    ));
    drop(fence);
    fixture.close().await;
}

async fn exact_stopped_activation_after_current_drain(
    fixture: &Fixture,
    context: RequestContext,
    command: AuthorityCommand,
) -> AuthorityReceipt {
    let AuthorityAction::Activate { fence_digest, .. } = &command.action else {
        panic!("expected the original stopped-target activation")
    };
    let expected_digest = command.digest().unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "stopped-target activation has no exact receipt after its current-term drain"
        );
        let current = fixture.leader().await;
        match current
            .receipt(context.clone(), &command.tenant, command.command_id)
            .await
        {
            Ok((Some(receipt), fence)) => {
                assert_eq!(receipt.receipt.command, command);
                assert_eq!(receipt.receipt.command_digest, expected_digest);
                match fence.release().await {
                    Ok(()) => return receipt.receipt,
                    Err(error) if error.code == ErrorCode::Unavailable => continue,
                    Err(error) => panic!("exact activation receipt release failed: {error:?}"),
                }
            }
            Ok((None, fence)) => match fence.release().await {
                Ok(()) => {}
                Err(error) if error.code == ErrorCode::Unavailable => continue,
                Err(error) => panic!("activation receipt absence release failed: {error:?}"),
            },
            Err(error) if error.code == ErrorCode::Unavailable => continue,
            Err(error) => panic!("exact activation receipt read failed: {error:?}"),
        }
        match current.execute(context.clone(), command.clone()).await {
            Ok((receipt, fence)) => {
                assert_eq!(receipt.receipt.command, command);
                assert_eq!(receipt.receipt.command_digest, expected_digest);
                match fence.release().await {
                    Ok(()) => return receipt.receipt,
                    Err(error) if error.code == ErrorCode::Unavailable => {}
                    Err(error) => panic!("activation response release failed: {error:?}"),
                }
            }
            Err(error)
                if error.code == ErrorCode::Unavailable
                    && error.message
                        == "exact fence drain has not completed; retry the same identity" =>
            {
                // An election starts a new process/term witness. Only advance
                // this fixture clock after observing that exact witness; an
                // old leader's elapsed interval cannot authorize the new one.
                let drains = current.drains.lock().unwrap();
                let witness = drains.get(fence_digest).unwrap();
                if witness.term == current.term() {
                    let ready_at = witness.started
                        + Duration::from_millis(
                            fixture.installation.manifest.drain_ms().unwrap(),
                        );
                    fixture.clock.0.fetch_max(
                        u64::try_from(ready_at.as_millis()).unwrap(),
                        Ordering::SeqCst,
                    );
                }
            }
            Err(error)
                if matches!(
                    error.code,
                    ErrorCode::UnknownOutcome | ErrorCode::Unavailable
                ) => {}
            Err(error) => panic!("stopped-target activation rejected before its receipt: {error:?}"),
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn target_stop_and_activation_ordering_preserves_committed_winner_and_current_admin_release()
{
    let fixture = Fixture::new().await;
    let service = fixture.leader().await;
    let source = fixture.enroll(&service).await;
    let replacement = target(source);
    let fenced = fixture
        .exact_administrative(fixture.command(AuthorityAction::Fence {
            incarnation: source,
            authority_epoch: 1,
        }))
        .await;
    let activate = fixture.command(AuthorityAction::Activate {
        fence_id: fenced.command.command_id,
        fence_digest: fenced.digest().unwrap(),
        target: replacement.clone(),
    });
    assert!(
        service
            .execute(fixture.context("operator"), activate.clone())
            .await
            .is_err()
    );
    fixture.clock.0.store(1000, Ordering::SeqCst);
    let stop = fixture.command(AuthorityAction::StopTarget {
        source_incarnation: source,
        source_epoch: 1,
        target: replacement,
    });
    let (activated, stopped) = tokio::join!(
        service.execute(fixture.context("operator"), activate),
        service.execute(fixture.context("operator"), stop.clone())
    );
    let activated = activated.unwrap().0.receipt;
    let stopped = stopped.unwrap().0.receipt;
    match &stopped.outcome {
        AuthorityOutcome::TargetStopped { .. } => {
            assert!(matches!(
                activated.outcome,
                AuthorityOutcome::Rejected { .. }
            ));
            let reference = TargetStopReference {
                tenant: "city".into(),
                command_id: stop.command_id,
                receipt_digest: stopped.digest().unwrap(),
            };
            assert!(
                service
                    .verify_target_stop(fixture.context("operator"), reference.clone())
                    .await
                    .is_err()
            );
            fixture.clock.0.store(2000, Ordering::SeqCst);
            let (_, fence) = service
                .verify_target_stop(fixture.context("operator"), reference.clone())
                .await
                .unwrap();
            let revoke = fixture.command(AuthorityAction::ReplaceAdministrators {
                administrators: BTreeSet::from(["new-admin".into()]),
            });
            assert_eq!(
                service
                    .execute(fixture.context("operator"), revoke)
                    .await
                    .err()
                    .unwrap()
                    .code,
                ErrorCode::UnknownOutcome
            );
            assert!(fence.release().await.is_err());
            assert!(
                service
                    .verify_target_stop(fixture.context("operator"), reference.clone())
                    .await
                    .is_err()
            );
            service
                .verify_target_stop(fixture.context("new-admin"), reference)
                .await
                .unwrap()
                .1
                .release()
                .await
                .unwrap();
        }
        AuthorityOutcome::TargetAlreadyActivated { original } => assert_eq!(**original, activated),
        other => panic!("unexpected stop outcome {other:?}"),
    }
    fixture.close().await;
}

#[tokio::test]
async fn target_stop_history_exceeds_former_record_ceiling_and_current_fences_are_explicit() {
    let fixture = Fixture::new().await;
    let service = fixture.leader().await;
    let source = fixture.enroll(&service).await;
    let request = fixture.command(AuthorityAction::StopTarget {
        source_incarnation: source,
        source_epoch: 1,
        target: target(source),
    });
    let receipt = service
        .execute(fixture.context("operator"), request.clone())
        .await
        .unwrap()
        .0
        .receipt;
    let reference = TargetStopReference {
        tenant: "city".into(),
        command_id: request.command_id,
        receipt_digest: receipt.digest().unwrap(),
    };
    let overflow = fixture.command(AuthorityAction::StopTarget {
        source_incarnation: source,
        source_epoch: 1,
        target: target(source),
    });
    let third = service.execute(fixture.context("operator"), overflow.clone()).await.unwrap().0.receipt;
    assert!(matches!(third.outcome, AuthorityOutcome::TargetStopped { .. }));
    let repeated = service.execute(fixture.context("operator"), overflow.clone()).await.unwrap().0.receipt;
    assert_eq!(third, repeated);
    assert!(
        service
            .verify_target_stop(fixture.context("operator"), reference.clone())
            .await
            .is_err()
    );
    fixture.clock.0.store(1000, Ordering::SeqCst);
    let mut short = fixture.context("operator");
    short.authorization = RequestAuthorization::from_verified_credential(
        fixture.epoch.now_ms().unwrap() + 1000,
        &fixture.epoch.observe().unwrap(),
        kasumi_types::CredentialResource::Authority {
            authority_id: fixture.installation.manifest.authority_id,
            partition: 0,
        },
    )
    .unwrap();
    let (_, fence) = service
        .verify_target_stop(short, reference.clone())
        .await
        .unwrap();
    fixture.clock.0.store(2000, Ordering::SeqCst);
    assert_eq!(
        fence.release().await.unwrap_err().code,
        ErrorCode::Unauthorized
    );
    let (_, current) = service
        .verify_target_stop(fixture.context("operator"), reference.clone())
        .await
        .unwrap();
    current.release().await.unwrap();
    let id = service.group.raft().metrics().borrow().id;
    fixture.router.isolate("independent-control", id, true);
    assert!(current.release().await.is_err());
    assert!(
        service
            .verify_target_stop(fixture.context("operator"), reference)
            .await
            .is_err()
    );
    fixture.router.isolate("independent-control", id, false);
    drop(fence);
    drop(current);
    fixture.close().await;
}

#[tokio::test]
async fn target_stop_queued_past_original_credential_expiry_accepts_no_tombstone() {
    let fixture = Fixture::new().await;
    let service = fixture.leader().await;
    let source = fixture.enroll(&service).await;
    let request = fixture.command(AuthorityAction::StopTarget {
        source_incarnation: source,
        source_epoch: 1,
        target: target(source),
    });
    let mut short = fixture.context("operator");
    short.authorization = RequestAuthorization::from_verified_credential(
        fixture.epoch.now_ms().unwrap() + 1000,
        &fixture.epoch.observe().unwrap(),
        kasumi_types::CredentialResource::Authority {
            authority_id: fixture.installation.manifest.authority_id,
            partition: 0,
        },
    )
    .unwrap();
    let gate = service.proposal.lock().await;
    let task = {
        let service = service.clone();
        let request = request.clone();
        tokio::spawn(async move { service.execute(short, request).await })
    };
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(!task.is_finished());
    fixture.clock.0.store(1000, Ordering::SeqCst);
    drop(gate);
    assert_eq!(
        task.await.unwrap().err().unwrap().code,
        ErrorCode::Unauthorized
    );
    assert!(
        service
            .receipt(fixture.context("operator"), "city", request.command_id)
            .await
            .unwrap()
            .0
            .is_none()
    );
    let AuthorityAction::StopTarget { target, .. } = request.action else {
        unreachable!()
    };
    let result = service
        .execute(
            fixture.context("operator"),
            fixture.command(AuthorityAction::PrepareTarget {
                source_incarnation: source,
                source_epoch: 1,
                target,
            }),
        )
        .await
        .unwrap()
        .0;
    assert!(matches!(
        result.receipt.outcome,
        AuthorityOutcome::TargetPrepared { .. }
    ));
    fixture.close().await;
}

#[test]
fn completed_drain_witness_eviction_preserves_active_waits_and_restarts_evicted_identity() {
    let mut witnesses = BTreeMap::new();
    let required = Duration::from_millis(100);
    let mut check = |id: &str, term, now| require_drain_witness(&mut witnesses,id,term,Duration::from_millis(now),required,2);
    assert_eq!(check("source-a",1,0).unwrap_err().code,ErrorCode::Unavailable);
    assert_eq!(check("target-a",1,50).unwrap_err().code,ErrorCode::Unavailable);
    assert_eq!(check("source-b",1,75).unwrap_err().code,ErrorCode::ResourceExhausted);
    assert_eq!(check("source-b",1,100).unwrap_err().code,ErrorCode::Unavailable);
    assert_eq!(check("target-a",1,149).unwrap_err().code,ErrorCode::Unavailable);
    check("target-a",1,150).unwrap();
    assert_eq!(check("source-a",1,150).unwrap_err().code,ErrorCode::Unavailable);
    assert_eq!(check("source-a",1,249).unwrap_err().code,ErrorCode::Unavailable);
    check("source-a",1,250).unwrap();
    assert_eq!(check("source-a",1,200).unwrap_err().code,ErrorCode::Unavailable);
    assert_eq!(check("source-a",1,299).unwrap_err().code,ErrorCode::Unavailable);
    check("source-a",1,300).unwrap();
    assert_eq!(check("source-a",2,300).unwrap_err().code,ErrorCode::Unavailable);
    check("source-a",2,400).unwrap();
    assert!(witnesses.len() <= 2);
}
