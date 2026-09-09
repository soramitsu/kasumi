// Durable membership phases are injected at the same boundary used by the
// native coordinator so restart cannot manufacture an unrecorded outcome.
use crate::state::maintenance_state::MaintenanceTransition;

impl Fixture {
    async fn maintenance_command(
        &self,
        action: AuthorityMaintenanceAction,
    ) -> AuthorityMaintenanceCommand {
        let service = self.leader().await;
        let configuration = service.backend.operational_configuration().unwrap();
        AuthorityMaintenanceCommand {
            operation_id: Uuid::new_v4(),
            expected_policy_epoch: configuration.policy_epoch,
            expected_operational_revision: configuration.revision,
            not_after_ms: 1_500_000,
            action,
        }
    }
    async fn maintenance(
        &self,
        request: AuthorityMaintenanceRequest,
    ) -> kasumi_types::Result<AuthorityMaintenanceStatus> {
        let service = self.leader().await;
        let (response, fence) = service
            .maintenance(self.context("operator"), request)
            .await?;
        fence.release().await?;
        match response {
            AuthorityMaintenanceResponse::Operation { status } => Ok(status),
            _ => panic!("expected operation status"),
        }
    }
    async fn add_fourth(&mut self) {
        self.add_fourth_with_budget(self.settings.resource_budget_bytes)
            .await;
    }
    async fn add_fourth_with_budget(&mut self, resource_budget_bytes: u64) {
        let id = 4;
        let mut settings = self.settings.clone();
        settings.resource_budget_bytes = resource_budget_bytes;
        let stores = TenantStorageSet::initialize_catalogs(
            NodeStore::create_new(
                self._dir.path().join("authority-4.redb"),
                kasumi_store::test_utils::NODE_STORE_ID,
                kasumi_store::ScratchDisk::fixture(),
            )
            .unwrap(),
            self.installation.tenant(),
            Arc::new(LocalKeyProvider::new([4; 32])),
            Arc::new(LocalKeyProvider::new([14; 32])),
            kasumi_store::StorageAccess::independent_authority(
                &self.installation.manifest,
                self.installation.partition,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        IndependentAuthority::initialize_storage(
            &stores,
            &self.installation,
            &self.bootstrap,
            &settings.installed_members[&id].verifier,
        )
        .unwrap();
        let service = IndependentAuthority::open_existing_with_clock(
            stores.clone(),
            self.installation.clone(),
            self.signing
                .for_verifier(kasumi_serving::test_utils::fixture_verifier(id))
                .unwrap()
                .signer,
            id,
            settings,
            self.router.clone(),
            Config {
                heartbeat_interval: 100,
                election_timeout_min: 500,
                election_timeout_max: 1000,
                ..Config::default()
            },
            self.epoch.clone(),
        )
        .await
        .unwrap();
        self.router.register(
            "independent-control".into(),
            id,
            service.raft_group().raft().clone(),
        );
        self.readiness.register(id, &service);
        service
            .install_maintenance_transport(self.readiness.clone())
            .unwrap();
        self.services.push(service);
        self.stores.push(stores);
    }
}

#[tokio::test]
async fn maintenance_byte_budget_expands_after_exhaustion_and_preserves_exact_history() {
    let mut fixture = Fixture::with_control_capacity(BTreeMap::new(), 32_000).await;
    let service = fixture.leader().await;
    let source = fixture.enroll(&service).await;
    let mut exhausted = None;
    for _ in 0..100 {
        let command = fixture.command(AuthorityAction::StopTarget {
            source_incarnation: source,
            source_epoch: 1,
            target: target(source),
        });
        match service
            .execute(fixture.context("operator"), command.clone())
            .await
        {
            Ok(_) => {}
            Err(error) => {
                assert_eq!(error.code, ErrorCode::ResourceExhausted);
                exhausted = Some(command);
                break;
            }
        }
    }
    let blocked = exhausted.expect("ordinary byte budget must exhaust");
    let command = fixture
        .maintenance_command(AuthorityMaintenanceAction::SetCapacity {
            capacity: AuthorityCapacity {
                max_tenants: 100,
                max_state_bytes: 8 << 20,
                maintenance_reserve_bytes: 1 << 20,
            },
        })
        .await;
    let completed = fixture
        .maintenance(AuthorityMaintenanceRequest::Start {
            command: command.clone(),
        })
        .await
        .unwrap();
    assert_eq!(completed.phase, AuthorityMaintenancePhase::Completed);
    service
        .execute(fixture.context("operator"), blocked.clone())
        .await
        .unwrap();
    let replay = fixture
        .maintenance(AuthorityMaintenanceRequest::Start {
            command: command.clone(),
        })
        .await
        .unwrap();
    assert_eq!(replay, completed);
    let mut wrong = command.clone();
    wrong.not_after_ms += 1;
    assert_eq!(
        fixture
            .maintenance(AuthorityMaintenanceRequest::Start { command: wrong })
            .await
            .err()
            .unwrap()
            .code,
        ErrorCode::Conflict
    );
    drop(service);
    fixture.reopen().await;
    assert_eq!(
        fixture
            .maintenance(AuthorityMaintenanceRequest::Status {
                operation_id: command.operation_id
            })
            .await
            .unwrap(),
        completed
    );
    let leader = fixture.leader().await;
    assert_eq!(
        leader
            .backend
            .operational_configuration()
            .unwrap()
            .capacity
            .max_state_bytes,
        8 << 20
    );
    use kasumi_raft::StateMachineBackend;
    let mut bytes = Vec::new();
    leader.backend.snapshot(&mut bytes).unwrap();
    leader
        .backend
        .validate_snapshot(&mut bytes.as_slice())
        .unwrap();
    fixture.close().await;
}

#[tokio::test]
async fn maintenance_requires_every_installed_peer_before_admission() {
    let fixture = Fixture::new().await;
    let leader = fixture.leader().await;
    let unavailable = fixture
        .services
        .iter()
        .find(|s| s.local_node_id != leader.local_node_id)
        .unwrap()
        .local_node_id;
    fixture.readiness.0.write().unwrap().remove(&unavailable);
    let command = fixture
        .maintenance_command(AuthorityMaintenanceAction::SetCapacity {
            capacity: AuthorityCapacity {
                max_tenants: 100,
                max_state_bytes: 16 << 20,
                maintenance_reserve_bytes: 1 << 20,
            },
        })
        .await;
    assert_eq!(
        fixture
            .maintenance(AuthorityMaintenanceRequest::Start {
                command: command.clone()
            })
            .await
            .err()
            .unwrap()
            .code,
        ErrorCode::Unavailable
    );
    assert!(
        leader
            .backend
            .maintenance_status(command.operation_id)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        leader.backend.operational_configuration().unwrap().revision,
        0
    );
    fixture.readiness.register(
        unavailable,
        fixture
            .services
            .iter()
            .find(|s| s.local_node_id == unavailable)
            .unwrap(),
    );
    assert_eq!(
        fixture
            .maintenance(AuthorityMaintenanceRequest::Start { command })
            .await
            .unwrap()
            .phase,
        AuthorityMaintenancePhase::Completed
    );
    fixture.close().await;
}

#[tokio::test]
async fn maintenance_prepared_stop_and_dispatched_restart_are_exact() {
    let mut fixture = Fixture::new().await;
    fixture.add_fourth().await;
    let command = fixture
        .maintenance_command(AuthorityMaintenanceAction::EnrollLearner {
            node_id: 4,
            member: fixture.settings.installed_members[&4].clone(),
        })
        .await;
    let leader = fixture.leader().await;
    let prepared = leader
        .maintenance_write(
            &fixture.context("operator"),
            leader.term(),
            MaintenanceTransition::Begin {
                command: command.clone(),
            },
        )
        .await
        .unwrap();
    assert_eq!(prepared.phase, AuthorityMaintenancePhase::Prepared);
    let stopped = fixture
        .maintenance(AuthorityMaintenanceRequest::Stop {
            operation_id: command.operation_id,
        })
        .await
        .unwrap();
    assert_eq!(stopped.phase, AuthorityMaintenancePhase::Stopped);
    assert_eq!(
        fixture
            .maintenance(AuthorityMaintenanceRequest::Start { command })
            .await
            .unwrap(),
        stopped
    );
    assert!(
        !leader
            .group
            .raft()
            .metrics()
            .borrow()
            .membership_config
            .nodes()
            .any(|(id, _)| *id == 4)
    );
    let command = fixture
        .maintenance_command(AuthorityMaintenanceAction::EnrollLearner {
            node_id: 4,
            member: fixture.settings.installed_members[&4].clone(),
        })
        .await;
    leader
        .maintenance_write(
            &fixture.context("operator"),
            leader.term(),
            MaintenanceTransition::Begin {
                command: command.clone(),
            },
        )
        .await
        .unwrap();
    leader
        .maintenance_write(
            &fixture.context("operator"),
            leader.term(),
            MaintenanceTransition::Dispatch {
                operation_id: command.operation_id,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        fixture
            .maintenance(AuthorityMaintenanceRequest::Stop {
                operation_id: command.operation_id
            })
            .await
            .err()
            .unwrap()
            .code,
        ErrorCode::Conflict
    );
    drop(leader);
    fixture.reopen().await;
    let observed = fixture
        .maintenance(AuthorityMaintenanceRequest::Status {
            operation_id: command.operation_id,
        })
        .await
        .unwrap();
    assert_eq!(observed.phase, AuthorityMaintenancePhase::Dispatched);
    let done = fixture
        .maintenance(AuthorityMaintenanceRequest::Resume {
            operation_id: command.operation_id,
        })
        .await
        .unwrap();
    assert_eq!(done.command, command);
    assert_eq!(done.phase, AuthorityMaintenancePhase::Completed);
    assert_eq!(
        fixture
            .maintenance(AuthorityMaintenanceRequest::Stop {
                operation_id: command.operation_id
            })
            .await
            .unwrap(),
        done
    );
    fixture.close().await;
}

#[tokio::test]
async fn maintenance_replaces_voter_then_permanently_revokes_and_restarts_full_drain() {
    let mut fixture = Fixture::new().await;
    fixture.add_fourth().await;
    let enroll = fixture
        .maintenance_command(AuthorityMaintenanceAction::EnrollLearner {
            node_id: 4,
            member: fixture.settings.installed_members[&4].clone(),
        })
        .await;
    assert_eq!(
        fixture
            .maintenance(AuthorityMaintenanceRequest::Start { command: enroll })
            .await
            .unwrap()
            .phase,
        AuthorityMaintenancePhase::Completed
    );
    let leader = fixture.leader().await;
    let removed = fixture
        .services
        .iter()
        .find(|s| s.local_node_id != leader.local_node_id && s.local_node_id != 4)
        .unwrap()
        .local_node_id;
    let voters = BTreeSet::from([1, 2, 3, 4])
        .difference(&BTreeSet::from([removed]))
        .copied()
        .collect();
    let replacement = fixture
        .maintenance_command(AuthorityMaintenanceAction::ReplaceVoters { voters })
        .await;
    assert_eq!(
        fixture
            .maintenance(AuthorityMaintenanceRequest::Start {
                command: replacement
            })
            .await
            .unwrap()
            .phase,
        AuthorityMaintenancePhase::Completed
    );
    let revoke = fixture
        .maintenance_command(AuthorityMaintenanceAction::RevokeMember { node_id: removed })
        .await;
    let draining = fixture
        .maintenance(AuthorityMaintenanceRequest::Start {
            command: revoke.clone(),
        })
        .await
        .unwrap();
    assert_eq!(draining.phase, AuthorityMaintenancePhase::Draining);
    assert!(leader.peer_allowed(removed).is_err());
    assert_eq!(
        fixture
            .maintenance(AuthorityMaintenanceRequest::Stop {
                operation_id: revoke.operation_id
            })
            .await
            .err()
            .unwrap()
            .code,
        ErrorCode::Conflict
    );
    fixture.clock.0.store(999, Ordering::SeqCst);
    assert_eq!(
        fixture
            .maintenance(AuthorityMaintenanceRequest::Resume {
                operation_id: revoke.operation_id
            })
            .await
            .unwrap()
            .phase,
        AuthorityMaintenancePhase::Draining
    );
    drop(leader);
    fixture.reopen().await;
    for service in &fixture.services {
        assert_eq!(
            service.bootstrap(),
            &fixture.bootstrap,
            "current voter replacement must not rewrite immutable genesis"
        );
    }

    assert_eq!(
        fixture
            .maintenance(AuthorityMaintenanceRequest::Resume {
                operation_id: revoke.operation_id
            })
            .await
            .unwrap()
            .phase,
        AuthorityMaintenancePhase::Draining
    );
    fixture.clock.0.store(1998, Ordering::SeqCst);
    assert_eq!(
        fixture
            .maintenance(AuthorityMaintenanceRequest::Resume {
                operation_id: revoke.operation_id
            })
            .await
            .unwrap()
            .phase,
        AuthorityMaintenancePhase::Draining
    );
    fixture.clock.0.store(1999, Ordering::SeqCst);
    assert_eq!(
        fixture
            .maintenance(AuthorityMaintenanceRequest::Resume {
                operation_id: revoke.operation_id
            })
            .await
            .unwrap()
            .phase,
        AuthorityMaintenancePhase::Completed
    );
    let delayed = fixture
        .maintenance_command(AuthorityMaintenanceAction::EnrollLearner {
            node_id: removed,
            member: fixture.settings.installed_members[&removed].clone(),
        })
        .await;
    assert!(matches!(
        fixture
            .maintenance(AuthorityMaintenanceRequest::Start { command: delayed })
            .await
            .unwrap()
            .phase,
        AuthorityMaintenancePhase::Rejected {
            code: ErrorCode::Conflict,
            ..
        }
    ));
    let leader = fixture.leader().await;
    use kasumi_raft::StateMachineBackend;
    let mut bytes = Vec::new();
    leader.backend.snapshot(&mut bytes).unwrap();
    leader
        .backend
        .validate_snapshot(&mut bytes.as_slice())
        .unwrap();
    fixture.close().await;
}

#[tokio::test]
async fn maintenance_store_cannot_reopen_as_another_member_identity() {
    let fixture = Fixture::new().await;
    let result = IndependentAuthority::open_existing_with_clock(
        fixture.stores[0].clone(),
        fixture.installation.clone(),
        fixture
            .signing
            .for_verifier(kasumi_serving::test_utils::fixture_verifier(4))
            .unwrap()
            .signer,
        4,
        fixture.settings.clone(),
        fixture.router.clone(),
        Config::default(),
        fixture.epoch.clone(),
    )
    .await;
    assert!(
        result
            .err()
            .unwrap()
            .to_string()
            .contains("another member identity")
    );
    fixture.close().await;
}

#[tokio::test]
async fn maintenance_learner_must_fit_current_capacity_after_bootstrap_growth() {
    let mut fixture = Fixture::new().await;
    let grow = fixture
        .maintenance_command(AuthorityMaintenanceAction::SetCapacity {
            capacity: AuthorityCapacity {
                max_tenants: 100,
                max_state_bytes: 8 << 20,
                maintenance_reserve_bytes: 1 << 20,
            },
        })
        .await;
    fixture
        .maintenance(AuthorityMaintenanceRequest::Start { command: grow })
        .await
        .unwrap();
    fixture.add_fourth_with_budget(5 << 20).await;
    let command = fixture
        .maintenance_command(AuthorityMaintenanceAction::EnrollLearner {
            node_id: 4,
            member: fixture.settings.installed_members[&4].clone(),
        })
        .await;
    assert_eq!(
        fixture
            .maintenance(AuthorityMaintenanceRequest::Start {
                command: command.clone()
            })
            .await
            .err()
            .unwrap()
            .code,
        ErrorCode::Unavailable
    );
    let leader = fixture.leader().await;
    assert!(
        leader
            .backend
            .maintenance_status(command.operation_id)
            .unwrap()
            .is_none()
    );
    assert!(
        !leader
            .backend
            .operational_configuration()
            .unwrap()
            .membership
            .members
            .contains_key(&4)
    );
    fixture.close().await;
}

#[tokio::test]
async fn maintenance_resource_acknowledgement_survives_lost_reply_before_admission() {
    let fixture = Fixture::new().await;
    let command = fixture
        .maintenance_command(AuthorityMaintenanceAction::SetCapacity {
            capacity: AuthorityCapacity {
                max_tenants: 100,
                max_state_bytes: 16 << 20,
                maintenance_reserve_bytes: 1 << 20,
            },
        })
        .await;
    let member = &fixture.services[0];
    member
        .check_maintenance_ready(member.bootstrap_digest(), 5 << 20, &command)
        .unwrap();
    assert!(
        member
            .backend
            .maintenance_status(command.operation_id)
            .unwrap()
            .is_none()
    );
    let mut smaller = fixture.settings.clone();
    smaller.resource_budget_bytes = 8 << 20;
    let result = IndependentAuthority::open_existing_with_clock(
        fixture.stores[0].clone(),
        fixture.installation.clone(),
        member.request_signer().unwrap(),
        1,
        smaller,
        fixture.router.clone(),
        Config::default(),
        fixture.epoch.clone(),
    )
    .await;
    assert!(
        result
            .err()
            .unwrap()
            .to_string()
            .contains("durably acknowledged maintenance floor")
    );
    fixture.close().await;
}

#[tokio::test]
async fn maintenance_removing_the_leader_resumes_the_same_committed_operation() {
    let mut fixture = Fixture::new().await;
    fixture.add_fourth().await;
    let enroll = fixture
        .maintenance_command(AuthorityMaintenanceAction::EnrollLearner {
            node_id: 4,
            member: fixture.settings.installed_members[&4].clone(),
        })
        .await;
    fixture
        .maintenance(AuthorityMaintenanceRequest::Start { command: enroll })
        .await
        .unwrap();
    let former = fixture.leader().await;
    let voters = BTreeSet::from([1, 2, 3, 4])
        .difference(&BTreeSet::from([former.local_node_id]))
        .copied()
        .collect();
    let command = fixture
        .maintenance_command(AuthorityMaintenanceAction::ReplaceVoters { voters })
        .await;
    let original_context = fixture.context("operator");
    match former
        .maintenance(
            original_context.clone(),
            AuthorityMaintenanceRequest::Start {
                command: command.clone(),
            },
        )
        .await
    {
        Ok(_) => {}
        Err(error) => assert!(matches!(
            error.code,
            ErrorCode::UnknownOutcome | ErrorCode::Unavailable
        )),
    }
    // An ambiguous return does not prove the membership phase has completed.
    // Resolve the same permanent command with its original finite invocation.
    let completed = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let current = fixture.leader().await;
            let attempt = current
                .maintenance(
                    original_context.clone(),
                    AuthorityMaintenanceRequest::Start {
                        command: command.clone(),
                    },
                )
                .await;
            let result = match attempt {
                Ok((response, fence)) => fence.release().await.map(|()| response),
                Err(error) => Err(error),
            };
            match result {
                Ok(AuthorityMaintenanceResponse::Operation { status }) => {
                    assert_eq!(status.command, command);
                    if status.phase == AuthorityMaintenancePhase::Completed {
                        break status;
                    }
                    assert!(
                        !status.phase.terminal(),
                        "replacement has a different terminal outcome"
                    );
                }
                Ok(_) => panic!("replacement receipt response kind differs"),
                Err(error) => assert!(
                    matches!(
                        error.code,
                        ErrorCode::UnknownOutcome | ErrorCode::Unavailable
                    ),
                    "exact replacement resolution failed: {error}"
                ),
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("original voter replacement did not resolve");
    let successor = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            for service in &fixture.services {
                if service.local_node_id == former.local_node_id {
                    continue;
                }
                let metric = service.group.raft().metrics().borrow().clone();
                if metric.current_leader == Some(metric.id)
                    && service.group.linearizable_barrier().await.is_ok()
                {
                    return service.clone();
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("completed voter replacement did not elect a current successor");
    assert_ne!(successor.local_node_id, former.local_node_id);
    assert_eq!(completed.command, command);
    assert_eq!(completed.phase, AuthorityMaintenancePhase::Completed);
    assert_eq!(
        fixture
            .maintenance(AuthorityMaintenanceRequest::Start { command })
            .await
            .unwrap(),
        completed
    );
    for service in &fixture.services {
        let lock = tokio::time::timeout(Duration::from_secs(2), service.proposal.lock())
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "member {} retains proposal ownership",
                    service.local_node_id
                )
            });
        drop(lock);
    }
    tokio::time::timeout(Duration::from_secs(15), fixture.close())
        .await
        .expect("authority owners did not drain");
}

#[tokio::test]
async fn authority_signer_cannot_substitute_another_physical_verifier_with_the_same_node_id() {
    let fixture = Fixture::new().await;
    let mut verifier = fixture.settings.installed_members[&1].verifier.clone();
    verifier.installation_id = Uuid::new_v4();
    let substituted = fixture.signing.for_verifier(verifier).unwrap();
    let result = IndependentAuthority::open_existing_with_clock(
        fixture.stores[0].clone(),
        fixture.installation.clone(),
        substituted.signer,
        1,
        fixture.settings.clone(),
        fixture.router.clone(),
        Config::default(),
        fixture.epoch.clone(),
    )
    .await;
    assert!(
        result
            .err()
            .unwrap()
            .to_string()
            .contains("physical verifier")
    );
    fixture.services[0]
        .request_signer()
        .unwrap()
        .check()
        .unwrap();
    fixture.close().await;
}
