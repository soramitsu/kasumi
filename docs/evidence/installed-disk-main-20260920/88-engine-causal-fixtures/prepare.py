from pathlib import Path
import shutil
root=Path('/Users/mtakemiya/dev/kasumi')
out=root/'target/installed-disk-validation/88-engine-causal-fixtures'
paths=['crates/kasumi-engine/tests/history.rs','crates/kasumi-engine/tests/lifecycle.rs','crates/kasumi-engine/tests/common/recovery_control.rs','crates/kasumi-engine/tests/schema_activation.rs']
for name in paths:
    for side in ['base','proposed']:
        dest=out/side/name
        dest.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(root/name,dest)
def edit(name,old,new):
    p=out/'proposed'/name
    text=p.read_text()
    assert text.count(old)==1,(name,text.count(old),old[:80])
    p.write_text(text.replace(old,new))
history=paths[0]
edit(history,'''async fn chunked_full_backup_restores_cold_history_and_permanent_identity_without_source_objects() {
    let root''','''async fn chunked_full_backup_restores_cold_history_and_permanent_identity_without_source_objects() {
    // Deliberate offline corruption starts before the next managed census.
    // Never reconcile an owner that already failed during an admitted read.
    fn external_change(disk: &kasumi_store::NodeDisk, change: impl FnOnce()) {
        assert_eq!(disk.snapshot().phase, kasumi_store::NodeDiskPhase::Open);
        disk.pause().unwrap();
        change();
        disk.reconcile(&kasumi_store::CensusCancellation::default())
            .unwrap();
        assert_eq!(disk.snapshot().phase, kasumi_store::NodeDiskPhase::Open);
    }
    let root''')
edit(history,'''    std::fs::remove_dir_all(&cold_path).unwrap();
    let node = physical''','''    external_change(&physical.storage.persistent, || {
        std::fs::remove_dir_all(&cold_path).unwrap();
    });
    let node = physical''')
edit(history,'''            std::fs::write(&dependency_path, corrupt).unwrap();
        } else if suffix == "missing" {
            std::fs::remove_file(&dependency_path).unwrap();
        }''','''            external_change(&physical.storage.persistent, || {
                std::fs::write(&dependency_path, corrupt).unwrap();
            });
        } else if suffix == "missing" {
            external_change(&physical.storage.persistent, || {
                std::fs::remove_file(&dependency_path).unwrap();
            });
        }''')
edit(history,'''        let target = TenantStore::initialize_catalog_fixture(
            node,
            "history".into(),''','''        let target = TenantStore::initialize_catalog_fixture(
            node.clone(),
            "history".into(),''')
edit(history,'''        assert!(
            kasumi_engine::restore_local(
                &restore_source,
                kasumi_store::test_utils::initialize_custody_fixture(
                    target.clone(),
                    std::sync::Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32]))
                )
                .await
                .unwrap(),''','''        let domains = kasumi_store::test_utils::initialize_custody_fixture(
            target.clone(),
            Arc::new(LocalKeyProvider::new([241; 32])),
        )
        .await
        .unwrap();
        assert!(
            kasumi_engine::restore_local(
                &restore_source,
                domains.clone(),''')
edit(history,'''        assert!(
            kasumi_store::test_utils::open_existing_custody_fixture(
                target.clone(),
                Arc::new(LocalKeyProvider::new([241; 32])),
            )
            .await
            .unwrap()
            .custody()
            .store()
            .get("raft.meta", b"node_id")
            .unwrap()
            .is_none()
        );
        audit.shutdown().await.unwrap();
        if suffix == "corrupt" {
            std::fs::write(&dependency_path, &valid_dependency).unwrap();
        }''','''        let reopened = kasumi_store::test_utils::open_existing_custody_fixture(
            target.clone(),
            Arc::new(LocalKeyProvider::new([241; 32])),
        )
        .await
        .unwrap();
        assert!(
            reopened
                .custody()
                .store()
                .get("raft.meta", b"node_id")
                .unwrap()
                .is_none()
        );
        reopened.custody().store().shutdown().await.unwrap();
        reopened.application().shutdown().await.unwrap();
        domains.custody().store().shutdown().await.unwrap();
        target.shutdown().await.unwrap();
        audit.shutdown().await.unwrap();
        node.shutdown().await.unwrap();
        if suffix == "corrupt" {
            external_change(&physical.storage.persistent, || {
                std::fs::write(&dependency_path, &valid_dependency).unwrap();
            });
        }''')
lifecycle=paths[1]
edit(lifecycle,'''    let change = f.change(epoch);
    db.lifecycle_control(
        f.context("owner"),
        LifecycleControlCommand::BeginPolicyChange(change.clone()),
    )
    .await
    .unwrap();
    assert_eq!(db.engine().generation().unwrap().state.audits.len(), 2);''','''    let change = f.change(epoch);
    let before = db.engine().generation().unwrap();
    // Initialization checks the installed topology through a strict read and
    // replays its exact genesis lifecycle installation, both durably audited.
    assert_eq!(
        before
            .state
            .audits
            .iter()
            .map(|event| (event.action.as_str(), event.collection.as_deref(), event.outcome.as_str()))
            .collect::<Vec<_>>(),
        vec![
            ("read", Some("topology"), "authorized_release"),
            ("lifecycle_control", None, "committed"),
        ]
    );
    let before_audits = serde_json::to_value(&before.state.audits).unwrap();
    let before_count = before.state.audits.len();
    let before_sequence = before.state.audit_retention.next_sequence;
    let before_pruned = before.state.audit_retention.pruned_before;
    drop(before);
    let begin_context = f.context("owner");
    let begin = db
        .lifecycle_control(
            begin_context.clone(),
            LifecycleControlCommand::BeginPolicyChange(change.clone()),
        )
        .await
        .unwrap();
    let after = db.engine().generation().unwrap();
    assert_eq!(after.state.audits.len(), before_count + 1);
    assert_eq!(after.state.audit_retention.next_sequence, before_sequence + 1);
    assert_eq!(after.state.audit_retention.pruned_before, before_pruned);
    assert_eq!(
        serde_json::to_value(after.state.audits.iter().take(before_count).collect::<Vec<_>>()).unwrap(),
        before_audits
    );
    let event = after.state.audits.back().unwrap();
    assert_eq!(event.event_id, format!("{}:{}", after.state.incarnation, begin.revision));
    assert_eq!(event.principal, begin_context.principal);
    assert_eq!(event.request_id, begin_context.request_id);
    assert_eq!(event.action, "lifecycle_control");
    assert_eq!(event.outcome, "committed");
    assert_eq!(event.data_revision, Some(begin.revision));
    assert!(event.timestamp_ms > 0);
    assert!(event.collection.is_none());
    drop(after);''')
recovery=paths[2]
edit(recovery,'''        ControlNode, ControlPlane, ControlTopology, DeploymentMode, TenantRoute,
    };
    let plane = ControlPlane::new(db.clone()).unwrap();
    plane.initialize(f.context("owner")).await.unwrap();
    let mut topology = ControlTopology {
        nodes: request
            .target_nodes
            .iter()
            .map(|(node, identity)| {
                (
                    *node,
                    ControlNode {
                        endpoint: request.materialization.voters[node].endpoint.clone(),
                        failure_domain: request.materialization.voters[node].failure_domain.clone(),
                        certificate_pins: BTreeSet::from([identity.certificate_sha256.clone()]),
                    },
                )
            })
            .collect(),
        tenants: BTreeMap::from([(
            request.tenant.clone(),
            TenantRoute {
                incarnation: request.source_incarnation.to_string(),
                mode: DeploymentMode::Replicated,
                voters: request.target_nodes.keys().copied().collect(),
            },
        )]),
    };''','''        ControlNode, ControlPlane, DeploymentMode, TenantRoute,
    };
    let plane = ControlPlane::new(db.clone()).unwrap();
    plane.require_initialized(&f.context("owner")).await.unwrap();
    let installed = read_topology(f).await;
    let mut topology = installed.topology;
    for (node, identity) in &request.target_nodes {
        topology.nodes.insert(
            *node,
            ControlNode {
                endpoint: request.materialization.voters[node].endpoint.clone(),
                failure_domain: request.materialization.voters[node].failure_domain.clone(),
                certificate_pins: BTreeSet::from([identity.certificate_sha256.clone()]),
            },
        );
    }
    assert!(
        topology
            .tenants
            .insert(
                request.tenant.clone(),
                TenantRoute {
                    incarnation: request.source_incarnation.to_string(),
                    mode: DeploymentMode::Replicated,
                    voters: request.target_nodes.keys().copied().collect(),
                },
            )
            .is_none()
    );''')
edit(recovery,'''            topology.clone(),
            Precondition::Absent,
            "recovery-source-topology".into(),''','''            topology.clone(),
            Precondition::Version(installed.version),
            "recovery-source-topology".into(),''')
edit(recovery,'''    let prepared = db
        .recovery_phase(f.context("owner"), operation, phase_id)''','''    // Preparation follows the current leader; the caller's cached handle can
    // now be a follower. Pin one original read credential before reacquiring it.
    let phase_context = f.context("owner");
    let db = f.leader().await;
    let prepared = db
        .recovery_phase(phase_context, operation, phase_id)''')
edit(recovery,'''    let phase = db
        .recovery_phase(f.context("owner"), operation, phase_id)
        .await
        .unwrap();
    let mut context = f.context_for("owner", duration);''','''    // Keep the same prepared command and dispatch limit through leadership
    // changes; this selects a current route before the single phase read.
    let phase_context = f.context("owner");
    let db = f.leader().await;
    let phase = db
        .recovery_phase(phase_context, operation, phase_id)
        .await
        .unwrap();
    let mut context = f.context_for("owner", duration);''')
schema=paths[3]
edit(schema,'''        db.schema_activation_status(&context("owner"), &stale)
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    db.shutdown().await.unwrap();''','''        db.schema_activation_status(&context("owner"), &stale)
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    // The generation retains its durable receipt store and physical file owner.
    // Its copied snapshot fences above remain valid after the owner is released.
    drop(before);
    db.shutdown().await.unwrap();''')
print('Created four proposed files; actual source unchanged.')
