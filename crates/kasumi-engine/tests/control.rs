mod common;

use kasumi_engine::control::*;
use kasumi_engine::test_utils::open_fixture;
use kasumi_store::{TenantStore, test_utils::LocalKeyProvider};
use kasumi_types::*;
use std::{collections::BTreeSet, sync::Arc};

fn context(principal: &str, tenant: &str) -> RequestContext {
    RequestContext {
        authorization: kasumi_types::RequestAuthorization::service_identity(),
        principal: principal.into(),
        tenant: tenant.into(),
        scopes: BTreeSet::from([Action::Admin, Action::Read, Action::Write]),
        request_id: "control-test".into(),
    }
}
fn topology() -> ControlTopology {
    ControlTopology {
        nodes: (1..=3)
            .map(|id| {
                (
                    id,
                    ControlNode {
                        endpoint: format!("https://node-{id}.example:7444"),
                        failure_domain: format!("zone-{id}"),
                        certificate_pins: BTreeSet::from([format!("{id:064x}")]),
                    },
                )
            })
            .collect(),
        tenants: [(
            "customer".into(),
            TenantRoute {
                incarnation: uuid::Uuid::new_v4().to_string(),
                mode: DeploymentMode::Replicated,
                voters: BTreeSet::from([1, 2, 3]),
            },
        )]
        .into(),
    }
}
#[test]
fn placement_rejects_shared_domains_unknown_nodes_duplicate_identities_and_cleartext() {
    let good = topology();
    good.validate().unwrap();
    let mut bad = good.clone();
    bad.nodes.get_mut(&2).unwrap().failure_domain = "zone-1".into();
    assert!(bad.validate().is_err());
    let mut bad = good.clone();
    bad.nodes.remove(&2);
    assert!(bad.validate().is_err());
    let mut bad = good.clone();
    bad.nodes.get_mut(&2).unwrap().certificate_pins = good.nodes[&1].certificate_pins.clone();
    assert!(bad.validate().is_err());
    let mut bad = good.clone();
    bad.nodes.get_mut(&2).unwrap().endpoint = "http://node-2.example".into();
    assert!(bad.validate().is_err());
    let mut bad = good.clone();
    bad.tenants.get_mut("customer").unwrap().voters.remove(&2);
    assert!(bad.validate().is_err());
    let mut bad = good;
    bad.tenants.get_mut("customer").unwrap().mode = DeploymentMode::Local;
    assert!(bad.validate().is_err());
}
#[tokio::test]
async fn control_updates_require_operator_authority_cas_and_survive_reopen() {
    let root = kasumi_store::test_utils::private_tempdir().unwrap();
    let physical =
        common::PhysicalFixture::new(&root.path().join("control.kv"), Default::default());
    let node = physical
        .storage
        .create_new(
            root.path().join("control.kv"),
            kasumi_store::test_utils::NODE_STORE_ID,
        )
        .unwrap();
    let audit = common::security_audit(node.clone(), physical.storage.admission.clone()).await;
    let store = TenantStore::initialize_catalog_fixture(
        node,
        CONTROL_TENANT.into(),
        Arc::new(LocalKeyProvider::new([44; 32])),
    )
    .await
    .unwrap();
    let policy = Policy {
        grants: vec![
            Grant {
                principal: "operator".into(),
                collection: None,
                actions: context("operator", CONTROL_TENANT).scopes,
            },
            Grant {
                principal: "writer".into(),
                collection: None,
                actions: BTreeSet::from([Action::Read, Action::Write]),
            },
        ],
        strict_read_audit: true,
    };
    let db = open_fixture(
        kasumi_store::test_utils::initialize_custody_fixture(
            store.clone(),
            std::sync::Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32])),
        )
        .await
        .unwrap(),
        policy,
        Limits::default(),
        audit.clone(),
    )
    .await
    .unwrap();
    let control = ControlPlane::new(db.clone()).unwrap();
    let operator = context("operator", CONTROL_TENANT);
    control.initialize(operator.clone()).await.unwrap();
    assert!(control.topology(&operator).await.unwrap().is_none());
    assert_eq!(
        ControlPlane::local_topology(&db).unwrap_err().to_string(),
        "control topology unavailable"
    );
    let empty = ControlPlane::select_local(&db).unwrap();
    assert!(empty.decode_topology().unwrap().is_none());
    assert!(empty.topology_document().unwrap().is_none());
    let missing = empty.require_installed_topology().unwrap_err();
    let original = missing
        .downcast_ref::<kasumi_engine::control::LocalTopologyFailure>()
        .unwrap()
        .validation_error()
        .unwrap();
    assert_eq!(original.code, ErrorCode::Corruption);
    assert_eq!(original.message, "installed Control topology is missing");
    assert_eq!(missing.to_string(), original.to_string());
    drop(missing);
    drop(empty);
    let topology = topology();
    let receipt = control
        .replace_topology(
            operator.clone(),
            topology.clone(),
            Precondition::Absent,
            "create".into(),
        )
        .await
        .unwrap();
    let captured = db.engine().generation().unwrap();
    let revision = captured.revision();
    let audits = captured.state.audits.len();
    let local = ControlPlane::local_topology(&db).unwrap();
    assert_eq!(local.version, receipt.revision);
    assert_eq!(local.topology, topology);
    assert_eq!(db.engine().generation().unwrap().revision(), revision);
    assert_eq!(
        db.engine().generation().unwrap().state.audits.len(),
        audits,
        "strict audit policy must not turn local observation into a read audit"
    );
    let selection = ControlPlane::select_local(&db).unwrap();
    selection
        .check_admission(&physical.storage.admission)
        .unwrap();
    let other_admission = kasumi_engine::admission::NodeAdmission::new(Default::default()).unwrap();
    assert_eq!(
        selection
            .check_admission(&other_admission)
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
    drop(other_admission);
    assert_eq!(selection.revision(), revision);
    assert_eq!(selection.topology_version(), Some(receipt.revision));
    let shared = selection.topology_document().unwrap().unwrap();
    assert_eq!(shared.version, receipt.revision);
    assert_eq!(
        selection.require_installed_topology().unwrap().topology,
        topology
    );
    assert_eq!(
        selection.decode_topology().unwrap().unwrap().topology,
        topology
    );
    assert!(selection.enrollment_document("absent").unwrap().is_none());
    assert_eq!(db.engine().generation().unwrap().revision(), revision);
    assert_eq!(db.engine().generation().unwrap().state.audits.len(), audits);
    let old = Arc::downgrade(&captured);
    drop(captured);
    assert_eq!(
        control.topology(&operator).await.unwrap().unwrap().topology,
        topology
    );
    assert!(
        old.upgrade().is_some(),
        "one coherent selection retains its selected metadata"
    );
    assert_eq!(selection.revision(), revision);
    assert_eq!(
        selection.require_installed_topology().unwrap().version,
        receipt.revision
    );
    drop(selection);
    assert_eq!(
        shared.version, receipt.revision,
        "source output survives its selection"
    );
    drop(shared.clone());
    assert!(
        old.upgrade().is_none(),
        "the audited read published a successor while local output retains only its typed copy"
    );
    assert_eq!(
        control
            .replace_topology(
                operator.clone(),
                topology.clone(),
                Precondition::Absent,
                "stale".into()
            )
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    assert_eq!(
        control
            .replace_topology(
                context("operator", "customer"),
                topology.clone(),
                Precondition::Version(receipt.revision),
                "spoof".into()
            )
            .await
            .unwrap_err()
            .code,
        ErrorCode::Forbidden
    );
    // Admin is checked by the ordered engine even when bypassing the typed wrapper.
    assert_eq!(
        db.mutate(
            context("writer", CONTROL_TENANT),
            MutationBatch {
                read_set: Vec::new(),
                idempotency_key: "bypass".into(),
                operations: vec![Mutation::Delete {
                    collection: "topology".into(),
                    id: "current".into(),
                    expected: Precondition::Any
                }]
            }
        )
        .await
        .unwrap_err()
        .code,
        ErrorCode::Forbidden
    );
    let closing = ControlPlane::select_local(&db).unwrap();
    db.raft_group().shutdown().await.unwrap();
    assert!(closing.check_access().is_err());
    assert!(closing.topology_document().is_err());
    assert!(closing.enrollment_document("absent").is_err());
    assert!(closing.decode_topology().is_err());
    assert!(closing.require_installed_topology().is_err());
    drop(closing);
    assert!(ControlPlane::select_local(&db).is_err());
    assert_eq!(
        shared.version, receipt.revision,
        "already released source survives closure"
    );
    assert!(
        ControlPlane::local_topology(&db).is_err(),
        "local access cannot survive the original Raft owner"
    );
    assert_eq!(
        local.topology, topology,
        "already returned DTO remains independently owned"
    );
    audit.drain().await;
    drop(shared);
    let reopened = open_fixture(
        kasumi_store::test_utils::open_existing_custody_fixture(
            store,
            std::sync::Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32])),
        )
        .await
        .unwrap(),
        Policy::default(),
        Limits::default(),
        audit.clone(),
    )
    .await
    .unwrap();
    let control = ControlPlane::new(reopened.clone()).unwrap();
    assert_eq!(
        control.topology(&operator).await.unwrap().unwrap().topology,
        topology
    );
    let selected = ControlPlane::select_local(&reopened).unwrap();
    let released = selected.topology_document().unwrap().unwrap();
    reopened.stores().application().seal();
    // A selected cache/source handle does not bypass current key access at a
    // new handoff. Previously returned immutable data stays caller-owned.
    assert!(selected.check_access().is_err());
    assert!(selected.topology_document().is_err());
    assert!(selected.enrollment_document("absent").is_err());
    assert!(selected.decode_topology().is_err());
    assert!(selected.require_installed_topology().is_err());
    assert_eq!(released.version, receipt.revision);
    drop(selected);
    drop(released);
    reopened.shutdown().await.unwrap();
    assert_eq!(local.version, receipt.revision);
    drop(local);
    audit.shutdown().await.unwrap();
}
