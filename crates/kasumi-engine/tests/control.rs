mod common;

use kasumi_engine::{control::*, open_local};
use kasumi_store::{NodeStore, TenantStore, test_utils::LocalKeyProvider};
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
    let root = tempfile::tempdir().unwrap();
    let node = NodeStore::open(root.path().join("control.redb")).unwrap();
    let audit = common::security_audit(node.clone()).await;
    let store = TenantStore::open(
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
    let db = open_local(store.clone(), policy, Limits::default(), audit.clone())
        .await
        .unwrap();
    let control = ControlPlane::new(db.clone()).unwrap();
    let operator = context("operator", CONTROL_TENANT);
    control.initialize(operator.clone()).await.unwrap();
    assert!(control.topology(&operator).await.unwrap().is_none());
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
    assert_eq!(
        control.topology(&operator).await.unwrap().unwrap().topology,
        topology
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
    db.raft_group().shutdown().await.unwrap();
    audit.drain().await;
    let reopened = open_local(store, Policy::default(), Limits::default(), audit.clone())
        .await
        .unwrap();
    let control = ControlPlane::new(reopened.clone()).unwrap();
    assert_eq!(
        control.topology(&operator).await.unwrap().unwrap().topology,
        topology
    );
    reopened.shutdown().await.unwrap();
    audit.shutdown().await;
}
