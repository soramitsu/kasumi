//! Streaming preserves the existing enrollment commitment, including JSON spelling.
use super::*;
use kasumi_types::control_topology::{ControlNode, ControlTopology, DeploymentMode, TenantRoute};
use kasumi_types::{Action, Grant, Policy};
use std::collections::BTreeSet;

fn proposal() -> Proposal {
    Proposal {
        format: 1,
        tenant: "tenant-東京-\"\\".into(),
        route: TenantRoute {
            incarnation: "b63744c9-1caf-4a95-884b-c7c4d261a12f".into(),
            mode: DeploymentMode::Local,
            voters: BTreeSet::from([1]),
        },
        nodes: BTreeMap::from([(
            1,
            ControlNode {
                endpoint: "https://node.invalid:8443/".into(),
                failure_domain: "rack-東京-\"\\".into(),
                certificate_pins: BTreeSet::from(["12".repeat(32)]),
            },
        )]),
        initial_policy: Policy {
            grants: vec![
                Grant {
                    principal: "operator-東京-\"\\".into(),
                    collection: None,
                    actions: BTreeSet::from([
                        Action::Read,
                        Action::Write,
                        Action::Admin,
                        Action::Audit,
                    ]),
                },
                Grant {
                    principal: "reader".into(),
                    collection: Some("accounts-\"\\".into()),
                    actions: BTreeSet::from([Action::Read]),
                },
            ],
            strict_read_audit: true,
        },
        initial_limits: kasumi_types::Limits::default(),
        application_keys: serde_json::json!({
            "kind": "file",
            "identity": "kasumi.file-key/e8b906e1-8385-4432-aeb7-5c4f38b4b97d/application"
        }),
        custody_keys: serde_json::json!({
            "kind": "transit",
            "endpoint": "https://vault.invalid:8200",
            "mount": "transit",
            "key_name": "custody",
            "namespace": "team/東京",
            "derived": true
        }),
        authority_id: Some(Uuid::parse_str("5e67bc58-4873-474f-b79b-2704997d252a").unwrap()),
    }
}

// Previous production algorithm, retained only as a prior-algorithm oracle for
// this first-release commitment. It intentionally materializes maps and bytes.
fn materialized_digest(proposal: &Proposal) -> Result<String> {
    ensure!(
        proposal.format == 1,
        "unsupported tenant enrollment proposal"
    );
    kasumi_types::validate_name(&proposal.tenant)?;
    ensure!(
        !Uuid::parse_str(&proposal.route.incarnation)?.is_nil(),
        "nil enrollment incarnation"
    );
    let topology = ControlTopology {
        nodes: proposal.nodes.clone(),
        tenants: BTreeMap::from([(proposal.tenant.clone(), proposal.route.clone())]),
    };
    topology.validate()?;
    kasumi_engine::validate_genesis_inputs(
        &proposal.tenant,
        &proposal.route.incarnation,
        &proposal.initial_policy,
        &proposal.initial_limits,
    )?;
    Ok(format!(
        "enrollment-v1-{}",
        hex::encode(Sha256::digest(serde_json::to_vec(proposal)?))
    ))
}

#[test]
fn streaming_digest_preserves_escaped_ids_file_transit_descriptors_and_current_policy() -> Result<()>
{
    let mut value = proposal();
    let bytes = serde_json::to_vec(&value)?;
    let text = std::str::from_utf8(&bytes)?;
    assert!(text.contains("東京-\\\"\\\\"));
    assert!(text.contains("\"strict_read_audit\":true"));
    assert!(text.contains("\"kind\":\"file\""));
    assert!(text.contains("\"kind\":\"transit\""));
    let original = value.digest()?;
    assert_eq!(original, materialized_digest(&value)?);
    assert_eq!(original.len(), 78);
    let round_trip: Proposal = serde_json::from_slice(&bytes)?;
    assert_eq!(round_trip.digest()?, original);

    // Policy/provider/authority changes remain part of the commitment.
    value.initial_policy.strict_read_audit = false;
    assert_ne!(value.digest()?, original);
    assert_eq!(value.digest()?, materialized_digest(&value)?);
    value = proposal();
    std::mem::swap(&mut value.application_keys, &mut value.custody_keys);
    assert_ne!(value.digest()?, original);
    assert_eq!(value.digest()?, materialized_digest(&value)?);
    value = proposal();
    value.authority_id = None;
    assert_ne!(value.digest()?, original);
    assert_eq!(value.digest()?, materialized_digest(&value)?);
    Ok(())
}

#[test]
fn streaming_digest_preserves_numeric_lexemes_and_escaped_keys_in_both_values() -> Result<()> {
    let mut value = proposal();
    value.application_keys = serde_json::from_str(
        r#"{"key\"\\東京":{"decimal":1.2300,"wide":123456789012345678901234567890},"text":"line\n\t\"\\"}"#,
    )?;
    value.custody_keys = serde_json::from_str(
        r#"{"other\"\\鍵":[9.2500e+42,0.000000000000000001,{"literal":"\u0000\"\\"}]}"#,
    )?;
    let bytes = serde_json::to_vec(&value)?;
    let text = std::str::from_utf8(&bytes)?;
    for spelling in [
        "1.2300",
        "123456789012345678901234567890",
        "9.2500e+42",
        "0.000000000000000001",
    ] {
        assert!(
            text.contains(spelling),
            "fixture lost numeric spelling {spelling}"
        );
    }
    let original = value.digest()?;
    assert_eq!(original, materialized_digest(&value)?);
    let decoded: Proposal = serde_json::from_slice(&bytes)?;
    assert_eq!(decoded.digest()?, original);
    // Decimal respelling is deliberately not canonicalized by this digest.
    let changed = text.replacen("1.2300", "1.23", 1);
    let changed: Proposal = serde_json::from_str(&changed)?;
    assert_ne!(changed.digest()?, original);
    assert_eq!(changed.digest()?, materialized_digest(&changed)?);
    Ok(())
}

#[test]
fn streaming_digest_preserves_validation_errors_before_hashing() {
    for mutation in 0..7 {
        let mut value = proposal();
        let expected = match mutation {
            0 => {
                value.format = 2;
                value.tenant.clear();
                "unsupported tenant enrollment proposal"
            }
            1 => {
                value.tenant.clear();
                value.route.incarnation = "not a uuid".into();
                "name must contain 1–256 bytes without control characters"
            }
            2 => {
                value.route.incarnation = Uuid::nil().to_string();
                value.nodes.clear();
                "nil enrollment incarnation"
            }
            3 => {
                value.nodes.get_mut(&1).unwrap().endpoint = "not a URL".into();
                value.route.voters.clear();
                "invalid node endpoint"
            }
            4 => {
                value.route.voters.clear();
                value.initial_policy.grants.clear();
                "deployment voter count is invalid"
            }
            5 => {
                value.initial_policy.grants.clear();
                "tenant needs an administrator"
            }
            _ => {
                value.initial_limits.max_policy_grants = 1;
                "policy grant quota exceeded"
            }
        };
        let actual = value.digest().unwrap_err();
        let previous = materialized_digest(&value).unwrap_err();
        assert_eq!(
            actual.to_string(),
            previous.to_string(),
            "mutation {mutation}"
        );
        assert!(
            actual.to_string().ends_with(expected),
            "mutation {mutation}: {actual}"
        );
        assert_eq!(
            actual.downcast_ref::<kasumi_types::Error>(),
            previous.downcast_ref::<kasumi_types::Error>(),
            "mutation {mutation}",
        );
    }
}
