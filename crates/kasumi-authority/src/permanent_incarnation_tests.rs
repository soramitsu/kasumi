use super::*;
use sha2::{Digest, Sha256};

// Before 04f8c199 the installed receipt capacity was at most 100,000.
// The reducer counted every receipt toward it, and restore independently
// required incarnations <= receipts. This bounds the old incarnation cohort
// even with no lifecycle receipts or outstanding reservations.
const FORMER_MAXIMUM: u64 = 100_000;

fn enrollment(template: &PreparedCommand, ordinal: u64) -> (PreparedCommand, Uuid) {
    let mut prepared = template.clone();
    prepared.command.tenant = format!("history-{ordinal:06}");
    prepared.command.command_id = Uuid::from_u128(u128::from(ordinal));
    let incarnation = Uuid::from_u128((1 << 96) + u128::from(ordinal));
    let AuthorityAction::Enroll {
        incarnation: id, ..
    } = &mut prepared.command.action
    else {
        panic!("the historical qualifier must enroll a distinct tenant");
    };
    *id = incarnation;
    (prepared, incarnation)
}

fn select(
    backend: &Backend,
    command: &PreparedCommand,
    index: u64,
    replay: bool,
) -> AuthorityReceipt {
    let bytes = serde_json::to_vec(&PreparedOperation::Administrative(Box::new(
        command.clone(),
    )))
    .unwrap();
    let mut pos = position(index);
    pos.command_sha256 = hex::encode(Sha256::digest(&bytes));
    let mut publisher = LocalPublisher::new(backend, false);
    let applied = backend.apply_with_publisher(&pos, AppliedInput::Command(&bytes), &mut publisher);
    assert_eq!(publisher.calls, 1);
    assert_eq!(publisher.writes == 0, replay);
    let receipt: kasumi_types::Result<AuthorityReceipt> =
        serde_json::from_slice(&publisher.finish(applied).unwrap().data).unwrap();
    receipt.unwrap()
}

fn retain_digest(hasher: &mut Sha256, receipt: &AuthorityReceipt) {
    let bytes = serde_json::to_vec(receipt).unwrap();
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

async fn persists_distinct_incarnations(count: u64) {
    let fixture = Fixture::with_capacity(AuthorityCapacity {
        max_tenants: count,
        max_state_bytes: 2 << 30,
        maintenance_reserve_bytes: 1 << 20,
    })
    .await;
    let template = fixture.command();
    let mut initial = Sha256::new();
    for index in 1..=count {
        let (command, incarnation) = enrollment(&template, index);
        let receipt = select(&fixture.backend, &command, index, false);
        assert_eq!(receipt.command, command.command);
        assert_eq!(receipt.revision, index);
        assert_eq!(
            receipt.outcome,
            AuthorityOutcome::Enrolled {
                incarnation,
                authority_epoch: 1
            }
        );
        retain_digest(&mut initial, &receipt);
    }
    let before = fixture.backend.meta().unwrap();
    assert_eq!(
        (before.tenants, before.incarnations, before.receipts),
        (count, count, count)
    );
    let fixture = fixture.reopen().await;
    let after = fixture.backend.meta().unwrap();
    assert_eq!(
        (after.tenants, after.incarnations, after.receipts),
        (count, count, count)
    );
    assert_eq!(after.state_bytes, before.state_bytes);
    let mut restored = Sha256::new();
    for index in 1..=count {
        let (command, incarnation) = enrollment(&template, index);
        let tenant = &command.command.tenant;
        let Some(Record::Incarnation(record)) = fixture
            .backend
            .record(&key_incarnation(tenant, incarnation))
            .unwrap()
        else {
            panic!("reopened permanent incarnation {index} is missing");
        };
        let receipt = fixture
            .backend
            .receipt(tenant, command.command.command_id)
            .unwrap()
            .unwrap();
        assert_eq!(record.tenant, *tenant);
        assert_eq!(record.incarnation, incarnation);
        assert_eq!(record.authority_epoch, 1);
        assert_eq!(record.receipt, receipt);
        assert_eq!(receipt.command, command.command);
        assert_eq!(receipt.revision, index);
        if index == 1 || index == count {
            assert_eq!(
                select(&fixture.backend, &command, count + index, true),
                receipt
            );
        }
        retain_digest(&mut restored, &receipt);
    }
    let original_sha256 = hex::encode(initial.finalize());
    assert_eq!(hex::encode(restored.finalize()), original_sha256);
    fixture.close().await;
    println!(
        "KASUMI_AUDIT_COMPONENT {}",
        serde_json::json!({
            "case": "permanent-incarnations", "prior_limit": FORMER_MAXIMUM,
            "selected": before.incarnations, "reopened": after.incarnations,
            "verified_receipts": count, "replayed_first_revision": 1, "replayed_last_revision": count,
            "ordered_receipts_sha256": original_sha256, "selected_bytes": after.state_bytes,
            "physical_reopen": true, "drained": true
        })
    );
}

#[tokio::test]
async fn selected_incarnations_and_receipts_survive_physical_reopen() {
    persists_distinct_incarnations(3).await;
}

#[tokio::test]
#[ignore = "qualifies the complete permanent Authority incarnation cohort"]
async fn authoritative_incarnations_cross_the_former_receipt_ceiling_and_reopen() {
    persists_distinct_incarnations(FORMER_MAXIMUM + 1).await;
}
