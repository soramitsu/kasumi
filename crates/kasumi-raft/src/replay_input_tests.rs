use super::*;
use crate::{
    application_payload::tests::Fixture,
    lifetime::{StorageDrain, StorageHandle},
    selected_application::allocation_tests,
};
use anyhow::Result;
use kasumi_store::{NodeDiskMemoryAdmission, WriteOp, test_utils::TestDiskMemory};
use std::{
    future::{Future, poll_fn},
    task::Poll,
    time::Duration,
};
const FORMAT: &[u8] = b"kasumi-log\x01";
fn id(index: u64) -> LogId<u64> {
    LogId::new(openraft::CommittedLeaderId::new(3, 7), index)
}
fn entry(bytes: Vec<u8>) -> Entry<TypeConfig> {
    Entry {
        log_id: id(11),
        payload: EntryPayload::Normal(RaftCommand::application(bytes)),
        initialization: None,
    }
}
#[tokio::test]
async fn real_stored_application_range_lends_same_point_grant_without_vec_or_control_allocation()
-> Result<()> {
    let fixture = Fixture::new().await?;
    let original = entry(vec![0x52; 64 << 10]);
    let encoded = crate::storage::encode_entry(&original)?;
    fixture
        .store
        .write_batch(&[WriteOp::put("commands", b"replay", encoded.as_slice())])?;
    drop(fixture.store.get_retained("commands", b"replay")?);
    let before = fixture.memory.snapshot();
    let (drain, lease) = StorageDrain::new();
    let handle = StorageHandle::new(fixture.store.clone(), Some(lease));
    let record = handle.get_retained("commands", b"replay")?.unwrap();
    let charged = fixture.memory.snapshot();
    assert_eq!(charged.live_reservations, before.live_reservations + 1);
    let decoded = allocation_tests::require_no_allocations(|| {
        decode_application_entry(&record, FORMAT).unwrap()
    });
    assert_eq!(decoded, original);
    assert_eq!(crate::storage::encode_entry(&decoded)?, encoded);
    let EntryPayload::Normal(RaftCommand::Application(input)) = &decoded.payload else {
        panic!("ordinary application");
    };
    let address = input.as_bytes().as_ptr();
    let start = address as usize - record.as_bytes().as_ptr() as usize;
    assert!(start < record.as_bytes().len());
    assert_eq!(
        input.as_bytes(),
        &record.as_bytes()[start..start + (64 << 10)]
    );
    let provider: Arc<dyn NodeDiskMemoryAdmission> = fixture.memory.clone();
    let foreign: Arc<dyn NodeDiskMemoryAdmission> = TestDiskMemory::new(256 << 20, 4096);
    let loan = allocation_tests::require_no_allocations(|| {
        let loan = input
            .input_loan(id(11))
            .unwrap()
            .expect("named actual replay input");
        loan.require_memory(&provider).unwrap();
        assert_eq!(
            loan.require_memory(&foreign),
            Err(InputBindingError::Foreign)
        );
        loan.require_bytes(id(11), &[0x52; 64 << 10]).unwrap();
        assert_eq!(
            loan.require_bytes(id(12), &[0x52; 64 << 10]),
            Err(InputBindingError::Foreign)
        );
        assert_eq!(
            loan.require_bytes(id(11), b"changed"),
            Err(InputBindingError::Foreign)
        );
        loan
    });
    assert!(input.input_loan(id(12)).is_err());
    // Wrong-ID public input_loan builds an existing ordinary diagnostic; only
    // exact receiver scalar require_* refusals above are allocation-free.
    let alias = allocation_tests::require_no_allocations(|| loan.retained_input());
    let mutation = kasumi_types::MutationBatch {
        idempotency_key: "not-a-point-fee-donation".into(),
        read_set: vec![],
        operations: vec![kasumi_types::Mutation::Delete {
            collection: "docs".into(),
            id: "row".into(),
            expected: kasumi_types::Precondition::Any,
        }],
    };
    allocation_tests::require_no_allocations(|| {
        assert!(
            alias
                .claim_mutation_change_tree(id(11), &mutation)
                .unwrap()
                .is_none(),
            "replay's original point lease has NO mutation-tree allowance"
        );
        assert!(matches!(
            alias.claim_mutation_change_tree(id(12), &mutation),
            Err(InputBindingError::Foreign)
        ));
        assert!(
            alias
                .claim_mutation_change_tree(id(11), &mutation)
                .unwrap()
                .is_none(),
            "an unproved replay producer never mints the leader one-shot owner"
        );
    });
    assert_eq!(
        fixture.memory.snapshot().attempts,
        charged.attempts,
        "decode, bind, loan and clone must not acquire a second grant"
    );
    drop(loan);
    drop(record);
    drop(decoded);
    drop(handle);
    assert_eq!(alias.as_bytes().as_ptr(), address);
    assert_eq!(fixture.memory.snapshot().used_bytes, charged.used_bytes);
    let waiting = drain.wait();
    tokio::pin!(waiting);
    poll_fn(|cx| {
        assert!(matches!(waiting.as_mut().poll(cx), Poll::Pending));
        Poll::Ready(())
    })
    .await;
    drop(alias);
    tokio::time::timeout(Duration::from_secs(5), drain.wait()).await?;
    assert_eq!(fixture.memory.snapshot().used_bytes, before.used_bytes);
    assert_eq!(
        fixture.memory.snapshot().live_reservations,
        before.live_reservations
    );
    fixture.shutdown().await
}
#[test]
fn borrowed_ordinary_wire_visitor_preserves_original_order_and_rejects_foreign_shapes_without_owned_decode()
-> Result<()> {
    for bytes in [Vec::new(), vec![0; 1], vec![0x97; 4096]] {
        let encoded = crate::storage::encode_entry(&entry(bytes.clone()))?;
        let borrowed = allocation_tests::require_no_allocations(|| {
            postcard::from_bytes::<BorrowedApplication<'_>>(&encoded[FORMAT.len()..]).unwrap()
        });
        assert_eq!(borrowed.log_id, id(11));
        assert_eq!(borrowed.body, bytes);
        let pointer = borrowed.body.as_ptr() as usize;
        assert!(
            pointer >= encoded.as_ptr() as usize
                && pointer + borrowed.body.len() <= encoded.as_ptr() as usize + encoded.len()
        );
    }
    let blank = Entry::<TypeConfig> {
        log_id: id(11),
        payload: EntryPayload::Blank,
        initialization: None,
    };
    let custody = Entry::<TypeConfig> {
        log_id: id(11),
        payload: EntryPayload::Normal(RaftCommand::Custody(vec![1, 2])),
        initialization: None,
    };
    let retirement = Entry::<TypeConfig> {
        log_id: id(11),
        payload: EntryPayload::Normal(RaftCommand::Retirement {
            application: vec![1],
            seed: vec![2],
        }),
        initialization: None,
    };
    let mut initialized = entry(vec![1]);
    initialized.initialization = Some(vec![1, 2]);
    for original in [blank, custody, retirement, initialized] {
        let encoded = crate::storage::encode_entry(&original)?;
        allocation_tests::require_no_allocations(|| {
            assert!(
                postcard::from_bytes::<BorrowedApplication<'_>>(&encoded[FORMAT.len()..]).is_err()
            )
        });
    }
    let mut extended = crate::storage::encode_entry(&entry(vec![1, 2, 3]))?;
    extended.extend([0x71, 0x82]);
    let legacy: Entry<TypeConfig> = postcard::from_bytes(&extended[FORMAT.len()..])?;
    let borrowed = postcard::from_bytes::<BorrowedApplication<'_>>(&extended[FORMAT.len()..])?;
    assert_eq!(borrowed.log_id, legacy.log_id);
    let EntryPayload::Normal(command) = legacy.payload else {
        panic!("normal application");
    };
    assert_eq!(
        borrowed.body,
        command.bytes(),
        "retain existing postcard trailing-byte behavior"
    );
    let encoded = crate::storage::encode_entry(&entry(vec![1, 2, 3]))?;
    for end in 0..encoded.len() - FORMAT.len() {
        allocation_tests::require_no_allocations(|| {
            assert!(
                postcard::from_bytes::<BorrowedApplication<'_>>(
                    &encoded[FORMAT.len()..FORMAT.len() + end]
                )
                .is_err()
            )
        });
    }
    Ok(())
}
