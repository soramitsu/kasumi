use super::*;
use crate::application_payload::tests::Fixture;
use anyhow::Result;
use std::{
    future::{Future, poll_fn},
    task::Poll,
    time::Duration,
};

#[tokio::test]
async fn escaped_registered_point_output_keeps_original_storage_lease_until_plaintext_credit_retires()
-> Result<()> {
    let fixture = Fixture::new().await?;
    let baseline = fixture.memory.snapshot();
    let (drain, lease) = StorageDrain::new();
    let handle = StorageHandle::new(fixture.store.clone(), Some(lease));
    let output = handle.get("commands", b"proposal")?.unwrap();
    let charged = fixture.memory.snapshot();
    assert!(charged.used_bytes > baseline.used_bytes);
    drop(handle);
    let waiting = drain.wait();
    tokio::pin!(waiting);
    poll_fn(|cx| {
        assert!(matches!(waiting.as_mut().poll(cx), Poll::Pending));
        Poll::Ready(())
    })
    .await;
    assert_eq!(output.as_bytes(), vec![0x71; 64 << 10]);
    assert_eq!(fixture.memory.snapshot().used_bytes, charged.used_bytes);
    drop(output);
    tokio::time::timeout(Duration::from_secs(5), drain.wait()).await?;
    assert_eq!(fixture.memory.snapshot().used_bytes, baseline.used_bytes);
    assert_eq!(
        fixture.memory.snapshot().live_reservations,
        baseline.live_reservations
    );
    fixture.shutdown().await
}
