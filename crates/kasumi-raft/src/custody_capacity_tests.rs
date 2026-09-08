//! Cross former lifetime/transport ceilings through the real encrypted tables;
//! only bounded records and temporary encrypted files are resident during build.
use crate::control::tests::{fixture, group, id, retirement_entry, seed};
use crate::{ControlLog, custody_machine, custody_records, custody_tables};
use anyhow::{Context, Result, ensure};
use kasumi_store::{EncryptedSpool, test_utils::FaultBackend};
use kasumi_types::{CustodyAction, CustodyRequest};
use openraft::storage::{RaftLogStorage, RaftLogStorageExt};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek, SeekFrom, Write};

fn spool_record(spool: &mut EncryptedSpool, value: &impl serde::Serialize) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(bytes.len() <= 64 << 10, "fixture record exceeds bound");
    spool.write_all(&(bytes.len() as u64).to_be_bytes())?;
    spool.write_all(&bytes)?;
    Ok(())
}
fn visit_spool(
    spool: &mut EncryptedSpool,
    mut visitor: impl FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    spool.seek(SeekFrom::Start(0))?;
    while spool.stream_position()? < spool.len() {
        let mut size = [0u8; 8];
        spool.read_exact(&mut size)?;
        let size = u64::from_be_bytes(size);
        ensure!(size <= 64 << 10, "fixture record exceeds bound");
        let mut bytes = vec![0; size as usize];
        spool.read_exact(&mut bytes)?;
        visitor(&bytes)?;
    }
    Ok(())
}
#[tokio::test]
async fn permanent_custody_exceeds_former_count_and_snapshot_ceilings_and_reopens() -> Result<()> {
    let disk = FaultBackend::new();
    let (domains, _, _, mut log) = fixture(disk.clone()).await?;
    log.blocking_append([
        openraft::Entry {
            log_id: id(0),
            payload: openraft::EntryPayload::Membership(openraft::Membership::new(
                vec![BTreeSet::from([1])],
                BTreeMap::from([(1, crate::BasicNode::new("local"))]),
            )),
        },
        retirement_entry()?,
    ])
    .await?;
    log.save_committed(Some(id(1))).await?;
    ensure!(
        ControlLog::open(domains.custody().clone(), 1, group())?.recover_retired()?,
        "retirement absent"
    );
    let (head, request, original, revision, context) = tokio::task::spawn_blocking(move || {
        let mut snapshot = custody_machine::capture(domains.custody())?;
        let mut head = custody_tables::load(domains.custody().store())?;
        let context = seed()?.0.context;
        let mut commands = EncryptedSpool::new(&kasumi_store::ScratchDisk::fixture(), 64 << 20)?;
        let mut audit = EncryptedSpool::new(&kasumi_store::ScratchDisk::fixture(), 64 << 20)?;
        let mut revision = 2u64;
        let mut original = None;
        for index in 0..4200 {
            let request = CustodyRequest {
                retirement: head.policy.origin.request.reference()?,
                command_id: format!("command-{index:08}"),
                expected_policy_epoch: head.policy.policy_epoch,
                not_after_ms: 1000,
                action: CustodyAction::SetLimits(head.policy.limits.clone()),
            };
            let (next, receipt, event) = head.apply(None, &context, &request, 100, revision)?;
            spool_record(&mut commands, &receipt)?;
            spool_record(&mut audit, &event)?;
            if original.is_none() {
                original = Some((request.clone(), receipt.clone()));
            }
            revision += 1;
            let (next, replay, event) =
                next.apply(Some(receipt.clone()), &context, &request, 100, revision)?;
            assert_eq!(receipt, replay);
            spool_record(&mut audit, &event)?;
            head = next;
            revision += 1;
        }
        assert!(head.commands > 4096 && head.audit > 8192);
        let mut builder =
            custody_records::Builder::new(&kasumi_store::ScratchDisk::fixture(), head.clone())?;
        visit_spool(&mut commands, |bytes| builder.command(bytes))?;
        let mut sequence = 0u64;
        visit_spool(&mut audit, |bytes| {
            builder.audit(&sequence.to_be_bytes(), bytes)?;
            sequence += 1;
            Ok(())
        })?;
        let records = builder.finish()?;
        let retirement = snapshot.retirement.as_mut().context("retirement absent")?;
        retirement.custody = head.clone();
        retirement.history_sha256 = records.sha256().into();
        retirement.records = Some(records);
        snapshot.meta.last_log_id = Some(id(revision - 1));
        let image = snapshot.encode(64 << 20)?;
        assert!(
            image.len() > 2 << 20,
            "fixture did not cross former closed transport ceiling"
        );
        assert!(
            snapshot.encode(2 << 20).is_err(),
            "configured transfer budget was ignored"
        );
        custody_machine::publish(domains.custody(), &snapshot, 64 << 20)?;
        drop(snapshot);
        drop(image);
        drop(log);
        drop(domains);
        let (request, original) = original.context("original receipt absent")?;
        Ok::<_, anyhow::Error>((head, request, original, revision, context))
    })
    .await??;
    let (reopened, _, _, _) = fixture(disk.crash()).await?;
    tokio::task::spawn_blocking(move || -> Result<()> {
        let current = custody_tables::load(reopened.custody().store())?;
        assert_eq!(current, head);
        let prior = custody_tables::receipt(reopened.custody().store(), &request.command_id)?;
        assert_eq!(prior.as_ref(), Some(&original));
        let (_, replay, event) = current.apply(prior.clone(), &context, &request, 100, revision)?;
        assert_eq!(replay, original);
        assert!(event.replay);
        let mut changed = request;
        changed.not_after_ms -= 1;
        assert!(
            current
                .apply(prior, &context, &changed, 100, revision)
                .is_err()
        );
        let loaded = custody_machine::load_snapshot(reopened.custody(), 64 << 20)?
            .context("snapshot absent")?;
        assert_eq!(loaded.retirement.as_ref().unwrap().custody, head);
        Ok(())
    })
    .await??;
    Ok(())
}
