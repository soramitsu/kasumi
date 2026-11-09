use super::*;
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{Seek, Write},
    ops::Bound::{Excluded, Included, Unbounded},
    process::Command,
};
use tempfile::tempdir;

fn read_all(db: &mut LiveDb) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut actual = Vec::new();
    db.visit_forward(Unbounded, Unbounded, usize::MAX, |key, value| {
        actual.push((key.to_vec(), value.to_vec()));
        Ok(())
    })
    .unwrap();
    actual
}

#[test]
fn overlay_scans_both_directions_handle_tombstones_replacements_bounds_and_user_errors() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("db");
    let mut db = LiveDb::create(&path).unwrap();
    db.commit(&[
        WalOp::Put(b"b", b"old"),
        WalOp::Put(b"d", b"d"),
        WalOp::Put(b"g", b"g"),
    ])
    .unwrap();
    db.checkpoint().unwrap();
    db.commit(&[
        WalOp::Put(b"", b""),
        WalOp::Put(b"a", b"a"),
        WalOp::Delete(b"b"),
        WalOp::Put(b"c", b"1"),
        WalOp::Put(b"c", b"2"),
        WalOp::Put(b"d", b"new"),
        WalOp::Delete(b"e"),
        WalOp::Put(b"z", b"z"),
    ])
    .unwrap();
    let expected: BTreeMap<Vec<u8>, Vec<u8>> = [
        (b"".as_slice(), b"".as_slice()),
        (b"a", b"a"),
        (b"c", b"2"),
        (b"d", b"new"),
        (b"g", b"g"),
        (b"z", b"z"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_vec(), v.to_vec()))
    .collect();
    for stage in 0..3 {
        if stage == 1 {
            drop(db);
            db = LiveDb::open(&path).unwrap();
        }
        if stage == 2 {
            db.checkpoint().unwrap();
        }
        for key in [b"".as_slice(), b"a", b"b", b"c", b"d", b"e", b"g", b"z"] {
            assert_eq!(db.get(key).unwrap().as_ref(), expected.get(key));
        }
        let bounds = [
            Unbounded,
            Included(b"a".as_slice()),
            Excluded(b"a".as_slice()),
            Included(b"g".as_slice()),
            Excluded(b"g".as_slice()),
        ];
        for lower in bounds {
            for upper in bounds {
                for reverse in [false, true] {
                    let mut baseline = expected
                        .iter()
                        .filter(|(key, _)| {
                            let key = key.as_slice();
                            (match lower {
                                Included(v) => key >= v,
                                Excluded(v) => key > v,
                                Unbounded => true,
                            }) && (match upper {
                                Included(v) => key <= v,
                                Excluded(v) => key < v,
                                Unbounded => true,
                            })
                        })
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect::<Vec<_>>();
                    if reverse {
                        baseline.reverse();
                    }
                    for limit in [0, 1, 2, usize::MAX] {
                        let mut actual = Vec::new();
                        let emit = |k: &[u8], v: &[u8]| {
                            actual.push((k.to_vec(), v.to_vec()));
                            Ok(())
                        };
                        let count = if reverse {
                            db.visit_reverse(lower, upper, limit, emit)
                        } else {
                            db.visit_forward(lower, upper, limit, emit)
                        }
                        .unwrap();
                        assert_eq!(actual, baseline[..limit.min(baseline.len())]);
                        assert_eq!(actual.len(), count);
                    }
                }
            }
        }
        assert_eq!(
            db.visit_reverse(Unbounded, Unbounded, 1, |_, _| Err(
                ErrorKind::BrokenPipe.into()
            ))
            .unwrap_err()
            .kind(),
            ErrorKind::BrokenPipe
        );
    }
}

#[test]
fn new_manifest_and_overlapping_generations_recover_exactly_one_state() {
    let parent = tempdir().unwrap();
    let path = parent.path().join("original");
    let mut db = LiveDb::create(&path).unwrap();
    db.commit(&[WalOp::Put(b"a", b"b")]).unwrap();
    db.checkpoint().unwrap();
    db.commit(&[WalOp::Put(b"a", b"b")]).unwrap();
    let old = db.head.clone();
    let old_manifest = fs::read(path.join(MANIFEST)).unwrap();
    let old_base = fs::read(path.join(old.entries[0].name(&old.id))).unwrap();
    let old_wal = fs::read(path.join(old.wal_name())).unwrap();
    db.checkpoint().unwrap();
    let new = db.head.clone();
    let new_manifest = fs::read(path.join(MANIFEST)).unwrap();
    let new_base = fs::read(path.join(new.entries[0].name(&new.id))).unwrap();
    let new_wal = fs::read(path.join(new.wal_name())).unwrap();
    drop(db);
    // Durable prefixes before publication can include half of either new
    // file or the temporary manifest. After publication either old file
    // might have been unlinked. Each image must remain exactly writable.
    for stage in 0..12 {
        let dir = parent.path().join(stage.to_string());
        fs::create_dir(&dir).unwrap();
        fs::write(
            dir.join(MANIFEST),
            if stage < 9 {
                &old_manifest
            } else {
                &new_manifest
            },
        )
        .unwrap();
        if stage < 11 {
            fs::write(dir.join(old.entries[0].name(&old.id)), &old_base).unwrap();
        }
        if stage < 10 || stage == 11 {
            fs::write(dir.join(old.wal_name()), &old_wal).unwrap();
        }
        if stage >= 1 {
            let n = if stage == 1 {
                0
            } else if stage == 2 {
                new_base.len() / 2
            } else {
                new_base.len()
            };
            fs::write(dir.join(new.entries[0].name(&new.id)), &new_base[..n]).unwrap();
        }
        if stage >= 4 {
            let n = if stage == 4 {
                0
            } else if stage == 5 {
                new_wal.len() / 2
            } else {
                new_wal.len()
            };
            fs::write(dir.join(new.wal_name()), &new_wal[..n]).unwrap();
        }
        if (7..9).contains(&stage) {
            let n = if stage == 7 {
                new_manifest.len() / 2
            } else {
                new_manifest.len()
            };
            fs::write(
                dir.join(Files::name(&old.id, "head-next")),
                &new_manifest[..n],
            )
            .unwrap();
        }
        let mut recovered = LiveDb::open(&dir).unwrap();
        assert_eq!(recovered.sequence(), 2, "stage {stage}");
        assert_eq!(recovered.get(b"a").unwrap().as_deref(), Some(&b"b"[..]));
        assert_eq!(
            recovered.commit(&[WalOp::Put(b"next", b"value")]).unwrap(),
            3
        );
        recovered.checkpoint().unwrap();
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 3);
        drop(recovered);
        assert_eq!(read_all(&mut LiveDb::open(&dir).unwrap()).len(), 2);
    }
}

#[test]
fn lock_and_process_exit_preserve_the_last_acknowledged_batch() {
    const ENV: &str = "KASUMI_LIVE_LOCK_TEST_DB";
    if let Some(path) = std::env::var_os(ENV) {
        let mode = std::env::var("KASUMI_LIVE_LOCK_TEST_MODE").unwrap();
        if mode == "blocked" {
            assert_eq!(
                LiveDb::open(path).err().unwrap().kind(),
                ErrorKind::WouldBlock
            );
        } else {
            let mut db = LiveDb::open(path).unwrap();
            db.commit(&[WalOp::Put(b"process", b"durable")]).unwrap();
            std::process::exit(0);
        }
        return;
    }
    let parent = tempdir().unwrap();
    let path = parent.path().join("db");
    let db = LiveDb::create(&path).unwrap();
    let child = |mode| {
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "live::tests::lock_and_process_exit_preserve_the_last_acknowledged_batch",
            ])
            .env(ENV, &path)
            .env("KASUMI_LIVE_LOCK_TEST_MODE", mode)
            .output()
            .unwrap()
    };
    let blocked = child("blocked");
    assert!(blocked.status.success(), "{blocked:?}");
    drop(db);
    let durable = child("write");
    assert!(durable.status.success(), "{durable:?}");
    let mut db = LiveDb::open(path).unwrap();
    assert_eq!(db.sequence(), 1);
    assert_eq!(
        db.get(b"process").unwrap().as_deref(),
        Some(&b"durable"[..])
    );
}

#[test]
fn oversized_batch_is_checkpointed_and_idle_checkpoint_has_no_effects() {
    let dir = tempdir().unwrap();
    let mut db = LiveDb::create_with_buffer(dir.path(), LIVE_CHECKPOINT_BYTES).unwrap();
    let before = db.stats();
    assert_eq!((before.file_syncs, before.directory_syncs), (2, 5));
    let value = vec![17; LIVE_CHECKPOINT_BYTES as usize + 1];
    db.commit(&[WalOp::Put(b"big", &value)]).unwrap();
    let done = db.stats();
    assert_eq!(
        (
            done.checkpoints,
            done.base_sequence,
            done.pending_bytes,
            done.delta_entries
        ),
        (1, 1, 0, 0)
    );
    assert_eq!(
        (
            done.file_syncs - before.file_syncs,
            done.directory_syncs - before.directory_syncs
        ),
        (4, 3)
    );
    db.checkpoint().unwrap();
    assert_eq!(db.stats().file_syncs, done.file_syncs);
    assert_eq!(db.stats().directory_syncs, done.directory_syncs);
    drop(db);
    let mut db = LiveDb::open(dir.path()).unwrap();
    assert_eq!(db.get(b"big").unwrap().unwrap(), value);
    let before = db.stats();
    db.commit(&[]).unwrap();
    assert_eq!(db.stats().file_syncs, before.file_syncs + 1);
    db.checkpoint().unwrap();
    assert_eq!(db.stats().base_sequence, 2);
}

#[test]
fn corrupt_selected_state_does_not_roll_back_to_an_inactive_generation() {
    let dir = tempdir().unwrap();
    let path = dir.path();
    let mut db = LiveDb::create(path).unwrap();
    db.commit(&[WalOp::Put(b"old", b"value")]).unwrap();
    db.checkpoint().unwrap();
    let head = db.head.clone();
    drop(db);
    let manifest = fs::read(path.join(MANIFEST)).unwrap();
    let mut damaged = manifest.clone();
    damaged[32] ^= 1;
    fs::write(path.join(MANIFEST), damaged).unwrap();
    assert_eq!(
        LiveDb::open(path).err().unwrap().kind(),
        ErrorKind::InvalidData
    );
    fs::write(path.join(MANIFEST), manifest).unwrap();
    let file = path.join(head.entries[0].name(&head.id));
    let contents = fs::read(&file).unwrap();
    let mut dirty = OpenOptions::new().write(true).open(&file).unwrap();
    dirty.seek(io::SeekFrom::Start(0)).unwrap();
    dirty.write_all(&[contents[0] ^ 1]).unwrap();
    drop(dirty);
    let mut db = LiveDb::open(path).unwrap();
    assert_eq!(db.get(b"old").unwrap_err().kind(), ErrorKind::InvalidData);
    db.commit(&[WalOp::Put(b"a", b"b")]).unwrap();
    assert_eq!(db.checkpoint().unwrap_err().kind(), ErrorKind::InvalidData);
    assert!(db.get(b"old").is_err());
    drop(db);
    fs::write(&file, &contents).unwrap();
    let mut reopened = LiveDb::open(path).unwrap();
    assert_eq!(reopened.sequence(), 2);
    assert_eq!(read_all(&mut reopened).len(), 2);
}

#[test]
fn initialization_requires_owned_names_and_exact_matching_genesis_prefixes() {
    let temp = tempdir().unwrap();
    let path = temp.path();
    fs::create_dir(path.join("creating")).unwrap();
    fs::write(path.join("wal.0"), b"user data").unwrap();
    assert!(LiveDb::create(path).is_err());
    assert!(LiveDb::open(path).is_err());
    assert_eq!(fs::read(path.join("wal.0")).unwrap(), b"user data");
    let (dir, _) = Files::lock(path, false).unwrap();
    assert_eq!(dir.creation_marker(None).unwrap(), None);
    drop(dir);

    let fresh = tempdir().unwrap();
    let (files, _) = Files::lock(fresh.path(), false).unwrap();
    let (id, budget) = files
        .creation_marker(Some(LIVE_DEFAULT_BUFFER_BYTES))
        .unwrap()
        .unwrap();
    let head = Head {
        budget,
        id,
        seq: 0,
        entries: vec![],
    };
    fs::write(fresh.path().join(head.wal_name()), b"foreign").unwrap();
    drop(files);
    assert!(LiveDb::create(fresh.path()).is_err());
    assert_eq!(
        fs::read(fresh.path().join(head.wal_name())).unwrap(),
        b"foreign"
    );
    let header = wal_header(0, head.binding());
    fs::write(fresh.path().join(head.wal_name()), &header[..27]).unwrap();
    fs::write(
        fresh.path().join(Files::name(&id, "head-next")),
        &head.encode()[..15],
    )
    .unwrap();
    let mut recovered = LiveDb::open(fresh.path()).unwrap();
    recovered.commit(&[WalOp::Put(b"ok", b"ok")]).unwrap();
    assert_eq!(recovered.get(b"ok").unwrap().unwrap(), b"ok");
}

#[test]
fn locked_database_follows_its_inode_across_rename_and_replacement() {
    let dir = tempdir().unwrap();
    let original = dir.path().join("db");
    let moved = dir.path().join("moved");
    let mut a = LiveDb::create(&original).unwrap();
    a.commit(&[WalOp::Put(b"a", b"a")]).unwrap();
    fs::rename(&original, &moved).unwrap();
    let mut b = LiveDb::create(&original).unwrap();
    b.commit(&[WalOp::Put(b"b", b"b")]).unwrap();
    a.checkpoint().unwrap();
    b.checkpoint().unwrap();
    drop((a, b));
    assert_eq!(
        read_all(&mut LiveDb::open(moved).unwrap()),
        vec![(b"a".to_vec(), b"a".to_vec())]
    );
    assert_eq!(
        read_all(&mut LiveDb::open(original).unwrap()),
        vec![(b"b".to_vec(), b"b".to_vec())]
    );
}

#[test]
fn active_wal_hardlinks_and_symlinks_are_refused_before_any_repair() {
    use std::os::unix::fs::symlink;
    let dir = tempdir().unwrap();
    let path = dir.path().join("db");
    let mut db = LiveDb::create(&path).unwrap();
    db.commit(&[WalOp::Put(b"key", b"value")]).unwrap();
    let wal = path.join(db.head.wal_name());
    drop(db);
    let rest = OpenOptions::new().append(true).open(&wal).unwrap();
    (&rest).write_all(b"KW").unwrap();
    drop(rest);
    let damaged = fs::read(&wal).unwrap();
    let alias = dir.path().join("alias");
    fs::hard_link(&wal, &alias).unwrap();
    assert!(LiveDb::open(&path).is_err());
    assert_eq!(fs::read(&alias).unwrap(), damaged);
    fs::remove_file(&wal).unwrap();
    symlink(&alias, &wal).unwrap();
    assert!(LiveDb::open(&path).is_err());
    assert_eq!(fs::read(&alias).unwrap(), damaged);
}

#[test]
fn carried_tiers_hide_deleted_and_overwritten_keys_across_reopen_and_full_compaction() {
    let dir = tempdir().unwrap();
    let mut db = LiveDb::create_with_buffer(dir.path(), LIVE_CHECKPOINT_BYTES).unwrap();
    let big = vec![9; LIVE_CHECKPOINT_BYTES as usize];
    let mut expected = BTreeMap::new();
    for i in 0..11u8 {
        let key = [i];
        let alt = [i % 3];
        let txn = [
            WalOp::Put(&key, b"row"),
            WalOp::Put(b"padding", &big),
            WalOp::Put(&alt, &key),
        ];
        db.commit(&txn).unwrap();
        expected.insert(key.to_vec(), b"row".to_vec());
        expected.insert(b"padding".to_vec(), big.clone());
        expected.insert(alt.to_vec(), key.to_vec());
        if i == 4 || i == 7 {
            db.commit(&[WalOp::Delete(&[1]), WalOp::Delete(&[])])
                .unwrap();
            expected.remove(&[1][..]);
        }
        assert_eq!(
            read_all(&mut db),
            expected.clone().into_iter().collect::<Vec<_>>()
        );
        if i == 6 {
            drop(db);
            db = LiveDb::open(dir.path()).unwrap();
        }
    }
    assert!(db.head.entries.len() > 1);
    let current = db.sequence();
    db.checkpoint().unwrap();
    assert_eq!(db.head.entries.len(), 1);
    assert_eq!(db.sequence(), current);
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 3);
    drop(db);
    assert_eq!(
        read_all(&mut LiveDb::open(dir.path()).unwrap()),
        expected.into_iter().collect::<Vec<_>>()
    );
}

#[test]
fn repeated_changes_reuse_the_delta_value_and_keep_the_original_checkpoint_charge() {
    let mut delta = Delta::new();
    let first = [1; 64];
    let key = b"cursor";
    assert_eq!(
        apply(&mut delta, &[WalOp::Put(key, &first)]),
        128 + 256 + 6 + 64
    );
    let pointer = delta[key.as_slice()].as_ref().unwrap().as_ptr();
    let charge = apply(
        &mut delta,
        &[WalOp::Put(key, b"next"), WalOp::Put(key, &[2; 64])],
    );
    assert_eq!(charge, 128 + 2 * (256 + 6) + 4 + 64);
    assert_eq!(delta[key.as_slice()].as_ref().unwrap().as_ptr(), pointer);
    assert_eq!(delta[key.as_slice()].as_deref(), Some(&[2; 64][..]));
    assert_eq!(apply(&mut delta, &[WalOp::Delete(key)]), 128 + 256 + 6);
    assert!(delta[key.as_slice()].is_none());
    apply(&mut delta, &[WalOp::Put(key, b"")]);
    assert_eq!(delta[key.as_slice()].as_deref(), Some(&b""[..]));
    assert_eq!(apply(&mut delta, &[]), 128);
}

#[test]
fn persisted_budget_controls_checkpoints_and_legacy_v2_reopens_unchanged() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("current");
    for budget in [0, LIVE_CHECKPOINT_BYTES - 1, (16 << 20) + 1] {
        assert!(LiveDb::create_with_buffer(&path, budget).is_err());
        assert!(!path.exists());
    }
    let mut db = LiveDb::create_with_buffer(&path, 2 << 20).unwrap();
    db.commit(&[WalOp::Put(b"v", &vec![7; 1 << 20])]).unwrap();
    assert_eq!(db.stats().checkpoints, 0);
    drop(db);
    let mut db = LiveDb::open(&path).unwrap();
    assert_eq!(db.checkpoint_budget(), 2 << 20);
    db.commit(&[WalOp::Put(b"v", &vec![9; 1 << 20])]).unwrap();
    assert_eq!(db.stats().checkpoints, 1);
    drop(db);
    assert_eq!(
        LiveDb::open(&path).unwrap().get(b"v").unwrap().unwrap(),
        vec![9; 1 << 20]
    );

    // A version-2 bootstrap has only a UUID marker and no budget in its manifest.
    let old = dir.path().join("v2");
    fs::create_dir(&old).unwrap();
    let uid = uuid::Uuid::new_v4();
    fs::create_dir(old.join(format!(".kasumi-init-v1-{}", uid.simple()))).unwrap();
    let mut db = LiveDb::open(&old).unwrap();
    assert_eq!(db.checkpoint_budget(), LIVE_CHECKPOINT_BYTES);
    db.commit(&[WalOp::Put(b"legacy", b"old")]).unwrap();
    db.checkpoint().unwrap();
    drop(db);
    assert_eq!(&fs::read(old.join(MANIFEST)).unwrap()[..8], b"KSLIVE02");
    assert_eq!(
        LiveDb::open(&old)
            .unwrap()
            .get(b"legacy")
            .unwrap()
            .as_deref(),
        Some(&b"old"[..])
    );
}

#[test]
fn sealed_reader_authenticates_wal_and_levels_without_changing_any_file() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("data");
    let mut writer = LiveDb::create(&path).unwrap();
    writer
        .commit(&[WalOp::Put(b"a", b"old"), WalOp::Put(b"b", b"keep")])
        .unwrap();
    writer.checkpoint().unwrap();
    writer
        .commit(&[WalOp::Delete(b"a"), WalOp::Put(b"c", b"new")])
        .unwrap();
    assert!(ReadOnlyLiveDb::open(&path).is_err());
    let seq = writer.sequence();
    let wal = path.join(writer.head.wal_name());
    // A stale file for the same database would be reclaimed by a writer reopen.
    let stale = path.join(Files::name(&writer.head.id, "wal-999-0"));
    drop(writer);
    fs::write(&stale, b"preserve me").unwrap();
    let inventory = || -> BTreeMap<_, _> {
        fs::read_dir(&path)
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (e.file_name(), fs::read(e.path()).unwrap())
            })
            .collect()
    };
    let before = inventory();
    let mut reader = ReadOnlyLiveDb::open(&path).unwrap();
    assert_eq!(reader.sequence(), seq);
    assert!(LiveDb::open(&path).is_err());
    assert_eq!(reader.get(b"a").unwrap(), None);
    assert_eq!(reader.get(b"c").unwrap().unwrap(), b"new");
    let mut rows = Vec::new();
    reader
        .visit_forward(Unbounded, Unbounded, usize::MAX, |k, v| {
            rows.push((k.to_vec(), v.to_vec()));
            Ok(())
        })
        .unwrap();
    assert_eq!(
        rows,
        [
            (b"b".to_vec(), b"keep".to_vec()),
            (b"c".to_vec(), b"new".to_vec())
        ]
    );
    drop(reader);
    assert_eq!(inventory(), before);
    let mut file = OpenOptions::new().append(true).open(&wal).unwrap();
    file.write_all(&[1, 2, 3]).unwrap();
    drop(file);
    let corrupt = inventory();
    assert!(ReadOnlyLiveDb::open(&path).is_err());
    assert_eq!(inventory(), corrupt);
}

#[test]
fn sealed_reader_preserves_a_repairable_incomplete_wal_frame() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("data");
    let mut db = LiveDb::create(&path).unwrap();
    db.commit(&[WalOp::Put(b"stable", b"previous")]).unwrap();
    let previous_sequence = db.sequence();
    let wal = path.join(db.head.wal_name());
    let previous_bytes = fs::read(&wal).unwrap();
    db.commit(&[WalOp::Put(b"stable", b"interrupted")]).unwrap();
    drop(db);

    let mut interrupted_bytes = fs::read(&wal).unwrap();
    assert!(interrupted_bytes.starts_with(&previous_bytes));
    interrupted_bytes.pop().unwrap();
    assert!(interrupted_bytes.len() > previous_bytes.len());
    fs::write(&wal, &interrupted_bytes).unwrap();
    assert_eq!(
        ReadOnlyLiveDb::open(&path).err().unwrap().to_string(),
        "incomplete WAL in read-only database"
    );
    assert_eq!(fs::read(&wal).unwrap(), interrupted_bytes);

    let mut recovered = LiveDb::open(&path).unwrap();
    assert_eq!(recovered.sequence(), previous_sequence);
    assert_eq!(
        recovered.get(b"stable").unwrap().as_deref(),
        Some(&b"previous"[..])
    );
    assert_eq!(fs::read(&wal).unwrap(), previous_bytes);
}

#[test]
fn filtered_import_reopen_compaction_and_tombstones_keep_all_current_keys() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("filtered");
    let mut db = LiveDb::create(&path).unwrap();
    let count = 8_000u16;
    let rows = (0..count).map(|n| Ok((n.to_be_bytes().to_vec(), vec![(n % 253) as u8; 600])));
    assert_eq!(
        db.load_sorted_with_filter(rows, u64::from(count)).unwrap(),
        u64::from(count)
    );
    drop(db);
    let mut db = LiveDb::open(&path).unwrap();
    for n in 0..count {
        assert_eq!(
            db.get(&n.to_be_bytes()).unwrap(),
            Some(vec![(n % 253) as u8; 600])
        );
    }
    assert_eq!(db.get(b"missing").unwrap(), None);
    db.commit(&[
        WalOp::Delete(&0u16.to_be_bytes()),
        WalOp::Put(b"", b""),
        WalOp::Put(b"later", b"value"),
    ])
    .unwrap();
    db.checkpoint().unwrap();
    drop(db);
    let mut db = ReadOnlyLiveDb::open(&path).unwrap();
    assert_eq!(db.get(&0u16.to_be_bytes()).unwrap(), None);
    assert_eq!(db.get(b"").unwrap(), Some(vec![]));
    assert_eq!(db.get(b"later").unwrap(), Some(b"value".to_vec()));
    let mut found = 0;
    db.visit_forward(Unbounded, Unbounded, usize::MAX, |_, _| {
        found += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(found, usize::from(count) + 1);
    drop(db);
    let mismatch = dir.path().join("mismatched");
    let mut broken = LiveDb::create(&mismatch).unwrap();
    assert!(
        broken
            .load_sorted_with_filter([Ok((b"k".to_vec(), vec![1]))], 2)
            .is_err()
    );
    drop(broken);
    let db = ReadOnlyLiveDb::open(&mismatch).unwrap();
    assert_eq!(db.sequence(), 0);
}
