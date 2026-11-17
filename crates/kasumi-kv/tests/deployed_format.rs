//! Native KV groups written by the deployed builds (`tests/deployed-format`).
//! Their root slots, garbage records, segment and arena headers and Fixed
//! directory pages keep the layout pinned in `support::layout`, and the
//! current code opens them, finishes their interrupted reclamation, compacts,
//! writes and reopens without changing a row.
use kasumi_kv as cache_types;
#[path = "../src/cache_test.rs"]
mod cache_test;
#[path = "../../../tests/deployed-format/support.rs"]
mod support;

use kasumi_kv::group::InMemoryGroup;
use kasumi_kv::{
    AdmissionError, CacheConfig, Core, GroupFile, MaintenanceBudget, MaintenancePolicy, Operation,
    OwnerFailed, ROOT_SLOT_BYTES, ResidentLease, RootSlot, ScanDirection, SegmentGroupBackend,
    StorageAdmission, StorageCompactionPhase,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ops::Bound;
use std::sync::Arc;
use support::{FIRST_CLEAN, FIRST_KILLED, FIXTURES, Fixtures, SECOND_CLEAN, layout};

const NODE: &str = "data/node.kv";
/// The store's two tables; a node group holds nothing else.
const TABLES: [&str; 2] = ["wrapped_keys_v1", "encrypted_records_v1"];
const MAX_VALUE: usize = 64 << 20;

#[derive(Default)]
struct UnlimitedAdmission;

impl StorageAdmission for UnlimitedAdmission {
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        Ok(())
    }
    fn reserve_workspace(&self, _bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
        Ok(Box::new(()))
    }
    fn reserve_growth(&self, _current: u64, _requested: u64) -> Result<(), AdmissionError> {
        Ok(())
    }
    fn settle_growth(&self, _actual: u64) -> Result<(), OwnerFailed> {
        Ok(())
    }
    fn owner_failed(&self) {}
    fn quote_cache_memory(
        &self,
        bytes: u64,
    ) -> Result<kasumi_kv::CacheMemoryQuote, kasumi_kv::AdmissionError> {
        cache_test::quote::<Self>(bytes)
    }
    fn reserve_cache_memory(
        self: std::sync::Arc<Self>,
        bytes: u64,
    ) -> Result<kasumi_kv::CacheMemoryLease, kasumi_kv::AdmissionError> {
        cache_test::reserve(self, bytes)
    }
}
impl cache_test::Provider for UnlimitedAdmission {
    fn acquire_cache(&self, _bytes: u64, _first: bool) -> Result<(), kasumi_kv::AdmissionError> {
        Ok(())
    }
    fn release_cache(&self, _bytes: u64, _last: bool) {}
}

fn root_file<'fixtures>(fixtures: &'fixtures Fixtures, fixture: &str) -> &'fixtures [u8] {
    fixtures.file(fixture, &format!("{NODE}/{}", layout::ROOT_FILE_NAME))
}

fn node_store_id<'fixtures>(fixtures: &'fixtures Fixtures, fixture: &str) -> &'fixtures [u8] {
    &root_file(fixtures, fixture)[layout::NODE_STORE_ID_AT]
}

/// The fixture's data files by name, with their envelopes removed.
fn data_files<'fixtures>(
    fixtures: &'fixtures Fixtures,
    fixture: &str,
) -> Vec<(String, &'fixtures [u8])> {
    fixtures
        .names(fixture, NODE)
        .into_iter()
        .filter(|name| name != layout::ROOT_FILE_NAME)
        .map(|name| {
            let file = fixtures.file(fixture, &format!("{NODE}/{name}"));
            let payload = &file[layout::ENVELOPE_BYTES.min(file.len())..];
            (name, payload)
        })
        .collect()
}

/// The group as the store's backend presents it to the native KV.
fn group(fixtures: &Fixtures, fixture: &str) -> InMemoryGroup {
    let group = InMemoryGroup::new();
    let slots = &root_file(fixtures, fixture)[layout::ENVELOPE_BYTES..];
    for (slot, bytes) in [RootSlot::A, RootSlot::B]
        .into_iter()
        .zip(slots.chunks(ROOT_SLOT_BYTES))
    {
        group.with_durable_root(slot, |durable| durable.copy_from_slice(bytes));
    }
    for (name, payload) in data_files(fixtures, fixture) {
        let file = GroupFile::parse_name(&name).expect("a canonical group file name");
        group.insert_foreign(file, payload.to_vec());
    }
    group
}

fn open(group: &InMemoryGroup, id: &[u8]) -> Core {
    match Core::open_with_backend(
        group.clone(),
        Arc::new(UnlimitedAdmission),
        id.try_into().unwrap(),
        CacheConfig::default(),
    ) {
        Ok(core) => core,
        Err(failure) => panic!(
            "the deployed group did not open: {:?}",
            failure.original_error()
        ),
    }
}

/// Every row of both tables: its table and key, and a digest of its value.
fn rows(core: &Core) -> BTreeMap<(&'static str, Vec<u8>), [u8; 32]> {
    let view = core.snapshot().unwrap();
    let mut rows = BTreeMap::new();
    for table in TABLES {
        assert!(view.table_exists(table).unwrap(), "{table}");
        let mut after: Option<Vec<u8>> = None;
        while let Some((key, value)) = view
            .seek_admitted(
                table,
                after.as_deref().map_or(Bound::Unbounded, Bound::Excluded),
                Bound::Unbounded,
                ScanDirection::Ascending,
                MAX_VALUE,
            )
            .unwrap()
        {
            after = Some(key.as_bytes().to_vec());
            rows.insert(
                (table, key.as_bytes().to_vec()),
                Sha256::digest(value.as_bytes()).into(),
            );
        }
    }
    rows
}

const STEP: MaintenanceBudget = MaintenanceBudget {
    units: 64,
    mutations: 1,
};

/// Finish whatever cycle the group reopened in, then run one complete cycle.
fn compact(core: &Core) {
    let idle =
        |core: &Core| core.maintenance_status().unwrap().phase == StorageCompactionPhase::Idle;
    for _ in 0..1_000_000 {
        if idle(core) {
            break;
        }
        assert_eq!(core.run_maintenance(STEP).unwrap().deferred, None);
    }
    assert!(idle(core), "the reopened cycle did not finish");
    let start = core.maintenance_status().unwrap().cycle;
    core.request_compaction().unwrap();
    for _ in 0..1_000_000 {
        assert_eq!(core.run_maintenance(STEP).unwrap().deferred, None);
        let status = core.maintenance_status().unwrap();
        if status.phase == StorageCompactionPhase::Idle && status.cycle > start {
            return;
        }
    }
    panic!("a requested compaction cycle did not finish");
}

#[test]
fn root_slots_keep_the_deployed_layout_and_garbage_tags() {
    let fixtures = Fixtures::load();
    for fixture in FIXTURES {
        let root = root_file(&fixtures, fixture);
        let garbage = layout::check_root_file(root);
        let last_segment = layout::le_u64(&root[layout::ENVELOPE_BYTES..], layout::LAST_SEGMENT_AT);
        let names: Vec<_> = data_files(&fixtures, fixture)
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        for (tag, id) in garbage.iter().flatten() {
            // The newest segment holds the log tail and is never garbage.
            assert!(
                *tag == layout::DIRECTORY_GARBAGE_TAG || *id < last_segment,
                "{fixture} lists its newest segment {id} as garbage"
            );
        }
        match fixture {
            // Stopped cleanly after its cycles: nothing is owed an unlink.
            FIRST_CLEAN | SECOND_CLEAN => assert!(garbage.iter().all(Vec::is_empty), "{fixture}"),
            // Killed while a published root listed files not yet forgotten.
            FIRST_KILLED => assert!(garbage.iter().any(|slot| !slot.is_empty()), "{fixture}"),
            _ => unreachable!(),
        }
        // The first 64 MiB segment was sealed and evacuated by the build that
        // wrote it, which relocated every value it kept, and is gone: unlinked,
        // or in the killed copy listed as garbage and left out of the copy as
        // after its unlink.
        assert!(last_segment > 1, "{fixture}");
        assert!(
            !names.contains(&GroupFile::segment(1).file_name()),
            "{fixture}"
        );
    }
}

#[test]
fn segments_and_fixed_directory_arenas_keep_the_deployed_headers() {
    let fixtures = Fixtures::load();
    for fixture in FIXTURES {
        let id = node_store_id(&fixtures, fixture);
        let (mut segments, mut pages) = (0, 0);
        for (name, payload) in data_files(&fixtures, fixture) {
            pages += layout::check_data_file(&name, payload, id);
            segments += usize::from(name.ends_with(".kvseg"));
        }
        assert!(segments >= 1 && pages >= 1, "{fixture}");
    }
}

#[test]
fn deployed_groups_open_compact_write_and_reopen_with_the_same_rows() {
    let fixtures = Fixtures::load();
    for fixture in FIXTURES {
        let id = node_store_id(&fixtures, fixture);
        let group = group(&fixtures, fixture);
        let core = open(&group, id);
        let original = rows(&core);
        assert!(
            original.len() > 100,
            "{fixture} holds {} rows",
            original.len()
        );

        // A cycle that starts at once and evacuates every old file: the rows
        // are then read from pages and segments this build wrote.
        core.configure_maintenance(MaintenancePolicy {
            growth_percent: 101,
            slack_bytes: 0,
            slack_files: 0,
            ..MaintenancePolicy::default()
        })
        .unwrap();
        let before = group.entries().unwrap();
        compact(&core);
        assert!(rows(&core) == original, "{fixture} after compaction");
        assert_eq!(core.maintenance_status().unwrap().garbage_files, 0);
        assert_ne!(
            group.entries().unwrap(),
            before,
            "{fixture} kept every file"
        );

        core.commit(&[Operation::create_table("deployed_format_probe")])
            .unwrap();
        core.commit(&[
            Operation::put("deployed_format_probe", b"written", b"by the current build"),
            Operation::put(TABLES[1], b"deployed-format-probe", b"beside deployed rows"),
        ])
        .unwrap();
        core.commit(&[Operation::delete(TABLES[1], b"deployed-format-probe")])
            .unwrap();
        assert!(rows(&core) == original, "{fixture} after writes");
        core.close().into_result().unwrap();

        // The durable image only, as after a power loss: the root keeps the
        // deployed format and the Fixed tag, and every arena this build
        // wrote is Fixed pages.
        let crashed = group.crash();
        for slot in [RootSlot::A, RootSlot::B] {
            let mut bytes = [0; ROOT_SLOT_BYTES];
            crashed.read_root(slot, &mut bytes).unwrap();
            assert!(layout::check_root_slot(&bytes, id).is_empty(), "{fixture}");
        }
        let mut pages = 0;
        for name in crashed.entries().unwrap() {
            let name = name.to_str().unwrap();
            if name == layout::ROOT_FILE_NAME {
                continue;
            }
            let file = GroupFile::parse_name(name).unwrap();
            let payload = crashed.durable_image(file).unwrap();
            pages += layout::check_data_file(name, &payload, id);
        }
        assert!(pages >= 1, "{fixture}");
        let reopened = open(&crashed, id);
        assert!(rows(&reopened) == original, "{fixture} after reopen");
        let view = reopened.snapshot().unwrap();
        assert_eq!(
            reopened
                .get_admitted(&view, "deployed_format_probe", b"written", 64)
                .unwrap()
                .unwrap()
                .as_bytes(),
            b"by the current build"
        );
        drop(view);
        reopened.close().into_result().unwrap();
    }
}

#[test]
fn the_killed_group_opens_and_the_clean_stop_after_it_kept_its_keys() {
    let fixtures = Fixtures::load();
    let read = |fixture: &str| {
        let core = open(
            &group(&fixtures, fixture),
            node_store_id(&fixtures, fixture),
        );
        let rows = rows(&core);
        core.close().into_result().unwrap();
        rows
    };
    let (killed, clean) = (read(FIRST_KILLED), read(FIRST_CLEAN));
    // The clean copy is the same installation after the first build
    // recovered from the kill and stopped cleanly. No wrapped key is ever
    // deleted, so each one the killed root reached is still there.
    let wrapped = killed
        .iter()
        .filter(|((table, _), _)| *table == TABLES[0])
        .collect::<Vec<_>>();
    assert!(!wrapped.is_empty());
    assert!(
        wrapped
            .into_iter()
            .all(|(key, value)| clean.get(key) == Some(value))
    );
    // The files the killed root listed were unlinked by that recovery.
    let listed = layout::check_root_file(root_file(&fixtures, FIRST_KILLED));
    let names: Vec<_> = data_files(&fixtures, FIRST_CLEAN)
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    for (tag, id) in listed.iter().flatten() {
        let name = match *tag {
            layout::SEGMENT_GARBAGE_TAG => GroupFile::segment(*id),
            _ => GroupFile::directory(*id),
        }
        .file_name();
        assert!(!names.contains(&name), "{name} survived the recovery");
    }
}

/// Pack the copies written by `scripts/deployed_format_fixture.py`:
/// `KASUMI_DEPLOYED_FORMAT_RAW=<its --out> cargo test -p kasumi-kv --test
/// deployed_format -- --ignored pack`.
#[test]
#[ignore = "rewrites tests/deployed-format from a generator run"]
fn pack() {
    let raw = std::env::var_os("KASUMI_DEPLOYED_FORMAT_RAW")
        .expect("KASUMI_DEPLOYED_FORMAT_RAW names the generator's output directory");
    support::pack(std::path::Path::new(&raw)).unwrap();
}
