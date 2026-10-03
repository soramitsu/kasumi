//! Sticky owner fencing and panic custody of the installed core.
//!
//! The admission fixture never latches on `owner_failed`: every assertion that
//! a failure stays sticky therefore observes the core's own fence, not a
//! failure remembered by the admission owner.

use kasumi_kv as cache_types;
#[path = "../src/cache_test.rs"]
mod cache_test;

use kasumi_kv::group::{FileKind, GroupFile, InMemoryGroup, SegmentGroupBackend};
use kasumi_kv::{
    AdmissionError, BackendCloseOutcome, BackendNativeDisposition, CacheConfig, Core, CoreError,
    CorePanic, Operation, OwnerFailed, ROOT_SLOT_BYTES, ResidentLease, RootSlot, StorageAdmission,
};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct FencingAdmission {
    fail_check: AtomicBool,
    fail_workspace: AtomicBool,
    deny_workspace: AtomicBool,
    panic_owner_failed: AtomicBool,
    owner_failed_calls: AtomicUsize,
}

impl FencingAdmission {
    fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn owner_failed_calls(&self) -> usize {
        self.owner_failed_calls.load(Ordering::Acquire)
    }

    fn heal(&self) {
        for flag in [&self.fail_check, &self.fail_workspace, &self.deny_workspace] {
            flag.store(false, Ordering::Release);
        }
    }
}

impl StorageAdmission for FencingAdmission {
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        if self.fail_check.load(Ordering::Acquire) {
            Err(OwnerFailed)
        } else {
            Ok(())
        }
    }

    fn reserve_workspace(&self, _bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
        if self.fail_workspace.load(Ordering::Acquire) {
            Err(AdmissionError::OwnerFailed)
        } else if self.deny_workspace.load(Ordering::Acquire) {
            Err(AdmissionError::CapacityDenied)
        } else {
            Ok(Box::new(()))
        }
    }

    fn reserve_growth(&self, _current: u64, _requested: u64) -> Result<(), AdmissionError> {
        Ok(())
    }

    fn settle_growth(&self, _actual: u64) -> Result<(), OwnerFailed> {
        Ok(())
    }

    fn owner_failed(&self) {
        self.owner_failed_calls.fetch_add(1, Ordering::AcqRel);
        if self.panic_owner_failed.load(Ordering::Acquire) {
            panic!("injected owner_failed panic");
        }
    }

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
impl cache_test::Provider for FencingAdmission {
    fn acquire_cache(&self, bytes: u64, first: bool) -> Result<(), kasumi_kv::AdmissionError> {
        let _ = first;
        let _ = bytes;
        if self.fail_workspace.load(Ordering::Acquire) {
            Err(AdmissionError::OwnerFailed)
        } else if self.deny_workspace.load(Ordering::Acquire) {
            Err(AdmissionError::CapacityDenied)
        } else {
            Ok(())
        }
    }
    fn release_cache(&self, bytes: u64, last: bool) {
        let _ = (bytes, last);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PanicPoint {
    /// Unwind before the ordinal effect reaches the volatile image.
    Before,
    /// Unwind after the ordinal effect; a sync also reached durable bytes.
    After,
}

#[derive(Default)]
struct Image {
    effects: usize,
    panic_at: Option<(usize, PanicPoint)>,
    panic_next_len: bool,
    panic_next_read: bool,
    close_attempts: usize,
    panic_next_close: bool,
    fail_owner_after_segment_sync: Option<Arc<FencingAdmission>>,
}

/// All group mutations are counted, including namespace and root publication.
/// The underlying group independently models volatile and durable images.
#[derive(Clone, Default)]
struct PanicBackend {
    group: InMemoryGroup,
    control: Arc<Mutex<Image>>,
}

impl PanicBackend {
    fn crash(&self) -> Self {
        Self {
            group: self.group.crash(),
            control: Arc::new(Mutex::new(Image::default())),
        }
    }

    fn image(&self) -> std::sync::MutexGuard<'_, Image> {
        // Injected panics release this lock before unwinding.
        self.control
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    fn panic_at(&self, ordinal: usize, point: PanicPoint) {
        let mut image = self.image();
        image.effects = 0;
        image.panic_at = Some((ordinal, point));
    }

    fn effects(&self) -> usize {
        self.image().effects
    }
    fn close_attempts(&self) -> usize {
        self.image().close_attempts
    }

    fn durable_image(&self) -> BTreeMap<String, Vec<u8>> {
        let durable = self.group.crash();
        let mut images = BTreeMap::new();
        for slot in [RootSlot::A, RootSlot::B] {
            let mut bytes = [0; ROOT_SLOT_BYTES];
            durable.read_root(slot, &mut bytes).unwrap();
            images.insert(format!("root-{slot:?}"), bytes.to_vec());
        }
        for name in durable.entries().unwrap() {
            let Some(file) = name.to_str().and_then(GroupFile::parse_name) else {
                continue;
            };
            images.insert(file.file_name(), durable.durable_image(file).unwrap());
        }
        images
    }

    fn durable_contains(&self, needle: &[u8]) -> bool {
        self.durable_image()
            .values()
            .any(|bytes| bytes.windows(needle.len()).any(|window| window == needle))
    }

    fn effect(&self, point: PanicPoint) -> bool {
        let mut image = self.image();
        if point == PanicPoint::Before {
            image.effects += 1;
        }
        image.panic_at == Some((image.effects, point))
    }

    fn mutate(&self, operation: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
        if self.effect(PanicPoint::Before) {
            panic!("injected effect panic");
        }
        operation()?;
        if self.effect(PanicPoint::After) {
            panic!("injected effect panic");
        }
        Ok(())
    }

    fn before_read(&self) {
        let should_panic = std::mem::take(&mut self.image().panic_next_read);
        if should_panic {
            panic!("injected read panic");
        }
    }
}

impl SegmentGroupBackend for PanicBackend {
    fn reserve_transaction(
        &self,
        plan: &kasumi_kv::TransactionSpacePlan,
    ) -> std::result::Result<(), kasumi_kv::TransactionReserveError> {
        self.group.reserve_transaction(plan)
    }
    fn finish_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
        self.group.finish_transaction(group_id, batch_seq)
    }
    fn cancel_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
        self.group.cancel_transaction(group_id, batch_seq)
    }

    fn read_root(&self, slot: RootSlot, out: &mut [u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        self.before_read();
        self.group.read_root(slot, out)
    }
    fn write_root(&self, slot: RootSlot, bytes: &[u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        self.mutate(|| self.group.write_root(slot, bytes))
    }
    fn sync_root(&self) -> io::Result<()> {
        self.mutate(|| self.group.sync_root())
    }
    fn visit_entries(&self, visitor: &mut dyn FnMut(&OsStr) -> io::Result<()>) -> io::Result<()> {
        self.group.visit_entries(visitor)
    }
    fn exists(&self, file: GroupFile) -> io::Result<bool> {
        self.group.exists(file)
    }
    fn create(&self, file: GroupFile) -> io::Result<()> {
        self.mutate(|| self.group.create(file))
    }
    fn len(&self, file: GroupFile) -> io::Result<u64> {
        let should_panic = std::mem::take(&mut self.image().panic_next_len);
        if should_panic {
            panic!("injected length panic");
        }
        self.group.len(file)
    }
    fn read(&self, file: GroupFile, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.before_read();
        self.group.read(file, at, out)
    }
    fn write(&self, file: GroupFile, at: u64, bytes: &[u8]) -> io::Result<()> {
        self.mutate(|| self.group.write(file, at, bytes))
    }
    fn set_len(&self, file: GroupFile, length: u64) -> io::Result<()> {
        self.mutate(|| self.group.set_len(file, length))
    }
    fn sync(&self, file: GroupFile) -> io::Result<()> {
        self.mutate(|| self.group.sync(file))?;
        if file.kind == FileKind::Segment {
            let admission = self.image().fail_owner_after_segment_sync.take();
            if let Some(admission) = admission {
                admission.fail_check.store(true, Ordering::Release);
            }
        }
        Ok(())
    }
    fn unlink(&self, file: GroupFile) -> io::Result<()> {
        self.mutate(|| self.group.unlink(file))
    }
    fn sync_names(&self) -> io::Result<()> {
        self.mutate(|| self.group.sync_names())
    }
    fn close(&self) -> BackendCloseOutcome {
        let mut image = self.image();
        image.close_attempts += 1;
        let should_panic = std::mem::take(&mut image.panic_next_close);
        drop(image);
        if should_panic {
            panic!("injected close panic");
        }
        self.group.close()
    }
}

const GROUP: [u8; 16] = [61; 16];
const OLD: &[u8] = b"old-acknowledged";
const NEW: &[u8] = b"new-unacknowledged";

fn baseline(admission: &Arc<FencingAdmission>) -> (Core, PanicBackend) {
    let backend = PanicBackend::default();
    let core = Core::create_with_backend(
        backend.clone(),
        admission.clone(),
        GROUP,
        CacheConfig::default(),
    )
    .unwrap();
    core.commit(&[
        Operation::create_table("items"),
        Operation::put("items", b"key", OLD),
        Operation::put("items", b"other", b"stable"),
    ])
    .unwrap();
    (core, backend)
}

fn churned(admission: &Arc<FencingAdmission>) -> (Core, PanicBackend) {
    let (core, backend) = baseline(admission);
    for value in [b"one".as_slice(), b"two", b"three"] {
        core.commit(&[Operation::put("items", b"scratch", value)])
            .unwrap();
    }
    core.commit(&[Operation::delete("items", b"scratch")])
        .unwrap();
    (core, backend)
}

fn read(core: &Core, key: &[u8]) -> Option<Vec<u8>> {
    let view = core.snapshot().unwrap();
    core.get_admitted(&view, "items", key, 64)
        .unwrap()
        .map(|value| value.as_bytes().to_vec())
}

fn reopen(backend: &PanicBackend) -> Core {
    Core::open_with_backend(
        backend.crash(),
        FencingAdmission::new(),
        GROUP,
        CacheConfig::default(),
    )
    .unwrap()
}

fn payload(panic: &CorePanic) -> Option<&'static str> {
    panic.with_payload(|payload| payload.downcast_ref::<&str>().copied())
}

fn unknown_commit_payload(error: &CoreError) -> Option<&'static str> {
    let CoreError::UnknownCommit(error) = error else {
        return None;
    };
    payload(error.get_ref()?.downcast_ref::<CorePanic>()?)
}

/// Every installed operation of a fenced, still open core reports
/// `OwnerFailed` without another admission callback or backend effect.
fn assert_sticky(core: &Core, admission: &FencingAdmission, backend: &PanicBackend) {
    let calls = admission.owner_failed_calls();
    let effects = backend.effects();
    assert!(core.is_fenced());
    assert!(matches!(core.snapshot(), Err(CoreError::OwnerFailed)));
    assert!(matches!(core.generation(), Err(CoreError::OwnerFailed)));
    assert!(matches!(
        core.committed_position(),
        Err(CoreError::OwnerFailed)
    ));
    assert!(matches!(core.compact(), Err(CoreError::OwnerFailed)));
    assert!(matches!(
        core.commit(&[Operation::put("items", b"key", b"retry")]),
        Err(CoreError::OwnerFailed)
    ));
    assert_eq!(admission.owner_failed_calls(), calls);
    assert_eq!(backend.effects(), effects);
}

fn close_drains(core: &Core) {
    let outcome = core.close();
    assert_eq!(
        outcome.native_disposition(),
        BackendNativeDisposition::Drained
    );
    outcome.into_result().unwrap();
    assert!(matches!(core.snapshot(), Err(CoreError::Closed)));
}

#[test]
fn failed_pre_commit_owner_calls_fence_once_without_any_backend_effect() {
    type Inject = fn(&FencingAdmission);
    let cases: [(&str, Inject); 2] = [
        ("check_owner", |admission| {
            admission.fail_check.store(true, Ordering::Release)
        }),
        ("reserve_workspace", |admission| {
            admission.fail_workspace.store(true, Ordering::Release)
        }),
    ];
    for (site, inject) in cases {
        let admission = FencingAdmission::new();
        let (core, backend) = baseline(&admission);
        let generation = core.generation().unwrap();
        let end = core.committed_position().unwrap();
        let durable = backend.durable_image();
        backend.panic_at(usize::MAX, PanicPoint::Before);

        inject(&admission);
        let result = core.commit(&[Operation::put("items", b"key", NEW)]);
        assert!(
            matches!(result, Err(CoreError::OwnerFailed)),
            "{site}: {result:?}"
        );
        assert_eq!(backend.effects(), 0, "{site} reached the backend");
        assert_eq!(admission.owner_failed_calls(), 1, "{site}");

        // Negative control: the admission owner has recovered, but only
        // close and a strict reopen may clear this instance's fence.
        admission.heal();
        assert_sticky(&core, &admission, &backend);
        close_drains(&core);
        assert_eq!(admission.owner_failed_calls(), 1, "{site}");

        assert_eq!(backend.durable_image(), durable);
        let reopened = reopen(&backend);
        assert!(!reopened.is_fenced());
        assert_eq!(reopened.generation().unwrap(), generation, "{site}");
        assert_eq!(reopened.committed_position().unwrap(), end, "{site}");
        assert_eq!(read(&reopened, b"key"), Some(OLD.to_vec()), "{site}");
    }
}

#[test]
fn failed_read_owner_check_is_sticky_for_every_snapshot_and_writer() {
    let admission = FencingAdmission::new();
    let (core, backend) = baseline(&admission);
    let view = core.snapshot().unwrap();
    admission.fail_check.store(true, Ordering::Release);
    assert!(matches!(
        view.table_exists("items"),
        Err(CoreError::OwnerFailed)
    ));
    assert_eq!(admission.owner_failed_calls(), 1);
    admission.heal();
    assert!(matches!(
        view.table_exists("items"),
        Err(CoreError::OwnerFailed)
    ));
    assert!(matches!(
        view.next_key_admitted("items", b"", None),
        Err(CoreError::OwnerFailed)
    ));
    assert!(matches!(
        core.get_admitted(&view, "items", b"key", 64),
        Err(CoreError::OwnerFailed)
    ));
    assert!(matches!(
        core.key_exists(&view, "items", b"key"),
        Err(CoreError::OwnerFailed)
    ));
    assert!(matches!(
        core.prefix_exists(&view, "items", b"k"),
        Err(CoreError::OwnerFailed)
    ));
    assert!(matches!(
        core.next_admitted(&view, "items", b"", None, 64),
        Err(CoreError::OwnerFailed)
    ));
    assert_sticky(&core, &admission, &backend);
    drop(view);
    close_drains(&core);
    assert_eq!(read(&reopen(&backend), b"key"), Some(OLD.to_vec()));
}

#[test]
fn unfenced_capacity_denial_has_no_effect_and_leaves_the_owner_usable() {
    let admission = FencingAdmission::new();
    let (core, backend) = baseline(&admission);
    let generation = core.generation().unwrap();
    backend.panic_at(usize::MAX, PanicPoint::Before);
    admission.deny_workspace.store(true, Ordering::Release);
    assert!(matches!(
        core.commit(&[Operation::put("items", b"key", NEW)]),
        Err(CoreError::CapacityDenied)
    ));
    // An unfenced error is the positive no-effect report.
    assert!(!core.is_fenced());
    assert_eq!(backend.effects(), 0);
    assert_eq!(admission.owner_failed_calls(), 0);
    assert_eq!(core.generation().unwrap(), generation);
    admission.heal();
    assert_eq!(read(&core, b"key"), Some(OLD.to_vec()));
    core.commit(&[Operation::put("items", b"key", NEW)])
        .unwrap();
    assert_eq!(read(&core, b"key"), Some(NEW.to_vec()));
    close_drains(&core);
    assert_eq!(read(&reopen(&backend), b"key"), Some(NEW.to_vec()));
}

#[test]
fn owner_failure_after_prepare_fences_and_restart_truncates_the_unpublished_records() {
    let admission = FencingAdmission::new();
    let (core, backend) = baseline(&admission);
    let generation = core.generation().unwrap();
    let end = core.committed_position().unwrap().unwrap();
    backend.image().fail_owner_after_segment_sync = Some(admission.clone());
    let error = core
        .commit(&[Operation::put("items", b"key", NEW)])
        .unwrap_err();
    // The checked group observes expiry immediately after the successful sync.
    // It preserves that owner-failure cause through the backend's I/O boundary.
    assert!(matches!(error, CoreError::Io(ref error)
        if error.get_ref().is_some_and(|cause| cause.is::<OwnerFailed>())));
    assert_eq!(admission.owner_failed_calls(), 1);
    admission.heal();
    assert_sticky(&core, &admission, &backend);

    // The synchronized operation records are durable past the selected commit.
    assert!(
        backend
            .group
            .durable_len(GroupFile::segment(end.segment_id))
            .unwrap() as u64
            > end.offset
    );
    assert!(backend.durable_contains(NEW));
    close_drains(&core);

    let restarted = backend.crash();
    let reopened = Core::open_with_backend(
        restarted.clone(),
        FencingAdmission::new(),
        GROUP,
        CacheConfig::default(),
    )
    .unwrap();
    assert_eq!(reopened.generation().unwrap(), generation);
    assert_eq!(reopened.committed_position().unwrap(), Some(end));
    assert_eq!(read(&reopened, b"key"), Some(OLD.to_vec()));
    // Reopen durably truncated the unpublished tail before exposing the core.
    assert_eq!(
        restarted
            .group
            .durable_len(GroupFile::segment(end.segment_id))
            .unwrap() as u64,
        end.offset
    );
    assert!(!restarted.durable_contains(NEW));
    reopened
        .commit(&[Operation::put("items", b"key", b"after-restart")])
        .unwrap();
    close_drains(&reopened);
    assert_eq!(
        read(&reopen(&restarted), b"key"),
        Some(b"after-restart".to_vec())
    );
}

#[test]
fn panic_at_every_commit_effect_fences_once_and_reopens_a_whole_generation() {
    let counting_admission = FencingAdmission::new();
    let (counting, counting_backend) = baseline(&counting_admission);
    counting_backend.panic_at(usize::MAX, PanicPoint::Before);
    counting
        .commit(&[
            Operation::put("items", b"key", NEW),
            Operation::delete("items", b"other"),
        ])
        .unwrap();
    let effect_count = counting_backend.effects();
    assert!(
        effect_count > 6,
        "expected operation, directory, commit and root effects"
    );

    for ordinal in 1..=effect_count {
        for point in [PanicPoint::Before, PanicPoint::After] {
            let admission = FencingAdmission::new();
            let (core, backend) = baseline(&admission);
            backend.panic_at(ordinal, point);
            let error = core
                .commit(&[
                    Operation::put("items", b"key", NEW),
                    Operation::delete("items", b"other"),
                ])
                .unwrap_err();
            // An unwinding commit never claims rollback; the original
            // payload stays inspectable behind the unknown outcome.
            assert_eq!(
                unknown_commit_payload(&error),
                Some("injected effect panic"),
                "effect {ordinal}: {error:?}"
            );
            assert_eq!(admission.owner_failed_calls(), 1, "effect {ordinal}");
            assert_sticky(&core, &admission, &backend);
            close_drains(&core);
            assert_eq!(admission.owner_failed_calls(), 1, "effect {ordinal}");

            let reopened = reopen(&backend);
            let observed = (read(&reopened, b"key"), read(&reopened, b"other"));
            let old = (Some(OLD.to_vec()), Some(b"stable".to_vec()));
            let new = (Some(NEW.to_vec()), None);
            assert!(
                observed == old || observed == new,
                "partial batch after effect {ordinal}: {observed:?}"
            );
        }
    }
}

#[test]
fn panic_at_every_compaction_effect_fences_once_and_reopens_every_live_value() {
    let counting_admission = FencingAdmission::new();
    let (counting, counting_backend) = churned(&counting_admission);
    counting_backend.panic_at(usize::MAX, PanicPoint::Before);
    counting.compact().unwrap();
    let effect_count = counting_backend.effects();
    assert!(
        effect_count > 6,
        "expected segment relocation, directory and retirement effects"
    );

    for ordinal in 1..=effect_count {
        for point in [PanicPoint::Before, PanicPoint::After] {
            let admission = FencingAdmission::new();
            let (core, backend) = churned(&admission);
            backend.panic_at(ordinal, point);
            let error = core.compact().unwrap_err();
            assert_eq!(
                match &error {
                    CoreError::Panicked(panic) => payload(panic),
                    _ => unknown_commit_payload(&error),
                },
                Some("injected effect panic"),
                "effect {ordinal}: compaction unwind must be retained: {error:?}"
            );
            assert_eq!(admission.owner_failed_calls(), 1, "effect {ordinal}");
            assert_sticky(&core, &admission, &backend);
            close_drains(&core);

            let reopened = Core::open_with_backend(
                backend.crash(),
                FencingAdmission::new(),
                GROUP,
                CacheConfig::default(),
            )
            .unwrap_or_else(|error| panic!("reopen after effect {ordinal}: {error}"));
            assert_eq!(read(&reopened, b"key"), Some(OLD.to_vec()));
            assert_eq!(read(&reopened, b"other"), Some(b"stable".to_vec()));
            assert_eq!(read(&reopened, b"scratch"), None);
        }
    }
}

#[test]
fn panicking_length_and_value_read_fence_once_and_keep_their_payloads() {
    let admission = FencingAdmission::new();
    let (core, backend) = baseline(&admission);
    backend.image().panic_next_len = true;
    let error = core
        .commit(&[Operation::put("items", b"key", NEW)])
        .unwrap_err();
    assert_eq!(
        unknown_commit_payload(&error),
        Some("injected length panic")
    );
    assert_eq!(admission.owner_failed_calls(), 1);
    assert_sticky(&core, &admission, &backend);
    close_drains(&core);
    assert_eq!(read(&reopen(&backend), b"key"), Some(OLD.to_vec()));

    let admission = FencingAdmission::new();
    let (core, backend) = baseline(&admission);
    let view = core.snapshot().unwrap();
    backend.image().panic_next_read = true;
    let Err(CoreError::Panicked(panic)) = core.get_admitted(&view, "items", b"key", 64) else {
        panic!("an unwinding value read must be retained and fenced");
    };
    assert_eq!(payload(&panic), Some("injected read panic"));
    assert_eq!(admission.owner_failed_calls(), 1);
    assert!(matches!(
        core.get_admitted(&view, "items", b"key", 64),
        Err(CoreError::OwnerFailed)
    ));
    assert!(matches!(
        view.table_exists("items"),
        Err(CoreError::OwnerFailed)
    ));
    drop(view);
    assert_sticky(&core, &admission, &backend);
    close_drains(&core);
    assert_eq!(read(&reopen(&backend), b"key"), Some(OLD.to_vec()));
}

#[test]
fn unwinding_owner_failed_callback_cannot_unlatch_the_fence() {
    let admission = FencingAdmission::new();
    let (core, backend) = baseline(&admission);
    admission.panic_owner_failed.store(true, Ordering::Release);
    admission.fail_check.store(true, Ordering::Release);
    assert!(matches!(
        core.commit(&[Operation::put("items", b"key", NEW)]),
        Err(CoreError::OwnerFailed)
    ));
    assert_eq!(admission.owner_failed_calls(), 1);
    assert_eq!(
        core.fence_panic().and_then(payload),
        Some("injected owner_failed panic")
    );
    admission.heal();
    assert_sticky(&core, &admission, &backend);
    close_drains(&core);
    assert_eq!(read(&reopen(&backend), b"key"), Some(OLD.to_vec()));
}

#[test]
fn poisoned_close_is_fenced_and_never_replays_native_close() {
    let admission = FencingAdmission::new();
    let (core, backend) = baseline(&admission);
    backend.image().panic_next_close = true;
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| core.close()));
    assert!(unwound.is_err());
    assert_eq!(backend.close_attempts(), 1);
    // The unwound close poisoned the state lock after entering native close.
    let repeat = core.close();
    assert_eq!(
        repeat.native_disposition(),
        BackendNativeDisposition::Retained
    );
    assert!(repeat.into_result().is_err());
    assert_eq!(backend.close_attempts(), 1);
    assert!(core.is_fenced());
    assert_eq!(admission.owner_failed_calls(), 1);
    assert!(matches!(core.snapshot(), Err(CoreError::Closed)));
    assert_eq!(read(&reopen(&backend), b"key"), Some(OLD.to_vec()));
}
