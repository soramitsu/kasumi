use super::*;
use crate::group::{ExistingFileSpace, FileSpaceRange, TransactionSpacePlan};
use crate::segment::ReplayStart;

const GROUP: [u8; 16] = *b"space-plan-root1";

fn empty_range() -> FileSpaceRange {
    FileSpaceRange {
        first_id: 0,
        count: 0,
        full_len: 0,
        minimum_len: 0,
        last_len: 0,
        total_len: 0,
    }
}
fn plan(root: &Superblock) -> TransactionSpacePlan {
    TransactionSpacePlan {
        group_id: *root.group_id(),
        root_generation: root.generation(),
        batch_seq: root
            .directory()
            .map_or(1, |commit| commit.start.batch_seq + 1),
        segment: None,
        directory: None,
        new_segments: empty_range(),
        new_directories: empty_range(),
    }
}
fn verify(plan: &TransactionSpacePlan, root: &Superblock) -> Result<(), CoreError> {
    let image = root.encode()?;
    validate_transaction_space_roots(plan, &image, &image)
}

#[test]
fn transaction_space_root_validation_uses_canonical_selection_and_exact_generation() {
    let initial = Superblock::genesis(GROUP).initialized().unwrap();
    let mut accepted = plan(&initial);
    verify(&accepted, &initial).unwrap();
    accepted.group_id[0] ^= 1;
    assert!(verify(&accepted, &initial).is_err());
    accepted = plan(&initial);
    accepted.root_generation += 1;
    assert!(verify(&accepted, &initial).is_err());
    accepted = plan(&initial);
    for sequence in [0, u64::MAX] {
        accepted.batch_seq = sequence;
        assert!(verify(&accepted, &initial).is_err());
    }
    let (pending, id) = initial.reserve_segment(None).unwrap();
    assert!(verify(&plan(&pending), &pending).is_err());
    let confirmed = pending.confirm_segment(id).unwrap();
    let mut current = plan(&confirmed);
    current.segment = Some(ExistingFileSpace {
        file: GroupFile::segment(id),
        initial_len: 64,
        maximum_len: 128,
    });
    current.new_segments = FileSpaceRange {
        first_id: id + 1,
        count: 1,
        full_len: 512,
        minimum_len: crate::segment::SEGMENT_HEADER_BYTES,
        last_len: 400,
        total_len: 400,
    };
    verify(&current, &confirmed).unwrap();
    current.new_segments.first_id += 1;
    assert!(verify(&current, &confirmed).is_err());
    current.new_segments = empty_range();
    current.segment.as_mut().unwrap().file.id += 1;
    assert!(verify(&current, &confirmed).is_err());
    current.segment = None;
    let (pending, _) = confirmed.reserve_directory().unwrap();
    assert!(verify(&plan(&pending), &pending).is_err());
    let a = confirmed.encode().unwrap();
    let b = Superblock::genesis([9; 16])
        .initialized()
        .unwrap()
        .encode()
        .unwrap();
    assert!(validate_transaction_space_roots(&current, &a, &b).is_err());
    assert!(
        validate_transaction_space_roots(
            &plan(&initial),
            &[0; ROOT_SLOT_BYTES],
            &[0; ROOT_SLOT_BYTES]
        )
        .is_err()
    );
}

#[test]
fn transaction_space_root_sequence_can_skip_aborted_attempts_but_not_committed_identity() {
    use crate::segment::test_support::Log;
    let mut log = Log::new(crate::segment::SEGMENT_BYTES);
    let committed = log
        .commit(&[crate::Operation::CreateTable { table: "t".into() }])
        .unwrap();
    let selected = log
        .root
        .install_directory(DirectoryCommit {
            root: committed.directory_root,
            start: ReplayStart {
                position: committed.end,
                batch_seq: committed.batch_seq,
                chain: committed.chain,
            },
        })
        .unwrap();
    let mut next = plan(&selected);
    verify(&next, &selected).unwrap();
    next.batch_seq = committed.batch_seq;
    assert!(verify(&next, &selected).is_err());
    next.batch_seq = committed.batch_seq + 7;
    verify(&next, &selected).unwrap();
    next.directory = Some(ExistingFileSpace {
        file: GroupFile::directory(1),
        initial_len: 4096,
        maximum_len: 4096 + 16384,
    });
    assert!(verify(&next, &selected).is_err());
}

#[test]
fn transaction_space_root_rejects_caller_supplied_truncated_native_minima() {
    let root = Superblock::genesis(GROUP).initialized().unwrap();
    for kind in [FileKind::Segment, FileKind::Directory] {
        let required = match kind {
            FileKind::Segment => crate::segment::SEGMENT_HEADER_BYTES,
            FileKind::Directory => crate::arena::HEADER_BYTES as u64,
            FileKind::Checkpoint => unreachable!(),
        };
        let mut request = plan(&root);
        let range = FileSpaceRange {
            first_id: 1,
            count: 1,
            minimum_len: 1,
            full_len: required,
            last_len: required,
            total_len: required,
        };
        match kind {
            FileKind::Segment => request.new_segments = range,
            FileKind::Directory => request.new_directories = range,
            FileKind::Checkpoint => unreachable!(),
        }
        request.validate().unwrap();
        assert!(verify(&request, &root).is_err());
        match kind {
            FileKind::Segment => request.new_segments.minimum_len = required,
            FileKind::Directory => request.new_directories.minimum_len = required,
            FileKind::Checkpoint => unreachable!(),
        }
        verify(&request, &root).unwrap();
        let confirmed = match kind {
            FileKind::Segment => root
                .reserve_segment(None)
                .unwrap()
                .0
                .confirm_segment(1)
                .unwrap(),
            FileKind::Directory => root
                .reserve_directory()
                .unwrap()
                .0
                .confirm_directory(1)
                .unwrap(),
            FileKind::Checkpoint => unreachable!(),
        };
        let mut existing = plan(&confirmed);
        let tail = ExistingFileSpace {
            file: GroupFile { kind, id: 1 },
            initial_len: 1,
            maximum_len: required,
        };
        match kind {
            FileKind::Segment => existing.segment = Some(tail),
            FileKind::Directory => existing.directory = Some(tail),
            FileKind::Checkpoint => unreachable!(),
        }
        existing.validate().unwrap();
        assert!(verify(&existing, &confirmed).is_err());
    }
}
