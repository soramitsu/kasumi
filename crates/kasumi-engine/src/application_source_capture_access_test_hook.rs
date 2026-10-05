//! One real queued capture denied only after its original reader has begun.
use super::Workspace;
use kasumi_raft::SelectionFailure;
use std::{cell::Cell, marker::PhantomData, rc::Rc};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Mode {
    Bare,
    OwningContext,
}
#[derive(Clone, Copy, Debug)]
pub(super) struct Observation {
    pub reader: Option<kasumi_store::StorageOwnerId>,
    pub selection_address: Option<usize>,
    pub denial_address: Option<usize>,
    mode: Mode,
}
thread_local! {
    static ACTIVE: Cell<Option<Observation>> = const { Cell::new(None) };
}
pub(super) struct Arm {
    _same_thread: PhantomData<Rc<()>>,
}
impl Arm {
    pub fn new(mode: Mode) -> Self {
        ACTIVE.with(|active| {
            assert!(active.get().is_none(), "capture access hook already armed");
            active.set(Some(Observation {
                reader: None,
                selection_address: None,
                denial_address: None,
                mode,
            }));
        });
        Self {
            _same_thread: PhantomData,
        }
    }
    pub fn observation(&self) -> Observation {
        ACTIVE.with(|active| active.get().expect("capture access hook armed"))
    }
}
impl Drop for Arm {
    fn drop(&mut self) {
        ACTIVE.with(|active| active.set(None));
    }
}

pub(super) fn after_queued_begin(
    view: &kasumi_store::TenantStorageReadView,
    application: &kasumi_store::TenantStore,
) {
    ACTIVE.with(|active| {
        let Some(mut observed) = active.get() else {
            return;
        };
        assert!(observed.reader.is_none(), "capture seal already consumed");
        observed.reader = Some(
            view.registered_reader_id()
                .expect("original real registered reader"),
        );
        active.set(Some(observed));
        application.seal();
    });
}

pub(super) fn selection_failure(original: SelectionFailure<Workspace>) -> anyhow::Error {
    let original: anyhow::Error = original.into();
    ACTIVE.with(|active| {
        let Some(mut observed) = active.get() else {
            return original;
        };
        assert!(
            observed.reader.is_some(),
            "selection context preceded actual queued reader"
        );
        assert!(
            observed.selection_address.is_none(),
            "selection failure already observed"
        );
        let outer: &(dyn std::error::Error + Send + Sync) = original.as_ref();
        let selection = outer.downcast_ref::<SelectionFailure<Workspace>>().unwrap();
        observed.selection_address = Some(std::ptr::from_ref(selection) as usize);
        let denial: &(dyn std::error::Error + Send + Sync) = selection.original_error().as_ref();
        let denial = denial
            .downcast_ref::<kasumi_store::KeyAccessDenied>()
            .expect("actual selected point access denial");
        observed.denial_address = Some(std::ptr::from_ref(denial) as usize);
        active.set(Some(observed));
        match observed.mode {
            Mode::Bare => original,
            Mode::OwningContext => original.context("owned original selection failure"),
        }
    })
}
