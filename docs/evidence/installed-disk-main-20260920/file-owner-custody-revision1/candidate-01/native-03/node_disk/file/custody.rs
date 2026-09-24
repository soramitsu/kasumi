//! Fixed retained failure slots. Reservation precedes all file descriptors.
use super::*;

pub(in crate::node_disk) struct CustodySlots {
    slots: Box<[Slot]>,
}
struct Slot {
    reserved: bool,
    resources: Option<FileResources>,
}
impl CustodySlots {
    fn count(handles: u32) -> io::Result<usize> {
        usize::try_from(handles)
            .map_err(|_| io::ErrorKind::InvalidInput)?
            .checked_add(1)
            .ok_or_else(|| io::ErrorKind::InvalidInput.into())
    }
    pub(in crate::node_disk) fn required_bytes(handles: u32) -> io::Result<u64> {
        let count =
            u64::try_from(Self::count(handles)?).map_err(|_| io::ErrorKind::InvalidInput)?;
        crate::disk_memory::allocation::<Slot>(count)
    }
    pub(in crate::node_disk) fn new(handles: u32) -> io::Result<Self> {
        let count = Self::count(handles)?;
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(count)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        slots.resize_with(count, || Slot {
            reserved: false,
            resources: None,
        });
        Ok(Self {
            slots: slots.into_boxed_slice(),
        })
    }
    pub(super) fn reserve(&mut self) -> io::Result<usize> {
        let index = self
            .slots
            .iter()
            .position(|slot| !slot.reserved)
            .ok_or(io::ErrorKind::StorageFull)?;
        self.slots[index].reserved = true;
        Ok(index)
    }
    pub(super) fn release(&mut self, index: usize) {
        let slot = &mut self.slots[index];
        assert!(
            slot.reserved && slot.resources.is_none(),
            "exact drained custody slot"
        );
        slot.reserved = false;
    }
    pub(super) fn retain(&mut self, resources: FileResources) {
        let slot = &mut self.slots[resources.custody_slot];
        assert!(
            slot.reserved && slot.resources.is_none(),
            "one retained outcome per admitted slot"
        );
        slot.resources = Some(resources);
    }
    pub(in crate::node_disk) fn internal_owners(&self) -> u32 {
        self.slots
            .iter()
            .filter_map(|slot| slot.resources.as_ref())
            .filter(|resources| resources.registration != 0)
            .count() as u32
    }
    pub(in crate::node_disk) fn retained_attempts(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.resources.is_some())
            .count()
    }
    pub(in crate::node_disk) fn close_diagnostic(&self) -> Option<(i32, i32)> {
        self.slots
            .iter()
            .filter_map(|slot| slot.resources.as_ref())
            .find_map(FileResources::close_diagnostic)
    }
    #[cfg(test)]
    pub(in crate::node_disk) fn first_error_address(&self) -> Option<usize> {
        self.slots
            .iter()
            .filter_map(|slot| slot.resources.as_ref())
            .find_map(|resources| {
                let original = resources.original_error.as_ref()?.lock().unwrap();
                original
                    .as_ref()
                    .map(|error| std::ptr::from_ref(error) as usize)
            })
    }
    pub(in crate::node_disk) fn close_retained(&mut self) -> io::Result<()> {
        for resources in self
            .slots
            .iter_mut()
            .filter_map(|slot| slot.resources.as_mut())
        {
            resources.close_descriptors()?;
        }
        Ok(())
    }
    pub(in crate::node_disk) fn retire_after_census(&mut self) {
        for slot in &mut self.slots {
            if let Some(resources) = slot.resources.take() {
                assert!(resources.drained(), "census requires actual native drain");
                // Actual heap backing and original outcomes retire before the slot.
                drop(resources);
                slot.reserved = false;
            }
        }
    }
}

impl FileResources {
    pub(super) fn empty() -> Self {
        Self {
            root: String::new(),
            relative: PathBuf::new(),
            parent_names: Box::new([]),
            parent: None,
            retiring_parent: None,
            retired_parent: None,
            name: None,
            identity: Identity(0, 0),
            binding: NamespaceBinding::root(Identity(0, 0)),
            budget: None,
            registration: 0,
            custody_slot: usize::MAX,
            allocation: None,
            provisional_file: None,
            provisional_close: None,
            original_error: None,
        }
    }
    pub(super) fn record_error(&self, error: io::Error) -> io::Error {
        let returned = super::super::native_file::projection(&error);
        let mut original = self
            .original_error
            .as_ref()
            .expect("retained outcome mutex")
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if original.is_none() {
            *original = Some(error);
        }
        returned
    }
    pub(super) fn has_failure(&self) -> bool {
        self.original_error.as_ref().is_some_and(|mutex| {
            mutex.is_poisoned()
                || mutex
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .is_some()
        }) || self.provisional_close.is_some()
            || self
                .parent
                .as_ref()
                .is_some_and(RetainedParent::has_failure)
            || self
                .retiring_parent
                .as_ref()
                .is_some_and(RetainedParent::has_failure)
            || self.budget.as_ref().is_some_and(|budget| {
                budget
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .close_outcome
                    .is_some()
            })
    }
    fn close_diagnostic(&self) -> Option<(i32, i32)> {
        fn diagnostic(outcome: &super::super::native_file::CloseOutcome) -> (i32, i32) {
            (
                outcome.descriptor,
                outcome.error.raw_os_error().expect("native close errno"),
            )
        }
        self.provisional_close
            .as_ref()
            .map(diagnostic)
            .or_else(|| {
                self.budget.as_ref().and_then(|budget| {
                    budget
                        .lock()
                        .unwrap_or_else(|poison| poison.into_inner())
                        .close_outcome
                        .as_ref()
                        .map(diagnostic)
                })
            })
            .or_else(|| {
                self.parent
                    .as_ref()
                    .and_then(RetainedParent::close_diagnostic)
            })
            .or_else(|| {
                self.retiring_parent
                    .as_ref()
                    .and_then(RetainedParent::close_diagnostic)
            })
    }
    pub(super) fn close_descriptors(&mut self) -> io::Result<()> {
        let mut first = super::super::native_file::close(
            &mut self.provisional_file,
            &mut self.provisional_close,
        )
        .err();
        if let Some(mutex) = &mut self.budget {
            let budget = mutex.get_mut().unwrap_or_else(|poison| poison.into_inner());
            let result =
                super::super::native_file::close(&mut budget.file, &mut budget.close_outcome);
            if first.is_none() {
                first = result.err();
            }
        }
        for parent in [&mut self.parent, &mut self.retiring_parent]
            .into_iter()
            .flatten()
        {
            let result = parent.close_resources();
            if first.is_none() {
                first = result.err();
            }
        }
        first.map_or(Ok(()), Err)
    }
    pub(super) fn drained(&self) -> bool {
        self.provisional_file.is_none()
            && self.provisional_close.is_none()
            && self.parent.as_ref().is_none_or(RetainedParent::drained)
            && self
                .retiring_parent
                .as_ref()
                .is_none_or(RetainedParent::drained)
            && self.budget.as_ref().is_none_or(|budget| {
                let budget = budget.lock().unwrap_or_else(|poison| poison.into_inner());
                budget.file.is_none() && budget.close_outcome.is_none()
            })
    }
}
