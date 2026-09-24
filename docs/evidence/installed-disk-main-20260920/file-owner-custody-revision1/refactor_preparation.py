from pathlib import Path
root=Path('target/installed-disk-validation/file-owner-custody-revision1')
p=root/'proposed/crates/kasumi-store/src/node_disk/file.rs'
s=p.read_text()
base=(root/'base/crates/kasumi-store/src/node_disk/file.rs').read_text()
a=base.index('        verify_parent(',base.index("impl PreparedFile<'_>"))
b=base.index('        Arc::get_mut(&mut self.allocation)',a)
body=base[a:b]
# Collapse multiline field chains before the exact scalar/resource substitutions.
import re
body=re.sub(r'self\s*\.state','self.state',body)
body=re.sub(r'self\s*\.parent','self.parent',body)
body=re.sub(r'self\s*\.disk','self.disk',body)
body=body.replace('&mut self.state','state').replace('&self.state','state').replace('self.state','state')
body=body.replace('self.disk','disk').replace('self.create','create').replace('self.work','work').replace('self.device','device').replace('self.admitted_growth','admitted_growth')
for field in ['root','parent_names','binding']:
    body=body.replace('self.'+field,'resources.'+field)
body=body.replace('&self.name','resources.name.as_ref().expect("prepared name")')
body=body.replace('self.parent.identity()','resources.parent.as_ref().expect("prepared parent").identity()')
body=body.replace('self.parent.file()','resources.parent.as_ref().expect("prepared parent").file()')
body=body.replace('&self.parent','resources.parent.as_ref().expect("prepared parent")')
body=body.replace('self.parent\n            .register','resources.parent.as_mut().expect("prepared parent")\n            .register')
body=body.replace('let file = match census::open_at','resources.provisional_file = Some(match census::open_at')
body=body.replace('        };\n        let mut already_owned', '        });\n        let file = resources.provisional_file.as_ref().expect("retained acquired file");\n        let mut already_owned',1)
body=body.replace('census::lock_nonallocating(&file,','census::lock_nonallocating(file,')
body=body.replace('self.budget.get_mut()','resources.budget.as_mut().expect("prepared budget").get_mut()')
body=body.replace('file: Some(file),','file: resources.provisional_file.take(),')
body=body.replace('            settled: enrolled.settled,','            settled: enrolled.settled,\n            close_outcome: None,')
assert 'self.' not in body, [line for line in body.splitlines() if 'self.' in line]
new='''// One serialized preparation owns its preallocated payload and custody slot
// before the first descriptor. A failed or unwound operation transfers that
// payload into State; it cannot unwind a raw File outside installed custody.
struct FilePreparation<'a> {
    disk: &'a Arc<NodeDisk>,
    resources: Option<FileResources>,
    state: Option<std::sync::MutexGuard<'a, State>>,
    executing: bool,
}
impl FilePreparation<'_> {
    fn acquire_parent(&mut self) -> io::Result<()> {
        let resources = self.resources.as_mut().expect("prepared resources");
        let state = self.state.as_mut().expect("prepared serialization");
        let result = resources.parent.as_mut().expect("prepared parent")
            .acquire(self.disk, state, &resources.root, &resources.parent_names);
        match result {
            Ok(()) => Ok(()),
            Err(error) => {
                self.disk.fail_locked(state);
                Err(resources.record_error(error))
            }
        }
    }
    fn error(&mut self, error: io::Error) -> io::Error {
        self.executing = false;
        let resources = self.resources.as_ref().expect("prepared resources");
        if self.state.as_ref().expect("prepared serialization").phase == NodeDiskPhase::Failed
            || resources.has_failure()
        {
            resources.record_error(error)
        } else { error }
    }
}
impl Drop for FilePreparation<'_> {
    fn drop(&mut self) {
        let Some(mut resources) = self.resources.take() else { return; };
        let state = self.state.as_mut().expect("custody retains serialization");
        let retain = self.executing || resources.has_failure()
            || state.phase == NodeDiskPhase::Failed;
        if retain || resources.close_descriptors().is_err() {
            self.disk.fail_locked(state);
            state.file_custody.retain(resources);
        } else {
            let slot = resources.custody_slot;
            // No native handle or owned backing remains when admission returns.
            drop(resources);
            state.file_custody.release(slot);
        }
    }
}

pub(super) struct PreparedFile<'a> {
    prepared: FilePreparation<'a>,
    device: u64,
    create: bool,
    work: Option<DiskWork>,
    admitted_growth: Option<(u64, u64)>,
}
impl PreparedFile<'_> {
    #[cfg(test)]
    pub(super) fn parent_descriptor(&self) -> std::os::fd::RawFd {
        self.prepared.resources.as_ref().expect("prepared resources")
            .parent.as_ref().expect("prepared parent").file().as_raw_fd()
    }
    pub(super) fn execute(mut self) -> io::Result<NodeDiskFile> {
        self.prepared.executing = true;
        let result = execute_prepared(
            self.prepared.disk,
            self.prepared.state.as_mut().expect("prepared serialization"),
            self.prepared.resources.as_mut().expect("prepared resources"),
            self.create, self.work, self.device, self.admitted_growth,
        );
        let identity = match result {
            Ok(identity) => identity,
            Err(error) => return Err(self.prepared.error(error)),
        };
        let mut resources = self.prepared.resources.take().expect("prepared resources");
        let mut allocation = resources.allocation.take().expect("prepared owner allocation");
        resources.identity = identity;
        Arc::get_mut(&mut allocation).expect("unpublished owner allocation")
            .write(FileOwner { disk: self.prepared.disk.clone(), resources });
        // SAFETY: the sole allocation is fully initialized; registration is infallible.
        let mut owner = unsafe { allocation.assume_init() };
        let registration = Arc::as_ptr(&owner) as usize;
        Arc::get_mut(&mut owner).expect("unregistered owner").registration = registration;
        let state = self.prepared.state.as_mut().expect("prepared serialization");
        state.open_files += 1;
        state.live.insert(identity, Arc::downgrade(&owner));
        Ok(NodeDiskFile(OwnedFileArc::new(owner)))
    }
}
fn execute_prepared(
    disk: &Arc<NodeDisk>, state: &mut State, resources: &mut FileResources,
    create: bool, work: Option<DiskWork>, device: u64,
    admitted_growth: Option<(u64, u64)>,
) -> io::Result<Identity> {
'''+body+'''        Ok(identity)
}

'''
a=s.index('// Preparation owns all heap storage')
b=s.index('// Abandoned target paths/FDs',a)
s=s[:a]+new+s[b:]
# Replace descriptor-producing prepare tail. All charged paths/mutexes/Arc before acquire.
a=s.index('        let selected = self.roots.get(root)',s.index('        let required = 1 + super::batch::reserved_files'))
b=s.index('\n    /// Consume the sole descriptor owner',a)
s=s[:a]+'''        let selected = self.roots.get(root).ok_or(io::ErrorKind::InvalidInput)?;
        let (name, parent_names, binding) = prepare_file_names(selected.identity, relative, &self.config)?;
        if create.is_some() && super::batch::reserved_binding(&state, binding) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let parent = RetainedParent::prepare_storage(self, root, &parent_names)?;
        let budget = Mutex::new(Budget {
            file: None, bytes: 0, pending: 0, reserved_len: 0, actual_len: 0,
            settled: false, close_outcome: None,
        });
        drop(budget.lock().expect("unpublished budget"));
        let original_error = Mutex::new(None);
        drop(original_error.lock().expect("unpublished original outcome"));
        let (allocation, admitted_growth) = match admitted {
            Some((allocation, bytes, length)) => (allocation, Some((bytes, length))),
            None => (Arc::<FileOwner>::new_uninit(), None),
        };
        let mut resources = FileResources {
            root: root.to_owned(), relative: relative.to_owned(), parent_names,
            parent: Some(parent), retiring_parent: None, retired_parent: None,
            name: Some(name), identity: Identity(0, 0), binding, budget: Some(budget),
            registration: 0, custody_slot: usize::MAX, allocation: Some(allocation),
            provisional_file: None, provisional_close: None, original_error,
        };
        resources.custody_slot = state.file_custody.reserve()?;
        let mut prepared = FilePreparation {
            disk: self, resources: Some(resources), state: Some(state), executing: false,
        };
        prepared.acquire_parent()?;
        Ok(PreparedFile { prepared, device: selected.identity.0,
            create: create.is_some(), work: create, admitted_growth })
    }
''' + s[b:]
# Include exact leaf validation: old generic file permits <= max_depth components.
a=s.index('fn prepare_parent_names(')
s=s[:a]+'''fn prepare_file_names(
    root: Identity, relative: &Path, config: &super::NodeDiskConfig,
) -> io::Result<(CString, Box<[CString]>, NamespaceBinding)> {
    use std::os::unix::ffi::OsStrExt;
    let parent_names = prepare_parent_names(relative, config)?;
    let leaf = relative.components().next_back().ok_or(io::ErrorKind::InvalidInput)?;
    let std::path::Component::Normal(leaf) = leaf else { return Err(io::ErrorKind::InvalidInput.into()); };
    if leaf.len() > config.max_name_bytes as usize || parent_names.len() >= config.max_depth as usize {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let name = CString::new(leaf.as_bytes()).map_err(|_| io::ErrorKind::InvalidInput)?;
    let parent = parent_names.iter().fold(NamespaceBinding::root(root), |binding, name| binding.child(name));
    let binding = parent.child(&name);
    Ok((name, parent_names, binding))
}

''' + s[a:]
p.write_text(s)
