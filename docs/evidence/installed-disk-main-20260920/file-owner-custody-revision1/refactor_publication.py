from pathlib import Path
import re
r=Path('target/installed-disk-validation/file-owner-custody-revision1')
p=r/'proposed/crates/kasumi-store/src/node_disk/file.rs'
s=p.read_text(); base=(r/'base/crates/kasumi-store/src/node_disk/file.rs').read_text()
a=base.index('        let mut renamed = false;',base.index("impl PreparedPublication<'_>"))
b=base.index('        Arc::get_mut(&mut allocation)',a)
body=base[a:b]
# Turn closure into a helper borrowing both admitted payloads.
body=body[:body.index('        if let Err(error) = result {')]
body=body.replace('let owner = &mut retained;', 'let owner = retained;')
body=body.replace('&mut state','state').replace('&state','state')
body=body.replace('&disk.roots[&root]', '&disk.roots[&target.root]')
body=body.replace('&parent_names', '&target.parent_names').replace('&parent)', 'target.parent.as_ref().expect("prepared destination parent"))')
body=body.replace('parent.file()', 'target.parent.as_ref().expect("prepared destination parent").file()')
body=body.replace('parent.identity()', 'target.parent.as_ref().expect("prepared destination parent").identity()')
body=body.replace('owner.parent.replace(parent)', 'owner.parent.replace(target.parent.take().expect("prepared destination parent"))')
body=body.replace('owner.parent_custody(), &parent', 'owner.parent_custody(), target.parent.as_ref().expect("prepared destination parent")')
body=body.replace('&name', 'target.name.as_ref().expect("prepared destination name")').replace('name.as_ptr()', 'target.name.as_ref().expect("prepared destination name").as_ptr()')
body=re.sub(r'\bbinding\b','target.binding',body)
# Undo member names affected by the token replacement.
body=body.replace('owner.target.binding','owner.binding').replace('.target.binding =','.binding =')
body=body.replace('std::mem::replace(&mut owner.root, root)', 'std::mem::replace(&mut owner.root, std::mem::take(&mut target.root))')
body=body.replace('owner.relative = relative;', 'owner.relative = std::mem::take(&mut target.relative);')
body=body.replace('std::mem::replace(&mut owner.parent_names, parent_names)', 'std::mem::replace(&mut owner.parent_names, std::mem::replace(&mut target.parent_names, Box::new([])))')
body=body.replace('owner.name = Some(name);','owner.name = target.name.take();')
# Parent custody remains with the owner on failed close; move nothing until drained.
needle='''            let old = owner
                .retiring_parent
                .take()'''
assert needle in body
body=body.replace(needle,'''            owner.retiring_parent.as_mut().expect("retained source parent")
                .close_resources()?;
            let old = owner
                .retiring_parent
                .take()''')
body=body.replace('.retire()', '.retire_drained()')
body+='''        if let Err(error) = result {
            if renamed || error.kind() != io::ErrorKind::AlreadyExists {
                disk.fail_locked(state);
                return Err(retained.record_error(error));
            }
            return Err(error);
        }
        Ok(())
'''
# Closure must reborrow, not move retained &mut needed for error retention afterwards.
body=body.replace('let owner = retained;', 'let owner = &mut *retained;')
new='''// Destination preparation unlocks before the source owner's recursive Drop.
pub(super) struct PreparedPublication<'a> {
    prepared: Option<FilePreparation<'a>>,
    retained: Option<FileOwner>,
}
impl Drop for PreparedPublication<'_> {
    fn drop(&mut self) {
        drop(self.prepared.take());
        drop(self.retained.take());
    }
}
impl PreparedPublication<'_> {
    #[cfg(test)]
    pub(super) fn parent_descriptor(&self) -> std::os::fd::RawFd {
        self.prepared.as_ref().expect("prepared destination").resources.as_ref()
            .expect("prepared resources").parent.as_ref().expect("prepared parent")
            .file().as_raw_fd()
    }
    pub(super) fn execute(mut self) -> io::Result<NodeDiskFile> {
        let prepared = self.prepared.as_mut().expect("prepared destination");
        prepared.executing = true;
        let result = execute_publication(
            prepared.disk, prepared.state.as_mut().expect("prepared serialization"),
            prepared.resources.as_mut().expect("prepared resources"),
            self.retained.as_mut().expect("retained publication owner"),
        );
        if let Err(error) = result { return Err(prepared.error(error)); }
        prepared.executing = false;
        let target = prepared.resources.as_mut().expect("prepared resources");
        let mut allocation = target.allocation.take().expect("prepared owner allocation");
        Arc::get_mut(&mut allocation).expect("unpublished publication allocation")
            .write(self.retained.take().expect("retained publication owner"));
        // SAFETY: initialized exactly once above; only infallible registration follows.
        let mut retained = OwnedFileArc::new(unsafe { allocation.assume_init() });
        let registration = Arc::as_ptr(&retained) as usize;
        Arc::get_mut(&mut retained).expect("unregistered publication Arc").registration = registration;
        *prepared.state.as_mut().expect("prepared serialization").live
            .get_mut(&retained.identity).expect("retained publication slot") = Arc::downgrade(&retained);
        Ok(NodeDiskFile(retained))
    }
}
fn execute_publication(
    disk: &Arc<NodeDisk>, state: &mut State, target: &mut FileResources,
    retained: &mut FileOwner,
) -> io::Result<()> {
'''+body+'}\n\n'
a=s.index('// Abandoned target paths/FDs'); b=s.index('#[cfg(test)]\n#[repr(u8)]',a)
s=s[:a]+new+s[b:]
a=s.index('        // The installed envelope includes one publication preparation.')
b=s.index('\n    fn reclaim(',a)
s=s[:a]+'''        // Hold the same serialization through all charged preparation and acquisition.
        let mut state = self.lock_state();
        if state.phase != NodeDiskPhase::Open || !self.device.lock().admission_ready() {
            return Err(io::ErrorKind::Other.into());
        }
        let selected = self.roots.get(root).ok_or(io::ErrorKind::InvalidInput)?;
        let (name, parent_names, binding) = prepare_file_names(selected.identity, relative, &self.config)?;
        if super::batch::reserved_binding(&state, binding) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let parent = RetainedParent::prepare_storage(self, root, &parent_names)?;
        let original_error = Mutex::new(None);
        drop(original_error.lock().expect("unpublished original outcome"));
        let mut resources = FileResources {
            root: root.to_owned(), relative: relative.to_owned(), parent_names,
            parent: Some(parent), retiring_parent: None, retired_parent: None,
            name: Some(name), identity: Identity(0, 0), binding, budget: None,
            registration: 0, custody_slot: usize::MAX,
            allocation: Some(Arc::<FileOwner>::new_uninit()),
            provisional_file: None, provisional_close: None, original_error,
        };
        resources.custody_slot = state.file_custody.reserve()?;
        let prepared = FilePreparation { disk: self, resources: Some(resources),
            state: Some(state), executing: false };
        // Never acquire a destination FD for an owner which cannot transfer.
        let retained = match file.0.try_unwrap() {
            Ok(owner) => owner,
            Err(owner) => {
                drop(prepared);
                drop(owner);
                return Err(io::ErrorKind::WouldBlock.into());
            }
        };
        let mut result = PreparedPublication { prepared: Some(prepared), retained: Some(retained) };
        result.prepared.as_mut().expect("prepared destination").acquire_parent()?;
        Ok(result)
    }
''' + s[b:]
p.write_text(s)
