from pathlib import Path
p=Path('target/installed-disk-validation/directory-managed-namespace/proposed/crates/kasumi-store/src/node_disk')
f=p/'namespace.rs';s=f.read_text();pos=s.index('    /// Compare every retained ancestor')
s=s[:pos]+'''    pub(super) fn prepared(identity: Identity, ancestors: Box<[Identity]>) -> Self {
        Self { file: None, identity, ancestors, registered: false }
    }
    pub(super) fn set_descriptor(&mut self, file: File) {
        assert!(self.file.is_none(), "prepared parent descriptor is installed once");
        self.file = Some(file);
    }
''' +s[pos:];f.write_text(s)
f=p/'directory/managed.rs';s=f.read_text().replace('pub enum NodeDiskDirectoryOperationKind { Create, Remove }','pub enum NodeDiskDirectoryOperationKind { Open, Create, Remove }')
s=s.replace('    plan: ParentTransition,','    plan: Option<ParentTransition>,')
s=s.replace('fn verify_parent(&mut self, disk: &NodeDisk) -> io::Result<()> {','fn verify_parent(&mut self, disk: &NodeDisk, ledger: Option<&crate::node_disk::fixed_map::Banks<AccountedInode>>) -> io::Result<()> {')
s=s.replace('''        root.verify_nonallocating()?;
        if self.parent''','''        root.verify_nonallocating()?;
        if let Some(ledger) = ledger { verify_enrolled(ledger, root.identity, &root.file.metadata()?)?; }
        if self.parent''')
s=s.replace('''            census::directory_nonallocating(&metadata)?;
            if Identity::of(&metadata)''','''            census::directory_nonallocating(&metadata)?;
            if let Some(ledger) = ledger { verify_enrolled(ledger, Identity::of(&metadata), &metadata)?; }
            if Identity::of(&metadata)''',1)
s=s.replace('''        census::directory_nonallocating(&retained)?;
        if Identity::of(&current.metadata()?)''','''        census::directory_nonallocating(&retained)?;
        if let Some(ledger) = ledger { verify_enrolled(ledger, self.parent.identity(), &retained)?; }
        if Identity::of(&current.metadata()?)''',1)
s=s.replace('        self.verify_parent(disk)?;','        self.verify_parent(disk, None)?;')
start=s.index('    pub fn open_child(');end=s.index('    /// Remove an empty non-root',start)
s=s[:start]+'''    pub fn open_child(&self, name: &CStr) -> io::Result<Self> {
        let owner = self.owner();
        let disk = &owner.disk;
        let mut state = disk.lock_state();
        prepare_child(owner, name, &mut state, None)?;
        let mut effect = Effect { disk, state: &mut state };
        let result = (|| {
            acquire_parent(owner, &mut effect)?;
            step(&mut effect, NodeDiskDirectoryOperationStep::OpenChild)?;
            let operation = effect.pending_directory.as_mut().expect("retained operation");
            operation.child = Some(census::open_at(operation.parent.file(), operation.name(), libc::O_RDONLY | libc::O_DIRECTORY)?);
            let metadata = operation.child.as_ref().expect("retained child").metadata()?;
            let identity = Identity::of(&metadata);
            let binding = operation.binding;
            let parent = operation.parent.identity();
            verify_enrolled(&effect.accounted, identity, &metadata)?;
            let entry = effect.accounted.get_mut(&identity).and_then(AccountedInode::directory_mut).expect("verified child");
            if entry.binding != binding || entry.parent != Some(parent) { return Err(io::ErrorKind::InvalidData.into()); }
            let handles = entry.live_handles.checked_add(1).ok_or(io::ErrorKind::InvalidData)?;
            entry.live_handles = handles;
            effect.pending_directory.as_mut().expect("retained operation").identity = Some(identity);
            Ok(publish_child(disk, &mut effect))
        })();
        if let Err(error) = &result {
            // A verified parent's unknown final absence is the only healthy
            // failed acquisition. Close every actual descriptor and backing
            // before returning its prepared slot; close uncertainty stays owned.
            let operation = effect.pending_directory.as_ref().expect("retained operation");
            let absent = error.kind() == io::ErrorKind::NotFound
                && operation.observation.step == NodeDiskDirectoryOperationStep::OpenChild
                && !effect.accounted.values().any(|entry| entry.binding() == operation.binding);
            if absent {
                operation_absent(&mut effect).inspect_err(|close| record_failure(disk, &mut effect, close))?;
            } else { record_failure(disk, &mut effect, error); }
        }
        result
    }

    /// Create exactly one absent child with its full policy allowance prepared
    /// before the first descriptor acquisition. This does not admit a multipart
    /// caller operation.
    pub fn create_child(&self, name: &CStr, work: DiskWork) -> io::Result<Self> {
        let owner = self.owner();
        let disk = &owner.disk;
        let mut state = disk.lock_state();
        prepare_child(owner, name, &mut state, Some(work))?;
        let mut effect = Effect { disk, state: &mut state };
        let result = (|| {
            acquire_parent(owner, &mut effect)?;
            effect.pending_directory.as_ref().expect("retained operation").plan.expect("create plan").activate(&mut effect);
            create_effect(disk, &mut effect)
        })();
        if let Err(error) = &result { record_failure(disk, &mut effect, error); }
        result
    }

''' +s[end:]
s=s.replace('''        self.verify(&state).inspect_err(|_| disk.fail_locked(&mut state))?;
        let entry''','''        let entry''')
s=s.replace('''        let entry = *state.accounted[&self.owner().identity].directory().expect("verified directory");
        if entry.children''','''        let entry = *state.accounted.get(&self.owner().identity).and_then(AccountedInode::directory).ok_or(io::ErrorKind::InvalidData)?;
        if !entry.settled { return Err(io::ErrorKind::InvalidData.into()); }
        if entry.children''')
s=s.replace('identity: Some(identity), allocation: None, plan,','identity: Some(identity), allocation: None, plan: Some(plan),')
s=s.replace('''        plan.activate(&mut effect);
        effect.accounted.get_mut(&identity).and_then(AccountedInode::directory_mut).expect("retained child").settled = false;
        let result = remove_effect(&disk, &mut effect, entry);''','''        let result = (|| {
            verify_preflight(&disk, &mut effect)?;
            effect.pending_directory.as_mut().expect("retained operation").verify_child(&disk)?;
            let metadata = effect.pending_directory.as_ref().expect("retained operation").child.as_ref().expect("retained child").metadata()?;
            verify_enrolled(&effect.accounted, identity, &metadata)?;
            plan.activate(&mut effect);
            effect.accounted.get_mut(&identity).and_then(AccountedInode::directory_mut).expect("retained child").settled = false;
            remove_effect(&disk, &mut effect, entry)
        })();''')
start=s.index('    let mut operation = state.pending_directory.take().expect("settled operation");');end=s.index('\nfn record_child',start)
s=s[:start]+'''    Ok(publish_child(disk, state))
}
fn publish_child(disk: &Arc<NodeDisk>, state: &mut State) -> NodeDiskDirectory {
    let mut operation = state.pending_directory.take().expect("settled operation");
    assert!(operation.walk_current.is_none() && operation.walk_next.is_none());
    let mut allocation = operation.allocation.take().expect("preallocated owner");
    Arc::get_mut(&mut allocation).expect("private owner allocation").write(DirectoryOwner {
        disk: disk.clone(), root: operation.root, names: operation.names,
        identity: operation.identity.expect("observed child"), file: operation.child,
        parent: Some(operation.parent), registered: true,
        #[cfg(test)] after_close: None,
    });
    // SAFETY: the sole admitted allocation is fully initialized above.
    NodeDiskDirectory(Some(unsafe { allocation.assume_init() }))
}
''' +s[end:]
s=s.replace('operation.plan.settle_observed(disk, state, [Some(observation), None])','operation.plan.expect("mutation plan").settle_observed(disk, state, [Some(observation), None])')
s=s.replace('    operation.verify_parent(disk)?;','    operation.verify_parent(disk, None)?;')
pos=s.index('\nfn create_effect(')
s=s[:pos]+'''
fn verify_enrolled(ledger: &crate::node_disk::fixed_map::Banks<AccountedInode>, identity: Identity,
    metadata: &std::fs::Metadata) -> io::Result<()> {
    census::directory_nonallocating(metadata)?;
    let entry = ledger.get(&identity).and_then(AccountedInode::directory).ok_or(io::ErrorKind::InvalidData)?;
    if !entry.settled || entry.len != metadata.len()
        || entry.bytes.checked_sub(entry.pending) != Some(census::directory_extent(metadata)?) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(())
}
fn verify_preflight(disk: &NodeDisk, state: &mut State) -> io::Result<()> {
    let State { pending_directory, accounted, .. } = state;
    pending_directory.as_mut().expect("retained operation").verify_parent(disk, Some(accounted))
}
fn acquire_parent(owner: &DirectoryOwner, state: &mut State) -> io::Result<()> {
    let operation = state.pending_directory.as_mut().expect("retained operation");
    operation.parent.set_descriptor(owner.file.as_ref().expect("live directory").try_clone()?);
    verify_preflight(&owner.disk, state)
}
fn prepare_child(owner: &DirectoryOwner, name: &CStr, state: &mut State, work: Option<DiskWork>) -> io::Result<()> {
    let disk = &owner.disk;
    ready(disk, state)?;
    if state.open_directories >= disk.config.max_open_directories { return Err(io::ErrorKind::StorageFull.into()); }
    let roots = u64::try_from(disk.roots.len()).map_err(|_| io::ErrorKind::InvalidData)?;
    if work.is_some() && state.directories.checked_sub(roots).is_none_or(|n| n >= disk.config.max_persistent_subdirectories) {
        return Err(io::ErrorKind::StorageFull.into());
    }
    if work.is_some() { state.accounted.try_reserve(1)?; }
    let names = child_names(owner, name)?;
    let parent_entry = *state.accounted.get(&owner.identity).and_then(AccountedInode::directory).ok_or(io::ErrorKind::InvalidData)?;
    let binding = parent_entry.binding.child(name);
    if work.is_some() && state.accounted.values().any(|entry| entry.binding() == binding) {
        return Err(io::ErrorKind::AlreadyExists.into());
    }
    parent_entry.live_handles.checked_add(1).ok_or(io::ErrorKind::InvalidData)?;
    let directories = if work.is_some() { state.directories.checked_add(1).ok_or(io::ErrorKind::StorageFull)? } else { state.directories };
    let plan = if let Some(work) = work {
        Some(ParentTransition::preflight(disk, state, (owner.identity, 1), None, Some(work))?)
    } else { None };
    let mut ancestors = Vec::new();
    ancestors.try_reserve_exact(owner.names.len() + 1).map_err(|_| io::ErrorKind::OutOfMemory)?;
    if let Some(parent) = &owner.parent { ancestors.extend_from_slice(parent.ancestors()); }
    ancestors.push(owner.identity);
    if ancestors.len() != owner.names.len() + 1 { return Err(io::ErrorKind::InvalidData.into()); }
    let mut parent = RetainedParent::prepared(owner.identity, ancestors.into_boxed_slice());
    let allocation = Arc::<DirectoryOwner>::new_uninit();
    let root = owner.root.clone();
    if let Some(work) = work { disk.reserve(state, disk.config.directory_policy.extent_bytes, work)?; }
    parent.register(disk, state).expect("preflighted parent registration");
    state.open_directories += 1;
    state.directories = directories;
    state.pending_directory = Some(PendingDirectory {
        observation: NodeDiskDirectoryOperation { kind: if work.is_some() { NodeDiskDirectoryOperationKind::Create } else { NodeDiskDirectoryOperationKind::Open },
            step: NodeDiskDirectoryOperationStep::Prepared, failure: None, close_failure: None, uncertain_close_descriptor: None },
        root, names, binding, parent, child: None, walk_current: None, walk_next: None, identity: None,
        allocation: Some(allocation), plan,
    });
    Ok(())
}
fn operation_absent(state: &mut State) -> io::Result<()> {
    let operation = state.pending_directory.as_mut().expect("retained absence");
    let parent = operation.parent.identity();
    operation.close_resources()?;
    if !namespace::can_retire_parent(state, parent) { return Err(io::ErrorKind::InvalidData.into()); }
    let owners = state.open_directories.checked_sub(1).ok_or(io::ErrorKind::InvalidData)?;
    drop(state.pending_directory.take());
    namespace::retire_parent(state, parent);
    state.open_directories = owners;
    Ok(())
}
''' +s[pos:]
f.write_text(s)
