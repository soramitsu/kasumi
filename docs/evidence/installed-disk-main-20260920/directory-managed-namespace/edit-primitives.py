from pathlib import Path
p=Path('target/installed-disk-validation/directory-managed-namespace/proposed/crates/kasumi-store/src/node_disk')
f=p/'namespace.rs'
s=f.read_text().replace('use std::{ffi::CString, fs::File, io};','use std::{ffi::CString, fs::File, io, os::unix::fs::MetadataExt};')
pos=s.index('    pub(super) fn file(&self)')
s=s[:pos]+'''    /// Compare every retained ancestor and the actual parent descriptor. This
    /// deliberately does not require the affected parent's pre-effect extent:
    /// the prepared transition owns that snapshot until explicit settlement.
    pub(super) fn verify(&self, root: &census::Root, names: &[CString]) -> io::Result<()> {
        root.verify_nonallocating()?;
        if self.ancestors.len() != names.len() + 1 || self.ancestors[0] != root.identity {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut current = root.file.try_clone()?;
        for (index, name) in names.iter().enumerate() {
            let child = census::open_at(&current, name, libc::O_RDONLY | libc::O_DIRECTORY)?;
            let metadata = child.metadata()?;
            census::directory_nonallocating(&metadata)?;
            if metadata.dev() != root.identity.0
                || Identity::of(&metadata) != self.ancestors[index + 1]
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            current = child;
        }
        let retained = self.file().metadata()?;
        census::directory_nonallocating(&retained)?;
        if Identity::of(&current.metadata()?) != self.identity
            || Identity::of(&retained) != self.identity
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(())
    }
''' +s[pos:]
s=s.replace('pub(super) struct ParentTransition {','#[derive(Clone, Copy)]\npub(super) struct ParentTransition {')
start=s.index('        if state.phase == NodeDiskPhase::Failed',s.index('impl ParentTransition'))
s=s[:start]+'''        let prepared = Self::preflight(disk, state, first, second, growth_work)?;
        prepared.activate(state);
        Ok(prepared)
    }

    /// Validate without invalidating the old ledger. Directory creation reserves
    /// its complete child allowance after this preflight, then activates both
    /// the parent plan and its already-owned pending operation without a gap.
    pub(super) fn preflight(
        disk: &NodeDisk,
        state: &mut State,
        first: (Identity, i8),
        second: Option<(Identity, i8)>,
        growth_work: Option<DiskWork>,
    ) -> io::Result<Self> {
''' +s[start:]
start=s.index('        // Validation has finished for both distinct parents.')
end=s.index('    /// Only a definite no-effect', start)
s=s[:start]+'''        Ok(Self { generation, changes })
    }

    pub(super) fn activate(&self, state: &mut State) {
        for change in self.changes.iter().flatten() {
            state.accounted.get_mut(&change.identity)
                .and_then(AccountedInode::directory_mut)
                .expect("prepared parent").settled = false;
        }
    }

''' +s[end:]
f.write_text(s)
f=p/'file.rs';s=f.read_text();start=s.index('fn verify_parent(');end=s.index('\nfn prepare_parent_names(',start)
s=s[:start]+'''fn verify_parent(root: &census::Root, names: &[CString], retained: &RetainedParent) -> io::Result<()> {
    retained.verify(root, names)
}
''' +s[end:];f.write_text(s)
f=p/'directory.rs';s=f.read_text().replace('//! This primitive does not authorize namespace mutation. Census establishes the\n//! exact identities/extents. Managed file effects settle their affected parents\n//! under the same state guard; other namespace changes require actual drain and\n//! fresh census until their explicit mutation protocol is implemented.','//! Census establishes exact identities/extents. Prepared child mutations retain\n//! affected-parent and unresolved-operation custody under the same State guard.')
s=s.replace('if names.len() >= depth as usize || name.len() > maximum as usize {','if names.len() + 1 >= depth as usize || name.len() > maximum as usize {')
start=s.index('        let root = root.to_owned();',s.index('impl NodeDisk'))
s=s[:start]+'''        self.open_directory_names(&mut state, root.to_owned(), names)
    }

    // Caller holds State and has checked the owner quota before any path/Arc
    // allocation. Both rooted and child opens share the same publication path.
    fn open_directory_names(
        self: &Arc<Self>,
        state: &mut State,
        root: String,
        names: Box<[CString]>,
    ) -> io::Result<NodeDiskDirectory> {
''' +s[start+len('        let root = root.to_owned();\n'):]
start=s.index('    fn open_directory_names(');end=s.index('\nimpl NodeDiskDirectory',start)
a=s[start:end].replace('walk(self, &state,','walk(self, state,').replace('self.fail_locked(&mut state)','self.fail_locked(state)').replace('prepare(self, &state,','prepare(self, state,').replace('parent.register(self, &mut state)','parent.register(self, state)').replace('        drop(state);\n','')
a=a.replace('Some(namespace::RetainedParent::prepare(self, state, &root, &names[..names.len() - 1])?)','Some(namespace::RetainedParent::prepare(self, state, &root, &names[..names.len() - 1])\n                .inspect_err(|_| self.fail_locked(state))?)')
s=s[:start]+a+s[end:]
pos=s.index('        Ok(())\n    }',s.index('    fn verify(&self'))
s=s[:pos]+'''        if let Some(parent) = &self.owner().parent {
            parent.verify(&self.owner().disk.roots[&self.owner().root],
                &self.owner().names[..self.owner().names.len() - 1])?;
        }
''' +s[pos:]
s=s.replace('if let Some(owner) = Arc::into_inner(self.0.take().expect("live directory custody")) {','if let Some(owner) = self.0.take().and_then(Arc::into_inner) {')
s += '\nmod managed;\npub use managed::{NodeDiskDirectoryOperation, NodeDiskDirectoryOperationKind, NodeDiskDirectoryOperationStep};\n'
f.write_text(s)
