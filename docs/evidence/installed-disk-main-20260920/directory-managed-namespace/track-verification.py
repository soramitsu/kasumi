from pathlib import Path
p=Path('target/installed-disk-validation/directory-managed-namespace/proposed/crates/kasumi-store/src/node_disk')
f=p/'namespace.rs';s=f.read_text();pos=s.index('    pub(super) fn register(');s=s[:pos]+'''    pub(super) fn ancestors(&self) -> &[Identity] { &self.ancestors }
''' +s[pos:];f.write_text(s)
f=p/'census.rs';s=f.read_text();a=s.index('        // SAFETY:',s.index('pub(super) fn verify_nonallocating'));b=s.index('        Ok(())',a)
s=s[:a]+'''        // lstat observes the preallocated rooted name without acquiring a
        // temporary descriptor whose close could become an untracked outcome.
        let mut observed: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::lstat(self.path_c.as_ptr(), &mut observed) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if observed.st_mode & libc::S_IFMT != libc::S_IFDIR
            || observed.st_mode & 0o077 != 0
            || observed.st_uid != unsafe { libc::geteuid() }
            || Identity(observed.st_dev as u64, observed.st_ino as u64) != self.identity
            || Identity::of(&self.file.metadata()?) != self.identity {
            return Err(io::ErrorKind::InvalidData.into());
        }
''' +s[b:];f.write_text(s)
f=p/'directory/managed.rs';s=f.read_text().replace('    child: Option<File>,','    child: Option<File>,\n    walk_current: Option<File>,\n    walk_next: Option<File>,',1)
a=s.index('    fn verify_parent(');b=s.index('    pub(in crate::node_disk) fn close_resources',a)
s=s[:a]+'''    fn verify_parent(&mut self, disk: &NodeDisk) -> io::Result<()> {
        let root = &disk.roots[&self.root];
        root.verify_nonallocating()?;
        if self.parent.ancestors().len() != self.names.len()
            || self.parent.ancestors()[0] != root.identity {
            return Err(io::ErrorKind::InvalidData.into());
        }
        for index in 0..self.names.len() - 1 {
            let current = self.walk_current.as_ref().unwrap_or(&root.file);
            self.walk_next = Some(census::open_at(current, &self.names[index], libc::O_RDONLY | libc::O_DIRECTORY)?);
            let metadata = self.walk_next.as_ref().expect("retained walk descriptor").metadata()?;
            census::directory_nonallocating(&metadata)?;
            if Identity::of(&metadata) != self.parent.ancestors()[index + 1] {
                return Err(io::ErrorKind::InvalidData.into());
            }
            Self::close_owned(self.walk_current.take(), NodeDiskDirectoryOperationStep::Verify, &mut self.observation)?;
            self.walk_current = self.walk_next.take();
        }
        let current = self.walk_current.as_ref().unwrap_or(&root.file);
        let retained = self.parent.file().metadata()?;
        census::directory_nonallocating(&retained)?;
        if Identity::of(&current.metadata()?) != self.parent.identity()
            || Identity::of(&retained) != self.parent.identity() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Self::close_owned(self.walk_current.take(), NodeDiskDirectoryOperationStep::Verify, &mut self.observation)
    }
    fn verify_child(&mut self, disk: &NodeDisk) -> io::Result<()> {
        self.verify_parent(disk)?;
        let mut observed: libc::stat = unsafe { std::mem::zeroed() };
        // No temporary child FD: inspect the one exact component without
        // following a replacement symlink, then compare the retained owner.
        if unsafe { libc::fstatat(self.parent.file().as_raw_fd(), self.name().as_ptr(),
            &mut observed, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let metadata = self.child.as_ref().expect("retained child").metadata()?;
        census::directory_nonallocating(&metadata)?;
        if observed.st_mode & libc::S_IFMT != libc::S_IFDIR
            || observed.st_mode & 0o077 != 0 || observed.st_uid != unsafe { libc::geteuid() }
            || Some(Identity(observed.st_dev as u64, observed.st_ino as u64)) != self.identity
            || Some(Identity::of(&metadata)) != self.identity {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(())
    }
''' +s[b:]
s=s.replace('''        self.close_one(true)?;''','''        Self::close_owned(self.walk_next.take(), NodeDiskDirectoryOperationStep::Verify, &mut self.observation)?;
        Self::close_owned(self.walk_current.take(), NodeDiskDirectoryOperationStep::Verify, &mut self.observation)?;
        self.close_one(true)?;''')
a=s.index('        let Some(file) = file else',s.index('    fn close_one('));b=s.index('\n}\n\nstruct Effect',a)
s=s[:a]+'''        Self::close_owned(file, step, &mut self.observation)
    }
    fn close_owned(file: Option<File>, step: NodeDiskDirectoryOperationStep,
        observation: &mut NodeDiskDirectoryOperation) -> io::Result<()> {
        let Some(file) = file else { return Ok(()) };
        let fd = file.into_raw_fd();
        // Exactly one close consumes the descriptor. A nonzero result is not
        // permission to retry a possibly recycled descriptor or release credit.
        let result = unsafe { libc::close(fd) };
        let result = if result == 0 { Ok(()) } else { Err(io::Error::last_os_error()) };
        #[cfg(test)]
        let result = result.and_then(|()| injected(step));
        if let Err(error) = result {
            observation.close_failure = Some(NodeDiskDirectoryFailure::new(step, &error));
            observation.uncertain_close_descriptor = Some(fd);
            return Err(error);
        }
        Ok(())
    }''' +s[b:]
s=s.replace('root, names, binding, parent, child: None, identity: None,','root, names, binding, parent, child: None, walk_current: None, walk_next: None, identity: None,')
s=s.replace('child: owner.file.take(), identity: Some(identity), allocation: None, plan,','child: owner.file.take(), walk_current: None, walk_next: None, identity: Some(identity), allocation: None, plan,')
s=s.replace('state.pending_directory.as_ref().expect("retained operation").verify_child(disk)?;','state.pending_directory.as_mut().expect("retained operation").verify_child(disk)?;\n    let operation = state.pending_directory.as_ref().expect("retained operation");\n    let metadata = operation.child.as_ref().expect("retained child").metadata()?;\n    let entry = state.accounted[&operation.identity.expect("recorded child")].directory().expect("recorded child");\n    if metadata.len() != entry.len || census::directory_extent(&metadata)? != entry.bytes - entry.pending {\n        return Err(io::ErrorKind::InvalidData.into());\n    }')
s=s.replace('let operation = state.pending_directory.as_ref().expect("retained operation");\n    operation.verify_parent(disk)?;', 'let operation = state.pending_directory.as_mut().expect("retained operation");\n    operation.verify_parent(disk)?;')
f.write_text(s)
