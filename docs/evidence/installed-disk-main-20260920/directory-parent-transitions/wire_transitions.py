from pathlib import Path
p=Path(__file__).resolve().parent/'proposed/crates/kasumi-store/src/node_disk'
f=p/'file.rs';s=f.read_text()
s=s.replace('    create: bool,\n    budget:', '    create: bool,\n    work: Option<DiskWork>,\n    budget:',1).replace('            create: create.is_some(),','            create: create.is_some(),\n            work: create,',1)
a='''    pub(super) fn execute(mut self) -> io::Result<NodeDiskFile> {
        if self.create {''';b='''    pub(super) fn execute(mut self) -> io::Result<NodeDiskFile> {
        verify_parent(&self.disk.roots[&self.root], &self.parent_names, &self.parent)
            .inspect_err(|_| self.disk.fail_locked(&mut self.state))?;
        if self.create {''';assert a in s;s=s.replace(a,b,1)
a='''        let flags = libc::O_RDWR''';b='''        let mut transition = if self.create {
            Some(ParentTransition::prepare(self.disk, &mut self.state, (self.parent.identity(), 1), None, self.work)?)
        } else { None };
        let flags = libc::O_RDWR''';assert a in s;s=s.replace(a,b,1)
a='''            Err(error) => {
                // An absent final leaf is harmless only if its complete name''';b='''            Err(error) => {
                if self.create && error.kind() == io::ErrorKind::AlreadyExists {
                    if let Err(rollback) = transition.take().expect("prepared creation parent")
                        .unchanged(self.disk, &mut self.state, &[&self.parent]) {
                        self.disk.fail_locked(&mut self.state);
                        return Err(rollback);
                    }
                }
                // An absent final leaf is harmless only if its complete name''';assert a in s;s=s.replace(a,b,1)
a='''                self.parent.file().sync_all()
            })();''';b='''                self.parent.file().sync_all()?;
                verify_parent(&self.disk.roots[&self.root], &self.parent_names, &self.parent)?;
                transition.take().expect("prepared creation parent")
                    .settle(self.disk, &mut self.state, &[&self.parent])
            })();''';assert a in s;s=s.replace(a,b,1)
a='''        *self.budget.get_mut().expect("unpublished budget") = Budget {''';b='''        self.parent.register(self.disk, &mut self.state)
            .inspect_err(|_| self.disk.fail_locked(&mut self.state))?;
        *self.budget.get_mut().expect("unpublished budget") = Budget {''';assert a in s;s=s.replace(a,b,1)
# Publication holds both descriptors in retained FileOwner on every error/unwind path.
a='''        let mut renamed = false;
        let result =''';b='''        let mut renamed = false;
        let mut transition = None;
        let result =''';assert a in s;s=s.replace(a,b,1)
a='''            #[cfg(target_os = "linux")]
            let status =''';b='''            transition = Some(ParentTransition::prepare(disk, &mut state,
                (owner.parent_custody().identity(), -1), Some((parent.identity(), 1)), Some(DiskWork::Maintenance))?);
            #[cfg(target_os = "linux")]
            let status =''';assert a in s;s=s.replace(a,b,1)
a='''            if status != 0 {
                return Err(io::Error::last_os_error());
            }
            renamed = true;
            let old_parent = owner
                .parent
                .replace(parent)
                .expect("live publication parent");
            owner.root = root;
            owner.relative = relative;
            owner.parent_names = parent_names;''';b='''            if status != 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::AlreadyExists {
                    transition.take().expect("prepared publication parents")
                        .unchanged(disk, &mut state, &[owner.parent_custody(), &parent])?;
                }
                return Err(error);
            }
            renamed = true;
            assert!(owner.retiring_parent.is_none(), "one prepared parent transfer");
            owner.retiring_parent = owner.parent.replace(parent);
            let old_root = std::mem::replace(&mut owner.root, root);
            owner.relative = relative;
            let old_parent_names = std::mem::replace(&mut owner.parent_names, parent_names);''';assert a in s;s=s.replace(a,b,1)
s=s.replace('            old_parent.sync_all()?;', '            owner.retiring_parent.as_ref().expect("retained source parent").file().sync_all()?;',1)
a='''            owner.parent().sync_all()?;
            #[cfg(test)]
            disk.namespace_checkpoint(NamespaceFailure::PublishVerify)?;''';b='''            owner.parent().sync_all()?;
            verify_parent(&disk.roots[&old_root], &old_parent_names, owner.retiring_parent.as_ref().expect("retained source parent"))?;
            #[cfg(test)]
            disk.namespace_checkpoint(NamespaceFailure::PublishVerify)?;''';assert a in s;s=s.replace(a,b,1)
# At the second publication extent comparison, the budget guard must be released before mutably transferring owner custody.
a='''            if AccountedFile::durable(owner.binding, bytes, pending, metadata.len())
                != budget.accounted(owner.binding)
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            Ok(())
        })();''';b='''            if AccountedFile::durable(owner.binding, bytes, pending, metadata.len())
                != budget.accounted(owner.binding)
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            drop(budget);
            transition.take().expect("prepared publication parents")
                .settle(disk, &mut state, &[owner.retiring_parent.as_ref().expect("retained source parent"), owner.parent_custody()])?;
            let old = owner.retiring_parent.take().expect("retained source parent").retire().expect("registered source parent");
            if !namespace::can_retire_parent(&state, old) { return Err(io::ErrorKind::InvalidData.into()); }
            namespace::retire_parent(&mut state, old);
            owner.parent.as_mut().expect("retained destination parent").register(disk, &mut state)?;
            Ok(())
        })();''';assert a in s;s=s.replace(a,b,1)
# Unlink settles the real parent's namespace before file charge retirement.
a='''            } else {
                actual.sync_all()?;
                if unsafe { libc::unlinkat(owner.parent().as_raw_fd(), owner.name().as_ptr(), 0) }''';b='''            } else {
                actual.sync_all()?;
                let transition = ParentTransition::prepare(self, &mut state, (owner.parent_custody().identity(), -1), None, None)?;
                if unsafe { libc::unlinkat(owner.parent().as_raw_fd(), owner.name().as_ptr(), 0) }''';assert a in s;s=s.replace(a,b,1)
a='''                owner.parent().sync_all()?;
                Ok((0, 0))''';b='''                owner.parent().sync_all()?;
                verify_parent(&self.roots[&owner.root], &owner.parent_names, owner.parent_custody())?;
                transition.settle(self, &mut state, &[owner.parent_custody()])?;
                Ok((0, 0))''';assert a in s;s=s.replace(a,b,1)
f.write_text(s)
# Actual directory reads expose observed allocation, not the unspent promise.
f=p/'directory.rs';s=f.read_text();a='''        Ok(state.accounted[&self.owner().identity]
            .directory()
            .expect("verified directory enrollment")
            .bytes)''';b='''        let entry = state.accounted[&self.owner().identity].directory().expect("verified directory enrollment");
        entry.bytes.checked_sub(entry.pending).ok_or_else(|| io::ErrorKind::InvalidData.into())''';assert a in s;s=s.replace(a,b,1);f.write_text(s)
# New bounded prepared ancestry backing has an explicit allowance as well.
f=p/'memory.rs';s=f.read_text();a='''        let handle = add(
            add(size::<file::FileOwner>()?, 16)?,
            add(NATIVE_HANDLE_WORKSPACE, add(paths, components)?)?,
        )?;''';b='''        let parent_ancestry = disk_memory::allocation::<Identity>(depth)?;
        let handle = add(
            add(size::<file::FileOwner>()?, 16)?,
            add(NATIVE_HANDLE_WORKSPACE, add(parent_ancestry, add(paths, components)?)?)?,
        )?;''';assert a in s;s=s.replace(a,b);f.write_text(s)
