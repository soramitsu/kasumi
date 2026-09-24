from pathlib import Path
import shutil,re
root=Path('/Users/mtakemiya/dev/kasumi');out=root/'target/installed-disk-validation/file-owner-retirement'
for rel in ['crates/kasumi-store/src/node_disk/file.rs','crates/kasumi-store/src/node_disk/tests.rs']:
 for layer in ['before','proposed']:
  p=out/layer/rel;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(root/rel,p)
p=out/'proposed/crates/kasumi-store/src/node_disk/file.rs';s=p.read_text()
# Only registered owners, not the raw prepared owner, carry takeable resources.
a=s.index('pub(super) struct FileOwner {');b=s.index('\n}\n',a)+3
part=s[a:b].replace('    parent: File,','    parent: Option<File>,').replace('    budget: Mutex<Budget>,','    budget: Option<Mutex<Budget>>,\n    registration: usize,')
s=s[:a]+part+s[b:]
s=s.replace('pub struct NodeDiskFile(Arc<FileOwner>);','pub struct NodeDiskFile(OwnedFileArc);\n\n/// Every private strong reference uses this retirement protocol. In particular,\n/// publication abandonment and failed exclusive unwrap must not let a raw Arc\n/// run FileOwner::drop while its backing allocation is still held implicitly.\n#[derive(Clone)]\nstruct OwnedFileArc(Option<Arc<FileOwner>>);\nimpl OwnedFileArc {\n    fn new(owner: Arc<FileOwner>) -> Self { Self(Some(owner)) }\n    fn try_unwrap(mut self) -> Result<FileOwner, Self> {\n        Arc::try_unwrap(self.0.take().expect("live file custody")).map_err(Self::new)\n    }\n}\nimpl std::ops::Deref for OwnedFileArc {\n    type Target = Arc<FileOwner>;\n    fn deref(&self) -> &Self::Target { self.0.as_ref().expect("live file custody") }\n}\nimpl std::ops::DerefMut for OwnedFileArc {\n    fn deref_mut(&mut self) -> &mut Self::Target { self.0.as_mut().expect("live file custody") }\n}\nimpl Drop for OwnedFileArc {\n    fn drop(&mut self) {\n        if let Some(arc) = self.0.take() {\n            if let Some(owner) = Arc::into_inner(arc) { drop(owner); }\n        }\n    }\n}')
# PreparedFile only has raw/provisional resources, so serialize through their destruction.
a=s.index('pub(super) struct PreparedFile<');b=s.index('\n}\n',a)+3
part=s[a:b];line='    state: std::sync::MutexGuard<\'a, State>,\n';assert line in part;part=part.replace(line,'');part=part[:-2]+line+'}\n';s=s[:a]+part+s[b:]
s=s.replace('                parent: self.parent,','                parent: Some(self.parent),',1).replace('                budget: self.budget,','                budget: Some(self.budget),\n                registration: 0,',1)
s=s.replace('        let owner = unsafe { self.allocation.assume_init() };','        let mut owner = unsafe { self.allocation.assume_init() };\n        let registration = Arc::as_ptr(&owner) as usize;\n        Arc::get_mut(&mut owner).expect("unregistered file owner").registration = registration;',1)
s=s.replace('        Ok(NodeDiskFile(owner))','        Ok(NodeDiskFile(OwnedFileArc::new(owner)))',1)
# Prepared publication temporaries must retire before releasing the serialization slot.
a=s.index('// Keep the state guard before the registered Arc:');b=s.index('\nimpl PreparedPublication',a)
s=s[:a]+'''// Abandoned target paths/FDs retire under serialization first. The guard then
// unlocks before registered custody runs its recursive retirement protocol.
pub(super) struct PreparedPublication<'a> {
    disk: &'a Arc<NodeDisk>,
    parent: File,
    name: CString,
    root: String,
    relative: PathBuf,
    parent_names: Box<[CString]>,
    binding: NamespaceBinding,
    state: std::sync::MutexGuard<'a, State>,
    retained: OwnedFileArc,
}
''' +s[b:]
s=s.replace('Arc::try_unwrap(file.0)','file.0.try_unwrap()')
s=s.replace('        let retained = Arc::new(owner);','        let retained = OwnedFileArc::new(Arc::new(owner));')
s=s.replace('        state.live.retain(|_, owner| owner.strong_count() != 0);','        // Retiring registrations remain exclusive until BOTH descriptors and\n        // their metadata backing are gone; strong_count == 0 is not drain.')
s=s.replace('''            if self
                .state
                .live
                .get(&identity)
                .is_some_and(|owner| owner.strong_count() != 0)''','''            if self.state.live.contains_key(&identity)''')
# Registered parent/budget accesses; prepared raw fields intentionally stay unchanged.
s=s.replace('owner.parent.as_raw_fd()', 'owner.parent().as_raw_fd()').replace('owner.parent.sync_all()', 'owner.parent().sync_all()')
s=s.replace('std::mem::replace(&mut owner.parent, parent)', 'owner.parent.replace(parent).expect("live publication parent")')
s=s.replace('self.0.parent.sync_all()', 'self.0.parent().sync_all()')
s=re.sub(r'owner\s*\.budget\b',lambda m:m.group(0)+'()',s)
# Success transfers the one exact weak registration while holding state.
s=s.replace('''        *state
            .live
            .get_mut(&retained.identity)''','''        let registration = Arc::as_ptr(&retained) as usize;
        Arc::get_mut(&mut retained).expect("unregistered publication Arc").registration = registration;
        *state
            .live
            .get_mut(&retained.identity)''',1)
# Methods inside FileOwner use a live resource accessor; Drop is replaced below.
a=s.index('impl FileOwner {');b=s.index('impl Drop for FileOwner {',a)
part=s[a:b].replace('self.budget.lock()', 'self.budget().lock()').replace('&self.parent,','self.parent(),')
part=part.replace('impl FileOwner {','''impl FileOwner {
    fn parent(&self) -> &File { self.parent.as_ref().expect("live parent descriptor") }
    fn budget(&self) -> &Mutex<Budget> { self.budget.as_ref().expect("live file budget") }
''',1)
s=s[:a]+part+s[b:]
# Reclaim destroys all owned resources and weak backing under state before credit.
a=s.index('    fn reclaim(');b=s.index('\n}\n\n// Return a conflict',a)
part=s[a:b].replace('        let owner = match file.0.try_unwrap()', '        let mut owner = match file.0.try_unwrap()')
old='''        drop(actual);
        state.open_files -= 1;
        state.live.remove(&owner.identity);
        let outcome = match result {'''
new='''        drop(actual);
        let old_bytes = budget.bytes;
        let old_pending = budget.pending;
        drop(budget);
        owner.retire_resources();
        if !owner.retire_registration(&mut state) {
            self.fail_locked(&mut state);
            return match result { Err(error) => Err(error), Ok(_) => Err(io::ErrorKind::InvalidData.into()) };
        }
        let outcome = match result {'''
assert old in part;part=part.replace(old,new)
start=part.index('        let outcome = match result {');tail=part[start:].replace('budget.bytes','old_bytes').replace('budget.pending','old_pending').replace('        drop(budget);\n','');part=part[:start]+tail
s=s[:a]+part+s[b:]
a=s.index('impl Drop for FileOwner {')
s=s[:a]+'''impl FileOwner {
    // This value is outside its original Arc. The live-map Weak is the last
    // admitted backing reference, and remains in place until resources retire.
    fn retire_resources(&mut self) {
        let Some(mut mutex) = self.budget.take() else { return; };
        let budget = mutex.get_mut().unwrap_or_else(|p| p.into_inner());
        drop(budget.file.take());
        #[cfg(test)]
        {
            let pause = self.disk.after_file_close.lock().unwrap().take();
            if let Some(pause) = pause {
                let _ = pause.entered.send(());
                pause.release.recv_timeout(std::time::Duration::from_secs(5)).expect("release closed-file fixture");
            }
        }
        drop(self.parent.take());
        drop(std::mem::take(&mut self.root));
        drop(std::mem::take(&mut self.relative));
        drop(std::mem::replace(&mut self.parent_names, Box::new([])));
        drop(std::mem::take(&mut self.name));
        // Includes the lazily initialized native mutex backing on Darwin.
        drop(mutex);
    }

    fn retire_registration(&mut self, state: &mut State) -> bool {
        if self.registration == 0 || !state.live.get(&self.identity)
            .is_some_and(|entry| entry.as_ptr() as usize == self.registration) {
            return false;
        }
        let Some(next) = state.open_files.checked_sub(1) else { return false; };
        // Dropping the exact last Weak frees the original Arc allocation before
        // the slot can fund another handle. No strong/weak reference escapes.
        drop(state.live.remove(&self.identity));
        self.registration = 0;
        state.open_files = next;
        true
    }
}

impl Drop for FileOwner {
    fn drop(&mut self) {
        let Some(mutex) = self.budget.as_mut() else { return; };
        let budget = mutex.get_mut().unwrap_or_else(|p| {
            let budget = p.into_inner();
            budget.settled = false;
            budget
        });
        let settled = budget.settled;
        if !settled { self.disk.fail(); }
        self.retire_resources();
        let disk = self.disk.clone();
        let mut state = disk.lock_state();
        if !settled {
            if let Some(enrolled) = state.accounted.get_mut(&self.identity) { enrolled.settled = false; }
            disk.fail_locked(&mut state);
        }
        if !self.retire_registration(&mut state) { disk.fail_locked(&mut state); }
    }
}
'''
p.write_text(s)
