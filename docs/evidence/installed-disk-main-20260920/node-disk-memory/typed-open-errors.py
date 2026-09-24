from pathlib import Path
import re
exec(Path('target/installed-disk-validation/node-disk-memory/migrate-fixtures.py').read_text().split('callrx=')[0])
root=OUT/'proposed/crates/kasumi-store/src'
p=root/'disk_memory.rs';s=p.read_text();at=s.index('/// Four independently')
s=s[:at]+'''/// Registry contention is returned inline before any resident acquisition.
/// Other constructor failures preserve their original diagnostic chain.
#[derive(Debug)]
pub enum DiskOpenError {
    RegistryBusy,
    Failed(anyhow::Error),
}
impl std::fmt::Display for DiskOpenError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RegistryBusy => formatter.write_str("installed disk registry is busy"),
            Self::Failed(error) => std::fmt::Display::fmt(error, formatter),
        }
    }
}
impl std::error::Error for DiskOpenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self { Self::RegistryBusy => None, Self::Failed(error) => Some(error.as_ref()) }
    }
}
impl From<anyhow::Error> for DiskOpenError {
    fn from(error:anyhow::Error) -> Self { Self::Failed(error) }
}
impl From<io::Error> for DiskOpenError {
    fn from(error:io::Error) -> Self { Self::Failed(error.into()) }
}
impl From<io::ErrorKind> for DiskOpenError {
    fn from(kind:io::ErrorKind) -> Self { io::Error::from(kind).into() }
}
pub(crate) fn require(condition:bool, message:&'static str) -> Result<(),DiskOpenError> {
    if condition { Ok(()) } else { Err(DiskOpenError::Failed(anyhow::Error::msg(message))) }
}

'''+s[at:];p.write_text(s)
p=root/'lib.rs';s=p.read_text().replace('pub use disk_memory::{DiskMemoryRequirements, NodeDiskMemoryAdmission};','pub use disk_memory::{DiskMemoryRequirements, DiskOpenError, NodeDiskMemoryAdmission};');p.write_text(s)
def change_ensures(s):
 m=mask(s);edits=[]
 for x in re.finditer(r'ensure!\s*\(',m):
  start=x.end()-1;end=close(m,start)
  edits.append((x.start(),start+1,'disk_memory::require('));edits.append((end+1,end+1,'?'))
 for a,b,v in sorted(edits,reverse=True):s=s[:a]+v+s[b:]
 return s
p=root/'node_disk.rs';s=p.read_text();s=s.replace('DiskMemoryRequirements, Lease, List, NodeDiskMemoryAdmission,','DiskMemoryRequirements, DiskOpenError, Lease, List, NodeDiskMemoryAdmission,')
if 'DiskOpenError' not in s[:600]:s='use crate::DiskOpenError;\n'+s
for name in ['open','open_fixture','open_inner','fixture_for_path']:
 a=s.index('    '+('fn ' if name=='open_inner' else 'pub fn ')+name+'(');body=s.index('{',a);end=close(mask(s),body)+1;part=s[a:end]
 part=part.replace('-> Result<Arc<Self>>','-> std::result::Result<Arc<Self>, DiskOpenError>').replace('.ok_or(io::ErrorKind::WouldBlock)?','.ok_or(DiskOpenError::RegistryBusy)?');part=change_ensures(part)
 s=s[:a]+part+s[end:]
p.write_text(s)
p=root/'scratch_disk.rs';s=p.read_text();s='use crate::DiskOpenError;\n'+s
for name in ['open','open_fixture','open_inner']:
 a=s.index('    '+('fn ' if name=='open_inner' else 'pub fn ')+name+'(');body=s.index('{',a);end=close(mask(s),body)+1;part=s[a:end]
 part=part.replace('-> Result<Arc<Self>>','-> std::result::Result<Arc<Self>, DiskOpenError>').replace('.ok_or(io::ErrorKind::WouldBlock)?','.ok_or(DiskOpenError::RegistryBusy)?');part=change_ensures(part)
 part=part.replace('CString::new(config.directory.as_os_str().as_bytes())?','CString::new(config.directory.as_os_str().as_bytes()).map_err(anyhow::Error::from)?').replace('return Err(error.context("creating scratch directory"))','return Err(error.context("creating scratch directory").into())')
 s=s[:a]+part+s[end:]
s=s.replace('Option<tempfile::TempDir>','Option<Arc<tempfile::TempDir>>')
p.write_text(s)
p=root/'device_disk.rs';s=p.read_text();s='use crate::DiskOpenError;\n'+s
# DeviceSelection::open and DeviceDisk::open/open_registered preserve inline Busy.
for token in ['    pub(crate) fn open(', '    fn open_registered(']:
 start=0
 while (a:=s.find(token,start))>=0:
  body=s.index('{',a);end=close(mask(s),body)+1;part=s[a:end]
  part=part.replace('-> std::io::Result<DeviceDisk>', '-> Result<DeviceDisk, DiskOpenError>').replace('-> std::io::Result<Self>', '-> Result<Self, DiskOpenError>')
  part=part.replace('.ok_or(std::io::ErrorKind::WouldBlock)?','.ok_or(DiskOpenError::RegistryBusy)?').replace('Self::Isolated => DeviceDisk::isolated(minimum, memory),','Self::Isolated => DeviceDisk::isolated(minimum, memory).map_err(Into::into),').replace('return Self::register(existing.device.clone(), minimum_free_bytes);','return Self::register(existing.device.clone(), minimum_free_bytes).map_err(Into::into);')
  s=s[:a]+part+s[end:];start=a+len(part)
p.write_text(s)
