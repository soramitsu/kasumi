from pathlib import Path
import json,hashlib,subprocess,os
p=Path(__file__).resolve().parent; root=Path.cwd(); s=p/'proposed/crates/kasumi-store/src'
(d:=p/'native-01').mkdir(exist_ok=False)
node=(s/'node_disk.rs').read_text()
def block(text,needle):
 start=text.index(needle); i=text.index('{',start); depth=1;j=i+1
 while depth:
  depth += (text[j]=='{')-(text[j]=='}');j+=1
 return text[start:j]
def decl(path,needle):return block(path.read_text(),needle)
common='''#![allow(dead_code)]
use std::{collections::{BTreeMap,HashMap},ffi::CString,fs::File,path::PathBuf,sync::{Arc,Mutex,Weak}};
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Ord, PartialOrd)] struct Identity(u64,u64);
#[derive(Clone, Copy, Debug, PartialEq, Eq)] struct NamespaceBinding([u8;32]);
'''
for item in ['struct AccountedFile','struct AccountedDirectory']:
 common+='#[derive(Clone, Copy, Debug, PartialEq, Eq)]\n'+block(node,item)+'\n'
common+=block(node,'impl AccountedFile')+'\n'
common+=f'#[path = {json.dumps(str(s/"node_disk/ledger.rs"))}] mod ledger;\nuse ledger::AccountedInode;\n'
(d/'ledger_tests.rs').write_text(common)
probe=common+'''extern crate self as anyhow;
pub type Result<T> = std::result::Result<T,std::io::Error>;
extern crate self as uuid;
#[repr(transparent)] pub struct Uuid([u8;16]);
mod libc { pub enum DIR {} }
trait NodeDiskMemoryAdmission: Send + Sync {}
trait RetireLease: Send + Sync {}
struct DiskMemoryLease(Option<Box<dyn RetireLease>>);
type Lease = DiskMemoryLease;
'''
probe+=block(node,'pub struct NodeDiskConfig')+'\nimpl NodeDiskConfig { fn validate(&self) -> Result<()> { Ok(()) } }\n'
probe+=block(node,'pub enum NodeDiskPhase')+'\n'
probe+=block(node,'struct State')+'\n'
probe+=block(node,'pub struct NodeDisk {')+'\n'
probe+=decl(root/'crates/kasumi-store/src/device_disk.rs','pub(crate) struct DeviceDisk')+'\nstruct Device;\n'
probe+='mod file { use super::*;\n'+decl(s/'node_disk/file.rs','struct Budget')+'\n'+decl(s/'node_disk/file.rs','pub(super) struct FileOwner')+'\n}\n'
probe+='mod directory { use super::*;\n'+decl(s/'node_disk/directory.rs','pub(super) struct DirectoryOwner')+'\n}\n'
probe+='mod census { use super::*;\n'+decl(s/'node_disk/census.rs','pub(super) struct Root')+'\n'+decl(s/'node_disk/census.rs','pub(super) struct Cursor')+'\n}\nuse census::Root;\n'
helpers=(root/'crates/kasumi-store/src/disk_memory.rs').read_text()
probe+='mod disk_memory { use std::io; const ALLOCATION_ALLOWANCE:u64=4096;\n'+helpers[helpers.index('pub(crate) fn overflow'):helpers.index('/// No global Vec/HashMap')]+'\n}\n'
probe+=f'#[path = {json.dumps(str(s/"node_disk/memory.rs"))}] mod memory;\n'
probe+='''fn main() {
    println!("Exact proposed memory.rs and ledger.rs, extracted field declarations; stub validation and external pointed-to implementations. Layout/formula evidence only, not compiled production/RSS qualification.");
    println!("AccountedFile={} AccountedDirectory={} AccountedInode={} Identity={} FileOwner={} DirectoryOwner={} State={} NodeDisk={}", size_of::<AccountedFile>(),size_of::<AccountedDirectory>(),size_of::<AccountedInode>(),size_of::<Identity>(),size_of::<file::FileOwner>(),size_of::<directory::DirectoryOwner>(),size_of::<State>(),size_of::<NodeDisk>());
    for (entries,handles,roots) in [(1_000_000,4096,vec![("data", "/var/lib/kasumi/data")]), (1_000_000,4096,vec![("data", "/var/lib/kasumi/data"),("metadata", "/var/lib/kasumi/metadata")]), (16_384,256,vec![("fixture", "/tmp/fixture-root-xx")])] {
        let config=NodeDiskConfig{roots:roots.iter().map(|(k,v)|(k.to_string(),PathBuf::from(v))).collect(),max_bytes:128<<30,maintenance_reserve_bytes:1<<30,min_free_bytes:1<<30,max_open_files:handles,max_open_directories:handles,max_census_entries:entries,max_depth:64,max_name_bytes:255};
        let (old,new)=ledger::capacities(entries,roots.len() as u64).unwrap();
        let table=|n:u64| 4*n.max(4)*(size_of::<(Identity,AccountedInode)>() as u64+16)+4096;
        let total=NodeDisk::required_metadata_bytes(&config).unwrap();
        println!("entries={entries} file_handles={handles} directory_handles={handles} roots={roots:?} old_max={old} new_max={new} old_table_bytes={} new_table_bytes={} total_metadata={total} mib={:.6} remaining_2gib={} ",table(old),table(new),total as f64/(1<<20) as f64,(2u64<<30)-total);
    }
}
'''
(d/'metadata_formula.rs').write_text(probe)
