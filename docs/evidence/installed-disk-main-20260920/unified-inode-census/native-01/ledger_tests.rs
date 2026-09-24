#![allow(dead_code)]
use std::{collections::{BTreeMap,HashMap},ffi::CString,fs::File,path::PathBuf,sync::{Arc,Mutex,Weak}};
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Ord, PartialOrd)] struct Identity(u64,u64);
#[derive(Clone, Copy, Debug, PartialEq, Eq)] struct NamespaceBinding([u8;32]);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AccountedFile {
    binding: NamespaceBinding,
    bytes: u64,
    pending: u64,
    actual_len: u64,
    reserved_len: u64,
    settled: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AccountedDirectory {
    binding: NamespaceBinding,
    parent: Option<Identity>,
    bytes: u64,
    len: u64,
    children: u64,
    live_handles: u32,
}
impl AccountedFile {
    fn durable(binding: NamespaceBinding, bytes: u64, pending: u64, len: u64) -> Self {
        Self {
            binding,
            bytes,
            pending,
            actual_len: len,
            reserved_len: len,
            settled: true,
        }
    }
}
#[path = "/Users/mtakemiya/dev/kasumi/target/installed-disk-validation/unified-inode-census/proposed/crates/kasumi-store/src/node_disk/ledger.rs"] mod ledger;
use ledger::AccountedInode;
