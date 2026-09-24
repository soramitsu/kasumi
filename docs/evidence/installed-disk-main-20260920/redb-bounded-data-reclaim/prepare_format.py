from pathlib import Path
r=Path('/Users/mtakemiya/dev/kasumi/target/installed-disk-validation/redb-bounded-data-reclaim/proposed/vendor/redb-4.2.0/src')
for p in r.rglob('*.rs'):
 s=p.read_text();s=s.replace('FILE_FORMAT_VERSION3','FILE_FORMAT_VERSION4').replace('UpgradeRequired','UnsupportedFileFormat')
 s=s.replace('Manual upgrade required. Expected file format version {FILE_FORMAT_VERSION4}, but file is version {actual}','Unsupported file format {actual}; this build requires canonical format {FILE_FORMAT_VERSION4}')
 p.write_text(s)
p=r/'tree_store/page_store/page_manager.rs';s=p.read_text();a=s.index('// Original file format.');b=s.index('\n#[derive(Copy, Clone)]',a)
s=s[:a]+'''// The sole canonical format: data deferred frees use fixed PageList records;
// obsolete system pages are excluded from the prepared winning allocator and
// returned to the live allocator only after that header is durable. Formats
// 1, 2 and 3 are rejected; no upgrade or historical-system-table decoder exists.
pub(crate) const FILE_FORMAT_VERSION4: u8 = 4;
'''+s[b:];p.write_text(s)
p=r/'tree_store/page_store/header.rs';s=p.read_text();s=s.replace('FILE_FORMAT_VERSION1, FILE_FORMAT_VERSION2, FILE_FORMAT_VERSION4, xxh3_checksum','FILE_FORMAT_VERSION4, xxh3_checksum');a=s.index('        match version {',s.index('impl TransactionHeader'));b=s.index('        let checksum =',a)
s=s[:a]+'''        if version != FILE_FORMAT_VERSION4 {
            return Err(DatabaseError::UnsupportedFileFormat(version));
        }
'''+s[b:];p.write_text(s)
p=r/'error.rs';s=p.read_text();s=s.replace('    InvalidPageList,','    InvalidPageList,\n    /// The canonical system namespace contains an explicitly forbidden old table.\n    ObsoleteSystemTable,')
s=s.replace('            StorageError::InvalidPageList => Error::InvalidPageList,','            StorageError::InvalidPageList => Error::InvalidPageList,\n            StorageError::ObsoleteSystemTable => Error::ObsoleteSystemTable,')
s=s.replace('            StorageError::InvalidPageList => write!(f, "invalid canonical page-list record"),','            StorageError::InvalidPageList => write!(f, "invalid canonical page-list record"),\n            StorageError::ObsoleteSystemTable => write!(f, "obsolete system table is forbidden"),')
s=s.replace('            Error::InvalidPageList => write!(f, "invalid canonical page-list record"),','            Error::InvalidPageList => write!(f, "invalid canonical page-list record"),\n            Error::ObsoleteSystemTable => write!(f, "obsolete system table is forbidden"),')
s=s.replace('The database file is in an old format and needs to be upgraded','The database file does not use this build\'s sole canonical format')
p.write_text(s)
# Presence checks intentionally avoid decoding the obsolete table payload/type.
p=r/'tree_store/table_tree.rs';s=p.read_text();needle='    pub(crate) fn get_table_untyped(\n';assert s.count(needle)==2
s=s.replace(needle,'''    pub(crate) fn contains_table_name(&self, name: &str) -> Result<bool> {
        Ok(self.tree.get(&name)?.is_some())
    }

'''+needle);p.write_text(s)
