use super::{Entry, LiveDb, MAX_LEVELS, live_levels};
use std::io;

impl LiveDb {
    /// Atomically initialize a pristine database from strictly increasing binary
    /// rows. Successful publication consumes sequence 1. A source or I/O error
    /// requires reopening the handle; recovery selects either the empty genesis
    /// or the fully written base. Continuing normal commits writes younger tiers.
    pub fn load_sorted(
        &mut self,
        rows: impl IntoIterator<Item = io::Result<(Vec<u8>, Vec<u8>)>>,
    ) -> io::Result<u64> {
        self.check()?;
        if self.sequence() != 0 {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "bulk loading requires an empty genesis",
            ));
        }
        self.fenced = true;
        // A bulk base has no comparable count of ordinary WAL batches. Keep it
        // below all younger levels until an explicit full checkpoint requests
        // merging it. This avoids rewriting a large import on its next flush.
        let mut entry = Entry {
            tier: (MAX_LEVELS - 1) as u8,
            sequence: 1,
            root: [0; 32],
        };
        let mut file = self.files.fresh(&entry.name(&self.head.id))?;
        let (root, count) = live_levels::write_sorted(&mut file, rows)?;
        entry.root = root;
        self.publish_level(entry, file, 0)?;
        Ok(count)
    }
}
