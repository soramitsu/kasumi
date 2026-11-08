use super::{FRAME_CHARGE, LIVE_GROUP_MAX_BATCHES, LIVE_GROUP_MAX_BYTES, LiveDb, apply, op_charge};
use crate::{WalOp, live_wal::validate_wal_batch};
use arrayvec::ArrayVec;
use std::io;

impl LiveDb {
    /// Commit independent, already available batches in order. Each batch keeps
    /// its own sequence and atomic WAL frame. Success acknowledges every returned
    /// sequence after one shared WAL synchronization. After an uncertain error
    /// or interruption, reopen and inspect the recovered sequence. A complete
    /// prefix of unacknowledged batches may be present.
    ///
    /// Multi-batch calls accept up to 64 batches with at most 512 KiB in total
    /// conservative delta charges (128 per batch, 256 per operation, plus key
    /// and value bytes). A singleton accepts the ordinary commit limits.
    pub fn commit_group(&mut self, batches: &[&[WalOp<'_>]]) -> io::Result<Vec<u64>> {
        self.check()?;
        if batches.len() > LIVE_GROUP_MAX_BATCHES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "too many batches in live group",
            ));
        }
        let first = self.sequence();
        first
            .checked_add(batches.len() as u64)
            .ok_or_else(|| io::Error::other("WAL sequence exhausted"))?;
        let mut sequences = Vec::new();
        sequences
            .try_reserve_exact(batches.len())
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        sequences.extend((1..=batches.len() as u64).map(|offset| first + offset));
        match batches {
            [] => return Ok(sequences),
            [one] => {
                self.commit(one)?;
                return Ok(sequences);
            }
            _ => {}
        }

        let mut sizes = ArrayVec::<usize, LIVE_GROUP_MAX_BATCHES>::new();
        let mut charge = 0;
        let mut before_last = 0;
        for batch in batches {
            sizes.push(validate_wal_batch(batch)?);
            before_last = charge;
            charge += FRAME_CHARGE;
            for &op in *batch {
                charge += match op {
                    WalOp::Put(key, value) => op_charge(key, Some(value)),
                    WalOp::Delete(key) => op_charge(key, None),
                };
            }
            if charge > LIVE_GROUP_MAX_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "live group exceeds the checkpoint byte budget",
                ));
            }
        }

        // A recovered tail may cross the checkpoint boundary on its final
        // frame only. Rotating before this group preserves that existing rule
        // for every possible torn prefix, including a full unsynced group.
        if self.checkpoint_due() || self.pending + before_last >= self.checkpoint_budget() {
            self.flush(false)?;
        }
        self.wal.append_group(batches, &sizes)?;
        for batch in batches {
            self.pending += apply(&mut self.delta, batch);
        }
        if self.checkpoint_due() {
            self.flush(false)?;
        }
        Ok(sequences)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grouped_blocks_keep_individual_sequences_and_share_one_file_barrier() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("db");
        let mut db = LiveDb::create(&path).unwrap();
        let before = db.stats();
        assert!(db.commit_group(&[]).unwrap().is_empty());
        let batches: &[&[WalOp<'_>]] = &[
            &[WalOp::Put(b"k", b"first")],
            &[],
            &[WalOp::Delete(b"k"), WalOp::Put(b"", b"")],
        ];
        assert_eq!(db.commit_group(batches).unwrap(), vec![1, 2, 3]);
        let after = db.stats();
        assert_eq!(after.file_syncs, before.file_syncs + 1);
        assert_eq!(after.directory_syncs, before.directory_syncs);
        assert_eq!(db.get(b"k").unwrap(), None);
        drop(db);
        let mut reopened = LiveDb::open(&path).unwrap();
        assert_eq!(reopened.sequence(), 3);
        assert_eq!(reopened.get(b"").unwrap(), Some(vec![]));
        assert_eq!(reopened.commit_group(&[&[]]).unwrap(), vec![4]);
    }

    #[test]
    fn invalid_groups_leave_a_nearly_full_tail_untouched_and_valid_group_rotates_first() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("db");
        let mut db =
            LiveDb::create_with_buffer(&path, super::super::LIVE_CHECKPOINT_BYTES).unwrap();
        let large = vec![42; db.checkpoint_budget() as usize - 900];
        db.commit(&[WalOp::Put(b"large", &large)]).unwrap();
        let before = db.stats();
        let bad = [WalOp::Delete(&[0; crate::MAX_KEY + 1])];
        let over_budget = [WalOp::Put(b"k", &large)];
        let small = [WalOp::Put(b"a", &[1; 256])];
        assert!(db.commit_group(&[&small, &bad]).is_err());
        assert!(db.commit_group(&[&small, &over_budget]).is_err());
        let too_many = [&[] as &[WalOp<'_>]; LIVE_GROUP_MAX_BATCHES + 1];
        assert!(db.commit_group(&too_many).is_err());
        assert_eq!(db.stats().wal_bytes, before.wal_bytes);
        assert_eq!(db.stats().file_syncs, before.file_syncs);
        assert_eq!(db.sequence(), 1);
        assert_eq!(
            db.commit_group(&[&small, &[], &small]).unwrap(),
            vec![2, 3, 4]
        );
        assert_eq!(db.stats().base_sequence, 1);
        drop(db);
        let mut reopened = LiveDb::open(&path).unwrap();
        assert_eq!(reopened.sequence(), 4);
        assert_eq!(reopened.get(b"large").unwrap(), Some(large));
        assert_eq!(reopened.get(b"a").unwrap(), Some(vec![1; 256]));
    }
}
