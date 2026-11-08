use super::{DIGEST, HEADER, Wal, WalOp, reserve, sync_durable};
use std::{
    fs::File,
    io::{self, Write},
};

impl Wal {
    // The live engine validated every batch and supplied exact raw sizes.
    // Construct the complete chain in bounded scratch before entering the
    // physical effect. The on-disk frames are identical to serial appends.
    pub(crate) fn append_group(
        &mut self,
        batches: &[&[WalOp<'_>]],
        sizes: &[usize],
    ) -> io::Result<()> {
        self.append_group_with_sync(batches, sizes, sync_durable)
    }

    pub(super) fn append_group_with_sync(
        &mut self,
        batches: &[&[WalOp<'_>]],
        sizes: &[usize],
        sync: impl FnOnce(&File) -> io::Result<()>,
    ) -> io::Result<()> {
        if self.fenced {
            return Err(io::Error::other("WAL writer requires recovery"));
        }
        debug_assert_eq!(batches.len(), sizes.len());
        debug_assert!(!batches.is_empty());
        let last = self
            .sequence
            .checked_add(batches.len() as u64)
            .ok_or_else(|| io::Error::other("WAL sequence exhausted"))?;
        let mut bytes = Vec::new();
        reserve(
            &mut bytes,
            sizes.iter().sum::<usize>() + batches.len() * (HEADER + DIGEST),
        )?;
        let mut previous = self.previous;
        for (index, (ops, size)) in batches.iter().zip(sizes).enumerate() {
            let sequence = self.sequence + index as u64 + 1;
            let (frame, digest) = self.encoder.encode(ops, *size, sequence, &previous)?;
            bytes.extend_from_slice(frame);
            previous = digest;
        }
        let end = self
            .end
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| io::Error::other("WAL file size exhausted"))?;
        self.fenced = true;
        self.file.write_all(&bytes)?;
        sync(&self.file)?;
        self.syncs = self.syncs.saturating_add(1);
        self.previous = previous;
        self.end = end;
        self.sequence = last;
        self.fenced = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::{WAL_HEADER, read_frames, validate_wal_batch};
    use super::*;
    use std::fs;

    #[test]
    fn group_wire_equals_serial_and_every_torn_prefix_recovers_complete_blocks() {
        let root = [13; 32];
        let source = tempfile::NamedTempFile::new().unwrap();
        let mut wal = Wal::initialize(source.reopen().unwrap(), 0, root).unwrap();
        let a = [WalOp::Put(b"a", b"first")];
        let b = [WalOp::Delete(b"a"), WalOp::Put(b"b", &[42; 256])];
        let batches: &[&[WalOp<'_>]] = &[&a, &[], &b];
        let sizes: Vec<_> = batches
            .iter()
            .map(|b| validate_wal_batch(b).unwrap())
            .collect();
        let mut ends = vec![WAL_HEADER as u64];
        for batch in batches {
            wal.append(batch).unwrap();
            ends.push(wal.len());
        }
        let expected = fs::read(source.path()).unwrap();
        let grouped = tempfile::NamedTempFile::new().unwrap();
        let mut wal = Wal::initialize(grouped.reopen().unwrap(), 0, root).unwrap();
        let result = wal.append_group_with_sync(batches, &sizes, |_| {
            Err(io::Error::other("injected group sync failure"))
        });
        assert!(result.is_err() && wal.is_fenced());
        assert_eq!((wal.sequence(), wal.syncs()), (0, 1));
        assert!(wal.append(&a).is_err());
        assert_eq!(fs::read(grouped.path()).unwrap(), expected);
        let tmp = tempfile::NamedTempFile::new().unwrap();
        for cut in WAL_HEADER..=expected.len() {
            fs::write(tmp.path(), &expected[..cut]).unwrap();
            let (seq, end, _, _) = read_frames(tmp.as_file(), 0, root, |seq, ops| {
                assert_eq!(ops, batches[(seq - 1) as usize]);
                Ok(())
            })
            .unwrap();
            let count = ends.partition_point(|end| *end <= cut as u64) - 1;
            assert_eq!((seq, end), (count as u64, ends[count]), "cut {cut}");
        }
    }
}
