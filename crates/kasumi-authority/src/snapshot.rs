//! Bounded authority records with encrypted point-addressed validation staging.
use super::*;
use kasumi_store::{EncryptedTable, TenantReadView};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
const MAGIC: &[u8; 8] = b"KASUMIA2";
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", content = "value", deny_unknown_fields)]
enum Frame {
    Meta(Box<Meta>),
    Entry(String, Box<Record>),
}
pub(super) struct SnapshotRecords(EncryptedTable);
impl SnapshotRecords {
    pub(super) fn get(&self, key: &str) -> Result<Option<Record>> {
        self.0
            .get(key.as_bytes())?
            .map(|bytes| serde_json::from_slice(&bytes).map_err(Into::into))
            .transpose()
    }
    pub(super) fn contains_key(&self, key: &str) -> Result<bool> {
        Ok(self.get(key)?.is_some())
    }
    pub(super) fn visit(&self, mut visitor: impl FnMut(&str, &Record) -> Result<()>) -> Result<()> {
        self.0.visit(|key, value| {
            if key == META {
                return Ok(());
            }
            visitor(std::str::from_utf8(key)?, &serde_json::from_slice(value)?)
        })
    }
    pub(super) fn replacements(&self) -> Vec<(&str, &EncryptedTable)> {
        vec![(NS, &self.0)]
    }
}
fn disk_budget(maximum: u64) -> Result<u64> {
    maximum
        .checked_mul(8)
        .and_then(|n| n.checked_add(64 << 20))
        .context("authority staging budget overflow")
}
pub(super) fn write(view: &TenantReadView, maximum: u64, output: &mut dyn Write) -> Result<()> {
    let meta: Meta = serde_json::from_slice(
        &view
            .get(NS, META, MAX_RECORD_BYTES)?
            .context("authority metadata missing")?,
    )?;
    let records = SnapshotRecords(EncryptedTable::new(
        view.scratch_disk(),
        disk_budget(maximum)?,
    )?);
    view.visit(NS, MAX_RECORD_BYTES, |key, bytes| {
        if key != META {
            let record: Record = serde_json::from_slice(bytes)?;
            records.0.insert(key, &serde_json::to_vec(&record)?)?;
        }
        Ok(())
    })?;
    output.write_all(MAGIC)?;
    let mut digest = Sha256::new();
    digest.update(MAGIC);
    let (mut count, mut total) = (0u64, 8u64);
    let mut emit = |frame: Frame| -> Result<()> {
        let bytes = serde_json::to_vec(&frame)?;
        ensure!(
            bytes.len() <= MAX_RECORD_BYTES + 8192,
            "authority frame exceeds bound"
        );
        let length = (bytes.len() as u64).to_be_bytes();
        output.write_all(&length)?;
        output.write_all(&bytes)?;
        digest.update(length);
        digest.update(&bytes);
        count = count
            .checked_add(1)
            .context("authority record count overflow")?;
        total = total
            .checked_add(8 + bytes.len() as u64)
            .context("authority snapshot byte overflow")?;
        Ok(())
    };
    emit(Frame::Meta(Box::new(meta)))?;
    records.visit(|key, record| emit(Frame::Entry(key.to_owned(), Box::new(record.clone()))))?;
    output.write_all(&0u64.to_be_bytes())?;
    output.write_all(&count.to_be_bytes())?;
    output.write_all(&total.to_be_bytes())?;
    output.write_all(&digest.finalize())?;
    Ok(())
}
pub(super) fn read(
    scratch_disk: &Arc<kasumi_store::ScratchDisk>,
    input: &mut dyn Read,
    maximum: u64,
) -> Result<Snapshot> {
    let mut magic = [0; 8];
    input.read_exact(&mut magic)?;
    ensure!(&magic == MAGIC, "unsupported authority snapshot format");
    let mut digest = Sha256::new();
    digest.update(magic);
    let (mut count, mut total, mut record_bytes) = (0u64, 8u64, 0u64);
    let mut meta = None;
    let mut previous = None;
    let records = SnapshotRecords(EncryptedTable::new(scratch_disk, disk_budget(maximum)?)?);
    loop {
        let mut length = [0; 8];
        input.read_exact(&mut length)?;
        let size = u64::from_be_bytes(length);
        if size == 0 {
            let mut footer = [0; 48];
            input.read_exact(&mut footer)?;
            ensure!(
                count > 0
                    && count == u64::from_be_bytes(footer[..8].try_into()?)
                    && total == u64::from_be_bytes(footer[8..16].try_into()?)
                    && digest.finalize().as_slice() == &footer[16..],
                "authority snapshot final authentication differs"
            );
            ensure!(
                input.read(&mut [0])? == 0,
                "authority snapshot trailing data"
            );
            return Ok(Snapshot {
                meta: meta.context("authority metadata absent")?,
                records,
            });
        }
        ensure!(
            size <= (MAX_RECORD_BYTES + 8192) as u64,
            "authority frame exceeds bound"
        );
        let mut bytes = vec![0; size as usize];
        input.read_exact(&mut bytes)?;
        let frame: Frame = serde_json::from_slice(&bytes)?;
        ensure!(
            serde_json::to_vec(&frame)? == bytes,
            "authority frame is not canonical"
        );
        digest.update(length);
        digest.update(&bytes);
        total = total
            .checked_add(8 + size)
            .context("authority snapshot byte overflow")?;
        count = count
            .checked_add(1)
            .context("authority record count overflow")?;
        match frame {
            Frame::Meta(value) => {
                ensure!(meta.is_none() && count == 1, "authority metadata misplaced");
                records.0.insert(META, &serde_json::to_vec(&value)?)?;
                meta = Some(*value);
            }
            Frame::Entry(key, value) => {
                ensure!(
                    meta.is_some()
                        && key.as_bytes() != META
                        && previous.as_ref().is_none_or(|p: &String| p < &key),
                    "authority record ordering differs"
                );
                let bytes = serde_json::to_vec(&value)?;
                record_bytes = record_bytes
                    .checked_add(bytes.len() as u64)
                    .context("authority record byte overflow")?;
                ensure!(
                    bytes.len() <= MAX_RECORD_BYTES && record_bytes <= maximum,
                    "authority staging quota exceeded"
                );
                records.0.insert(key.as_bytes(), &bytes)?;
                previous = Some(key);
            }
        }
    }
}

#[cfg(test)]
pub(crate) fn rewrite_for_test(
    bytes: &[u8],
    mut rewrite: impl FnMut(&mut serde_json::Value),
) -> Vec<u8> {
    let mut input = &bytes[8..];
    let mut output = MAGIC.to_vec();
    let mut digest = Sha256::new();
    digest.update(MAGIC);
    let (mut count, mut total) = (0u64, 8u64);
    loop {
        let mut length = [0; 8];
        input.read_exact(&mut length).unwrap();
        let size = u64::from_be_bytes(length) as usize;
        if size == 0 {
            break;
        }
        let mut bytes = vec![0; size];
        input.read_exact(&mut bytes).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        rewrite(&mut value);
        let frame: Frame = serde_json::from_value(value).unwrap();
        let bytes = serde_json::to_vec(&frame).unwrap();
        let length = (bytes.len() as u64).to_be_bytes();
        output.extend_from_slice(&length);
        output.extend_from_slice(&bytes);
        digest.update(length);
        digest.update(&bytes);
        count += 1;
        total += 8 + bytes.len() as u64;
    }
    output.extend_from_slice(&0u64.to_be_bytes());
    output.extend_from_slice(&count.to_be_bytes());
    output.extend_from_slice(&total.to_be_bytes());
    output.extend_from_slice(&digest.finalize());
    output
}
