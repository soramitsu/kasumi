//! Canonical snapshot transport: one bounded metadata record, fixed-size data
//! records, and an authenticated terminal byte count, record count, and digest.
//! No aggregate length is narrowed to the platform's allocation size.
use crate::storage::{SnapshotEnvelope, SnapshotKind};
use anyhow::{Result, ensure};
use kasumi_store::{EncryptedSpool, SnapshotImage};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

const MAGIC: &[u8; 8] = b"KASUMIS2";
const METADATA: u8 = 1;
const DATA: u8 = 2;
const END: u8 = 3;
const CHUNK: usize = 64 << 10;
const MAX_METADATA: usize = 2 << 20;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    version: u32,
    kind: SnapshotKind,
    meta: openraft::SnapshotMeta<u64, crate::BasicNode>,
    retirement: Option<crate::snapshot_custody::SnapshotRetirement>,
}

fn frame(writer: &mut dyn Write, tag: u8, bytes: &[u8], digest: &mut Sha256) -> Result<()> {
    let mut header = [0; 9];
    header[0] = tag;
    header[1..].copy_from_slice(&(bytes.len() as u64).to_be_bytes());
    writer.write_all(&header)?;
    writer.write_all(bytes)?;
    digest.update(header);
    digest.update(bytes);
    Ok(())
}

impl SnapshotEnvelope {
    pub(crate) fn encode(&self, limit: u64) -> Result<SnapshotImage> {
        SnapshotImage::capture(limit, |writer| {
            let header = serde_json::to_vec(&Header {
                version: self.version,
                kind: self.kind,
                meta: self.meta.clone(),
                retirement: self.retirement.clone(),
            })?;
            ensure!(
                header.len() <= MAX_METADATA,
                "snapshot metadata limit exceeded"
            );
            writer.write_all(MAGIC)?;
            let mut digest = Sha256::new();
            digest.update(MAGIC);
            frame(writer, METADATA, &header, &mut digest)?;
            let mut reader = self.backend.reader();
            let mut buffer = vec![0; CHUNK];
            let mut total = 0u64;
            let mut records = 0u64;
            while total < self.backend.len() {
                let count = (self.backend.len() - total).min(CHUNK as u64) as usize;
                reader.read_exact(&mut buffer[..count])?;
                frame(writer, DATA, &buffer[..count], &mut digest)?;
                total = total
                    .checked_add(count as u64)
                    .ok_or_else(|| anyhow::anyhow!("snapshot byte overflow"))?;
                records = records
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("snapshot count overflow"))?;
            }
            writer.write_all(&[END])?;
            writer.write_all(&total.to_be_bytes())?;
            writer.write_all(&records.to_be_bytes())?;
            writer.write_all(&digest.finalize())?;
            Ok(())
        })
    }

    pub(crate) fn decode(reader: &mut dyn Read, limit: u64) -> Result<Self> {
        let mut magic = [0; 8];
        reader.read_exact(&mut magic)?;
        ensure!(&magic == MAGIC, "unsupported snapshot stream format");
        let mut digest = Sha256::new();
        digest.update(magic);
        let mut header = None;
        let mut spool = EncryptedSpool::new(limit)?;
        let mut records = 0u64;
        let mut encoded_bytes = 8u64;
        let mut short_record = false;
        loop {
            let mut tag = [0];
            reader.read_exact(&mut tag)?;
            if tag[0] == END {
                let mut footer = [0; 48];
                reader.read_exact(&mut footer)?;
                ensure!(
                    header.is_some()
                        && u64::from_be_bytes(footer[..8].try_into()?) == spool.len()
                        && u64::from_be_bytes(footer[8..16].try_into()?) == records
                        && digest.finalize().as_slice() == &footer[16..],
                    "snapshot terminal authentication differs"
                );
                ensure!(
                    encoded_bytes
                        .checked_add(49)
                        .is_some_and(|bytes| bytes <= limit),
                    "snapshot exceeds byte limit"
                );
                ensure!(reader.read(&mut tag)? == 0, "trailing snapshot bytes");
                break;
            }
            let mut length = [0; 8];
            reader.read_exact(&mut length)?;
            let size = u64::from_be_bytes(length);
            let cap = match tag[0] {
                METADATA if header.is_none() => MAX_METADATA,
                DATA if header.is_some() && !short_record => CHUNK,
                _ => anyhow::bail!("invalid snapshot record ordering"),
            };
            ensure!(
                size > 0 && size <= cap as u64,
                "snapshot record size invalid"
            );
            encoded_bytes = encoded_bytes
                .checked_add(9)
                .and_then(|n| n.checked_add(size))
                .filter(|n| *n <= limit)
                .ok_or_else(|| anyhow::anyhow!("snapshot exceeds byte limit"))?;
            let mut bytes = vec![0; size as usize];
            reader.read_exact(&mut bytes)?;
            digest.update(tag);
            digest.update(length);
            digest.update(&bytes);
            if tag[0] == METADATA {
                let value: Header = serde_json::from_slice(&bytes)?;
                ensure!(
                    value.version == 1 && serde_json::to_vec(&value)? == bytes,
                    "noncanonical snapshot metadata"
                );
                header = Some(value);
            } else {
                spool.write_all(&bytes)?;
                records = records
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("snapshot count overflow"))?;
                short_record = size < CHUNK as u64;
            }
        }
        let header = header.expect("terminal record checked metadata");
        Ok(Self {
            version: header.version,
            kind: header.kind,
            meta: header.meta,
            retirement: header.retirement,
            backend: SnapshotImage::freeze(spool)?,
        })
    }
}
