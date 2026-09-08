//! Canonical typed transport with bounded metadata, custody receipts/events and
//! payload chunks. Final counts and one digest authenticate every record.
use crate::storage::{SnapshotEnvelope, SnapshotKind};
use anyhow::{Context, Result, ensure};
use kasumi_store::{EncryptedSpool, SnapshotImage};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

const MAGIC: &[u8; 8] = b"KASUMIS3";
const METADATA: u8 = 1;
const COMMAND: u8 = 2;
const AUDIT: u8 = 3;
const DATA: u8 = 4;
const END: u8 = 5;
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
            let (mut commands, mut audit) = (0u64, 0u64);
            if let Some(retirement) = &self.retirement {
                retirement.validate(&self.meta)?;
                retirement.verified_records()?.visit(|tag, bytes| {
                    let (tag, count) = if tag == 1 {
                        (COMMAND, &mut commands)
                    } else {
                        (AUDIT, &mut audit)
                    };
                    frame(writer, tag, bytes, &mut digest)?;
                    *count = count
                        .checked_add(1)
                        .context("custody record count overflow")?;
                    Ok(())
                })?;
            }
            let mut reader = self.backend.reader();
            let mut buffer = vec![0; CHUNK];
            let (mut total, mut records) = (0u64, 0u64);
            while total < self.backend.len() {
                let count = (self.backend.len() - total).min(CHUNK as u64) as usize;
                reader.read_exact(&mut buffer[..count])?;
                frame(writer, DATA, &buffer[..count], &mut digest)?;
                total = total
                    .checked_add(count as u64)
                    .context("snapshot byte overflow")?;
                records = records.checked_add(1).context("snapshot count overflow")?;
            }
            writer.write_all(&[END])?;
            for count in [total, records, commands, audit] {
                writer.write_all(&count.to_be_bytes())?;
            }
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
        let mut header: Option<Header> = None;
        let mut custody: Option<crate::custody_records::Builder> = None;
        let mut spool = EncryptedSpool::new(limit)?;
        let (mut records, mut commands, mut audit) = (0u64, 0u64, 0u64);
        let mut encoded_bytes = 8u64;
        let mut previous_tag = 0u8;
        let mut previous_command: Option<String> = None;
        let mut short_record = false;
        loop {
            let mut tag = [0];
            reader.read_exact(&mut tag)?;
            if tag[0] == END {
                let mut footer = [0; 64];
                reader.read_exact(&mut footer)?;
                ensure!(header.is_some(), "snapshot metadata absent");
                for (slot, expected) in [spool.len(), records, commands, audit]
                    .into_iter()
                    .enumerate()
                {
                    ensure!(
                        u64::from_be_bytes(footer[slot * 8..slot * 8 + 8].try_into()?) == expected,
                        "snapshot terminal count differs"
                    );
                }
                ensure!(
                    digest.finalize().as_slice() == &footer[32..],
                    "snapshot terminal authentication differs"
                );
                ensure!(
                    encoded_bytes
                        .checked_add(65)
                        .is_some_and(|bytes| bytes <= limit),
                    "snapshot exceeds byte limit"
                );
                ensure!(reader.read(&mut tag)? == 0, "trailing snapshot bytes");
                break;
            }
            ensure!(tag[0] >= previous_tag, "invalid snapshot record ordering");
            let mut length = [0; 8];
            reader.read_exact(&mut length)?;
            let size = u64::from_be_bytes(length);
            let cap = match tag[0] {
                METADATA if header.is_none() => MAX_METADATA,
                COMMAND | AUDIT if custody.is_some() => crate::custody_tables::RECORD_BYTES,
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
                .context("snapshot exceeds byte limit")?;
            let mut bytes = vec![0; size as usize];
            reader.read_exact(&mut bytes)?;
            digest.update(tag);
            digest.update(length);
            digest.update(&bytes);
            match tag[0] {
                METADATA => {
                    let value: Header = serde_json::from_slice(&bytes)?;
                    ensure!(
                        value.version == 1 && serde_json::to_vec(&value)? == bytes,
                        "noncanonical snapshot metadata"
                    );
                    if let Some(retirement) = &value.retirement {
                        retirement.validate(&value.meta)?;
                        custody = Some(crate::custody_records::Builder::new(
                            retirement.custody.clone(),
                        )?);
                    }
                    header = Some(value);
                }
                COMMAND => {
                    let value: kasumi_types::CustodyReceipt = serde_json::from_slice(&bytes)?;
                    ensure!(
                        previous_command
                            .as_ref()
                            .is_none_or(|old| old < &value.command_id),
                        "noncanonical custody command ordering"
                    );
                    previous_command = Some(value.command_id);
                    custody
                        .as_mut()
                        .context("custody head absent")?
                        .command(&bytes)?;
                    commands = commands.checked_add(1).context("custody count overflow")?;
                }
                AUDIT => {
                    custody
                        .as_mut()
                        .context("custody head absent")?
                        .audit(&audit.to_be_bytes(), &bytes)?;
                    audit = audit.checked_add(1).context("custody count overflow")?;
                }
                DATA => {
                    spool.write_all(&bytes)?;
                    records = records.checked_add(1).context("snapshot count overflow")?;
                    short_record = size < CHUNK as u64;
                }
                _ => unreachable!("record tag checked above"),
            }
            previous_tag = tag[0];
        }
        let mut header = header.context("snapshot metadata absent")?;
        if let Some(builder) = custody {
            let records = builder.finish()?;
            let retirement = header
                .retirement
                .as_mut()
                .context("custody metadata absent")?;
            ensure!(
                records.sha256() == retirement.history_sha256,
                "custody history digest differs"
            );
            retirement.records = Some(records);
        }
        Ok(Self {
            version: header.version,
            kind: header.kind,
            meta: header.meta,
            retirement: header.retirement,
            backend: SnapshotImage::freeze(spool)?,
        })
    }
}
