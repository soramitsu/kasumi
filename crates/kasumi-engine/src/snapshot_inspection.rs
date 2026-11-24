//! Fixed-size framing and JSON-work inspection across arbitrary input boundaries.
//! Semantic decoding independently checks every kind against the authenticated image.
use super::{MAGIC, StreamSummary, authenticated_summary, record_work::Meter};
use anyhow::{Result, ensure};
use sha2::{Digest, Sha256};
use std::io::{ErrorKind, Read};

#[derive(Clone, Copy)]
enum Field {
    Magic,
    Length,
    Kind(u64),
    Payload(usize),
    Footer,
    End,
    Failed,
}

pub(crate) struct StreamInspector {
    field: Field,
    fixed: [u8; 48],
    filled: usize,
    kind: u8,
    hash: Sha256,
    work: Meter,
    summary: StreamSummary,
}

impl StreamInspector {
    pub(crate) fn new() -> Self {
        Self {
            field: Field::Magic,
            fixed: [0; 48],
            filled: 0,
            kind: 0,
            hash: Sha256::new(),
            work: Meter::default(),
            summary: StreamSummary::empty(),
        }
    }

    fn needed(&self) -> usize {
        match self.field {
            Field::Magic | Field::Length => 8 - self.filled,
            Field::Kind(_) => 1,
            Field::Payload(remaining) => remaining,
            Field::Footer => self.fixed.len() - self.filled,
            Field::End | Field::Failed => 0,
        }
    }

    pub(crate) fn push(&mut self, bytes: &[u8]) -> Result<()> {
        self.consume(bytes)
            .inspect_err(|_| self.field = Field::Failed)
    }

    fn consume(&mut self, mut bytes: &[u8]) -> Result<()> {
        while !bytes.is_empty() {
            let needed = self.needed();
            ensure!(needed > 0, "trailing snapshot data");
            let (part, rest) = bytes.split_at(bytes.len().min(needed));
            bytes = rest;
            if let Field::Payload(remaining) = self.field {
                self.hash.update(part);
                self.work.consume(part)?;
                self.field = if part.len() == remaining {
                    let work = std::mem::take(&mut self.work).finish()?;
                    self.summary.record_work(self.kind, work)?;
                    Field::Length
                } else {
                    Field::Payload(remaining - part.len())
                };
                continue;
            }
            self.fixed[self.filled..self.filled + part.len()].copy_from_slice(part);
            self.filled += part.len();
            if part.len() == needed {
                self.finish_field()?;
            }
        }
        Ok(())
    }

    fn finish_field(&mut self) -> Result<()> {
        self.filled = 0;
        self.field = match self.field {
            Field::Magic => {
                ensure!(
                    &self.fixed[..8] == MAGIC,
                    "unsupported tenant snapshot format"
                );
                self.hash.update(MAGIC);
                Field::Length
            }
            Field::Length => match u64::from_be_bytes(self.fixed[..8].try_into()?) {
                0 => Field::Footer,
                bytes => Field::Kind(bytes),
            },
            Field::Kind(bytes) => {
                let kind = self.fixed[0];
                ensure!(
                    (self.summary.records == 0 && kind == 0)
                        || (self.summary.records > 0 && kind > 0 && kind >= self.kind),
                    "snapshot typed frames duplicated or unordered"
                );
                self.summary.add(kind, bytes)?;
                self.kind = kind;
                self.hash.update(bytes.to_be_bytes());
                self.hash.update([kind]);
                Field::Payload(usize::try_from(bytes)?)
            }
            Field::Footer => {
                self.summary = authenticated_summary(
                    std::mem::take(&mut self.hash),
                    self.summary,
                    &self.fixed,
                )?;
                Field::End
            }
            Field::Payload(_) | Field::End | Field::Failed => {
                unreachable!("only fixed framing fields are accumulated")
            }
        };
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<StreamSummary> {
        if matches!(self.field, Field::End) {
            Ok(self.summary)
        } else {
            Err(std::io::Error::from(ErrorKind::UnexpectedEof).into())
        }
    }
}

pub(crate) fn inspect(reader: &mut dyn Read) -> Result<StreamSummary> {
    let mut inspector = StreamInspector::new();
    let mut buffer = [0; 64 << 10];
    while inspector.needed() > 0 {
        let take = inspector.needed().min(buffer.len());
        reader.read_exact(&mut buffer[..take])?;
        inspector.push(&buffer[..take])?;
    }
    ensure!(reader.read(&mut [0])? == 0, "trailing snapshot data");
    inspector.finish()
}
