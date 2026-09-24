//! Exact current-writer JSON admission for bounded durable records.
//! The caller retains its physical byte bound before decoding this value.
use anyhow::{Result, ensure};
use serde::Serialize;
use std::io::{self, Write};

struct Compare<'a> {
    remaining: &'a [u8],
    matches: bool,
}

impl Write for Compare<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.matches {
            if let Some(remaining) = self.remaining.strip_prefix(bytes) {
                self.remaining = remaining;
            } else {
                self.matches = false;
            }
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) fn require_current_writer_bytes<T: Serialize>(
    original: &[u8],
    decoded: &T,
    name: &str,
) -> Result<()> {
    let mut compare = Compare {
        remaining: original,
        matches: true,
    };
    serde_json::to_writer(&mut compare, decoded)?;
    ensure!(
        compare.matches && compare.remaining.is_empty(),
        "noncanonical {name}"
    );
    Ok(())
}
