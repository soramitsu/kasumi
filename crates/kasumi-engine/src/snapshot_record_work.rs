//! Structural accounting before any record DTO is allocated. This meter is
//! deliberately not a JSON decoder: canonical serde decoding remains mandatory.
//! It counts every string (including keys), scalar and container, even if serde
//! would ignore/overwrite it. Malformed framing/nesting is rejected early.
//!
//! The transient model reserves four simultaneous representations, each with
//! twofold container capacity: buffered Serde Content, the final DTO/Value tree,
//! an immutable-row validation clone, and canonical/table serialization work.
//! Each site owns one (String, Value) map slot, one Value/Content-sized slot, two
//! pointers and a Vec header. String/numeric wire bytes reserve the same eight
//! copies, plus the original record. Escaped decoded strings cannot exceed their
//! wire bytes; arbitrary-precision numeric lexemes are counted even for `0`.
//! The separate 64 MiB maintenance floor owns fixed DTOs, redb caches and framing.
//! This checked accounting model is not an allocator-enforced hard RSS bound.
use anyhow::{Result, ensure};

const MAX_DEPTH: usize = 128;
const REPRESENTATIONS: u64 = 4;
const CAPACITY_FACTOR: u64 = 2;

fn site_bytes() -> u64 {
    (std::mem::size_of::<(String, serde_json::Value)>()
        + std::mem::size_of::<serde_json::Value>()
        + std::mem::size_of::<(*const (), *const ())>()
        + std::mem::size_of::<Vec<()>>()) as u64
}

pub(super) struct Meter {
    wire_bytes: u64,
    scalar_bytes: u64,
    sites: u64,
    stack: [u8; MAX_DEPTH],
    depth: usize,
    quoted: bool,
    escaped: bool,
    scalar: bool,
}
impl Default for Meter {
    fn default() -> Self {
        Self {
            wire_bytes: 0,
            scalar_bytes: 0,
            sites: 0,
            stack: [0; MAX_DEPTH],
            depth: 0,
            quoted: false,
            escaped: false,
            scalar: false,
        }
    }
}
impl Meter {
    fn site(&mut self) -> Result<()> {
        self.sites = self.sites.checked_add(1).ok_or_else(overflow)?;
        Ok(())
    }
    pub(super) fn consume(&mut self, bytes: &[u8]) -> Result<()> {
        self.wire_bytes = self
            .wire_bytes
            .checked_add(bytes.len() as u64)
            .ok_or_else(overflow)?;
        for &byte in bytes {
            if self.quoted {
                if self.escaped {
                    self.escaped = false;
                } else if byte == b'"' {
                    self.quoted = false;
                    continue;
                } else if byte == b'\\' {
                    self.escaped = true;
                }
                self.scalar_bytes = self.scalar_bytes.checked_add(1).ok_or_else(overflow)?;
                continue;
            }
            match byte {
                b'"' => {
                    self.site()?;
                    self.quoted = true;
                    self.scalar = false;
                }
                b'{' | b'[' => {
                    self.site()?;
                    ensure!(
                        self.depth < MAX_DEPTH,
                        "snapshot JSON nesting exceeds limit"
                    );
                    self.stack[self.depth] = byte;
                    self.depth += 1;
                    self.scalar = false;
                }
                b'}' | b']' => {
                    ensure!(self.depth > 0, "unbalanced snapshot JSON container");
                    self.depth -= 1;
                    ensure!(
                        self.stack[self.depth] == if byte == b'}' { b'{' } else { b'[' },
                        "mismatched snapshot JSON container"
                    );
                    self.scalar = false;
                }
                b':' | b',' | b' ' | b'\r' | b'\n' | b'\t' => self.scalar = false,
                _ => {
                    if !self.scalar {
                        self.site()?;
                        self.scalar = true;
                    }
                    self.scalar_bytes = self.scalar_bytes.checked_add(1).ok_or_else(overflow)?;
                }
            }
        }
        Ok(())
    }
    pub(super) fn finish(self) -> Result<u64> {
        ensure!(
            self.depth == 0 && !self.quoted && !self.escaped && self.sites > 0,
            "incomplete snapshot JSON structure"
        );
        self.sites
            .checked_mul(site_bytes())
            .and_then(|bytes| bytes.checked_add(self.scalar_bytes))
            .and_then(|bytes| bytes.checked_mul(REPRESENTATIONS))
            .and_then(|bytes| bytes.checked_mul(CAPACITY_FACTOR))
            .and_then(|bytes| bytes.checked_add(self.wire_bytes))
            .ok_or_else(overflow)
    }
}
fn overflow() -> anyhow::Error {
    anyhow::anyhow!("snapshot structural work overflow")
}
pub(super) fn measure(bytes: &[u8]) -> Result<u64> {
    let mut meter = Meter::default();
    meter.consume(bytes)?;
    meter.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dense_numeric_sites_are_charged_before_serde_and_independent_of_token_width() {
        let short = b"[0,0,0,0]";
        let long = b"[1234567890123456789012345678901234567890]";
        assert!(measure(short).unwrap() > measure(long).unwrap());
        assert!(measure(short).unwrap() > short.len() as u64 * 32);
        let mut meter = Meter::default();
        for byte in short {
            meter.consume(&[*byte]).unwrap();
        }
        assert_eq!(meter.finish().unwrap(), measure(short).unwrap());
        let mut overflow = Meter {
            sites: u64::MAX,
            ..Default::default()
        };
        assert!(overflow.consume(b"0").is_err());
        let overflow = Meter {
            sites: u64::MAX,
            ..Default::default()
        };
        assert!(overflow.finish().is_err());
    }

    #[test]
    fn escaped_and_duplicate_keys_are_counted_with_bounded_depth_before_decode() {
        let input = br#"{"x":"\u0061\ud83d\ude00\\\"","x":{"$serde_json::private::Number":"123456789012345678901234567890"}}"#;
        let expected = measure(input).unwrap();
        for width in 1..=17 {
            let mut meter = Meter::default();
            for part in input.chunks(width) {
                meter.consume(part).unwrap();
            }
            assert_eq!(meter.finish().unwrap(), expected);
        }
        assert!(expected > measure(br#"{"x":"a"}"#).unwrap());
        assert!(measure(&[b'['; MAX_DEPTH + 1]).is_err());
        for invalid in [b"[}".as_slice(), b"\"open", b"[0", b""] {
            assert!(measure(invalid).is_err());
        }
    }
}
