//! Lossless physical document encoding. Logical JSON and custody digests do not change.
//!
//! Large string leaves are immutable content-addressed chunks. A sink must use a
//! tenant/incarnation-scoped encrypted namespace, verify an existing chunk before
//! reusing it, and durably install every chunk before publishing its manifest.
//! No object is deleted here: generation/snapshot reachability owns reclamation.
//! Readers must retain the exact selected native view and reserve the bounded
//! output, decoded Value and callback workspace before calling this module.
#[cfg(test)]
use anyhow::bail;
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::{self, Write};

pub(crate) const STRING_THRESHOLD: usize = 4096;
// Divisible by three: independently encoded full chunks have no base64 padding.
pub(crate) const BLOB_CHUNK_BYTES: usize = 48 * 1024;
const FORMAT: u32 = 1;

/// Admission limits are supplied by the owning read/write corridor. They are
/// checked before output allocation or blob reads, not after reconstruction.
#[derive(Clone, Copy, Debug)]
pub(crate) struct BodyLimits {
    pub canonical_bytes: usize,
    pub manifest_bytes: usize,
    pub fragments: usize,
    pub blobs: usize,
    pub depth: usize,
}

/// This digest is a content identity, not a complete physical storage key.
/// The enclosing native namespace must additionally bind tenant/incarnation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(deny_unknown_fields)]
pub(crate) struct BlobReference {
    pub sha256: [u8; 32],
    pub bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BodyManifest {
    format: u32,
    pub canonical_bytes: u64,
    pub canonical_sha256: [u8; 32],
    fragments: Vec<Fragment>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Fragment {
    Literal(String),
    String(StringReference),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StringReference {
    encoding: Encoding,
    canonical_bytes: u64,
    chunks: Vec<BlobReference>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Encoding {
    /// Chunks contain the exact canonical JSON string, including its quotes.
    Json,
    LowerHex,
    UpperHex,
    Base64,
}

struct CanonicalDigest {
    hash: Sha256,
    bytes: usize,
    limit: usize,
}
impl CanonicalDigest {
    fn new(limit: usize) -> Self {
        Self {
            hash: Sha256::new(),
            bytes: 0,
            limit,
        }
    }
}
impl Write for CanonicalDigest {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self
            .bytes
            .checked_add(bytes.len())
            .filter(|next| *next <= self.limit)
            .ok_or_else(|| io::Error::other("document canonical byte limit exceeded"))?;
        self.hash.update(bytes);
        self.bytes = next;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct Encoder<'a, F> {
    limits: BodyLimits,
    digest: CanonicalDigest,
    literal: Vec<u8>,
    fragments: Vec<Fragment>,
    blobs: usize,
    put: &'a mut F,
}
impl<F: FnMut(&BlobReference, &[u8]) -> Result<()>> Encoder<'_, F> {
    fn json_inline<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<()> {
        serde_json::to_writer(InlineWriter(self), value)?;
        Ok(())
    }
    fn inline(&mut self, bytes: &[u8]) -> Result<()> {
        self.digest.write_all(bytes)?;
        self.literal.try_reserve(bytes.len())?;
        self.literal.extend_from_slice(bytes);
        Ok(())
    }
    fn fragment(&mut self, fragment: Fragment) -> Result<()> {
        ensure!(
            self.fragments.len() < self.limits.fragments,
            "document fragment limit exceeded"
        );
        self.fragments.try_reserve(1)?;
        self.fragments.push(fragment);
        Ok(())
    }
    fn flush_literal(&mut self) -> Result<()> {
        if !self.literal.is_empty() {
            let text = String::from_utf8(std::mem::take(&mut self.literal))?;
            self.fragment(Fragment::Literal(text))?;
        }
        Ok(())
    }
    fn put_chunk(&mut self, bytes: &[u8], chunks: &mut Vec<BlobReference>) -> Result<()> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= BLOB_CHUNK_BYTES,
            "invalid document chunk size"
        );
        ensure!(
            self.blobs < self.limits.blobs,
            "document blob limit exceeded"
        );
        chunks.try_reserve(1)?;
        let reference = BlobReference {
            sha256: Sha256::digest(bytes).into(),
            bytes: bytes.len() as u64,
        };
        (self.put)(&reference, bytes)?;
        chunks.push(reference);
        self.blobs += 1;
        Ok(())
    }
    fn string(&mut self, string: &str) -> Result<()> {
        if string.len() < STRING_THRESHOLD {
            return self.json_inline(string);
        }
        self.flush_literal()?;
        let before = self.digest.bytes;
        // Hash the original logical spelling, independently of the physical codec.
        serde_json::to_writer(&mut self.digest, string)?;
        let encoding = classify(string);
        let mut chunks = Vec::new();
        match encoding {
            Encoding::LowerHex | Encoding::UpperHex => {
                for encoded in string.as_bytes().chunks(BLOB_CHUNK_BYTES * 2) {
                    self.put_chunk(&hex::decode(encoded)?, &mut chunks)?;
                }
            }
            Encoding::Base64 => {
                for encoded in string.as_bytes().chunks(BLOB_CHUNK_BYTES / 3 * 4) {
                    self.put_chunk(&STANDARD.decode(encoded)?, &mut chunks)?;
                }
            }
            Encoding::Json => {
                let mut writer = ChunkWriter {
                    encoder: self,
                    chunks: &mut chunks,
                    pending: Vec::new(),
                };
                serde_json::to_writer(&mut writer, string)?;
                writer.finish()?;
            }
        }
        self.fragment(Fragment::String(StringReference {
            encoding,
            canonical_bytes: (self.digest.bytes - before) as u64,
            chunks,
        }))
    }
    fn value(&mut self, value: &Value, depth: usize) -> Result<()> {
        ensure!(depth <= self.limits.depth, "document depth limit exceeded");
        match value {
            Value::String(string) => self.string(string),
            Value::Array(values) => {
                self.inline(b"[")?;
                for (index, value) in values.iter().enumerate() {
                    if index != 0 {
                        self.inline(b",")?;
                    }
                    self.value(
                        value,
                        depth.checked_add(1).context("document depth overflow")?,
                    )?;
                }
                self.inline(b"]")
            }
            Value::Object(values) => {
                self.inline(b"{")?;
                // Match CanonicalJsonValue even when preserve_order is enabled.
                if values.keys().is_sorted() {
                    for (index, (key, value)) in values.iter().enumerate() {
                        self.entry(index, key, value, depth)?;
                    }
                } else {
                    let mut entries = Vec::new();
                    entries.try_reserve_exact(values.len())?;
                    entries.extend(values.iter());
                    entries.sort_unstable_by_key(|(key, _)| *key);
                    for (index, (key, value)) in entries.into_iter().enumerate() {
                        self.entry(index, key, value, depth)?;
                    }
                }
                self.inline(b"}")
            }
            _ => self.json_inline(value),
        }
    }
    fn entry(&mut self, index: usize, key: &str, value: &Value, depth: usize) -> Result<()> {
        if index != 0 {
            self.inline(b",")?;
        }
        // Object keys are never interpreted as external references or Serde markers.
        self.json_inline(key)?;
        self.inline(b":")?;
        self.value(
            value,
            depth.checked_add(1).context("document depth overflow")?,
        )
    }
}

struct InlineWriter<'a, 'b, F>(&'a mut Encoder<'b, F>);
impl<F: FnMut(&BlobReference, &[u8]) -> Result<()>> Write for InlineWriter<'_, '_, F> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.inline(bytes).map_err(io::Error::other)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A large opaque string is escaped directly into bounded chunks; no second
/// complete escaped-string allocation is retained while encoding it.
struct ChunkWriter<'a, 'b, F> {
    encoder: &'a mut Encoder<'b, F>,
    chunks: &'a mut Vec<BlobReference>,
    pending: Vec<u8>,
}
impl<F: FnMut(&BlobReference, &[u8]) -> Result<()>> ChunkWriter<'_, '_, F> {
    fn finish(&mut self) -> Result<()> {
        if !self.pending.is_empty() {
            self.encoder.put_chunk(&self.pending, self.chunks)?;
            self.pending.clear();
        }
        Ok(())
    }
}
impl<F: FnMut(&BlobReference, &[u8]) -> Result<()>> Write for ChunkWriter<'_, '_, F> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut rest = bytes;
        while !rest.is_empty() {
            let take = rest.len().min(BLOB_CHUNK_BYTES - self.pending.len());
            self.pending.try_reserve(take).map_err(io::Error::other)?;
            self.pending.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
            if self.pending.len() == BLOB_CHUNK_BYTES {
                self.finish().map_err(io::Error::other)?;
            }
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn classify(string: &str) -> Encoding {
    let bytes = string.as_bytes();
    if bytes.len().is_multiple_of(2) {
        if bytes
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        {
            return Encoding::LowerHex;
        }
        if bytes
            .iter()
            .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(b))
        {
            return Encoding::UpperHex;
        }
    }
    if bytes.len().is_multiple_of(4)
        && !bytes[..bytes.len().saturating_sub(2)].contains(&b'=')
        && bytes.chunks(BLOB_CHUNK_BYTES / 3 * 4).all(|chunk| {
            // Exact round trip rejects non-zero trailing bits and alternate spellings.
            STANDARD
                .decode(chunk)
                .is_ok_and(|raw| STANDARD.encode(raw).as_bytes() == chunk)
        })
    {
        return Encoding::Base64;
    }
    Encoding::Json
}

pub(crate) fn encode_body(
    body: &Value,
    limits: BodyLimits,
    mut put: impl FnMut(&BlobReference, &[u8]) -> Result<()>,
) -> Result<BodyManifest> {
    let mut encoder = Encoder {
        limits,
        digest: CanonicalDigest::new(limits.canonical_bytes),
        literal: Vec::new(),
        fragments: Vec::new(),
        blobs: 0,
        put: &mut put,
    };
    encoder.value(body, 0)?;
    encoder.flush_literal()?;
    let manifest = BodyManifest {
        format: FORMAT,
        canonical_bytes: encoder.digest.bytes as u64,
        canonical_sha256: encoder.digest.hash.finalize().into(),
        fragments: encoder.fragments,
    };
    manifest.validate(limits)?;
    // Check the durable representation's limit without retaining an encoded copy.
    let mut count = CanonicalDigest::new(limits.manifest_bytes);
    serde_json::to_writer(&mut count, &manifest)?;
    Ok(manifest)
}

impl BodyManifest {
    fn validate(&self, limits: BodyLimits) -> Result<usize> {
        ensure!(self.format == FORMAT, "unsupported document body encoding");
        let bytes =
            usize::try_from(self.canonical_bytes).context("document byte length overflow")?;
        ensure!(
            bytes != 0 && bytes <= limits.canonical_bytes,
            "document canonical byte limit exceeded"
        );
        ensure!(
            !self.fragments.is_empty() && self.fragments.len() <= limits.fragments,
            "document fragment limit exceeded"
        );
        let mut total = 0u64;
        let mut blobs = 0usize;
        for fragment in &self.fragments {
            let length = match fragment {
                Fragment::Literal(text) => {
                    ensure!(!text.is_empty(), "empty document literal");
                    text.len() as u64
                }
                Fragment::String(string) => {
                    ensure!(!string.chunks.is_empty(), "empty document string chunks");
                    blobs = blobs
                        .checked_add(string.chunks.len())
                        .context("document blob count overflow")?;
                    ensure!(blobs <= limits.blobs, "document blob limit exceeded");
                    let mut raw = 0u64;
                    for (index, chunk) in string.chunks.iter().enumerate() {
                        ensure!(
                            chunk.bytes != 0 && chunk.bytes <= BLOB_CHUNK_BYTES as u64,
                            "invalid document chunk size"
                        );
                        ensure!(
                            index + 1 == string.chunks.len()
                                || chunk.bytes == BLOB_CHUNK_BYTES as u64,
                            "short nonterminal document chunk"
                        );
                        raw = raw
                            .checked_add(chunk.bytes)
                            .context("document raw byte count overflow")?;
                    }
                    let expected = match string.encoding {
                        Encoding::Json => raw,
                        Encoding::LowerHex | Encoding::UpperHex => raw
                            .checked_mul(2)
                            .and_then(|n| n.checked_add(2))
                            .context("document hex length overflow")?,
                        Encoding::Base64 => raw
                            .checked_add(2)
                            .map(|n| n / 3)
                            .and_then(|n| n.checked_mul(4))
                            .and_then(|n| n.checked_add(2))
                            .context("document base64 length overflow")?,
                    };
                    ensure!(
                        expected == string.canonical_bytes,
                        "document string length differs"
                    );
                    expected
                }
            };
            total = total
                .checked_add(length)
                .context("document canonical length overflow")?;
            ensure!(
                total <= self.canonical_bytes,
                "document fragments exceed canonical length"
            );
        }
        ensure!(
            total == self.canonical_bytes,
            "document fragment length differs"
        );
        Ok(bytes)
    }

    pub(crate) fn to_bytes(&self, limits: BodyLimits) -> Result<Vec<u8>> {
        self.validate(limits)?;
        let mut output = LimitedOutput::new(limits.manifest_bytes);
        serde_json::to_writer(&mut output, self)?;
        Ok(output.bytes)
    }

    pub(crate) fn from_bytes(bytes: &[u8], limits: BodyLimits) -> Result<Self> {
        ensure!(
            bytes.len() <= limits.manifest_bytes,
            "document manifest byte limit exceeded"
        );
        let manifest: Self = serde_json::from_slice(bytes)?;
        manifest.validate(limits)?;
        Ok(manifest)
    }

    #[cfg(test)]
    pub(crate) fn blob_references(&self) -> impl Iterator<Item = &BlobReference> {
        self.fragments
            .iter()
            .filter_map(|fragment| match fragment {
                Fragment::String(string) => Some(string.chunks.iter()),
                Fragment::Literal(_) => None,
            })
            .flatten()
    }
}

struct LimitedOutput {
    bytes: Vec<u8>,
    limit: usize,
}
impl LimitedOutput {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }
}
impl Write for LimitedOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        ensure_io(
            self.bytes
                .len()
                .checked_add(bytes.len())
                .is_some_and(|n| n <= self.limit),
        )?;
        self.bytes
            .try_reserve(bytes.len())
            .map_err(io::Error::other)?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn ensure_io(ok: bool) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other("document output byte limit exceeded"))
    }
}

/// Reconstruct the exact canonical bytes, verifying every chunk and the complete
/// logical digest. The caller must also compare the manifest's digest and length
/// to its authenticated document descriptor. No decoded body cache is created.
pub(crate) fn reconstruct_body<B: AsRef<[u8]>>(
    manifest: &BodyManifest,
    limits: BodyLimits,
    mut get: impl FnMut(&BlobReference) -> Result<B>,
) -> Result<Vec<u8>> {
    let bytes = manifest.validate(limits)?;
    let mut output = Vec::new();
    output.try_reserve_exact(bytes)?;
    for fragment in &manifest.fragments {
        match fragment {
            Fragment::Literal(text) => output.extend_from_slice(text.as_bytes()),
            Fragment::String(string) => {
                if string.encoding != Encoding::Json {
                    output.push(b'"');
                }
                for reference in &string.chunks {
                    let value = get(reference)?;
                    let value = value.as_ref();
                    ensure!(
                        value.len() as u64 == reference.bytes,
                        "document blob length differs"
                    );
                    ensure!(
                        <[u8; 32]>::from(Sha256::digest(value)) == reference.sha256,
                        "document blob digest differs"
                    );
                    match string.encoding {
                        Encoding::Json => output.extend_from_slice(value),
                        Encoding::LowerHex => append_hex(&mut output, value, b"0123456789abcdef"),
                        Encoding::UpperHex => append_hex(&mut output, value, b"0123456789ABCDEF"),
                        Encoding::Base64 => {
                            let length = base64::encoded_len(value.len(), true)
                                .context("document base64 length overflow")?;
                            let start = output.len();
                            let end = start
                                .checked_add(length)
                                .context("document output length overflow")?;
                            ensure!(end <= bytes, "document base64 output exceeds bound");
                            output.resize(end, 0);
                            ensure!(
                                STANDARD.encode_slice(value, &mut output[start..])? == length,
                                "document base64 encoded length differs"
                            );
                        }
                    }
                }
                if string.encoding != Encoding::Json {
                    output.push(b'"');
                }
            }
        }
    }
    ensure!(
        output.len() == bytes,
        "document reconstructed length differs"
    );
    ensure!(
        <[u8; 32]>::from(Sha256::digest(&output)) == manifest.canonical_sha256,
        "document reconstructed digest differs"
    );
    Ok(output)
}

fn append_hex(output: &mut Vec<u8>, bytes: &[u8], alphabet: &[u8; 16]) {
    // Both the full output capacity and this exact 2:1 expansion were checked
    // before any source read. Encode into that allocation, without a temporary.
    for &byte in bytes {
        output.push(alphabet[usize::from(byte >> 4)]);
        output.push(alphabet[usize::from(byte & 15)]);
    }
}

#[cfg(test)]
pub(crate) fn decode_body<B: AsRef<[u8]>>(
    manifest: &BodyManifest,
    limits: BodyLimits,
    get: impl FnMut(&BlobReference) -> Result<B>,
) -> Result<Value> {
    let bytes = reconstruct_body(manifest, limits, get)?;
    check_json_depth(&bytes, limits.depth)?;
    let body: Value = serde_json::from_slice(&bytes)?;
    // Literal marker objects and arbitrary precision numbers retain their exact
    // logical type; parse/serialize bridges cannot silently reinterpret them.
    let mut digest = CanonicalDigest::new(limits.canonical_bytes);
    serde_json::to_writer(&mut digest, &kasumi_types::CanonicalJsonValue(&body))?;
    if digest.bytes as u64 != manifest.canonical_bytes
        || <[u8; 32]>::from(digest.hash.finalize()) != manifest.canonical_sha256
    {
        anyhow::bail!("decoded document is not the exact canonical body");
    }
    Ok(body)
}

// Check structural depth before serde allocates any decoded containers. Syntax
// and UTF-8 are still checked by serde; strings and escaped braces do not count.
#[cfg(test)]
fn check_json_depth(bytes: &[u8], limit: usize) -> Result<()> {
    let mut depth = 0usize;
    let mut string = false;
    let mut escaped = false;
    for &byte in bytes {
        if string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                string = false;
            }
            continue;
        }
        match byte {
            b'[' | b'{' => {
                ensure!(depth <= limit, "document depth limit exceeded");
                depth = depth.checked_add(1).context("document depth overflow")?;
            }
            b']' | b'}' => {
                depth = depth
                    .checked_sub(1)
                    .context("document unbalanced containers")?;
            }
            b'"' => {
                ensure!(depth <= limit, "document depth limit exceeded");
                string = true;
            }
            b' ' | b'\r' | b'\n' | b'\t' | b',' | b':' => {}
            _ => ensure!(depth <= limit, "document depth limit exceeded"),
        }
    }
    ensure!(depth == 0 && !string, "document incomplete JSON");
    Ok(())
}

#[cfg(test)]
#[path = "document_encoding_tests.rs"]
mod tests;
