//! Canonical portable application bootstrap manifest shared by its writer and
//! selected-view validators. This wire DTO is not proof that body chunks have
//! been rehashed or that a caller is authorized to reconstruct/serve them.
use serde::{Deserialize, Serialize};

pub const APPLICATION_BOOTSTRAP_CHUNK_BYTES: usize = 4 << 20;
// Existing four-field writer bound; no new format or lower accepted limit.
pub const APPLICATION_BOOTSTRAP_MANIFEST_BYTES: usize = 256;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationBootstrapManifest {
    pub format: u32,
    pub bytes: u64,
    pub chunks: u64,
    pub digest: String,
}

impl ApplicationBootstrapManifest {
    /// Decode the exact existing canonical writer representation. Callers must
    /// separately authenticate/reconstruct and verify all body chunks.
    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        anyhow::ensure!(
            bytes.len() <= APPLICATION_BOOTSTRAP_MANIFEST_BYTES,
            "bootstrap manifest exceeds current writer bound"
        );
        let manifest: Self = serde_json::from_slice(bytes)?;
        anyhow::ensure!(
            manifest.format == 2
                && manifest.bytes > 0
                && manifest.chunks
                    == manifest
                        .bytes
                        .div_ceil(APPLICATION_BOOTSTRAP_CHUNK_BYTES as u64)
                && manifest.digest.len() == 64
                && manifest
                    .digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "invalid bootstrap manifest"
        );
        anyhow::ensure!(
            serde_json::to_vec(&manifest)? == bytes,
            "noncanonical bootstrap manifest"
        );
        Ok(manifest)
    }
}
