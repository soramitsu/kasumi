//! Dense membership is independent of versioned manifest mappings.
use super::*;

pub(crate) const CATALOG_MEMBER_BYTES: usize = 376;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CatalogMember {
    pub(crate) catalog: CatalogId,
    pub(crate) scope: Hash,
    pub(crate) ordinal: u64,
    pub(crate) name_hash: Hash,
    len: u16,
    name: [u8; 256],
}
impl CatalogMember {
    pub(crate) fn new(
        catalog: CatalogId,
        scope: Hash,
        ordinal: u64,
        name: &str,
    ) -> Result<Self, CodecError> {
        super::super::check_id(name)?;
        catalog.0.check()?;
        let mut member = Self {
            catalog,
            scope,
            ordinal,
            name_hash: name_hash(name)?,
            len: name.len() as u16,
            name: [0; 256],
        };
        member.name[..name.len()].copy_from_slice(name.as_bytes());
        Ok(member)
    }
    pub(crate) fn name(&self) -> &str {
        std::str::from_utf8(&self.name[..self.len as usize]).expect("validated catalog name")
    }
    fn check(&self) -> Result<(), CodecError> {
        self.catalog.0.check()?;
        let len = self.len as usize;
        if !(1..=256).contains(&len) {
            return Err(CodecError::Name);
        }
        let name = std::str::from_utf8(&self.name[..len]).map_err(|_| CodecError::Name)?;
        super::super::check_id(name)?;
        zero(&self.name[len..])?;
        if name_hash(name)? != self.name_hash {
            return Err(CodecError::Digest);
        }
        Ok(())
    }
    pub(crate) fn encode(&self, out: &mut [u8]) -> Result<(), CodecError> {
        if out.len() != CATALOG_MEMBER_BYTES {
            return Err(CodecError::Length);
        }
        self.check()?;
        out.fill(0);
        out[..8].copy_from_slice(b"KSPMEM01");
        out[8..10].copy_from_slice(&1_u16.to_le_bytes());
        self.catalog.0.write(&mut out[16..40]);
        out[40..72].copy_from_slice(&self.scope);
        put_u64(out, 72, self.ordinal);
        out[80..112].copy_from_slice(&self.name_hash);
        out[112..114].copy_from_slice(&self.len.to_le_bytes());
        out[120..].copy_from_slice(&self.name);
        Ok(())
    }
    pub(crate) fn decode(
        bytes: &[u8],
        catalog: CatalogId,
        scope: Hash,
        ordinal: u64,
    ) -> Result<Self, CodecError> {
        if bytes.len() != CATALOG_MEMBER_BYTES {
            return Err(CodecError::Length);
        }
        if &bytes[..8] != b"KSPMEM01" || u16_at(bytes, 8) != 1 {
            return Err(CodecError::Format);
        }
        zero(&bytes[10..16])?;
        zero(&bytes[114..120])?;
        let member = Self {
            catalog: CatalogId(ObjectId::read(&bytes[16..40])),
            scope: array(bytes, 40),
            ordinal: u64_at(bytes, 72),
            name_hash: array(bytes, 80),
            len: u16_at(bytes, 112),
            name: bytes[120..].try_into().expect("fixed member"),
        };
        member.check()?;
        if member.catalog != catalog || member.scope != scope || member.ordinal != ordinal {
            return Err(CodecError::Identity);
        }
        Ok(member)
    }
    pub(crate) fn key(catalog: CatalogId, ordinal: u64) -> [u8; 32] {
        let mut key = [0; 32];
        catalog.0.write(&mut key[..24]);
        put_u64(&mut key, 24, ordinal);
        key
    }
}
