//! A bounded, allocation-free shape pass before Serde builds a key catalog.
//! The resulting lease follows the decoded owner beyond its read transaction.
use super::*;
use serde::de::{IgnoredAny, MapAccess, Visitor};
use std::{
    fmt,
    ops::{Deref, DerefMut},
};

pub(super) struct AdmittedKeyCatalog {
    catalog: KeyCatalog,
    charge: Option<DiskMemoryLease>,
}

impl AdmittedKeyCatalog {
    pub(super) fn admit_backup_manifest_decode(
        header: &[u8],
        memory: Arc<dyn NodeDiskMemoryAdmission>,
    ) -> Result<DiskMemoryLease> {
        ensure!(
            header.len() <= crate::backup::HEADER_LIMIT,
            "backup manifest too large"
        );
        let mut decoder = serde_json::Deserializer::from_slice(header);
        let shape = BackupManifestShape::deserialize(&mut decoder)
            .context("invalid backup manifest shape")?;
        decoder.end().context("invalid backup manifest shape")?;
        ensure!(shape.keys <= 1024, "too many retained data keys");
        let required = typed_catalog_budget_for_shape(header.len(), shape.keys)?;
        memory
            .reserve_installed(required)
            .context("backup manifest typed allocation admission denied")
    }

    pub(super) fn admit_backup_manifest_clone(
        manifest: &impl Serialize,
        keys: usize,
        memory: Arc<dyn NodeDiskMemoryAdmission>,
    ) -> Result<DiskMemoryLease> {
        ensure!(keys <= 1024, "too many retained data keys");
        let mut count = ByteCount::new(crate::backup::HEADER_LIMIT);
        serde_json::to_writer(&mut count, manifest).context("backup manifest too large")?;
        let required = typed_catalog_budget_for_shape(count.len(), keys)?;
        memory
            .reserve_installed(required)
            .context("backup manifest clone admission denied")
    }

    pub(super) fn unadmitted(catalog: KeyCatalog) -> Self {
        Self {
            catalog,
            charge: None,
        }
    }

    pub(super) fn decode(
        bytes: &[u8],
        tenant: &str,
        memory: Arc<dyn NodeDiskMemoryAdmission>,
    ) -> Result<Self> {
        let required = typed_catalog_budget(bytes)?;
        let charge = memory
            .reserve_installed(required)
            .context("key catalog typed allocation admission denied")?;
        let catalog = NodeStore::catalog_from_bytes(bytes, tenant)?;
        Ok(Self {
            catalog,
            charge: Some(charge),
        })
    }

    pub(super) fn clone_for_refresh(
        catalog: &KeyCatalog,
        memory: Arc<dyn NodeDiskMemoryAdmission>,
    ) -> Result<Self> {
        let required = typed_catalog_budget_for_owned(catalog)?;
        let charge = memory
            .reserve_installed(required)
            .context("key catalog refresh clone admission denied")?;
        Ok(Self {
            catalog: catalog.clone(),
            charge: Some(charge),
        })
    }

    pub(super) fn clone_for_backup(
        catalog: &KeyCatalog,
        memory: Arc<dyn NodeDiskMemoryAdmission>,
    ) -> Result<Self> {
        let required = typed_catalog_budget_for_owned(catalog)?;
        let charge = memory
            .reserve_installed(required)
            .context("key catalog backup clone admission denied")?;
        Ok(Self {
            catalog: catalog.clone(),
            charge: Some(charge),
        })
    }

    pub(super) fn clone_for_mutation(
        catalog: &KeyCatalog,
        memory: Arc<dyn NodeDiskMemoryAdmission>,
    ) -> Result<Self> {
        // Refuse an invalid in-memory source before cloning. Reserve for any
        // valid successor because rotation/rewrap may enlarge owned strings.
        typed_catalog_budget_for_owned(catalog)?;
        let required = typed_catalog_budget_for_shape(MAX_KEY_CATALOG_BYTES, 1024)?;
        let charge = memory
            .reserve_installed(required)
            .context("key catalog mutation clone admission denied")?;
        Ok(Self {
            catalog: catalog.clone(),
            charge: Some(charge),
        })
    }

    pub(super) fn into_parts(self) -> (KeyCatalog, Option<DiskMemoryLease>) {
        (self.catalog, self.charge)
    }
}
impl From<KeyCatalog> for AdmittedKeyCatalog {
    fn from(catalog: KeyCatalog) -> Self {
        Self::unadmitted(catalog)
    }
}

impl Deref for AdmittedKeyCatalog {
    type Target = KeyCatalog;
    fn deref(&self) -> &Self::Target {
        &self.catalog
    }
}

impl DerefMut for AdmittedKeyCatalog {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.catalog
    }
}

impl PartialEq<KeyCatalog> for AdmittedKeyCatalog {
    fn eq(&self, other: &KeyCatalog) -> bool {
        self.catalog == *other
    }
}

impl PartialEq<AdmittedKeyCatalog> for KeyCatalog {
    fn eq(&self, other: &AdmittedKeyCatalog) -> bool {
        *self == other.catalog
    }
}

impl PartialEq for AdmittedKeyCatalog {
    fn eq(&self, other: &Self) -> bool {
        self.catalog == other.catalog
    }
}
impl Eq for AdmittedKeyCatalog {}

impl Serialize for AdmittedKeyCatalog {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        self.catalog.serialize(serializer)
    }
}

struct CatalogShape {
    keys: usize,
}

struct BackupManifestShape {
    keys: usize,
}
impl<'de> Deserialize<'de> for BackupManifestShape {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct ShapeVisitor;
        impl<'de> Visitor<'de> for ShapeVisitor {
            type Value = BackupManifestShape;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("backup manifest object")
            }
            fn visit_map<M: MapAccess<'de>>(
                self,
                mut map: M,
            ) -> std::result::Result<Self::Value, M::Error> {
                let mut keys = 0usize;
                while let Some(name) = map.next_key::<&str>()? {
                    if name == "catalog" {
                        keys = keys
                            .checked_add(map.next_value::<CatalogShape>()?.keys)
                            .ok_or_else(|| {
                                serde::de::Error::custom("too many retained data keys")
                            })?;
                    } else {
                        map.next_value::<IgnoredAny>()?;
                    }
                }
                Ok(BackupManifestShape { keys })
            }
        }
        deserializer.deserialize_map(ShapeVisitor)
    }
}

struct ByteCount {
    len: usize,
    max: usize,
}
impl ByteCount {
    fn new(max: usize) -> Self {
        Self { len: 0, max }
    }
    fn len(&self) -> usize {
        self.len
    }
}
impl std::io::Write for ByteCount {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.len = self
            .len
            .checked_add(bytes.len())
            .filter(|size| *size <= self.max)
            .ok_or_else(|| std::io::Error::other("serialized byte quota exceeded"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl<'de> Deserialize<'de> for CatalogShape {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct ShapeVisitor;
        impl<'de> Visitor<'de> for ShapeVisitor {
            type Value = CatalogShape;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("key catalog object")
            }
            fn visit_map<M: MapAccess<'de>>(
                self,
                mut map: M,
            ) -> std::result::Result<Self::Value, M::Error> {
                let mut keys = 0usize;
                while let Some(name) = map.next_key::<&str>()? {
                    if name == "keys" {
                        keys = keys
                            .checked_add(map.next_value::<KeyCount>()?.0)
                            .ok_or_else(|| {
                                serde::de::Error::custom("too many retained data keys")
                            })?;
                    } else {
                        map.next_value::<IgnoredAny>()?;
                    }
                }
                Ok(CatalogShape { keys })
            }
        }
        deserializer.deserialize_map(ShapeVisitor)
    }
}

struct KeyCount(usize);
impl<'de> Deserialize<'de> for KeyCount {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct CountVisitor;
        impl<'de> Visitor<'de> for CountVisitor {
            type Value = KeyCount;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("key catalog map")
            }
            fn visit_map<M: MapAccess<'de>>(
                self,
                mut map: M,
            ) -> std::result::Result<Self::Value, M::Error> {
                let mut count = 0usize;
                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
                    count += 1;
                    if count > 1024 {
                        return Err(serde::de::Error::custom("too many retained data keys"));
                    }
                }
                Ok(KeyCount(count))
            }
        }
        deserializer.deserialize_map(CountVisitor)
    }
}

fn typed_catalog_budget(bytes: &[u8]) -> Result<u64> {
    ensure!(
        bytes.len() <= MAX_KEY_CATALOG_BYTES,
        "key catalog byte quota exceeded"
    );
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let shape = CatalogShape::deserialize(&mut decoder).context("invalid key catalog shape")?;
    decoder.end().context("invalid key catalog shape")?;
    typed_catalog_budget_for_shape(bytes.len(), shape.keys)
}

fn typed_catalog_budget_for_owned(catalog: &KeyCatalog) -> Result<u64> {
    ensure!(catalog.keys.len() <= 1024, "too many retained data keys");
    // Count the current writer's bytes without constructing a second catalog
    // buffer. This pass has no owned JSON tree or cloned key strings.
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .filter(|size| *size <= MAX_KEY_CATALOG_BYTES)
                .ok_or_else(|| std::io::Error::other("key catalog byte quota exceeded"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    serde_json::to_writer(&mut count, catalog).context("key catalog byte quota exceeded")?;
    typed_catalog_budget_for_shape(count.0, catalog.keys.len())
}

fn typed_catalog_budget_for_shape(serialized_bytes: usize, keys: usize) -> Result<u64> {
    // The schema has one BTreeMap with at most 1,024 entries. Each entry owns
    // at most five strings, plus an internal map node. Other variants contain
    // only a fixed number of strings/boxes. Four times the wire length covers
    // decoded payload and geometric string capacity; the per-key/fixed terms
    // include the allocator allowance for every separate owned allocation.
    let payload = disk_memory::mul(u64::try_from(serialized_bytes)?, 4)?;
    let per_key = disk_memory::add(
        disk_memory::allocation::<(String, WrappedKey)>(1)?,
        disk_memory::mul(disk_memory::ALLOCATION_ALLOWANCE, 5)?,
    )?;
    let keys = disk_memory::mul(u64::try_from(keys)?, per_key)?;
    Ok(disk_memory::add(
        disk_memory::add(payload, keys)?,
        disk_memory::add(disk_memory::allocation::<KeyCatalog>(1)?, 64 << 10)?,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shape_pass_rejects_large_map_before_typed_decode() {
        let mut input = String::from("{\"keys\":{");
        for index in 0..1025 {
            if index > 0 {
                input.push(',');
            }
            input.push_str(&format!("\"{index}\":null"));
        }
        input.push_str("}}");
        assert!(
            format!("{:#}", typed_catalog_budget(input.as_bytes()).unwrap_err())
                .contains("too many retained data keys")
        );
    }
}
