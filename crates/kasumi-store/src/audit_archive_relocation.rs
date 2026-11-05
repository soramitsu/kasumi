//! Moving a private tenant audit archive cache to another installed directory.
//! Objects are copied through the same exact publication as a new segment, the
//! stored placement changes only through an explicit checked rewrite, and a
//! source object is deleted only while its bytes still match the given link.
use super::*;

/// One name in a cache directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuditCacheEntry {
    /// A published immutable object, `<uuid>.audit`.
    Object(Uuid),
    /// The staging name of an interrupted publication, `<uuid>.audit.pending`.
    /// Pruning applies only after its object is published, so it holds no
    /// history that is not still in the hot audit records.
    Staging(Uuid),
}

/// The configured placement differs from the one this store installed.
#[derive(Debug)]
pub struct TenantAuditPlacementDiffers {
    pub installed_cache: String,
    pub installed_destination: String,
    pub configured_cache: String,
    pub configured_destination: String,
}
impl std::fmt::Display for TenantAuditPlacementDiffers {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "installed tenant audit placement differs: installed cache {} and destination {}, \
             configured cache {} and destination {}",
            self.installed_cache,
            self.installed_destination,
            self.configured_cache,
            self.configured_destination
        )
    }
}
impl std::error::Error for TenantAuditPlacementDiffers {}

/// The reference a complete object's own canonical header and bytes bind.
/// This decrypts nothing; a verifier must still authenticate the object.
pub fn inspect_audit_object(bytes: &[u8]) -> Result<AuditArchiveReference> {
    Ok(decode_object(bytes)?.1)
}

/// The directory of a filesystem archive identity, as `identity()` wrote it.
pub fn filesystem_archive_directory(identity: &str) -> Option<&Path> {
    identity.strip_prefix("filesystem:").map(Path::new)
}

/// The identity a filesystem archive installed at `directory` reports.
pub fn filesystem_archive_identity(directory: &Path) -> String {
    filesystem_identity(directory)
}

impl FilesystemAuditArchive {
    /// The installed directory holding this archive's objects.
    pub fn directory(&self) -> &Path {
        &self.root
    }

    /// Every entry in name order. Anything but an object or a staging name is
    /// refused: a cache holds nothing else.
    pub fn entries(&self) -> Result<Vec<AuditCacheEntry>> {
        self.directory.verified_identity()?;
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry.file_name();
            let text = name
                .to_str()
                .with_context(|| format!("audit cache entry {name:?} is not an object name"))?;
            ensure!(
                entry.file_type()?.is_file(),
                "audit cache entry {} in {} is not a regular file",
                text,
                self.root.display()
            );
            let (id, staging) = match text.strip_suffix(".audit.pending") {
                Some(id) => (id, true),
                None => (
                    text.strip_suffix(".audit").with_context(|| {
                        format!(
                            "audit cache {} holds an unrelated entry {text}",
                            self.root.display()
                        )
                    })?,
                    false,
                ),
            };
            let object = Uuid::parse_str(id)
                .ok()
                .filter(|object| !object.is_nil() && object.to_string() == id)
                .with_context(|| format!("audit cache entry {text} is not a canonical object"))?;
            entries.push(if staging {
                AuditCacheEntry::Staging(object)
            } else {
                AuditCacheEntry::Object(object)
            });
        }
        self.directory.verified_identity()?;
        entries.sort_unstable();
        Ok(entries)
    }

    /// A published object's exact bytes, read through its enrolled handle.
    fn read_published(&self, object: Uuid) -> Result<Vec<u8>> {
        let path = self.root.join(format!("{object}.audit"));
        let (root, relative) = self.disk.binding(&path)?;
        let file = self.disk.open_file(root, relative)?;
        let length = file.observed_len()?;
        ensure!(
            length <= MAX_AUDIT_SEGMENT_BYTES as u64,
            "invalid audit archive object"
        );
        let mut bytes = vec![0; usize::try_from(length)?];
        file.read_exact_at(&mut bytes, 0)?;
        Ok(bytes)
    }

    /// The link a published object's own bytes bind.
    pub fn object_link(&self, object: Uuid) -> Result<AuditArchiveLink> {
        let reference = inspect_audit_object(&self.read_published(object)?)?;
        ensure!(
            reference.object.object_id == object,
            "audit cache object {object} names another object"
        );
        Ok(reference.object)
    }

    /// Copy one published object into `target` through exact publication:
    /// staging name, file and directory synchronization, create-only rename and
    /// a complete readback against the digest of the source bytes. An
    /// identical object already in `target` is accepted, so a copy resumes.
    pub fn copy_object(
        &self,
        store: &TenantStore,
        object: Uuid,
        target: &Self,
    ) -> Result<AuditArchiveReference> {
        ensure!(
            !Arc::ptr_eq(&self.publication, &target.publication) && self.root != target.root,
            "an audit cache cannot be copied into itself"
        );
        let bytes = self.read_published(object)?;
        let reference = inspect_audit_object(&bytes)?;
        ensure!(
            reference.object.object_id == object,
            "audit cache object {object} names another object"
        );
        target.publish_blocking(&store.copy_audit_segment(reference.clone(), &bytes)?)?;
        Ok(reference)
    }

    /// Delete a published object only while its bytes are exactly `link`'s.
    pub fn delete_object(&self, link: &AuditArchiveLink) -> Result<()> {
        let path = self.root.join(format!("{}.audit", link.object_id));
        let (root, relative) = self.disk.binding(&path)?;
        let file = self.disk.open_file(root, relative)?;
        read_object(&file, link, false)?;
        self.disk.delete_file(file)?;
        self.directory.sync_all()?;
        Ok(())
    }

    /// Delete the staging name an interrupted publication left.
    pub fn delete_staging(&self, object: Uuid) -> Result<()> {
        let path = self.root.join(format!("{object}.audit.pending"));
        let (root, relative) = self.disk.binding(&path)?;
        let file = self.disk.open_file(root, relative)?;
        self.disk.delete_file(file)?;
        self.directory.sync_all()?;
        Ok(())
    }

    /// Remove this emptied cache directory, consuming its only handle.
    pub fn remove_empty(self) -> Result<()> {
        ensure!(
            self.entries()?.is_empty(),
            "audit cache {} is not empty",
            self.root.display()
        );
        let Self { directory, .. } = self;
        directory.remove_if_empty()?;
        Ok(())
    }
}

impl TenantStore {
    /// The `(cache, destination)` identities this store installed, if any.
    pub fn installed_tenant_audit_placement(&self) -> Result<Option<(String, String)>> {
        self.check_access()?;
        self.get(PLACEMENT, b"identity")?
            .map(|stored| decode_placement(&stored))
            .transpose()
    }

    /// Rewrite the installed placement from the cache identified by `from` to
    /// `to`, keeping its destination choice: a local-replica-only placement
    /// moves with its cache and an external destination is unchanged. The
    /// caller must already hold a verified copy of every object of `from` in
    /// `to`. Returns false when the placement already names `to`. Run before
    /// any placement is installed in this process.
    pub fn relocate_tenant_audit_cache(
        &self,
        from: &str,
        to: &FilesystemAuditArchive,
    ) -> Result<bool> {
        self.check_access()?;
        let placement = self.audit_placement.lock();
        ensure!(
            placement.is_none(),
            "relocate the tenant audit cache before installing its placement"
        );
        let stored = self
            .get(PLACEMENT, b"identity")?
            .context("tenant audit placement was never installed")?;
        let (cache, destination) = decode_placement(&stored)?;
        let target = to.identity();
        if cache == target {
            return Ok(false);
        }
        ensure!(
            cache == from,
            "installed tenant audit cache {cache} is not the move source {from}"
        );
        let destination = if destination == cache {
            target.clone()
        } else {
            destination
        };
        self.write_batch(&[crate::WriteOp::put(
            PLACEMENT,
            b"identity",
            placement_identity(&target, &destination)?.as_slice(),
        )])?;
        drop(placement);
        self.check_access()?;
        Ok(true)
    }
}
