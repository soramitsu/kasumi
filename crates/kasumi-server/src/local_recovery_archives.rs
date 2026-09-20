use super::*;
use kasumi_store::{AuditArchivePublicationObserver, FilesystemAuditArchive};
use kasumi_types::AuditArchiveReference;
use sha2::{Digest, Sha256};

const OBJECTS: &str = "standalone-recovery-archive-objects";
const CACHE: &str = "tenant-audit-archives";
const PAGE: usize = 256;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Object {
    reference: AuditArchiveReference,
    #[serde(deserialize_with = "kasumi_types::require_explicit_option")]
    staged: Option<private_files::FileIdentity>,
    #[serde(deserialize_with = "kasumi_types::require_explicit_option")]
    published: Option<private_files::FileIdentity>,
}
fn key(operation: Uuid, object: Uuid) -> Vec<u8> {
    [
        operation.as_bytes().as_slice(),
        object.as_bytes().as_slice(),
    ]
    .concat()
}
struct Observer {
    store: Arc<TenantStore>,
    operation: Uuid,
    incarnation: Uuid,
    directory: PathBuf,
    identity: private_files::DirectoryIdentity,
}
impl Observer {
    fn check(&self) -> Result<()> {
        self.store.check_access()?;
        ensure!(
            private_files::directory_identity(&self.directory)? == self.identity,
            "owned archive directory was substituted"
        );
        let record: GenerationRecord = decode(
            &self
                .store
                .get(GENERATIONS, self.incarnation.as_bytes())?
                .context("archive generation owner absent")?,
        )?;
        ensure!(
            matches!(record, GenerationRecord::Reserved { operation_id } | GenerationRecord::Active { operation_id } if operation_id == self.operation),
            "archive generation is permanently stopped or belongs to another operation"
        );
        Ok(())
    }
    fn update(
        &self,
        reference: &AuditArchiveReference,
        staged: Option<&private_files::FileIdentity>,
        published: Option<&private_files::FileIdentity>,
    ) -> Result<()> {
        self.check()?;
        reference.validate()?;
        let key = key(self.operation, reference.object.object_id);
        let mut object = match self.store.get(OBJECTS, &key)? {
            Some(bytes) => {
                let object: Object = decode(&bytes)?;
                ensure!(
                    object.reference == *reference,
                    "archive publication identity was reused"
                );
                object
            }
            None => {
                ensure!(
                    staged.is_none() && published.is_none(),
                    "archive preparation must precede its physical files"
                );
                Object {
                    reference: reference.clone(),
                    staged: None,
                    published: None,
                }
            }
        };
        if let Some(identity) = staged {
            ensure!(
                object.published.is_none()
                    && object.staged.as_ref().is_none_or(|old| old == identity),
                "archive staging inode was substituted"
            );
            object.staged = Some(identity.clone());
        }
        if let Some(identity) = published {
            ensure!(
                object.staged.as_ref() == Some(identity)
                    && object.published.as_ref().is_none_or(|old| old == identity),
                "archive publication lacks its original staging inode"
            );
            object.published = Some(identity.clone());
        }
        self.store
            .write_batch(&[WriteOp::put(OBJECTS, key, encoded(&object)?)])?;
        self.check()
    }
}
impl AuditArchivePublicationObserver for Observer {
    fn prepare(&self, reference: &AuditArchiveReference) -> Result<()> {
        self.update(reference, None, None)
    }
    fn staged(
        &self,
        reference: &AuditArchiveReference,
        identity: &private_files::FileIdentity,
    ) -> Result<()> {
        self.update(reference, Some(identity), None)
    }
    fn published(
        &self,
        reference: &AuditArchiveReference,
        identity: &private_files::FileIdentity,
    ) -> Result<()> {
        self.update(reference, None, Some(identity))
    }
}
impl Operator {
    pub(super) fn prepare_archives(&self, journal: &mut Journal) -> Result<()> {
        let directory = journal.target_directory.join(CACHE);
        if journal.archive_directory.is_none() {
            if directory.try_exists()? {
                private_files::check_directory(&directory)?;
                ensure!(
                    std::fs::read_dir(&directory)?.next().is_none(),
                    "unbound archive directory is not empty"
                );
            } else {
                private_files::create_directory(&directory)?;
            }
            journal.archive_directory = Some(private_files::directory_identity(&directory)?);
            self.store().write_batch(&[
                WriteOp::put(
                    OPERATIONS,
                    journal.status.request.operation_id.as_bytes(),
                    encoded(journal)?,
                ),
                WriteOp::put(
                    PHASES,
                    format!("{}/archive-directory", journal.status.phase_id).as_bytes(),
                    encoded(&journal.archive_directory)?,
                ),
            ])?;
        }
        ensure!(
            Some(private_files::directory_identity(&directory)?) == journal.archive_directory,
            "owned archive directory was substituted"
        );
        Ok(())
    }
    pub(super) fn observed_archives(
        &self,
        journal: &Journal,
    ) -> Result<Arc<FilesystemAuditArchive>> {
        let directory = journal.target_directory.join(CACHE);
        let identity = journal
            .archive_directory
            .clone()
            .context("archive directory has no durable ownership binding")?;
        ensure!(
            private_files::directory_identity(&directory)? == identity,
            "owned archive directory was substituted"
        );
        Ok(Arc::new(
            FilesystemAuditArchive::open(&directory, self.audit.store().persistent_disk().clone())?
                .with_publication_observer(Arc::new(Observer {
                    store: self.audit.store().clone(),
                    operation: journal.status.request.operation_id,
                    incarnation: journal.status.request.target_incarnation,
                    directory,
                    identity,
                })),
        ))
    }

    /// One bounded pass, under the stopped generation's exclusive database lock.
    /// Ownership rows and phase records remain in the original security store.
    pub(super) fn cleanup_archives(&self, journal: &Journal) -> Result<bool> {
        self.require_cleanup_disk()?;
        let directory = journal.target_directory.join(CACHE);
        if !directory.try_exists()? {
            return Ok(true);
        }
        let identity = private_files::directory_identity(&directory)?;
        if let Some(expected) = &journal.archive_directory {
            ensure!(
                &identity == expected,
                "cleanup refuses substituted archive directory"
            );
        } else {
            ensure!(
                std::fs::read_dir(&directory)?.next().is_none(),
                "cleanup refuses an unbound populated archive directory"
            );
        }
        for (index, entry) in std::fs::read_dir(&directory)?.enumerate() {
            if index == PAGE {
                return Ok(false);
            }
            let entry = entry?;
            ensure!(
                entry.file_type()?.is_file(),
                "cleanup refuses a linked or nested archive entry"
            );
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("archive entry name invalid"))?;
            let (text, pending) = if let Some(text) = name.strip_suffix(".audit.pending") {
                (text, true)
            } else {
                (
                    name.strip_suffix(".audit")
                        .context("cleanup refuses an unrelated archive entry")?,
                    false,
                )
            };
            let id = Uuid::parse_str(text)?;
            ensure!(
                !id.is_nil() && id.to_string() == text,
                "archive entry identity is not canonical"
            );
            let object: Object = decode(
                &self
                    .store()
                    .get(OBJECTS, &key(journal.status.request.operation_id, id))?
                    .context("cleanup refuses an unowned archive object")?,
            )?;
            object.reference.validate()?;
            ensure!(
                object.reference.object.object_id == id,
                "archive ownership identity differs"
            );
            let path = entry.path();
            let file = crate::standalone::open_installed_file(
                &self.config.persistent_disk,
                self.store().persistent_disk(),
                &path,
            )?;
            let file_identity = file.identity()?;
            let file_length = file.observed_len()?;
            if let Some(expected) = &object.staged {
                ensure!(
                    &file_identity == expected,
                    "cleanup refuses a substituted archive inode"
                );
            } else {
                // A crash between exclusive empty-file creation and the first
                // inode commit can leave only this prepared, empty staging name.
                ensure!(
                    pending && file_length == 0 && object.published.is_none(),
                    "archive file appeared before its physical ownership commit"
                );
            }
            ensure!(
                file_length <= object.reference.ciphertext_bytes,
                "archive staging file exceeds its committed dependency"
            );
            if !pending {
                ensure!(
                    object
                        .published
                        .as_ref()
                        .is_none_or(|expected| *expected == file_identity),
                    "archive final inode differs"
                );
                let mut hash = Sha256::new();
                let mut bytes = 0u64;
                let mut buffer = [0u8; 64 << 10];
                while bytes < file_length {
                    let read = usize::try_from((file_length - bytes).min(buffer.len() as u64))?;
                    file.read_exact_at(&mut buffer[..read], bytes)?;
                    bytes = bytes
                        .checked_add(read as u64)
                        .context("archive length overflow")?;
                    ensure!(
                        bytes <= object.reference.ciphertext_bytes,
                        "archive final length grew"
                    );
                    hash.update(&buffer[..read]);
                }
                ensure!(
                    bytes == object.reference.ciphertext_bytes
                        && hex::encode(hash.finalize())
                            == object.reference.object.ciphertext_sha256,
                    "cleanup refuses substituted archive contents"
                );
            }
            ensure!(
                private_files::directory_identity(&directory)? == identity
                    && private_files::file_identity(&path)? == file_identity,
                "archive ownership changed during cleanup"
            );
            self.store().persistent_disk().delete_file(file)?;
        }
        if std::fs::read_dir(&directory)?.next().is_some() {
            return Ok(false);
        }
        ensure!(
            private_files::directory_identity(&directory)? == identity,
            "archive directory changed during cleanup"
        );
        // Exact directory mutation/accounting still needs a NodeDisk owner API.
        self.require_cleanup_disk()?;
        std::fs::remove_dir(&directory)?;
        private_files::sync_parent(&directory)?;
        Ok(true)
    }
}
