//! Renewable credentials read from an operator-installed, atomically replaced file.
//! Each load opens one inode and returns an owned, zeroized snapshot. No stale
//! value is cached when a replacement is malformed, missing, or inaccessible.
use anyhow::{Context, Result, ensure};
use std::{
    io::Read,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

pub const MAX_CREDENTIAL_BYTES: usize = 64 << 10;

/// Implementations must return a fresh snapshot for every request. Deliberately
/// neither Debug nor Serialize; callers must not include values in diagnostics.
pub trait CredentialSource: Send + Sync {
    fn load(&self) -> Result<Zeroizing<String>>;
}
impl<F> CredentialSource for F
where
    F: Fn() -> Result<Zeroizing<String>> + Send + Sync,
{
    fn load(&self) -> Result<Zeroizing<String>> {
        self()
    }
}

#[derive(Clone, Debug)]
pub struct FileCredentialSource {
    path: PathBuf,
}
impl FileCredentialSource {
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        ensure!(
            path.as_ref().is_absolute(),
            "credential path must be absolute"
        );
        Ok(Self {
            path: path.as_ref().to_owned(),
        })
    }
}
impl CredentialSource for FileCredentialSource {
    fn load(&self) -> Result<Zeroizing<String>> {
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = options
            .open(&self.path)
            .context("opening installed credential file")?;
        let before = file.metadata()?;
        ensure!(before.is_file(), "credential must be a regular file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            ensure!(
                before.mode() & 0o077 == 0 && before.uid() == unsafe { libc::geteuid() },
                "credential file must be owned by this user with owner-only permissions"
            );
        }
        ensure!(
            before.len() > 0 && before.len() <= MAX_CREDENTIAL_BYTES as u64,
            "credential file is empty or too large"
        );
        let mut bytes = Zeroizing::new(Vec::new());
        (&file)
            .take(MAX_CREDENTIAL_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        let after = file.metadata()?;
        ensure!(
            bytes.len() <= MAX_CREDENTIAL_BYTES
                && before.len() == after.len()
                && before.modified()? == after.modified()?
                && bytes.len() as u64 == after.len(),
            "credential file changed during read; publish replacements with atomic rename"
        );
        let value = std::str::from_utf8(&bytes).context("credential is not UTF-8")?;
        Ok(Zeroizing::new(value.to_owned()))
    }
}

/// Token files may end in a single Unix or Windows newline, as emitted by CLI
/// writers. All other whitespace/control bytes are rejected before transport.
pub fn token(source: &dyn CredentialSource) -> Result<Zeroizing<String>> {
    let mut value = source.load()?;
    if value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    }
    ensure!(
        !value.is_empty() && value.len() <= 16 << 10 && value.bytes().all(|b| b.is_ascii_graphic()),
        "credential token is empty or malformed"
    );
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    fn publish(path: &Path, value: &[u8]) {
        use std::{io::Write, os::unix::fs::PermissionsExt};
        let mut file = tempfile::NamedTempFile::new_in(path.parent().unwrap()).unwrap();
        file.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .unwrap();
        file.write_all(value).unwrap();
        file.as_file().sync_all().unwrap();
        file.persist(path).unwrap();
    }
    #[test]
    #[cfg(unix)]
    fn replacement_is_fresh_and_failure_never_reuses_previous_secret() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        let source = FileCredentialSource::new(&path).unwrap();
        publish(&path, b"first\n");
        assert_eq!(&*token(&source).unwrap(), "first");
        publish(&path, b"second\r\n");
        assert_eq!(&*token(&source).unwrap(), "second");
        publish(&path, b"broken\nheader");
        assert!(token(&source).is_err());
        publish(&path, b"third");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(source.load().is_err());
        std::fs::remove_file(&path).unwrap();
        assert!(source.load().is_err());
    }
    #[test]
    #[cfg(unix)]
    fn rejects_symlinks_special_files_and_oversized_credentials() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        let link = dir.path().join("link");
        publish(&path, b"secret");
        symlink(&path, &link).unwrap();
        assert!(FileCredentialSource::new(link).unwrap().load().is_err());
        assert!(
            FileCredentialSource::new(dir.path())
                .unwrap()
                .load()
                .is_err()
        );
        publish(&path, &vec![b'a'; MAX_CREDENTIAL_BYTES + 1]);
        assert!(FileCredentialSource::new(path).unwrap().load().is_err());
    }
}
