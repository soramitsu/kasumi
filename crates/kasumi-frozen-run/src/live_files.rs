//! All database names are relative to the exclusively locked directory fd.
//! Each generation file also carries the database incarnation in its name.
use crate::{invalid, live_wal::sync_durable};
use rustix::fs::{self, AtFlags, Dir, Mode, OFlags};
use std::os::unix::fs::MetadataExt;
use std::{
    collections::BTreeSet,
    ffi::OsStr,
    fs::File,
    io::{self, ErrorKind, Read, Write},
    path::Path,
};
use uuid::Uuid;

pub(super) const MANIFEST: &str = "MANIFEST";
const CREATE_PREFIX: &str = ".kasumi-init-v1-";

pub(super) struct Files {
    directory: File,
}
impl Files {
    pub(super) fn lock(path: &Path, create: bool) -> io::Result<(Self, u64)> {
        let full = std::path::absolute(path)?;
        let full = if full.file_name().is_none() {
            full.canonicalize()?
        } else {
            full
        };
        let name = full.file_name().ok_or_else(|| {
            io::Error::new(
                ErrorKind::InvalidInput,
                "database cannot be the filesystem root",
            )
        })?;
        let parent = File::open(
            full.parent()
                .ok_or_else(|| invalid("missing live parent"))?,
        )?;
        if create {
            match fs::mkdirat(&parent, name, Mode::from_raw_mode(0o700)) {
                Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                Err(e) => return Err(e.into()),
            }
        }
        let directory = File::from(fs::openat(
            &parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        directory.try_lock()?;
        if create {
            parent.sync_all()?;
        }
        Ok((Self { directory }, u64::from(create)))
    }

    pub(super) fn sync(&self, count: &mut u64) -> io::Result<()> {
        self.directory.sync_all()?;
        *count = count.saturating_add(1);
        Ok(())
    }

    fn names(&self, mut visit: impl FnMut(&str) -> io::Result<()>) -> io::Result<()> {
        let entries = Dir::read_from(&self.directory)?;
        for entry in entries {
            let entry = entry?;
            let name = entry
                .file_name()
                .to_str()
                .map_err(|_| invalid("non-UTF8 live database entry"))?;
            if name != "." && name != ".." {
                visit(name)?;
            }
        }
        Ok(())
    }

    /// The marker is an atomic name containing a fresh, syntactically valid
    /// incarnation. Ordinary filenames never authorize destructive bootstrap.
    pub(super) fn creation_marker(&self, create: bool) -> io::Result<Option<[u8; 16]>> {
        let mut count = 0;
        let mut marker = None;
        self.names(|name| {
            count += 1;
            if let Some(suffix) = name.strip_prefix(CREATE_PREFIX) {
                let id = Uuid::parse_str(suffix)
                    .map_err(|_| invalid("invalid live bootstrap identity"))?;
                if suffix != id.simple().to_string()
                    || id.get_version_num() != 4
                    || marker.replace(*id.as_bytes()).is_some()
                {
                    return Err(invalid("invalid live bootstrap marker"));
                }
                // NOFOLLOW and DIRECTORY refuse symlinks and foreign file types.
                let marker = fs::openat(
                    &self.directory,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
                    Mode::empty(),
                )?;
                for entry in Dir::read_from(marker)? {
                    if !matches!(entry?.file_name().to_bytes(), b"." | b"..") {
                        return Err(invalid("nonempty live creation marker"));
                    }
                }
            }
            Ok(())
        })?;
        if marker.is_none() && create {
            if count != 0 {
                return Err(io::Error::new(
                    ErrorKind::AlreadyExists,
                    "live database requires an empty directory",
                ));
            }
            let id = Uuid::new_v4();
            fs::mkdirat(
                &self.directory,
                Self::marker(id.as_bytes()),
                Mode::from_raw_mode(0o700),
            )?;
            marker = Some(*id.as_bytes());
        }
        Ok(marker)
    }

    fn marker(id: &[u8; 16]) -> String {
        format!("{CREATE_PREFIX}{}", Uuid::from_bytes(*id).simple())
    }
    pub(super) fn remove_marker(&self, id: &[u8; 16]) -> io::Result<bool> {
        match fs::unlinkat(&self.directory, Self::marker(id), AtFlags::REMOVEDIR) {
            Ok(()) => Ok(true),
            Err(rustix::io::Errno::NOENT) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
    pub(super) fn name(id: &[u8; 16], suffix: &str) -> String {
        format!(".kasumi-{}-{suffix}", Uuid::from_bytes(*id).simple())
    }
    pub(super) fn read(&self, name: &str) -> io::Result<File> {
        self.open(name, OFlags::RDONLY)
    }
    pub(super) fn writable(&self, name: &str) -> io::Result<File> {
        let file = self.open(name, OFlags::RDWR)?;
        file.try_lock()?;
        Ok(file)
    }
    pub(super) fn fresh(&self, name: &str) -> io::Result<File> {
        self.open(name, OFlags::RDWR | OFlags::CREATE | OFlags::EXCL)
    }
    fn open(&self, name: &str, flags: OFlags) -> io::Result<File> {
        debug_assert!(!name.as_bytes().contains(&b'/'));
        let file = File::from(fs::openat(
            &self.directory,
            OsStr::new(name),
            flags | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?);
        let meta = file.metadata()?;
        if !meta.is_file() || meta.nlink() != 1 {
            return Err(invalid("live database requires private regular files"));
        }
        Ok(file)
    }
    pub(super) fn publish(&self, id: &[u8; 16], bytes: &[u8], syncs: &mut u64) -> io::Result<()> {
        let temp = Self::name(id, "head-next");
        let mut file = self.fresh(&temp)?;
        file.write_all(bytes)?;
        sync_durable(&file)?;
        self.sync(syncs)?;
        fs::renameat(&self.directory, temp, &self.directory, MANIFEST)?;
        self.sync(syncs)
    }
    pub(super) fn remove(&self, name: &str) -> io::Result<bool> {
        match self.read(name) {
            Ok(_) => {
                fs::unlinkat(&self.directory, name, AtFlags::empty())?;
                Ok(true)
            }
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// A crashed bootstrap can leave only prefixes of this exact empty
    /// incarnation. Validate every file, then remove those private fragments.
    pub(super) fn reset_bootstrap(
        &self,
        id: &[u8; 16],
        expected: &[(&str, &[u8])],
    ) -> io::Result<()> {
        let marker = Self::marker(id);
        self.names(|name| {
            if name == marker {
                return Ok(());
            }
            let (_, bytes) = expected
                .iter()
                .find(|(known, _)| name == *known)
                .ok_or_else(|| invalid("foreign file in live bootstrap"))?;
            let mut file = self.read(name)?;
            let len = file.metadata()?.len();
            if len > bytes.len() as u64 {
                return Err(invalid("foreign data in live bootstrap"));
            }
            let mut found = vec![0; len as usize];
            file.read_exact(&mut found)?;
            if found != bytes[..found.len()] {
                return Err(invalid("invalid live bootstrap prefix"));
            }
            Ok(())
        })?;
        for (name, _) in expected {
            self.remove(name)?;
        }
        Ok(())
    }

    /// Sweep only canonical engine allocation names for this UUID. Caller
    /// first synchronizes the selected manifest and all of its active names.
    pub(super) fn reclaim(&self, id: &[u8; 16], keep: &BTreeSet<String>) -> io::Result<bool> {
        let prefix = Self::name(id, "");
        let mut obsolete = Vec::new();
        self.names(|name| {
            if keep.contains(name) {
                return Ok(());
            }
            let Some(suffix) = name.strip_prefix(&prefix) else {
                return Ok(());
            };
            let numeric = |s: &str| s.parse::<u64>().ok().is_some_and(|n| n.to_string() == s);
            let known = suffix == "head-next"
                || suffix.strip_prefix("wal-").is_some_and(|ids| {
                    ids.split_once('-')
                        .is_some_and(|(seq, tier)| numeric(seq) && numeric(tier))
                })
                || suffix.strip_prefix("run-").is_some_and(|ids| {
                    ids.split_once('-')
                        .is_some_and(|(seq, part)| numeric(seq) && numeric(part))
                });
            if known {
                if obsolete.len() >= 2 * 64 + 8 {
                    return Err(invalid("too many unselected live generations"));
                }
                obsolete.push(name.to_owned());
            }
            Ok(())
        })?;
        let changed = !obsolete.is_empty();
        for name in obsolete {
            self.remove(&name)?;
        }
        Ok(changed)
    }
}
