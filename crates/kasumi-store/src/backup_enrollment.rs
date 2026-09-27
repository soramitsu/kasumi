//! Enrolled filesystem backup roots.
//!
//! Enrollment is the only path that creates a destination root: one admitted
//! namespace operation creates the directory and its fixed marker, synchronizes
//! both and reads the marker back through a fresh retained open. Opening never
//! creates, marks or repairs a root. The marker binds the directory to one
//! installed owner and namespace UUID and is verified, durably, on every open.
//! The directory descriptor identity is captured at open and re-verified with
//! its complete enrolled ancestry around every operation. `st_dev` is never
//! compared across opens, so a remount that renumbers the device keeps its
//! binding, while a marker copied into another directory does not. A root is
//! never enrolled inside another enrolled root.
//!
//! No marker descriptor is retained: NodeDisk file opens are exclusive, and a
//! process may legitimately hold several destinations for one enrolled root.
use super::Directory;
use crate::backup_marker::{MARKER_BYTES, Marker, validate_identity};
use crate::node_disk::{NamespaceAdmission, NamespacePart, NamespacePartKind};
use anyhow::{Context, Result, bail, ensure};
use kasumi_types::{BackupNamespaceBinding, TrustVerifierIdentity};
use std::{
    ffi::{CStr, CString},
    path::Path,
    sync::Arc,
};
use uuid::Uuid;

/// Fixed marker leaf of every enrolled root. Backup and session names are
/// UUID-derived, so no destination operation can address or replace it.
pub(crate) const MARKER_NAME: &CStr = c"kasumi-backup.marker";

fn marker_leaf() -> &'static Path {
    use std::os::unix::ffi::OsStrExt;
    Path::new(std::ffi::OsStr::from_bytes(MARKER_NAME.to_bytes()))
}

/// One retained enrolled root and the identity its marker was verified in.
pub(crate) struct EnrolledRoot {
    root: Directory,
    identity: (u64, u64),
    binding: BackupNamespaceBinding,
}

impl EnrolledRoot {
    /// Create one absent root below an enrolled parent within an installed
    /// accounting root, then its marker, in a single admitted operation. No
    /// ancestor is created. An existing root is never marked, adopted or
    /// repaired: only this owner's own marker for `namespace_id`, bound to the
    /// same directory, completes an interrupted enrollment.
    pub(crate) fn enroll(
        path: &Path,
        disk: Arc<crate::NodeDisk>,
        owner: &TrustVerifierIdentity,
        namespace_id: Uuid,
    ) -> Result<Self> {
        use std::os::unix::ffi::OsStrExt;
        validate_identity(owner, namespace_id)
            .context("invalid backup destination enrollment identity")?;
        let marker_path = path.join(marker_leaf());
        let (root, marker_relative) = disk.binding(&marker_path)?;
        let relative = marker_relative
            .parent()
            .context("backup destination binding")?;
        ensure!(
            !relative.as_os_str().is_empty(),
            "a backup destination root must be created below an installed accounting root"
        );
        let parent = disk.open_directory(
            root,
            relative.parent().context("backup destination parent")?,
        )?;
        let name = CString::new(
            relative
                .file_name()
                .context("backup destination name")?
                .as_bytes(),
        )?;
        // This witness is declared before every owned directory, file and
        // admission, which all retire before the namespace lane is released.
        let claim = parent.claim_descendants(&[name.as_c_str()])?;
        // The single namespace lane keeps another enrollment from publishing a
        // marker between this check and the admission below.
        reject_enrolled_ancestor(&disk, root, relative)?;
        match parent.open_child(&name) {
            Ok(existing) => {
                drop(existing);
                drop(claim);
                return Self::open_marked(path, disk, |marker| {
                    marker.owner() == owner && marker.namespace_id() == namespace_id
                });
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && disk.snapshot().phase == crate::NodeDiskPhase::Open => {}
            Err(error) => return Err(error.into()),
        }
        let mut admission = disk.admit_claimed_namespace(
            &claim,
            &[
                NamespacePart {
                    root,
                    relative,
                    kind: NamespacePartKind::Directory,
                },
                NamespacePart {
                    root,
                    relative: marker_relative,
                    kind: NamespacePartKind::File {
                        length: MARKER_BYTES as u64,
                    },
                },
            ],
            crate::DiskWork::Foreground,
        )?;
        let directory = Directory(
            parent.create_admitted_child(&name, &mut admission)?,
            disk.clone(),
            path.to_owned(),
        );
        #[cfg(test)]
        test_cut::check(path, test_cut::Step::RootCreated)?;
        let (device, inode) = directory.verified_identity()?;
        let marker = Marker::new(owner.clone(), namespace_id, device, inode)?;
        let file = write_marker(&directory, &mut admission, &marker)?;
        admission.finish()?;
        #[cfg(test)]
        test_cut::check(path, test_cut::Step::MarkerSynced)?;
        drop((file, directory, parent));
        drop(claim);
        // Read back through a fresh retained open; nothing is trusted from the
        // creating descriptors.
        Self::open_marked(path, disk, |found| found == &marker)
    }

    /// Open an existing root whose marker is exactly `binding`. No directory,
    /// marker or repair is ever created by this path.
    pub(crate) fn open(
        path: &Path,
        disk: Arc<crate::NodeDisk>,
        binding: &BackupNamespaceBinding,
    ) -> Result<Self> {
        binding.validate()?;
        let expected =
            Marker::from_binding(binding).context("invalid filesystem backup binding")?;
        Self::open_marked(path, disk, |found| found == &expected)
    }

    /// Test fixtures keep the historical raw constructor shape: create or adopt
    /// the root and mark an unmarked one with the fixture owner. This path is
    /// absent from production builds.
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn fixture(
        path: &Path,
        disk: Arc<crate::NodeDisk>,
        owner: &TrustVerifierIdentity,
    ) -> Result<Self> {
        let directory = Directory::open_or_create(path, disk.clone())?;
        let (device, inode) = directory.verified_identity()?;
        let claim = directory.0.claim_descendants(&[MARKER_NAME])?;
        let marker_path = path.join(marker_leaf());
        let (root, relative) = disk.binding(&marker_path)?;
        match disk.open_file(root, relative) {
            Ok(existing) => drop(existing),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                directory.check()?;
                let mut admission = disk.admit_claimed_namespace(
                    &claim,
                    &[NamespacePart {
                        root,
                        relative,
                        kind: NamespacePartKind::File {
                            length: MARKER_BYTES as u64,
                        },
                    }],
                    crate::DiskWork::Foreground,
                )?;
                let marker = Marker::new(owner.clone(), Uuid::new_v4(), device, inode)?;
                let file = write_marker(&directory, &mut admission, &marker)?;
                admission.finish()?;
                drop(file);
            }
            Err(error) => return Err(error.into()),
        }
        drop(directory);
        drop(claim);
        Self::open_marked(path, disk, |found| found.owner() == owner)
    }

    fn open_marked(
        path: &Path,
        disk: Arc<crate::NodeDisk>,
        accept: impl FnOnce(&Marker) -> bool,
    ) -> Result<Self> {
        let root = Directory::open(path, disk.clone())?;
        let identity = root.verified_identity()?;
        let marker_path = path.join(marker_leaf());
        let (disk_root, relative) = disk.binding(&marker_path)?;
        let marker = match disk.open_file(disk_root, relative) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // Only an unknown marker is a healthy absence; an enrolled one
                // disappearing has already fenced the owner.
                root.check()
                    .map_err(|failure| anyhow::Error::new(error).context(failure))?;
                bail!("backup destination root is not enrolled");
            }
            Err(error) => return Err(error.into()),
        };
        let bytes = read_marker(&marker)?;
        let decoded = Marker::decode(&bytes).context("invalid backup destination marker")?;
        ensure!(
            accept(&decoded),
            "backup destination marker belongs to another owner or namespace"
        );
        // The inode survives a remount but not a copied marker. The device
        // number is deliberately not compared: a remount may renumber it.
        ensure!(
            decoded.inode() == identity.1,
            "backup destination marker was bound to another directory"
        );
        // Visible bytes of an interrupted enrollment are trusted only after
        // they, their directory entry and the root itself are durable.
        marker.sync_all_and_parent()?;
        root.sync_all()?;
        ensure!(
            read_marker(&marker)? == bytes,
            "backup destination marker changed while opening"
        );
        drop(marker);
        let enrolled = Self {
            root,
            identity,
            binding: decoded.binding(),
        };
        enrolled.verify()?;
        Ok(enrolled)
    }

    /// Re-verify the retained descriptor and its complete enrolled path against
    /// the identity the marker was verified in. NodeDisk fences a changed path,
    /// descriptor or ledger itself; its refusal while a sibling owner of the
    /// device is uncertain is not a change here and clears through that
    /// sibling's census, so it is returned without fencing this owner.
    pub(crate) fn verify(&self) -> Result<()> {
        let identity = self
            .root
            .verified_identity()
            .context("enrolled backup destination root could not be verified")?;
        if identity != self.identity {
            self.root.1.fail();
            bail!("enrolled backup destination directory changed");
        }
        Ok(())
    }

    /// The exact physical identity, verified at the time of the call.
    pub(crate) fn binding(&self) -> Result<BackupNamespaceBinding> {
        self.verify()?;
        Ok(self.binding.clone())
    }

    /// Verify before and after one effect. An effect whose root cannot be
    /// re-verified afterwards is unconfirmed; it is reported as a failure and
    /// left in place, never removed or reported as a rollback.
    pub(crate) fn run<T>(&self, operation: impl FnOnce(&Directory) -> Result<T>) -> Result<T> {
        self.verify()?;
        let outcome = operation(&self.root);
        #[cfg(test)]
        test_after_effect::run(self.path());
        match (outcome, self.verify()) {
            (outcome, Ok(())) => outcome,
            (Ok(_), Err(failure)) => Err(failure.context(
                "backup destination was not re-verified after its effect; the outcome is unconfirmed",
            )),
            (Err(error), Err(failure)) => Err(error.context(failure)),
        }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.root.2
    }
}

/// A root below another enrolled root would place its directory and marker in
/// that destination's namespace, where its session reclamation rejects them.
/// Every enrolled ancestor, up to and including the accounting root, must be
/// unmarked. The walk is bounded by the path depth NodeDisk already admitted.
fn reject_enrolled_ancestor(
    disk: &Arc<crate::NodeDisk>,
    root: &str,
    relative: &Path,
) -> Result<()> {
    for ancestor in relative.ancestors().skip(1) {
        match disk.open_file(root, &ancestor.join(marker_leaf())) {
            Ok(marker) => {
                drop(marker);
                bail!("a backup destination root cannot be enrolled inside another enrolled root");
            }
            // Only an unknown marker is a healthy absence; an enrolled one
            // disappearing has already fenced the owner.
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && disk.snapshot().phase == crate::NodeDiskPhase::Open => {}
            Err(error) => {
                return Err(anyhow::Error::new(error)
                    .context("backup destination ancestor could not be checked for a marker"));
            }
        }
    }
    Ok(())
}

// The admission already charges the fixed extent; the marker is complete and
// durable, with its directory entry, before the admission may finish.
fn write_marker(
    directory: &Directory,
    admission: &mut NamespaceAdmission,
    marker: &Marker,
) -> Result<crate::NodeDiskFile> {
    let bytes = marker.encode();
    let path = directory.2.join(marker_leaf());
    let (root, relative) = directory.1.binding(&path)?;
    let file = directory
        .1
        .create_admitted_file(admission, root, relative)?;
    #[cfg(test)]
    test_cut::check(&directory.2, test_cut::Step::MarkerCreated)?;
    file.grow_reserved(MARKER_BYTES as u64)?;
    file.write_all_at(&bytes, 0)?;
    #[cfg(test)]
    test_cut::check(&directory.2, test_cut::Step::MarkerWritten)?;
    file.sync_all_and_parent()?;
    Ok(file)
}

fn read_marker(file: &crate::NodeDiskFile) -> Result<[u8; MARKER_BYTES]> {
    ensure!(
        file.observed_len()? == MARKER_BYTES as u64,
        "invalid backup destination marker"
    );
    let mut bytes = [0; MARKER_BYTES];
    file.read_exact_at(&mut bytes, 0)?;
    Ok(bytes)
}

/// Deterministic process-crash cuts. An armed cut returns before the next
/// step; its unfinished admission fences the owner exactly as a crash would.
#[cfg(test)]
pub(crate) mod test_cut {
    use anyhow::{Result, ensure};
    use std::{
        collections::BTreeMap,
        path::{Path, PathBuf},
        sync::{Mutex, OnceLock},
    };

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Step {
        RootCreated,
        MarkerCreated,
        MarkerWritten,
        MarkerSynced,
    }
    fn cuts() -> &'static Mutex<BTreeMap<PathBuf, Step>> {
        static CUTS: OnceLock<Mutex<BTreeMap<PathBuf, Step>>> = OnceLock::new();
        CUTS.get_or_init(Default::default)
    }
    pub(crate) struct Guard(PathBuf);
    impl Drop for Guard {
        fn drop(&mut self) {
            cuts().lock().unwrap().remove(&self.0);
        }
    }
    pub(crate) fn arm(root: &Path, step: Step) -> Guard {
        assert!(
            cuts()
                .lock()
                .unwrap()
                .insert(root.to_owned(), step)
                .is_none()
        );
        Guard(root.to_owned())
    }
    pub(super) fn check(root: &Path, step: Step) -> Result<()> {
        let mut cuts = cuts().lock().unwrap();
        let armed = cuts.get(root) == Some(&step);
        if armed {
            cuts.remove(root);
        }
        ensure!(
            !armed,
            "injected crash after backup enrollment step {step:?}"
        );
        Ok(())
    }
}

/// Deterministic interleaving after an operation's effect and before its
/// closing verification, keyed by the configured root path.
#[cfg(test)]
pub(crate) mod test_after_effect {
    use std::{
        collections::BTreeMap,
        path::{Path, PathBuf},
        sync::{Mutex, OnceLock},
    };

    type Hook = Box<dyn FnOnce() + Send>;
    fn hooks() -> &'static Mutex<BTreeMap<PathBuf, Hook>> {
        static HOOKS: OnceLock<Mutex<BTreeMap<PathBuf, Hook>>> = OnceLock::new();
        HOOKS.get_or_init(Default::default)
    }
    pub(crate) struct Guard(PathBuf);
    impl Drop for Guard {
        fn drop(&mut self) {
            hooks().lock().unwrap().remove(&self.0);
        }
    }
    pub(crate) fn arm(root: &Path, hook: impl FnOnce() + Send + 'static) -> Guard {
        assert!(
            hooks()
                .lock()
                .unwrap()
                .insert(root.to_owned(), Box::new(hook))
                .is_none()
        );
        Guard(root.to_owned())
    }
    pub(super) fn run(root: &Path) {
        let hook = hooks().lock().unwrap().remove(root);
        if let Some(hook) = hook {
            hook();
        }
    }
}
