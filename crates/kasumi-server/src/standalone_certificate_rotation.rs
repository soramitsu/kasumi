//! Stopped certificate rotation as one recoverable generation publication.
//!
//! The rotation journals its plan in the security store before its first
//! write. It writes every replacement key and certificate into private
//! generation directories, `tls/generation-<id>` for the listeners and
//! `profiles/generation-<id>` for the generated client identities, and
//! publishes each by one exclusive rename once it is complete and synced.
//! Readers switch by pointer: `kasumi.json` names the listener files and each
//! profile names its client identity, so startup, a SIGHUP reload and every
//! client read a complete old or a complete new pair, never a mix. Files are
//! never rewritten in place. A rerun after any interruption resumes the
//! journaled generation, finishes admission, configuration, Control topology
//! and profiles, and only then retires the replaced files and the journal.
use super::*;

const NS: &str = "standalone-certificate-rotation";
const PENDING: &[u8] = b"pending";
const MAX_JOURNAL: usize = 64 << 10;
const MAX_CLIENT_IDENTITIES: usize = 128;
const LISTENERS: [&str; 3] = ["mcp", "native", "admin"];
const GENERATION_PREFIX: &str = "generation-";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    generation: Uuid,
    /// The listener files being replaced, by listener.
    listeners: BTreeMap<String, TlsFiles>,
    /// The generated client identities being replaced, by name.
    clients: BTreeMap<String, TlsFiles>,
}

/// The complete replacement generation.
struct Generation {
    listeners: BTreeMap<String, TlsFiles>,
    clients: BTreeMap<String, TlsFiles>,
}

/// Whether a rotation is journaled and unfinished. Its profiles, pins and
/// topology may name either generation, so nothing may serve or issue
/// certificate-bound credentials until a rerun finishes it.
pub(crate) fn pending(store: &TenantStore) -> Result<bool> {
    Ok(store.get_bounded(NS, PENDING, MAX_JOURNAL)?.is_some())
}

/// Run or resume the rotation. `attempt` names this attempt's audit events
/// and its Control topology command.
pub(super) async fn rotate(
    configuration: &Path,
    owner: &OperatorState,
    attempt: &str,
) -> Result<serde_json::Value> {
    let config = RuntimeConfig::load(configuration)?;
    let root = installation_root(&config)?.to_owned();
    let store = owner.audit.store().clone();
    let issuer_material = Issuer::load(&root)?;
    let journal = match store.get_bounded(NS, PENDING, MAX_JOURNAL)? {
        Some(bytes) => serde_json::from_slice::<Journal>(bytes.as_bytes())?,
        None => {
            let clients = installed_client_identities(&root)?;
            ensure!(
                clients.len() <= MAX_CLIENT_IDENTITIES,
                "more than {MAX_CLIENT_IDENTITIES} generated client identities in profiles/"
            );
            let journal = Journal {
                generation: Uuid::new_v4(),
                listeners: BTreeMap::from([
                    ("mcp".to_owned(), config.mcp.tls.clone()),
                    ("native".to_owned(), config.native.tls.clone()),
                    ("admin".to_owned(), config.admin.tls.clone()),
                ]),
                clients,
            };
            store.write_batch(&[kasumi_store::WriteOp::put(
                NS,
                PENDING,
                serde_json::to_vec(&journal)?,
            )])?;
            journal
        }
    };
    boundary(&root, "journal")?;
    let issuer = issuer_material.issuer()?;
    let listeners = LISTENERS.map(|name| (name.to_owned(), false));
    let clients = journal
        .clients
        .keys()
        .map(|name| (name.clone(), true))
        .collect::<Vec<_>>();
    let generation = Generation {
        listeners: publish_directory(
            &root,
            &root.join("tls").join(generation_name(journal.generation)),
            &listeners,
            &issuer,
        )?,
        clients: publish_directory(
            &root,
            &root
                .join("profiles")
                .join(generation_name(journal.generation)),
            &clients,
            &issuer,
        )?,
    };
    // Admit every replacement client certificate before anything presents it.
    let mut client_pins = BTreeMap::new();
    for (name, files) in &generation.clients {
        let pin = files.load()?.certificate_pin();
        crate::client_pins::enroll_configured(&config, pin, name)?;
        boundary(&root, "admitted")?;
        client_pins.insert(name.clone(), pin);
    }
    let config = publish_configuration(configuration, &generation.listeners)?;
    boundary(&root, "configuration")?;
    let native_pin = hex::encode(config.native.tls.load()?.certificate_pin());
    let admin_pin = hex::encode(config.admin.tls.load()?.certificate_pin());
    let mcp_pin = hex::encode(config.mcp.tls.load()?.certificate_pin());
    commit_topology(owner, &mcp_pin, attempt).await?;
    boundary(&root, "topology")?;
    publish_profiles(
        &root,
        &journal,
        &generation,
        &native_pin,
        &admin_pin,
        &owner.credentials,
    )?;
    for (name, pin) in &client_pins {
        crate::client_pins::retire_configured(&config, name, *pin)?;
        boundary(&root, "retired-pin")?;
    }
    retire_replaced(&root, &journal, &generation)?;
    store.write_batch(&[kasumi_store::WriteOp::delete(NS, PENDING)])?;
    Ok(serde_json::json!({
        "native_certificate_pin": native_pin,
        "admin_certificate_pin": admin_pin,
        "client_identities": generation.clients,
    }))
}

/// The retained CA, checked as a matching pair before any leaf is signed.
struct Issuer {
    certificate: Vec<u8>,
    key: zeroize::Zeroizing<Vec<u8>>,
}
impl Issuer {
    fn load(root: &Path) -> Result<Self> {
        let key = private_files::read(&root.join("operator/ca-key.pem"), 1 << 20)?;
        let certificate = private_files::read(&root.join("tls/ca.pem"), 1 << 20)?.to_vec();
        // Rustls checks the certificate's public key against the private key.
        // Parsing two PEM files is insufficient.
        let identity = kasumi_transport::TlsIdentity::from_pem(&certificate, &key)?;
        kasumi_transport::server_config(&identity, kasumi_transport::ClientAuthentication::OAuth)?;
        Ok(Self { certificate, key })
    }
    fn issuer(&self) -> Result<rcgen::Issuer<'static, rcgen::KeyPair>> {
        let key = rcgen::KeyPair::from_pem(std::str::from_utf8(&self.key)?)?;
        Ok(rcgen::Issuer::from_ca_cert_pem(
            std::str::from_utf8(&self.certificate)?,
            key,
        )?)
    }
}

fn generation_name(generation: Uuid) -> String {
    format!("{GENERATION_PREFIX}{generation}")
}

/// Whether `directory` is a rotation generation directly inside `parent`.
pub(super) fn is_generation_directory(directory: &Path, parent: &Path) -> bool {
    directory.parent() == Some(parent)
        && directory
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_prefix(GENERATION_PREFIX))
            .is_some_and(|id| Uuid::parse_str(id).is_ok())
}

fn validate_pair(certificate: &[u8], key: &[u8]) -> Result<()> {
    let identity = kasumi_transport::TlsIdentity::from_pem(certificate, key)?;
    kasumi_transport::server_config(&identity, kasumi_transport::ClientAuthentication::OAuth)?;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    std::fs::File::open(path)?.sync_all()?;
    Ok(())
}

/// The complete generation directory `directory` holding `names`. A published
/// directory is only revalidated and synced again: an earlier attempt may have
/// failed after its rename. An unpublished partial one was never named by
/// anything and is rebuilt from new keys.
fn publish_directory(
    root: &Path,
    directory: &Path,
    names: &[(String, bool)],
    issuer: &rcgen::Issuer<'_, impl rcgen::SigningKey>,
) -> Result<BTreeMap<String, TlsFiles>> {
    let files = names
        .iter()
        .map(|(name, _)| (name.clone(), identity_files(directory, name)))
        .collect::<BTreeMap<_, _>>();
    match std::fs::symlink_metadata(directory) {
        Ok(_) => {
            private_files::check_directory(directory)?;
            sync_directory(directory)?;
            private_files::sync_parent(directory)?;
            for (name, files) in &files {
                files
                    .load()
                    .and_then(|identity| {
                        kasumi_transport::server_config(
                            &identity,
                            kasumi_transport::ClientAuthentication::OAuth,
                        )
                    })
                    .with_context(|| {
                        format!("published {name} certificate generation is damaged")
                    })?;
            }
            return Ok(files);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let partial = directory.with_extension("partial");
    match std::fs::symlink_metadata(&partial) {
        Ok(_) => {
            private_files::check_directory(&partial)?;
            std::fs::remove_dir_all(&partial)?;
            private_files::sync_parent(&partial)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    private_files::create_directory(&partial)?;
    boundary(root, "generation-directory")?;
    for (name, client) in names {
        let (certificate, key) = leaf(name, issuer, *client)?;
        validate_pair(certificate.as_bytes(), key.as_bytes())?;
        let staged = identity_files(&partial, name);
        private_files::create(&staged.private_key, key.as_bytes())?;
        boundary(root, "generation-key")?;
        private_files::create(&staged.certificate, certificate.as_bytes())?;
        boundary(root, "generation-certificate")?;
    }
    sync_directory(&partial)?;
    boundary(root, "generation-sync")?;
    private_files::rename_exclusive(&partial, directory)?;
    boundary(root, "generation-published")?;
    Ok(files)
}

/// Point the listeners at the new generation with one atomic replacement.
fn publish_configuration(
    configuration: &Path,
    listeners: &BTreeMap<String, TlsFiles>,
) -> Result<RuntimeConfig> {
    let mut config = RuntimeConfig::load(configuration)?;
    let mcp = &listeners["mcp"];
    let native = &listeners["native"];
    let admin = &listeners["admin"];
    if config.mcp.tls == *mcp && config.native.tls == *native && config.admin.tls == *admin {
        // An earlier attempt may have failed after its rename, before its sync.
        sync_directory(configuration)?;
        private_files::sync_parent(configuration)?;
        return Ok(config);
    }
    config.mcp.tls = mcp.clone();
    config.native.tls = native.clone();
    config.admin.tls = admin.clone();
    config.validate()?;
    private_files::replace(configuration, &serde_json::to_vec_pretty(&config)?)?;
    Ok(config)
}

/// Commit the standalone Control node's MCP certificate pin.
async fn commit_topology(owner: &OperatorState, mcp_pin: &str, attempt: &str) -> Result<()> {
    let control = owner.control().await?;
    let committed = async {
        let context = offline_context(&control)?;
        let plane = kasumi_engine::control::ControlPlane::new(control.clone())?;
        plane.require_initialized(&context).await?;
        let mut current = plane
            .topology(&context)
            .await?
            .context("installed Control topology is missing")?;
        let node = current
            .topology
            .nodes
            .get_mut(&1)
            .context("standalone control node is missing")?;
        let pins = BTreeSet::from([mcp_pin.to_owned()]);
        if node.certificate_pins != pins {
            node.certificate_pins = pins;
            plane
                .replace_topology(
                    context,
                    current.topology,
                    kasumi_types::Precondition::Version(current.version),
                    format!("certificate-rotation-{attempt}"),
                )
                .await?;
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    control.shutdown().await?;
    committed
}

/// The generated client identities this installation's profiles present, by
/// name: `<name>.pem` and `<name>-key.pem` in `profiles/` or in an earlier
/// rotation generation there. An identity elsewhere is not the installation's
/// to replace.
fn installed_client_identities(root: &Path) -> Result<BTreeMap<String, TlsFiles>> {
    let profiles = root.join("profiles");
    let mut identities = BTreeMap::new();
    for (_, profile) in installed_profiles(&profiles)? {
        let certificate = &profile.identity.certificate;
        let (Some(directory), Some(name)) = (
            certificate.parent(),
            certificate.file_stem().and_then(|stem| stem.to_str()),
        ) else {
            continue;
        };
        if directory != profiles && !is_generation_directory(directory, &profiles) {
            continue;
        }
        let generated = identity_files(directory, name);
        if TlsFiles::from(profile.identity.clone()) == generated {
            identities.insert(name.to_owned(), generated);
        }
    }
    Ok(identities)
}

/// The loadable profiles directly in `profiles/`, in name order.
fn installed_profiles(profiles: &Path) -> Result<Vec<(PathBuf, ClientProfile)>> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(profiles)? {
        let path = entry?.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "json")
            && let Ok(profile) = ClientProfile::load(&path)
        {
            found.push((path, profile));
        }
    }
    found.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(found)
}

/// Pin every profile in `profiles/` to the new listener certificates and move
/// each that presents a replaced client identity to its replacement. Each
/// profile is one atomic replacement; an unchanged one is synced again.
fn publish_profiles(
    root: &Path,
    journal: &Journal,
    generation: &Generation,
    native_pin: &str,
    admin_pin: &str,
    credentials: &LocalCredentials,
) -> Result<()> {
    for (path, mut profile) in installed_profiles(&root.join("profiles"))? {
        let before = serde_json::to_vec_pretty(&profile)?;
        profile.native_certificate_pin = native_pin.to_owned();
        // Generated profiles name only this installation's admin listener.
        for member in profile.administrative_members.values_mut() {
            member.certificate_pins = BTreeSet::from([admin_pin.to_owned()]);
        }
        let identity = TlsFiles::from(profile.identity.clone());
        if let Some(name) = journal.clients.iter().find_map(|(name, replaced)| {
            (*replaced == identity || generation.clients[name] == identity).then_some(name)
        }) {
            let next = &generation.clients[name];
            credentials.rotate_installed_certificate(
                &path,
                &profile,
                || Ok(journal.clients[name].load()?.certificate_pin()),
                next.load()?.certificate_pin(),
                || boundary(root, "credential-ledger"),
            )?;
            boundary(root, "credential")?;
            profile.identity = next.clone().into();
        }
        let after = serde_json::to_vec_pretty(&profile)?;
        if after == before {
            private_files::sync_parent(&path)?;
        } else {
            private_files::replace(&path, &after)?;
        }
        boundary(root, "profile")?;
    }
    Ok(())
}

/// Unlink the replaced files the installation generated, in `tls/`,
/// `profiles/` or an earlier generation there, then sync their directories
/// and remove emptied earlier generations. Files elsewhere were configured by
/// the operator and are left alone.
fn retire_replaced(root: &Path, journal: &Journal, generation: &Generation) -> Result<()> {
    let tls = root.join("tls");
    let profiles = root.join("profiles");
    let owned = |directory: &Path| {
        directory == tls
            || directory == profiles
            || is_generation_directory(directory, &tls)
            || is_generation_directory(directory, &profiles)
    };
    let replaced = journal
        .listeners
        .iter()
        .map(|(name, files)| (files, &generation.listeners[name]))
        .chain(
            journal
                .clients
                .iter()
                .map(|(name, files)| (files, &generation.clients[name])),
        );
    let mut directories = BTreeSet::new();
    for (old, new) in replaced {
        for (path, current) in [
            (&old.certificate, &new.certificate),
            (&old.private_key, &new.private_key),
        ] {
            let Some(directory) = path.parent() else {
                continue;
            };
            if path == current || !owned(directory) {
                continue;
            }
            match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            boundary(root, "retired-file")?;
            directories.insert(directory.to_owned());
        }
    }
    for directory in &directories {
        match std::fs::File::open(directory) {
            Ok(opened) => opened.sync_all()?,
            // An earlier attempt synced and then removed this emptied generation.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        }
        boundary(root, "retired-sync")?;
    }
    for directory in directories
        .iter()
        .filter(|directory| **directory != tls && **directory != profiles)
    {
        // Another file left in an earlier generation keeps it.
        match std::fs::remove_dir(directory) {
            Ok(()) => {
                private_files::sync_parent(directory)?;
                boundary(root, "retired-directory")?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) if error.kind() == std::io::ErrorKind::DirectoryNotEmpty => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

/// A named step boundary. Tests interrupt a rotation at any of them.
fn boundary(root: &Path, name: &'static str) -> Result<()> {
    #[cfg(test)]
    interruption::reached(root, name)?;
    #[cfg(not(test))]
    let _ = (root, name);
    Ok(())
}

#[cfg(test)]
pub(super) mod interruption {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    #[derive(Default)]
    struct Plan {
        /// Fail at this many-th boundary reached, counting from one.
        stop_at: Option<usize>,
        reached: Vec<&'static str>,
    }
    fn plans() -> &'static Mutex<BTreeMap<PathBuf, Plan>> {
        static PLANS: OnceLock<Mutex<BTreeMap<PathBuf, Plan>>> = OnceLock::new();
        PLANS.get_or_init(Default::default)
    }
    /// Record every boundary of rotations of `root`'s installation and fail
    /// the `stop_at`-th one, if any.
    pub(crate) fn plan(root: &Path, stop_at: Option<usize>) {
        plans().lock().unwrap().insert(
            root.to_owned(),
            Plan {
                stop_at,
                reached: Vec::new(),
            },
        );
    }
    /// The boundaries reached since `plan`, ending the plan.
    pub(crate) fn finish(root: &Path) -> Vec<&'static str> {
        plans()
            .lock()
            .unwrap()
            .remove(root)
            .map(|plan| plan.reached)
            .unwrap_or_default()
    }
    pub(super) fn reached(root: &Path, name: &'static str) -> Result<()> {
        let mut plans = plans().lock().unwrap();
        let Some(plan) = plans.get_mut(root) else {
            return Ok(());
        };
        plan.reached.push(name);
        ensure!(
            plan.stop_at != Some(plan.reached.len()),
            "injected interruption after rotation boundary {} ({name})",
            plan.reached.len()
        );
        Ok(())
    }
}

#[cfg(test)]
#[path = "standalone_certificate_rotation_tests.rs"]
mod tests;
