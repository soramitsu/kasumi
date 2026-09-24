/// The one pre-admitted registry allocation owns either an unfinished initial
/// census or its installed owner. Preparing remains inspectable after an
/// uncertain close, including when the original constructor unwinds.
enum Registration {
    Preparing(PreparedResources),
    Installed(Arc<NodeDisk>),
    Transition,
}
struct RegisteredDisk {
    identity: Identity,
    registration: Registration,
    _charge: Lease,
}
impl RegisteredDisk {
    fn config(&self) -> Option<&NodeDiskConfig> {
        match &self.registration {
            Registration::Preparing(prepared) => Some(&prepared.config),
            Registration::Installed(owner) => Some(&owner.config),
            Registration::Transition => None,
        }
    }
    fn roots(&self) -> Option<&BTreeMap<String, Root>> {
        match &self.registration {
            Registration::Preparing(prepared) => Some(&prepared.roots),
            Registration::Installed(owner) => Some(&owner.roots),
            Registration::Transition => None,
        }
    }
    fn owner(&self) -> std::result::Result<&Arc<NodeDisk>, DiskOpenError> {
        match &self.registration {
            Registration::Installed(owner) => Ok(owner),
            Registration::Preparing(prepared) => {
                let error = prepared.streams.close_error().map(anyhow::Error::from)
                    .unwrap_or_else(|| anyhow::anyhow!("initial census is incomplete"));
                Err(error.context(format!(
                    "initial census retains {} unretired native streams; process restart required",
                    prepared.streams.outstanding())).into())
            }
            Registration::Transition => Err(anyhow::anyhow!("initial census publication is incomplete").into()),
        }
    }
}
type RegisteredDisks = parking_lot::Mutex<List<RegisteredDisk>>;
fn registry() -> &'static RegisteredDisks {
    static REGISTRY: RegisteredDisks = parking_lot::Mutex::new(List::new());
    &REGISTRY
}

/// All backing/descriptor owners retire before the owner lease on ordinary
/// failure. The registry's own lease retires after its actual list node.
struct PreparedResources {
    config: NodeDiskConfig,
    memory: Arc<dyn NodeDiskMemoryAdmission>,
    roots: BTreeMap<String, Root>,
    ancestor_locks: Vec<File>,
    accounted: fixed_map::Banks<AccountedInode>,
    live: fixed_map::Banks<Weak<file::FileOwner>>,
    streams: census::Streams,
    charge: Lease,
}
struct PreparingRegistration<'a> {
    installed: &'a mut List<RegisteredDisk>,
    identity: Identity,
    committed: bool,
}
impl PreparingRegistration<'_> {
    fn entry(&mut self) -> &mut RegisteredDisk {
        self.installed.find_mut(|entry| entry.identity == self.identity)
            .expect("registered initial census")
    }
    fn prepared(&mut self) -> &mut PreparedResources {
        match &mut self.entry().registration {
            Registration::Preparing(prepared) => prepared,
            _ => unreachable!("unpublished initial census"),
        }
    }
    fn take(&mut self) -> PreparedResources {
        assert_eq!(self.prepared().streams.outstanding(), 0, "unretired initial census stream");
        assert!(self.prepared().streams.close_errno().is_none(), "uncertain initial census close");
        match std::mem::replace(&mut self.entry().registration, Registration::Transition) {
            Registration::Preparing(prepared) => prepared,
            _ => unreachable!("unpublished initial census"),
        }
    }
    fn commit(&mut self, owner: Arc<NodeDisk>) {
        self.entry().registration = Registration::Installed(owner);
        self.committed = true;
    }
}
impl Drop for PreparingRegistration<'_> {
    fn drop(&mut self) {
        if self.committed { return; }
        if let Registration::Preparing(prepared) = &self.entry().registration {
            if prepared.streams.outstanding() != 0 {
                // The pre-effect registry node remains the actual owner of all
                // resource backing, locks, leases AND native close diagnostics.
                // A later constructor reports this retained failure. Never retry
                // a possibly consumed DIR or allocate a detached retention task.
                return;
            }
        }
        // Removing the actual node deallocates its backing before returning
        // the value; ordered fields then retire resources before lease credit.
        drop(self.installed.remove(|entry| entry.identity == self.identity));
    }
}
