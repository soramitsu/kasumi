/// Pre-publication census owns the same funded resources as an installed owner.
/// Fields retire backing/FDs before their leases on every ordinary error path.
struct PreparedResources {
    roots: BTreeMap<String, Root>,
    ancestor_locks: Vec<File>,
    accounted: fixed_map::Banks<AccountedInode>,
    live: fixed_map::Banks<Weak<file::FileOwner>>,
    charge: Lease,
    registry_charge: Lease,
}
struct PreparedCensus {
    resources: Option<PreparedResources>,
    streams: census::Streams,
}
impl PreparedCensus {
    fn take(&mut self) -> PreparedResources {
        assert_eq!(self.streams.outstanding(), 0, "unretired initial census stream");
        assert!(self.streams.close_errno().is_none(), "uncertain initial census close");
        self.resources.take().expect("prepared census resources")
    }
}
impl Drop for PreparedCensus {
    fn drop(&mut self) {
        if self.streams.outstanding() != 0 {
            // A failed closedir may have consumed its pointer. Never retry it
            // or credit its resident reservation. Retain the existing roots,
            // ancestor locks, both banks and actual admission leases until
            // process exit. Root locks also prevent another owner adopting this
            // uncertain namespace. No new retention allocation is introduced.
            if let Some(resources) = self.resources.take() { std::mem::forget(resources); }
        }
    }
}
