//! Exact installed-provider quotation only. No grant, access or capture authority.
use super::*;
use crate::disk_memory::{add, overflow};
use kasumi_kv::{PointReadRequests, ProtectedReadRequests};
use std::io;

/// Fixed-size quote bound to the actual encrypted pair and installed provider.
/// Key-ID bounds come from those catalogs, never a caller-selected maximum.
/// It has no buffer and no admission lease. Recheck it after catalog changes;
/// even a successful recheck is not a guard against a later key rotation.
pub struct PairedReadMemoryQuote {
    application: Arc<TenantStore>,
    custody: Arc<TenantStore>,
    provider: Arc<dyn NodeDiskMemoryAdmission>,
    key_id_bytes: [usize; 2],
    retained: u64,
    begin_scratch: u64,
    rights: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct PointReadMemoryQuote {
    plaintext: u64,
    native: u64,
    ciphertext: usize,
}
impl PointReadMemoryQuote {
    pub fn plaintext_bytes(&self) -> u64 {
        self.plaintext
    }
    /// Bounds and PageBuffer coexist; the later admitted output is separate.
    /// Both phases conservatively retain their former temporary CachedBytes
    /// allowances, although directory/admitted value reads now use their own
    /// output on retention refusal. Retained optional caches, descriptor
    /// capacity and arbitrary errors remain separate.
    pub fn native_peak_bytes(&self) -> u64 {
        self.native
    }
    pub fn ciphertext_limit(&self) -> usize {
        self.ciphertext
    }
    /// Conservative overlap: native output remains owned during plaintext decode.
    pub fn peak_bytes(&self) -> io::Result<u64> {
        add(self.plaintext, self.native)
    }
}
fn native_charge(provider: &dyn NodeDiskMemoryAdmission, request: u64) -> io::Result<u64> {
    provider.quote_installed(
        crate::node_file::segment_group::workspace_provider_request_bytes(request)?,
    )
}
fn point_native(provider: &dyn NodeDiskMemoryAdmission, limit: usize) -> io::Result<u64> {
    let request = PointReadRequests::new(limit).map_err(|_| overflow())?;
    let directory = add(
        add(
            native_charge(provider, request.bounds_request_bytes())?,
            native_charge(provider, request.page_request_bytes())?,
        )?,
        native_charge(provider, request.page_fallback_request_bytes())?,
    )?;
    let value = add(
        native_charge(provider, request.output_request_bytes())?,
        native_charge(provider, request.value_fallback_request_bytes())?,
    )?;
    Ok(directory.max(value))
}
fn key_id_bytes(store: &TenantStore) -> usize {
    store
        .state
        .read()
        .keys
        .keys()
        .map(String::len)
        .max()
        .unwrap_or(0)
}
impl TenantStorageSet {
    /// Quotes one registered read shared by these two encrypted domains.
    /// The actual native owner is still required to acquire any snapshot right.
    pub fn quote_read_memory(&self) -> io::Result<PairedReadMemoryQuote> {
        let application = &self.application;
        let custody = &self.custody.store;
        if !Arc::ptr_eq(&application.node, &custody.node) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        #[cfg(any(test, feature = "test-utils"))]
        if application.node.db.has_fixture_direct_database() {
            return Err(io::ErrorKind::Unsupported.into());
        }
        let provider = application.persistent_disk().memory();
        for store in [application, custody] {
            if !Arc::ptr_eq(provider, store.persistent_disk().memory())
                || !Arc::ptr_eq(provider, store.scratch_disk().memory())
            {
                return Err(io::ErrorKind::InvalidInput.into());
            }
        }
        let [report, census] = RegisteredNodeRead::memory_requests()?;
        let retained = add(
            add(
                provider.quote_installed(report)?,
                provider.quote_installed(census)?,
            )?,
            add(
                native_charge(
                    provider.as_ref(),
                    ProtectedReadRequests::snapshot_backing_request_bytes(),
                )?,
                native_charge(
                    provider.as_ref(),
                    ProtectedReadRequests::pin_backing_request_bytes(),
                )?,
            )?,
        )?;
        // check_bytes_table drops one table before checking the other. Its type
        // output and directory scratch retire before the temporary name Arc.
        let type_probe = point_native(provider.as_ref(), 2)?;
        let names = [CATALOG.name().len(), RECORDS.name().len()];
        let mut begin_scratch = type_probe;
        for name in names {
            begin_scratch = begin_scratch.max(
                ProtectedReadRequests::table_name_backing_bytes(name).map_err(|_| overflow())?,
            );
        }
        let rights = native_charge(
            provider.as_ref(),
            ProtectedReadRequests::rights_request_bytes(),
        )?;
        Ok(PairedReadMemoryQuote {
            application: application.clone(),
            custody: custody.clone(),
            provider: provider.clone(),
            key_id_bytes: [key_id_bytes(application), key_id_bytes(custody)],
            retained,
            begin_scratch,
            rights,
        })
    }
}
impl PairedReadMemoryQuote {
    pub fn retained_bytes(&self) -> u64 {
        self.retained
    }
    pub fn begin_peak_bytes(&self) -> io::Result<u64> {
        add(self.retained, self.begin_scratch)
    }
    /// Separate once-per-pool installation request; not a second per-read pin.
    pub fn source_rights_bytes(&self) -> u64 {
        self.rights
    }
    /// Two Store leases and two native leases coexist after begin. This counts
    /// constructor requests, not a custom provider's global ledger slots.
    pub fn retained_lease_requests(&self) -> usize {
        4
    }
    /// Conservative seven-lease envelope retaining the former temporary page
    /// allowance. Direct directory reads now need only Bounds + PageBuffer
    /// beyond the retained four; aggregation may use fewer global ledger slots.
    pub fn peak_lease_requests(&self) -> usize {
        7
    }
    pub fn require_memory(&self, expected: &Arc<dyn NodeDiskMemoryAdmission>) -> io::Result<()> {
        if Arc::ptr_eq(&self.provider, expected) {
            Ok(())
        } else {
            Err(io::ErrorKind::InvalidInput.into())
        }
    }
    pub fn require_domains(
        &self,
        application: &Arc<TenantStore>,
        custody: &Arc<TenantStore>,
    ) -> io::Result<()> {
        if !Arc::ptr_eq(&self.application, application) || !Arc::ptr_eq(&self.custody, custody) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        for (store, ceiling) in [application, custody].into_iter().zip(self.key_id_bytes) {
            if key_id_bytes(store) > ceiling {
                return Err(io::ErrorKind::InvalidInput.into());
            }
        }
        Ok(())
    }
    /// Exact mandatory retained point backing, including simultaneous native
    /// bounds/page/output and Store plaintext/AAD. Optional caches and cold-file
    /// descriptors retain their separate budgets. No grant is acquired here.
    pub fn prepared_point_peak_bytes(
        &self,
        namespace_bytes: usize,
        key_bytes: usize,
        value_bytes: usize,
    ) -> io::Result<u64> {
        let backing = self.prepared_point_backing_bytes(namespace_bytes, key_bytes, value_bytes)?;
        Ok(self.begin_peak_bytes()?.max(add(self.retained, backing)?))
    }
    /// Actual four coexisting point grants, without a reader or optional cache.
    /// A transferred workspace remains charged while the queued root begins.
    pub fn prepared_point_backing_bytes(
        &self,
        namespace_bytes: usize,
        key_bytes: usize,
        value_bytes: usize,
    ) -> io::Result<u64> {
        self.require_domains(&self.application, &self.custody)?;
        let layout = super::prepared_point_read::point_buffer_layout(
            namespace_bytes,
            key_bytes,
            value_bytes,
            self.application.tenant.len().max(self.custody.tenant.len()),
            self.key_id_bytes.into_iter().max().unwrap_or(0),
        )?;
        let requests = PointReadRequests::new(layout.encrypted_bytes).map_err(|_| overflow())?;
        let mut backing = self.provider.quote_installed(layout.charge_bytes)?;
        for request in [
            kasumi_kv::PreparedPointRead::shell_request_bytes(),
            kasumi_kv::PreparedPointRead::directory_request_bytes(),
            requests.output_request_bytes(),
        ] {
            backing = add(backing, native_charge(self.provider.as_ref(), request)?)?;
        }
        Ok(backing)
    }
    pub fn application_get(
        &self,
        namespace_bytes: usize,
        key_bytes: usize,
        max_value_bytes: usize,
    ) -> io::Result<PointReadMemoryQuote> {
        self.point(0, namespace_bytes, key_bytes, max_value_bytes)
    }
    pub fn custody_get(
        &self,
        namespace_bytes: usize,
        key_bytes: usize,
        max_value_bytes: usize,
    ) -> io::Result<PointReadMemoryQuote> {
        self.point(1, namespace_bytes, key_bytes, max_value_bytes)
    }
    fn point(
        &self,
        domain: usize,
        namespace_bytes: usize,
        key_bytes: usize,
        max_value_bytes: usize,
    ) -> io::Result<PointReadMemoryQuote> {
        self.require_domains(&self.application, &self.custody)?;
        let store = if domain == 0 {
            &self.application
        } else {
            &self.custody
        };
        let plaintext = plaintext_get_workspace_bytes(
            store.tenant().len(),
            namespace_bytes,
            key_bytes,
            max_value_bytes,
        )?;
        let ciphertext = encrypted_record_length(
            namespace_bytes,
            key_bytes,
            max_value_bytes,
            self.key_id_bytes[domain],
        )
        .filter(|bytes| *bytes <= MAX_BATCH)
        .ok_or_else(overflow)?;
        Ok(PointReadMemoryQuote {
            plaintext,
            native: point_native(self.provider.as_ref(), ciphertext)?,
            ciphertext,
        })
    }
}

#[cfg(test)]
#[path = "read_memory_quote_tests.rs"]
mod tests;
