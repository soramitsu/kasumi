//! Immutable ciphertext custody through blocking jobs and HTTP body retirement.
use super::*;
use crate::{DiskMemoryLease, NodeDiskMemoryAdmission, PlaintextValue, disk_memory};
use std::{fmt, ops::Deref};

enum Bytes {
    Generated {
        bytes: Zeroizing<Vec<u8>>,
        _charge: DiskMemoryLease,
    },
    Recovered(PlaintextValue),
}

struct Backing {
    bytes: Bytes,
    _allocation: DiskMemoryLease,
    owner: Arc<dyn NodeDiskMemoryAdmission>,
}

/// Ciphertext whose actual backing remains admitted through its final user.
/// Sharing retains the same bytes and leases; it does not allocate or copy.
pub struct AuditCiphertext {
    backing: Option<Arc<Backing>>,
}

impl AuditCiphertext {
    pub(super) fn generated(
        bytes: Zeroizing<Vec<u8>>,
        charge: DiskMemoryLease,
        owner: Arc<dyn NodeDiskMemoryAdmission>,
        allocation: DiskMemoryLease,
    ) -> Self {
        Self {
            backing: Some(Arc::new(Backing {
                bytes: Bytes::Generated {
                    bytes,
                    _charge: charge,
                },
                _allocation: allocation,
                owner,
            })),
        }
    }

    pub(super) fn recovered(
        bytes: PlaintextValue,
        owner: Arc<dyn NodeDiskMemoryAdmission>,
        allocation: DiskMemoryLease,
    ) -> Self {
        Self {
            backing: Some(Arc::new(Backing {
                bytes: Bytes::Recovered(bytes),
                _allocation: allocation,
                owner,
            })),
        }
    }

    pub(super) fn allocation_bytes() -> std::io::Result<u64> {
        disk_memory::arc::<Backing>()
    }

    pub(super) fn owner(&self) -> &Arc<dyn NodeDiskMemoryAdmission> {
        &self.backing.as_ref().expect("live ciphertext").owner
    }

    pub fn as_bytes(&self) -> &[u8] {
        match &self.backing.as_ref().expect("live ciphertext").bytes {
            Bytes::Generated { bytes, .. } => bytes,
            Bytes::Recovered(bytes) => bytes.as_bytes(),
        }
    }

    /// Retain the same admitted immutable backing for an independent worker.
    pub fn share(&self) -> Self {
        Self {
            backing: self.backing.clone(),
        }
    }

    #[cfg(test)]
    pub(super) fn fixture_flip_last_byte(&mut self) {
        let backing = Arc::get_mut(self.backing.as_mut().expect("live ciphertext"))
            .expect("exclusive ciphertext fixture");
        match &mut backing.bytes {
            Bytes::Generated { bytes, .. } => *bytes.last_mut().unwrap() ^= 1,
            Bytes::Recovered(_) => panic!("stored plaintext backing is immutable"),
        }
    }
}

impl Drop for AuditCiphertext {
    fn drop(&mut self) {
        // Every shared owner follows this path; no Weak or raw Arc escapes.
        // into_inner guarantees one concurrent final owner receives Backing
        // only after the actual Arc node has been deallocated. Backing then
        // retires its bytes before either installed lease returns capacity.
        if let Some(backing) = self.backing.take() {
            drop(Arc::into_inner(backing));
        }
    }
}

impl AsRef<[u8]> for AuditCiphertext {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}
impl Deref for AuditCiphertext {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_bytes()
    }
}
impl fmt::Debug for AuditCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditCiphertext")
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}
impl<T: AsRef<[u8]>> PartialEq<T> for AuditCiphertext {
    fn eq(&self, other: &T) -> bool {
        self.as_bytes() == other.as_ref()
    }
}
impl Eq for AuditCiphertext {}
impl PartialEq<AuditCiphertext> for Vec<u8> {
    fn eq(&self, other: &AuditCiphertext) -> bool {
        self.as_slice() == other.as_bytes()
    }
}

impl PreparedAuditSegment {
    pub(super) fn share(&self) -> Result<Self> {
        let charge = self
            .ciphertext
            .owner()
            .clone()
            .reserve_installed(reference_allocation(&self.reference)?)
            .context("audit publication metadata admission denied")?;
        Ok(Self {
            reference: self.reference.clone(),
            ciphertext: self.ciphertext.share(),
            _reference_charge: charge,
        })
    }
}

pub(super) fn reference_allocation(reference: &AuditArchiveReference) -> std::io::Result<u64> {
    let mut bytes = 0;
    for text in [
        Some(reference.object.ciphertext_sha256.as_str()),
        reference
            .previous
            .as_ref()
            .map(|link| link.ciphertext_sha256.as_str()),
        Some(reference.key.provider.as_str()),
        Some(reference.key.key_ref.as_str()),
        Some(reference.key.wrapped_key_sha256.as_str()),
    ]
    .into_iter()
    .flatten()
    {
        bytes = disk_memory::add(
            bytes,
            disk_memory::allocation::<u8>(
                u64::try_from(text.len()).map_err(|_| disk_memory::overflow())?,
            )?,
        )?;
    }
    Ok(bytes)
}

pub(super) fn memory_owner(store: &TenantStore) -> Arc<dyn NodeDiskMemoryAdmission> {
    #[cfg(any(test, feature = "test-utils"))]
    if store.node.body().db.has_fixture_direct_database() {
        return store.node.scratch_disk().memory().clone();
    }
    store.node.memory().clone()
}

impl TenantStore {
    /// Append one pre-admitted ciphertext copy to its two metadata writes and
    /// commit them atomically. The exact copied WriteOp cannot escape the call.
    pub fn write_audit_ciphertext_batch(
        &self,
        metadata: [crate::WriteOp; 2],
        namespace: &str,
        key: &[u8],
        segment: &PreparedAuditSegment,
    ) -> Result<()> {
        self.check_access()?;
        let mut admitted = 0;
        for length in [namespace.len(), key.len(), segment.ciphertext.len()] {
            admitted = disk_memory::add(
                admitted,
                disk_memory::allocation::<u8>(u64::try_from(length)?)?,
            )?;
        }
        let _charge = memory_owner(self)
            .reserve_installed(admitted)
            .context("audit pending ciphertext write admission denied")?;
        let [first, second] = metadata;
        let operations = [
            first,
            second,
            crate::WriteOp::put(namespace, key, segment.ciphertext.as_bytes()),
        ];
        self.write_batch(&operations)
    }

    /// Preserve a charged stored value as archive ciphertext, without copying.
    pub fn recover_audit_segment(
        &self,
        reference: AuditArchiveReference,
        bytes: PlaintextValue,
    ) -> Result<PreparedAuditSegment> {
        self.check_access()?;
        validate_prepared(&reference, bytes.as_bytes())?;
        let owner = memory_owner(self);
        bytes.require_memory(&owner)?;
        let metadata = owner
            .clone()
            .reserve_installed(reference_allocation(&reference)?)
            .context("audit archive metadata admission denied")?;
        let allocation = owner
            .clone()
            .reserve_installed(AuditCiphertext::allocation_bytes()?)
            .context("audit archive shared custody admission denied")?;
        let ciphertext = AuditCiphertext::recovered(bytes, owner, allocation);
        self.check_access()?;
        Ok(PreparedAuditSegment {
            reference,
            ciphertext,
            _reference_charge: metadata,
        })
    }

    /// Admit and copy a borrowed transport payload for independently owned work.
    pub fn copy_audit_segment(
        &self,
        reference: AuditArchiveReference,
        bytes: &[u8],
    ) -> Result<PreparedAuditSegment> {
        self.check_access()?;
        validate_prepared(&reference, bytes)?;
        let owner = memory_owner(self);
        let metadata = owner
            .clone()
            .reserve_installed(reference_allocation(&reference)?)
            .context("audit archive metadata admission denied")?;
        let allocation = owner
            .clone()
            .reserve_installed(AuditCiphertext::allocation_bytes()?)
            .context("audit archive shared custody admission denied")?;
        let admitted = disk_memory::allocation::<u8>(u64::try_from(bytes.len())?)?;
        let charge = owner
            .clone()
            .reserve_installed(admitted)
            .context("audit archive ciphertext copy admission denied")?;
        let mut copied = Zeroizing::new(Vec::new());
        copied
            .try_reserve_exact(bytes.len())
            .context("audit archive ciphertext allocation failed")?;
        ensure!(
            u64::try_from(copied.capacity())? <= admitted,
            "audit ciphertext allocation exceeds admission"
        );
        copied.extend_from_slice(bytes);
        let ciphertext = AuditCiphertext::generated(copied, charge, owner, allocation);
        self.check_access()?;
        Ok(PreparedAuditSegment {
            reference,
            ciphertext,
            _reference_charge: metadata,
        })
    }
}

pub(super) fn validate_prepared(reference: &AuditArchiveReference, bytes: &[u8]) -> Result<()> {
    reference.validate()?;
    let mut digest = [0u8; 64];
    hex::encode_to_slice(Sha256::digest(bytes), &mut digest)?;
    ensure!(
        bytes.len() as u64 == reference.ciphertext_bytes
            && digest == reference.object.ciphertext_sha256.as_bytes(),
        "invalid prepared audit segment"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::allocation_tests::{
        DeallocationObservation, observe_deallocation, observe_one_allocation,
    };
    use crate::test_utils::{LocalKeyProvider, TestDiskMemory, private_tempdir};

    const LIMIT: u64 = 256 << 20;

    struct ObservedCredit(Arc<DeallocationObservation>);
    impl Drop for ObservedCredit {
        fn drop(&mut self) {
            assert!(
                self.0.finished(),
                "actual allocation must retire before installed credit"
            );
        }
    }

    #[test]
    fn final_shared_node_deallocates_before_its_resident_credit() {
        let memory: Arc<dyn NodeDiskMemoryAdmission> = TestDiskMemory::new(LIMIT, 4096);
        let observation = Arc::new(DeallocationObservation::new(false));
        let allocation = DiskMemoryLease::new(ObservedCredit(observation.clone()));
        let charge = memory.clone().reserve_installed(4096).unwrap();
        let bytes = Zeroizing::new(b"retained ciphertext".to_vec());
        let (ciphertext, address) = observe_one_allocation(
            std::mem::size_of::<Backing>() + 2 * std::mem::size_of::<usize>(),
            || AuditCiphertext::generated(bytes, charge, memory, allocation),
        );
        let shared = ciphertext.share();
        drop(ciphertext);
        assert!(!observation.finished());
        observe_deallocation(address as *const (), &observation, || drop(shared));
        assert!(observation.finished());
        assert_eq!(observation.count(), 1);
    }

    #[test]
    fn final_shared_payload_deallocates_before_its_resident_credit() {
        let memory: Arc<dyn NodeDiskMemoryAdmission> = TestDiskMemory::new(LIMIT, 4096);
        let observation = Arc::new(DeallocationObservation::new(false));
        let charge = DiskMemoryLease::new(ObservedCredit(observation.clone()));
        let allocation = memory
            .clone()
            .reserve_installed(AuditCiphertext::allocation_bytes().unwrap())
            .unwrap();
        let bytes = Zeroizing::new(b"retained ciphertext".to_vec());
        let address = bytes.as_ptr() as usize;
        let ciphertext = AuditCiphertext::generated(bytes, charge, memory, allocation);
        let shared = ciphertext.share();
        drop(ciphertext);
        assert!(!observation.finished());
        observe_deallocation(address as *const (), &observation, || drop(shared));
        assert!(observation.finished());
        assert_eq!(observation.count(), 1);
    }

    struct Fixture {
        store: Arc<TenantStore>,
        memory: Arc<TestDiskMemory>,
        _directory: tempfile::TempDir,
        _scratch_directory: tempfile::TempDir,
    }

    impl Fixture {
        async fn new() -> Self {
            let memory = TestDiskMemory::new(LIMIT, 4096);
            let directory = private_tempdir().unwrap();
            let scratch_directory = private_tempdir().unwrap();
            let scratch = crate::ScratchDisk::fixture(scratch_directory.path(), memory.clone());
            let node = crate::NodeStore::create_new_fixture(
                directory.path().join("archive-ciphertext.kv"),
                crate::test_utils::NODE_STORE_ID,
                memory.clone(),
                scratch,
            )
            .unwrap();
            let store = TenantStore::initialize_catalog_fixture(
                node,
                "tenant".into(),
                Arc::new(LocalKeyProvider::new([83; 32])),
            )
            .await
            .unwrap();
            Self {
                store,
                memory,
                _directory: directory,
                _scratch_directory: scratch_directory,
            }
        }

        fn segment(&self) -> PreparedAuditSegment {
            let mut builder = AuditSegmentBuilder::new(Uuid::new_v4(), 0, None).unwrap();
            builder.push(0, b"charged audit event").unwrap();
            self.store.encrypt_audit_segment(builder).unwrap()
        }

        fn leave_available(&self, available: u64) -> DiskMemoryLease {
            let before = self.memory.snapshot();
            let filler = LIMIT
                - before.bookkeeping_bytes
                - before.used_bytes
                - available
                - TestDiskMemory::required_reservation_bytes(0).unwrap();
            self.memory.clone().reserve_installed(filler).unwrap()
        }
    }

    #[tokio::test]
    async fn shared_ciphertext_keeps_actual_backing_admitted_until_final_owner() {
        let fixture = Fixture::new().await;
        let baseline = fixture.memory.snapshot();
        let segment = fixture.segment();
        let retained = fixture.memory.snapshot();
        let first = segment.ciphertext.share();
        let second = first.share();
        let length = segment.ciphertext.len();
        assert_eq!(first.as_ptr(), segment.ciphertext.as_ptr());
        assert_eq!(second.as_ptr(), first.as_ptr());
        assert_eq!(fixture.memory.snapshot().attempts, retained.attempts);
        drop(segment);
        let shared = fixture.memory.snapshot();
        assert!(shared.used_bytes > baseline.used_bytes);
        drop(first);
        assert_eq!(fixture.memory.snapshot().used_bytes, shared.used_bytes);
        assert_eq!(second.len(), length);
        assert_eq!(&second[..8], MAGIC);
        drop(second);
        assert_eq!(fixture.memory.snapshot().used_bytes, baseline.used_bytes);
        assert_eq!(
            fixture.memory.snapshot().live_reservations,
            baseline.live_reservations
        );
    }

    #[tokio::test]
    async fn recovered_ciphertext_refuses_a_different_installed_memory_owner_before_admission() {
        let source = Fixture::new().await;
        let destination = Fixture::new().await;
        let original = source.segment();
        source
            .store
            .write_batch(&[crate::WriteOp::put(
                "archive",
                b"pending",
                original.ciphertext.as_bytes(),
            )])
            .unwrap();
        let source_baseline = source.memory.snapshot();
        let destination_baseline = destination.memory.snapshot();
        let value = source.store.get("archive", b"pending").unwrap().unwrap();
        let error = destination
            .store
            .recover_audit_segment(original.reference.clone(), value)
            .err()
            .expect("equivalent policies cannot substitute the original installed owner");
        assert!(format!("{error:#}").contains("plaintext installed memory owner differs"));
        assert_eq!(
            destination.memory.snapshot().attempts,
            destination_baseline.attempts
        );
        assert_eq!(
            destination.memory.snapshot().used_bytes,
            destination_baseline.used_bytes
        );
        assert_eq!(
            source.memory.snapshot().used_bytes,
            source_baseline.used_bytes
        );
    }

    #[tokio::test]
    async fn recovered_ciphertext_moves_charged_point_backing_without_copying() {
        let fixture = Fixture::new().await;
        let original = fixture.segment();
        fixture
            .store
            .write_batch(&[crate::WriteOp::put(
                "archive",
                b"pending",
                original.ciphertext.as_bytes(),
            )])
            .unwrap();
        let reference = original.reference.clone();
        drop(original);
        let baseline = fixture.memory.snapshot();
        let value = fixture.store.get("archive", b"pending").unwrap().unwrap();
        let pointer = value.as_ptr();
        let segment = fixture
            .store
            .recover_audit_segment(reference, value)
            .unwrap();
        assert_eq!(segment.ciphertext.as_ptr(), pointer);
        let shared = segment.ciphertext.share();
        drop(segment);
        assert!(fixture.memory.snapshot().used_bytes > baseline.used_bytes);
        assert_eq!(shared.as_ptr(), pointer);
        drop(shared);
        assert_eq!(fixture.memory.snapshot().used_bytes, baseline.used_bytes);
    }

    #[tokio::test]
    async fn borrowed_ciphertext_copy_refuses_before_allocation_and_releases_partial_admission() {
        let fixture = Fixture::new().await;
        let segment = fixture.segment();
        let metadata = TestDiskMemory::required_reservation_bytes(
            reference_allocation(&segment.reference).unwrap(),
        )
        .unwrap();
        let custody = TestDiskMemory::required_reservation_bytes(
            AuditCiphertext::allocation_bytes().unwrap(),
        )
        .unwrap();
        let payload = TestDiskMemory::required_reservation_bytes(
            disk_memory::allocation::<u8>(segment.ciphertext.len() as u64).unwrap(),
        )
        .unwrap();
        let held = fixture.leave_available(metadata + custody + payload - 1);
        let before = fixture.memory.snapshot();
        let error = fixture
            .store
            .copy_audit_segment(segment.reference.clone(), segment.ciphertext.as_bytes())
            .err()
            .expect("copy must refuse before allocation");
        assert!(format!("{error:#}").contains("audit archive ciphertext copy admission denied"));
        assert_eq!(fixture.memory.snapshot().used_bytes, before.used_bytes);
        assert_eq!(
            fixture.memory.snapshot().live_reservations,
            before.live_reservations
        );
        drop(held);
        let copied = fixture
            .store
            .copy_audit_segment(segment.reference.clone(), segment.ciphertext.as_bytes())
            .unwrap();
        assert_eq!(copied.ciphertext, segment.ciphertext);
        assert_ne!(copied.ciphertext.as_ptr(), segment.ciphertext.as_ptr());
    }

    #[tokio::test]
    async fn pending_ciphertext_admission_failure_commits_none_of_its_metadata() {
        let fixture = Fixture::new().await;
        let segment = fixture.segment();
        let held = fixture.leave_available(0);
        let before = fixture.memory.snapshot();
        let error = fixture
            .store
            .write_audit_ciphertext_batch(
                [
                    crate::WriteOp::put("audit", b"head", b"first"),
                    crate::WriteOp::put("audit", b"pending", b"second"),
                ],
                "audit",
                b"pending-ciphertext",
                &segment,
            )
            .unwrap_err();
        assert!(format!("{error:#}").contains("audit pending ciphertext write admission denied"));
        assert_eq!(fixture.memory.snapshot().used_bytes, before.used_bytes);
        drop(held);
        for key in [b"head".as_slice(), b"pending", b"pending-ciphertext"] {
            assert!(fixture.store.get("audit", key).unwrap().is_none());
        }
    }
}
