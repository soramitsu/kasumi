//! Fixed first-release filesystem backup marker bytes.
//!
//! This codec does not prove installation, directory custody, or source
//! authority. Enrollment compares a decoded value with the expected owner and
//! namespace and with the retained directory it was read through; the caller
//! must still compare the resulting binding with its authenticated record.

use kasumi_types::{BackupNamespaceBinding, TrustVerifierIdentity};
use sha2::{Digest, Sha256};
use std::io;
use uuid::Uuid;

const MAGIC: &[u8; 8] = b"KSMBND01";
const VERSION: u16 = 1;
const BODY_BYTES: usize = 68;
pub(crate) const MARKER_BYTES: usize = BODY_BYTES + 32;
const LENGTH_BYTES: [u8; 2] = [0, 100];

/// Data only. Neither construction nor decoding is an installed owner proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Marker {
    owner: TrustVerifierIdentity,
    namespace_id: Uuid,
    device: u64,
    inode: u64,
}

impl Marker {
    pub(crate) fn new(
        owner: TrustVerifierIdentity,
        namespace_id: Uuid,
        device: u64,
        inode: u64,
    ) -> io::Result<Self> {
        validate_identity(&owner, namespace_id)?;
        if device == 0 || inode == 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(Self {
            owner,
            namespace_id,
            device,
            inode,
        })
    }

    /// The expected marker for an exact installed binding. S3 has no marker.
    pub(crate) fn from_binding(binding: &BackupNamespaceBinding) -> io::Result<Self> {
        let BackupNamespaceBinding::Filesystem {
            installation_id,
            origin_node_id,
            namespace_id,
            device,
            inode,
        } = binding
        else {
            return Err(io::ErrorKind::InvalidInput.into());
        };
        Self::new(
            TrustVerifierIdentity {
                installation_id: *installation_id,
                node_id: *origin_node_id,
            },
            *namespace_id,
            *device,
            *inode,
        )
    }

    /// The durable binding is exactly the marker contents. `device` and `inode`
    /// record the enrollment observation; a remount may renumber `st_dev`, so
    /// no open compares it with a live descriptor.
    pub(crate) fn binding(&self) -> BackupNamespaceBinding {
        BackupNamespaceBinding::Filesystem {
            installation_id: self.owner.installation_id,
            origin_node_id: self.owner.node_id,
            namespace_id: self.namespace_id,
            device: self.device,
            inode: self.inode,
        }
    }

    pub(crate) fn owner(&self) -> &TrustVerifierIdentity {
        &self.owner
    }

    pub(crate) fn namespace_id(&self) -> Uuid {
        self.namespace_id
    }

    pub(crate) fn inode(&self) -> u64 {
        self.inode
    }

    /// Exact 100-byte marker. The digest detects corruption, not forgery.
    pub(crate) fn encode(&self) -> [u8; MARKER_BYTES] {
        let mut bytes = [0_u8; MARKER_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
        bytes[10..12].copy_from_slice(&LENGTH_BYTES);
        bytes[12..28].copy_from_slice(self.owner.installation_id.as_bytes());
        bytes[28..36].copy_from_slice(&self.owner.node_id.to_be_bytes());
        bytes[36..52].copy_from_slice(self.namespace_id.as_bytes());
        bytes[52..60].copy_from_slice(&self.device.to_be_bytes());
        bytes[60..68].copy_from_slice(&self.inode.to_be_bytes());
        let digest = Sha256::digest(&bytes[..BODY_BYTES]);
        bytes[BODY_BYTES..].copy_from_slice(&digest);
        bytes
    }

    pub(crate) fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != MARKER_BYTES
            || &bytes[..8] != MAGIC
            || u16::from_be_bytes(bytes[8..10].try_into().expect("fixed marker")) != VERSION
            || bytes[10..12] != LENGTH_BYTES[..]
            || bytes[BODY_BYTES..] != Sha256::digest(&bytes[..BODY_BYTES])[..]
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let owner = TrustVerifierIdentity {
            installation_id: Uuid::from_bytes(bytes[12..28].try_into().expect("fixed marker")),
            node_id: u64::from_be_bytes(bytes[28..36].try_into().expect("fixed marker")),
        };
        let namespace_id = Uuid::from_bytes(bytes[36..52].try_into().expect("fixed marker"));
        let device = u64::from_be_bytes(bytes[52..60].try_into().expect("fixed marker"));
        let inode = u64::from_be_bytes(bytes[60..68].try_into().expect("fixed marker"));
        let marker = Self::new(owner, namespace_id, device, inode)
            .map_err(|_| io::ErrorKind::InvalidData)?;
        if marker.encode().as_slice() != bytes {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(marker)
    }
}

/// Enrollment validates its caller identity before any namespace effect.
pub(crate) fn validate_identity(
    owner: &TrustVerifierIdentity,
    namespace_id: Uuid,
) -> io::Result<()> {
    if owner.validate().is_err()
        || namespace_id.get_version() != Some(uuid::Version::Random)
        || namespace_id.get_variant() != uuid::Variant::RFC4122
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn marker() -> Marker {
        Marker::new(
            TrustVerifierIdentity {
                installation_id: Uuid::parse_str("00112233-4455-4677-8899-aabbccddeeff").unwrap(),
                node_id: 7,
            },
            Uuid::parse_str("123e4567-e89b-42d3-a456-426614174000").unwrap(),
            0x0102_0304_0506_0708,
            0x1112_1314_1516_1718,
        )
        .unwrap()
    }

    fn resign(bytes: &mut [u8; MARKER_BYTES]) {
        let digest = Sha256::digest(&bytes[..BODY_BYTES]);
        bytes[BODY_BYTES..].copy_from_slice(&digest);
    }

    #[test]
    fn exact_first_release_vector_round_trips() {
        let marker = marker();
        let bytes = marker.encode();
        assert_eq!(bytes.len(), MARKER_BYTES);
        assert_eq!(usize::from(u16::from_be_bytes(LENGTH_BYTES)), MARKER_BYTES);
        assert_eq!(
            hex::encode(bytes),
            concat!(
                "4b534d424e4430310001006400112233445546778899aabbccddeeff",
                "0000000000000007123e4567e89b42d3a456426614174000",
                "01020304050607081112131415161718",
                "30803fe8b85ef117487d06789b5fb9b42c20493e8ef5ba13831cb005e8baeb87",
            )
        );
        assert_eq!(Marker::decode(&bytes).unwrap(), marker);
        assert_eq!(Marker::decode(&bytes).unwrap().encode(), bytes);
    }

    #[test]
    fn length_version_magic_and_digest_corruption_reject() {
        let bytes = marker().encode();
        assert!(Marker::decode(&bytes[..MARKER_BYTES - 1]).is_err());
        assert!(Marker::decode(&[bytes.as_slice(), &[0]].concat()).is_err());
        assert!(Marker::decode(b"legacy backup marker").is_err());
        for offset in [0, 8, 10, 12, 28, 36, 52, 60, BODY_BYTES, MARKER_BYTES - 1] {
            let mut corrupt = bytes;
            corrupt[offset] ^= 1;
            assert!(Marker::decode(&corrupt).is_err(), "accepted byte {offset}");
        }
        let mut unknown_version = bytes;
        unknown_version[9] = 2;
        resign(&mut unknown_version);
        assert!(Marker::decode(&unknown_version).is_err());
        let mut wrong_declared_length = bytes;
        wrong_declared_length[11] -= 1;
        resign(&mut wrong_declared_length);
        assert!(Marker::decode(&wrong_declared_length).is_err());
    }

    #[test]
    fn filesystem_binding_is_exactly_the_marker_and_s3_has_none() {
        let marker = marker();
        let binding = marker.binding();
        binding.validate().unwrap();
        assert_eq!(
            binding,
            BackupNamespaceBinding::Filesystem {
                installation_id: marker.owner().installation_id,
                origin_node_id: 7,
                namespace_id: marker.namespace_id(),
                device: 0x0102_0304_0506_0708,
                inode: marker.inode(),
            }
        );
        assert_eq!(Marker::from_binding(&binding).unwrap(), marker);
        assert!(
            Marker::from_binding(&BackupNamespaceBinding::S3 {
                https_origin: "https://s3.example/".into(),
                region: "ap-northeast-1".into(),
                bucket: "backups".into(),
                prefix: String::new(),
            })
            .is_err()
        );
        for (owner, namespace_id) in [
            (
                TrustVerifierIdentity {
                    installation_id: Uuid::nil(),
                    node_id: 7,
                },
                marker.namespace_id(),
            ),
            (
                TrustVerifierIdentity {
                    node_id: 0,
                    ..marker.owner().clone()
                },
                marker.namespace_id(),
            ),
            (marker.owner().clone(), Uuid::nil()),
            (marker.owner().clone(), Uuid::from_u128(1)),
        ] {
            assert!(validate_identity(&owner, namespace_id).is_err());
        }
    }

    #[test]
    fn invalid_owner_namespace_and_directory_reject_even_with_valid_digest() {
        let original = marker().encode();
        for range in [12..28, 28..36, 36..52, 52..60, 60..68] {
            let mut corrupt = original;
            corrupt[range].fill(0);
            resign(&mut corrupt);
            assert!(Marker::decode(&corrupt).is_err());
        }
        let mut wrong_version = original;
        wrong_version[42] = (wrong_version[42] & 0x0f) | 0x10;
        resign(&mut wrong_version);
        assert!(Marker::decode(&wrong_version).is_err());
        let mut wrong_variant = original;
        wrong_variant[44] &= 0x3f;
        resign(&mut wrong_variant);
        assert!(Marker::decode(&wrong_variant).is_err());
        assert!(Marker::new(marker().owner, Uuid::nil(), 1, 1).is_err());
    }
}
