//! Shared physical node-file identities derived only from immutable installed
//! inputs. These helpers do not verify authentication or grant storage access;
//! their callers must already own the selected installation/journal identities.
use anyhow::{Result, ensure};
use kasumi_types::TrustVerifierIdentity;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub fn signer_verifier(verifier: &TrustVerifierIdentity) -> Result<Uuid> {
    verifier.validate()?;
    Ok(derive(
        b"kasumi.node-file.signer-verifier.v1",
        &[
            verifier.installation_id.as_bytes(),
            &verifier.node_id.to_be_bytes(),
        ],
    ))
}

pub fn target_journal(control_incarnation: Uuid, verifier: &TrustVerifierIdentity) -> Result<Uuid> {
    require_id(control_incarnation)?;
    verifier.validate()?;
    Ok(derive(
        b"kasumi.node-file.target-journal.v1",
        &[
            control_incarnation.as_bytes(),
            verifier.installation_id.as_bytes(),
            &verifier.node_id.to_be_bytes(),
        ],
    ))
}

pub fn target_generation(
    control_incarnation: Uuid,
    tenant: &str,
    target_incarnation: Uuid,
    verifier: &TrustVerifierIdentity,
) -> Result<Uuid> {
    require_id(control_incarnation)?;
    kasumi_types::validate_name(tenant)?;
    require_id(target_incarnation)?;
    verifier.validate()?;
    Ok(derive(
        b"kasumi.node-file.target-generation.v1",
        &[
            control_incarnation.as_bytes(),
            tenant.as_bytes(),
            target_incarnation.as_bytes(),
            verifier.installation_id.as_bytes(),
            &verifier.node_id.to_be_bytes(),
        ],
    ))
}

/// File identity for an explicitly prepared management generation. The node's
/// installed database UUID and selected resource identity remain fixed across
/// later serving reopen; the authenticated generation descriptor is separate.
pub fn administrative_generation(
    database_id: Uuid,
    tenant: &str,
    target_incarnation: Uuid,
) -> Result<Uuid> {
    require_id(database_id)?;
    kasumi_types::validate_name(tenant)?;
    require_id(target_incarnation)?;
    Ok(derive(
        b"kasumi.node-file.administrative-generation.v1",
        &[
            database_id.as_bytes(),
            tenant.as_bytes(),
            target_incarnation.as_bytes(),
        ],
    ))
}

pub fn local_generation(
    installation_id: Uuid,
    operation_id: Uuid,
    target_incarnation: Uuid,
) -> Result<Uuid> {
    require_id(installation_id)?;
    require_id(operation_id)?;
    require_id(target_incarnation)?;
    Ok(derive(
        b"kasumi.node-file.local-generation.v1",
        &[
            installation_id.as_bytes(),
            operation_id.as_bytes(),
            target_incarnation.as_bytes(),
        ],
    ))
}

fn require_id(id: Uuid) -> Result<()> {
    ensure!(!id.is_nil(), "installed node identity input is nil");
    Ok(())
}

fn derive(domain: &[u8], fields: &[&[u8]]) -> Uuid {
    let mut digest = Sha256::new();
    digest.update((domain.len() as u64).to_be_bytes());
    digest.update(domain);
    for field in fields {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    let digest = digest.finalize();
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest[..16]);
    // Custom SHA-256 derivation uses UUID version 8, RFC variant.
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn immutable_identity_derivations_are_stable_and_domain_separated() {
        let a = Uuid::from_u128(1);
        let b = Uuid::from_u128(2);
        let c = Uuid::from_u128(3);
        let verifier = TrustVerifierIdentity {
            installation_id: a,
            node_id: 4,
        };
        let local = local_generation(a, b, c).unwrap();
        assert_eq!(local, local_generation(a, b, c).unwrap());
        assert_ne!(local, local_generation(a, c, b).unwrap());
        assert_ne!(local, local_generation(b, b, c).unwrap());
        assert_ne!(
            signer_verifier(&verifier).unwrap(),
            target_journal(b, &verifier).unwrap()
        );
        assert_ne!(
            target_journal(b, &verifier).unwrap(),
            target_journal(c, &verifier).unwrap()
        );
        assert_ne!(
            target_journal(b, &verifier).unwrap(),
            target_generation(b, "tenant", c, &verifier).unwrap()
        );
        assert_ne!(
            target_generation(b, "tenant", c, &verifier).unwrap(),
            target_generation(b, "other", c, &verifier).unwrap()
        );
        assert_ne!(
            target_generation(b, "tenant", c, &verifier).unwrap(),
            target_generation(b, "tenant", a, &verifier).unwrap()
        );
        assert_ne!(
            signer_verifier(&verifier).unwrap(),
            signer_verifier(&TrustVerifierIdentity {
                installation_id: a,
                node_id: 5
            })
            .unwrap()
        );
        let managed = administrative_generation(a, "tenant", c).unwrap();
        assert_eq!(managed, administrative_generation(a, "tenant", c).unwrap());
        assert_ne!(managed, administrative_generation(b, "tenant", c).unwrap());
        assert_ne!(managed, administrative_generation(a, "other", c).unwrap());
        assert_ne!(managed, administrative_generation(a, "tenant", b).unwrap());
        assert_ne!(managed, local);
        assert_ne!(
            managed,
            target_generation(b, "tenant", c, &verifier).unwrap()
        );
        assert!(administrative_generation(Uuid::nil(), "tenant", c).is_err());
        assert!(administrative_generation(a, "../tenant", c).is_err());
        assert!(!local.is_nil());
        assert!(local_generation(a, Uuid::nil(), c).is_err());
        assert!(target_journal(Uuid::nil(), &verifier).is_err());
        assert!(
            signer_verifier(&TrustVerifierIdentity {
                installation_id: Uuid::nil(),
                node_id: 4
            })
            .is_err()
        );
    }
}
