//! Exact physical lookup for installed backup destinations. This table is not
//! a Control claim, source-authority proof, or permission to write a session.
//! Filesystem destinations cannot enter until their installed marker is bound.
use crate::{BackupDestination, S3BackupDestination};
use anyhow::{Context, Result, ensure};
use kasumi_types::BackupNamespaceBinding;
use std::{collections::BTreeMap, sync::Arc};

/// Bounds installed physical identities independently of alias cardinality.
pub const MAX_EXACT_BACKUP_DESTINATIONS: usize = 256;

/// Canonical prefix segments have no empty component, so slash-boundary
/// containment cannot confuse `capture/a` with `capture/ab`.
fn prefix_contains(parent: &str, child: &str) -> bool {
    parent.is_empty()
        || parent == child
        || child
            .strip_prefix(parent)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

#[derive(Default)]
pub struct ExactBackupDestinationIndex {
    by_binding: BTreeMap<BackupNamespaceBinding, Arc<dyn BackupDestination>>,
}

impl ExactBackupDestinationIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit only an identity derived by the validated, immutable S3 adapter.
    /// A second adapter whose prefix contains or is contained by an installed
    /// prefix is ambiguous, including across signing regions or aliases.
    pub fn install_s3(
        &mut self,
        destination: Arc<S3BackupDestination>,
    ) -> Result<BackupNamespaceBinding> {
        let binding = destination.namespace_binding()?;
        // S3 object URLs use origin/bucket/prefix, not the signing region.
        // A nested prefix can address keys in another adapter's session-object
        // grammar, so even distinct full bindings must not overlap.
        let collision = self.by_binding.keys().any(|existing| {
            matches!(
                (existing, &binding),
                (
                    BackupNamespaceBinding::S3 {
                        https_origin: old_origin,
                        bucket: old_bucket,
                        prefix: old_prefix,
                        ..
                    },
                    BackupNamespaceBinding::S3 {
                        https_origin: new_origin,
                        bucket: new_bucket,
                        prefix: new_prefix,
                        ..
                    }
                ) if old_origin == new_origin
                    && old_bucket == new_bucket
                    && (prefix_contains(old_prefix, new_prefix)
                        || prefix_contains(new_prefix, old_prefix))
            )
        });
        ensure!(!collision, "S3 object namespace already installed");
        ensure!(
            self.by_binding.len() < MAX_EXACT_BACKUP_DESTINATIONS,
            "physical backup destination index is full"
        );
        self.by_binding.insert(binding.clone(), destination);
        Ok(binding)
    }

    /// Exact lookup only. Missing or malformed bindings never use an alias,
    /// nearby prefix, renewed credential, or another physical namespace.
    pub fn resolve(&self, binding: &BackupNamespaceBinding) -> Result<Arc<dyn BackupDestination>> {
        binding.validate()?;
        self.by_binding
            .get(binding)
            .cloned()
            .context("bound physical backup destination is unavailable")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::S3BackupConfig;

    fn destination(prefix: &str, credential: &str) -> Arc<S3BackupDestination> {
        destination_with_region(prefix, "ap-northeast-1", credential)
    }

    fn destination_with_region(
        prefix: &str,
        region: &str,
        credential: &str,
    ) -> Arc<S3BackupDestination> {
        Arc::new(
            S3BackupDestination::new(S3BackupConfig {
                endpoint: "https://s3.example/".into(),
                region: region.into(),
                bucket: "backups".into(),
                prefix: prefix.into(),
                credential: Arc::new({
                    let credential = credential.to_owned();
                    move || {
                        Ok(zeroize::Zeroizing::new(
                            serde_json::json!({
                                "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                                "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                                "session_token": credential,
                            })
                            .to_string(),
                        ))
                    }
                }),
                ca_pem: None,
                max_bytes: 1 << 20,
            })
            .unwrap(),
        )
    }

    #[test]
    fn exact_identity_survives_registry_growth_but_never_redirects() {
        let original = destination("capture/a", "first");
        let original_binding = original.namespace_binding().unwrap();
        let changed = destination("capture/b", "second");
        let changed_binding = changed.namespace_binding().unwrap();
        let mut index = ExactBackupDestinationIndex::new();
        assert_eq!(
            index.install_s3(original.clone()).unwrap(),
            original_binding
        );
        let resolved = index.resolve(&original_binding).unwrap();
        let expected: Arc<dyn BackupDestination> = original;
        assert!(Arc::ptr_eq(&resolved, &expected));
        assert!(index.resolve(&changed_binding).is_err());
        index.install_s3(changed).unwrap();
        assert!(Arc::ptr_eq(
            &index.resolve(&original_binding).unwrap(),
            &expected
        ));
    }

    #[test]
    fn duplicate_rotated_credentials_and_unbound_filesystem_reject() {
        let original = destination("capture/a", "first");
        let binding = original.namespace_binding().unwrap();
        let mut index = ExactBackupDestinationIndex::new();
        index.install_s3(original).unwrap();
        // Rotating credentials must not mint another physical identity.
        assert_eq!(
            destination("capture/a", "rotated")
                .namespace_binding()
                .unwrap(),
            binding
        );
        assert!(
            index
                .install_s3(destination("capture/a", "rotated"))
                .is_err()
        );
        let filesystem = BackupNamespaceBinding::Filesystem {
            installation_id: uuid::Uuid::new_v4(),
            origin_node_id: 7,
            namespace_id: uuid::Uuid::new_v4(),
            device: 1,
            inode: 2,
        };
        assert!(index.resolve(&filesystem).is_err());
    }

    #[test]
    fn different_signing_regions_cannot_claim_the_same_s3_object_keys() {
        let first = destination_with_region("capture/a", "ap-northeast-1", "first");
        let first_binding = first.namespace_binding().unwrap();
        let different_region = destination_with_region("capture/a", "us-east-1", "second");
        assert_ne!(first_binding, different_region.namespace_binding().unwrap());
        let mut index = ExactBackupDestinationIndex::new();
        index.install_s3(first).unwrap();
        assert!(index.install_s3(different_region).is_err());
        assert!(index.resolve(&first_binding).is_ok());
    }

    #[test]
    fn nested_prefixes_cannot_claim_each_others_session_object_keys() {
        let mut index = ExactBackupDestinationIndex::new();
        let parent = destination("capture/a", "parent");
        let parent_binding = index.install_s3(parent).unwrap();
        let session = uuid::Uuid::from_u128(71);
        let child_prefix = format!("capture/a/sessions/{session}/objects");
        assert!(
            index
                .install_s3(destination(&child_prefix, "child"))
                .is_err()
        );
        assert!(
            index
                .install_s3(destination("capture/a/b", "child"))
                .is_err()
        );
        assert!(index.install_s3(destination("", "bucket-root")).is_err());
        // Slash boundaries preserve separate sibling namespaces.
        assert!(
            index
                .install_s3(destination("capture/ab", "sibling"))
                .is_ok()
        );
        assert!(index.resolve(&parent_binding).is_ok());

        let mut reverse = ExactBackupDestinationIndex::new();
        reverse
            .install_s3(destination(&child_prefix, "child"))
            .unwrap();
        assert!(
            reverse
                .install_s3(destination("capture/a", "parent"))
                .is_err()
        );
    }

    #[test]
    fn index_limit_rejects_a_new_namespace_without_losing_existing_bindings() {
        let mut index = ExactBackupDestinationIndex::new();
        let first = index.install_s3(destination("capture/0", "first")).unwrap();
        for i in 1..MAX_EXACT_BACKUP_DESTINATIONS {
            index
                .install_s3(destination(&format!("capture/{i}"), "other"))
                .unwrap();
        }
        assert!(
            index
                .install_s3(destination("capture/overflow", "other"))
                .is_err()
        );
        assert!(index.resolve(&first).is_ok());
    }
}
