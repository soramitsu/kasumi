//! Installed archive locations. The canonical segment bound is always 8 MiB;
//! expandable retained-byte capacity belongs to the audit retention budget.
use crate::administration::DestinationConfig;
use anyhow::Result;
use kasumi_store::{AuditArchiveDestination, FilesystemAuditArchive, S3AuditArchive};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Arc};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuditDestinationConfig {
    Filesystem {
        directory: PathBuf,
    },
    S3 {
        endpoint: String,
        region: String,
        bucket: String,
        prefix: String,
        credentials_file: PathBuf,
        ca_certificate: Option<PathBuf>,
    },
}
impl AuditDestinationConfig {
    fn bounded_destination(&self) -> DestinationConfig {
        let max_bytes = kasumi_types::MAX_AUDIT_SEGMENT_BYTES;
        match self {
            Self::Filesystem { directory } => DestinationConfig::Filesystem {
                directory: directory.clone(),
                max_bytes,
            },
            Self::S3 {
                endpoint,
                region,
                bucket,
                prefix,
                credentials_file,
                ca_certificate,
            } => DestinationConfig::S3 {
                endpoint: endpoint.clone(),
                region: region.clone(),
                bucket: bucket.clone(),
                prefix: prefix.clone(),
                credentials_file: credentials_file.clone(),
                ca_certificate: ca_certificate.clone(),
                max_bytes,
            },
        }
    }
    pub(crate) fn validate(&self) -> Result<()> {
        self.bounded_destination().validate()
    }
    pub(crate) fn open(&self) -> Result<Arc<dyn AuditArchiveDestination>> {
        self.validate()?;
        Ok(match self {
            Self::Filesystem { directory } => Arc::new(FilesystemAuditArchive::open(directory)?),
            Self::S3 {
                endpoint,
                region,
                bucket,
                prefix,
                credentials_file,
                ca_certificate,
            } => Arc::new(S3AuditArchive::new(Arc::new(
                kasumi_store::S3BackupDestination::new(kasumi_store::S3BackupConfig {
                    endpoint: endpoint.clone(),
                    region: region.clone(),
                    bucket: bucket.clone(),
                    prefix: prefix.clone(),
                    credential: Arc::new(kasumi_transport::credentials::FileCredentialSource::new(
                        credentials_file,
                    )?),
                    ca_pem: ca_certificate
                        .as_ref()
                        .map(|path| crate::runtime::read_bounded(path, 1 << 20))
                        .transpose()?,
                    max_bytes: kasumi_types::MAX_AUDIT_SEGMENT_BYTES,
                })?,
            ))),
        })
    }
}
