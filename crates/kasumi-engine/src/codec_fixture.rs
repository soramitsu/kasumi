//! Private codec-test scope. Callers select and retain their explicit bounded governor.
use std::sync::Arc;
pub(crate) struct ScratchScope {
    pub(crate) disk: Arc<kasumi_store::ScratchDisk>,
    _directory: tempfile::TempDir,
}
impl ScratchScope {
    pub(crate) fn new(
        memory: Arc<dyn kasumi_store::NodeDiskMemoryAdmission>,
    ) -> anyhow::Result<Self> {
        let directory = kasumi_store::test_utils::private_tempdir()?;
        let disk = kasumi_store::ScratchDisk::fixture(directory.path().join("scratch"), memory);
        Ok(Self {
            disk,
            _directory: directory,
        })
    }
}
