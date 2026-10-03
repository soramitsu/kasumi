//! Unwired complete known-path source quote. No admission or pool activation.
use super::*;

pub(super) struct SourceMemoryQuote {
    pub(super) peak: u64,
    pub(super) retained: u64,
    pub(super) planning_peak: u64,
    pub(super) rights: u64,
    pub(super) native: kasumi_store::PairedReadMemoryQuote,
}
impl SourceRoots {
    pub(super) fn quote_source_plan(
        &self,
        plan: &PreparedSelectionPlan,
    ) -> Result<SourceMemoryQuote> {
        plan.require_stores(&self.stores)?;
        let native = self.stores.quote_read_memory()?;
        let expected: Arc<dyn kasumi_store::NodeDiskMemoryAdmission> =
            self.admission.memory().clone();
        native.require_memory(&expected)?;
        let floor = cell_bytes()?;
        let add = |bytes: u64| {
            floor
                .checked_add(bytes)
                .context("source owner quote overflow")
        };
        Ok(SourceMemoryQuote {
            peak: add(plan.prepared_read_peak_bytes(&native)?)?,
            retained: add(native
                .retained_bytes()
                .checked_add(plan.retained_bytes())
                .context("source retained quote overflow")?)?,
            planning_peak: add(plan.planning_read_peak_bytes(&native)?)?,
            rights: native.source_rights_bytes(),
            native,
        })
    }
}
