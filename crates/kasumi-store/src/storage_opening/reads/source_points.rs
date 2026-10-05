//! Narrow prepared loans keep the actual protected source and report in place.
use super::*;

fn ready(state: &ReaderState) -> bool {
    let Some(source) = &state.source else {
        return false;
    };
    !source.closed
        && !state.has_failures()
        && match state.phase {
            NodeReadPhase::SourceCaptured => true,
            NodeReadPhase::SourceHistory => {
                source.native_committed
                    && source.census_native_committed
                    && source.locally_committed
            }
            _ => false,
        }
}

impl RegisteredNodeRead {
    pub(crate) fn is_protected_source(&self) -> bool {
        self.registration.owner().state.lock().source.is_some()
    }

    pub(crate) fn verify_source_tables_prepared(
        &self,
        workspace: &mut kasumi_kv::PreparedPointRead,
    ) -> Result<(), NodeReadAccessError> {
        let request = self.registration.owner();
        let mut state = request.state.lock();
        if !ready(&state) {
            return Err(NodeReadAccessError::Unavailable);
        }
        if state.tables.success() {
            return Ok(());
        }
        state.outcomes_released = false;
        state.tables = Observation::Entered;
        let source = &state.source.as_ref().unwrap().native;
        match catch_unwind(AssertUnwindSafe(|| {
            source
                .check_bytes_table_prepared(crate::CATALOG, workspace)
                .map_err(NodeReadTablesError::Catalog)?;
            source
                .check_bytes_table_prepared(crate::RECORDS, workspace)
                .map_err(NodeReadTablesError::Records)
        })) {
            Ok(result) => state.tables = Observation::Returned(result),
            Err(payload) => {
                state.tables = Observation::Panicked(payload);
                request
                    .database
                    .owner()
                    .stopped
                    .store(true, Ordering::Release);
            }
        }
        if state.tables.success() {
            Ok(())
        } else {
            state.phase = NodeReadPhase::Failed;
            Err(NodeReadAccessError::Reported)
        }
    }

    fn source_read_prepared<T>(
        &self,
        read: impl FnOnce(&BoundSourceRead) -> Result<T, BoundedReadError>,
    ) -> Result<T, NodeReadAccessError> {
        let request = self.registration.owner();
        let mut state = request.state.lock();
        if !ready(&state) || !state.tables.success() {
            return Err(NodeReadAccessError::Unavailable);
        }
        state.outcomes_released = false;
        state.read_failure = Observation::Entered;
        let source = &state.source.as_ref().unwrap().native;
        match catch_unwind(AssertUnwindSafe(|| read(source))) {
            Ok(Ok(value)) => {
                state.read_failure = Observation::Returned(Ok(()));
                Ok(value)
            }
            Ok(Err(error)) => {
                state.read_failure = Observation::Returned(Err(error));
                state.phase = NodeReadPhase::Failed;
                Err(NodeReadAccessError::Reported)
            }
            Err(payload) => {
                state.read_failure = Observation::Panicked(payload);
                state.phase = NodeReadPhase::Failed;
                request
                    .database
                    .owner()
                    .stopped
                    .store(true, Ordering::Release);
                Err(NodeReadAccessError::Reported)
            }
        }
    }

    pub(crate) fn source_record_bytes_prepared<'workspace>(
        &self,
        key: &[u8],
        max_value_bytes: usize,
        workspace: &'workspace mut kasumi_kv::PreparedPointRead,
    ) -> Result<Option<&'workspace [u8]>, NodeReadAccessError> {
        self.source_read_prepared(|source| {
            source.get_bytes_prepared(crate::RECORDS, key, max_value_bytes, workspace)
        })
    }

    pub(crate) fn source_record_length_prepared(
        &self,
        key: &[u8],
        workspace: &mut kasumi_kv::PreparedPointRead,
    ) -> Result<Option<usize>, NodeReadAccessError> {
        self.source_read_prepared(|source| {
            source.point_length_prepared(crate::RECORDS, key, workspace)
        })
    }
}
