//! Precommit rollback preserves the actual current root and exact first cause.
use super::*;

#[derive(Debug)]
pub enum SourceHistoryRefusal {
    Metadata(io::Error),
    Native(kasumi_kv::SourceHistoryRefusal),
    Census(io::Error),
}
impl std::fmt::Display for SourceHistoryRefusal {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Metadata(error) | Self::Census(error) => std::fmt::Display::fmt(error, out),
            Self::Native(error) => std::fmt::Display::fmt(error, out),
        }
    }
}
impl std::error::Error for SourceHistoryRefusal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Metadata(error) | Self::Census(error) => Some(error),
            Self::Native(error) => Some(error),
        }
    }
}

#[derive(Debug)]
pub enum SourceHistoryAbort {
    /// Contention prevented observation; current remains unavailable.
    Pending,
    /// Unknown or entered work stays in its original registered owner.
    Retained,
    /// Every provisional native/metadata/census owner positively retired.
    Restored {
        refusal: Option<SourceHistoryRefusal>,
    },
}

impl NodeReadReport<'_> {
    /// A cause transferred from a positively canceled subowner remains here
    /// until all other cleanup is positive. Unknown cleanup never drops it.
    pub fn source_history_refusal(&self) -> Option<&SourceHistoryRefusal> {
        self.state.source.as_ref()?.history_refusal.as_ref()
    }
    pub fn source_history_metadata_preparation(
        &self,
    ) -> Option<TerminalObservation<'_, io::Error>> {
        Some(
            self.state
                .source
                .as_ref()?
                .history
                .as_ref()?
                .preparation()
                .original(),
        )
    }
    pub fn source_history_metadata_cleanup(&self) -> Option<TerminalObservation<'_, Infallible>> {
        Some(self.state.source.as_ref()?.history.as_ref()?.cleanup())
    }
    pub fn source_history_native_disposal(&self) -> Option<TerminalObservation<'_, Infallible>> {
        self.state.source.as_ref()?.native.history_disposal()
    }
}

impl RegisteredNodeRead {
    pub fn abort_source_history(&self) -> SourceHistoryAbort {
        let request = self.registration.owner();
        let Some(mut state) = request.state.try_lock() else {
            return SourceHistoryAbort::Pending;
        };
        if state.phase != NodeReadPhase::SourceHistory
            || state.transaction.is_some()
            || observed_failure(state.begin.borrow())
            || observed_failure(state.tables.borrow())
            || observed_failure(state.outer.borrow())
            || observed_failure(state.output_admission.borrow())
            || observed_failure(state.read_failure.borrow())
            || observed_failure(state.body_panic.borrow())
            || observed_failure(state.finish_outer.borrow())
        {
            return SourceHistoryAbort::Retained;
        }
        let Some(source) = state.source.as_mut() else {
            return SourceHistoryAbort::Retained;
        };
        if source.closed
            || source.native_entered
            || source.native_committed
            || source.census_native_committed
            || source.locally_committed
            || !source.preparation.succeeded()
            || !source.capture.succeeded()
            || source.entry_mark.failed()
            || !source.committed_mark.pending()
            || !source.history_commit.pending()
            || !source.local_completion.pending()
            || source.history_prepare.failed()
            || source.history_abort_native.failed()
            || source.history_abort_metadata.failed()
            || source.history_abort_disposal.failed()
            || source.cancellation.failed()
            || !source.native_close.pending()
            || !source.native_dispose.pending()
            || !source.metadata_retire.pending()
            || !source.metadata_dispose.pending()
            || !source.pool_dispose.pending()
        {
            return SourceHistoryAbort::Retained;
        }
        let setup_refused = source.census_refused
            && matches!(source.history_setup, MetadataAttempt::Returned(Err(_)))
            && source.exchange.is_none()
            && source.history.is_none()
            && source.history_prepare.pending();
        if !setup_refused && !source.history_setup.succeeded() {
            return SourceHistoryAbort::Retained;
        }
        if source
            .history
            .as_ref()
            .is_some_and(|history| !history.abortable())
        {
            return SourceHistoryAbort::Retained;
        }
        if !source.history_native_aborted {
            let Some(opening) = request.database.owner().state.try_lock() else {
                return SourceHistoryAbort::Pending;
            };
            let Some(database) = opening.engine.retained_database() else {
                return SourceHistoryAbort::Retained;
            };
            source.history_abort_native.run(|| {
                if let kasumi_kv::SourceHistoryAbort::Restored { refusal } =
                    source.native.abort_history(database)?
                {
                    source.history_refusal = refusal.map(SourceHistoryRefusal::Native);
                    source.history_native_aborted = true;
                }
                Ok(())
            });
            if !source.history_abort_native.succeeded() || !source.history_native_aborted {
                return SourceHistoryAbort::Retained;
            }
        }
        if !source.history_metadata_aborted {
            source.history_abort_metadata.run(|| {
                if let Some(history) = &mut source.history {
                    if !history.abort()? {
                        return Ok(());
                    }
                    // Check before moving an original. Even an impossible
                    // double-cause state must keep both existing owners.
                    if history.preparation().clean_history_refusal()
                        && source.history_refusal.is_some()
                    {
                        return Err(io::ErrorKind::InvalidData.into());
                    }
                    if let Some(error) = history.take_refusal() {
                        source.history_refusal = Some(SourceHistoryRefusal::Metadata(error));
                    }
                }
                source.history_metadata_aborted = true;
                Ok(())
            });
            if !source.history_abort_metadata.succeeded() || !source.history_metadata_aborted {
                return SourceHistoryAbort::Retained;
            }
        }
        if let Some(exchange) = &mut source.exchange
            && !source.census_cancelled
        {
            source.cancellation.retry_success();
            source.cancellation.run(|| {
                match request
                    .provider
                    .storage_census()
                    .cancel_source_exchange(exchange)
                {
                    StorageCensusDisposition::Retired => source.census_cancelled = true,
                    StorageCensusDisposition::Retained => {}
                    StorageCensusDisposition::Stale => {
                        return Err(io::ErrorKind::InvalidData.into());
                    }
                }
                Ok(())
            });
            if !source.census_cancelled {
                return if source.cancellation.failed()
                    || !request
                        .provider
                        .storage_census()
                        .source_exchange_can_retry_cancellation(exchange)
                {
                    SourceHistoryAbort::Retained
                } else {
                    SourceHistoryAbort::Pending
                };
            }
        }
        if setup_refused && source.history_refusal.is_none() {
            let MetadataAttempt::Returned(Err(error)) =
                std::mem::replace(&mut source.history_setup, MetadataAttempt::Pending)
            else {
                unreachable!("checked exact census refusal")
            };
            source.history_refusal = Some(SourceHistoryRefusal::Census(error));
        }
        source.history_abort_disposal.run(|| {
            drop(source.history.take());
            drop(source.replacement_hold.take());
            source.exchange.take();
            Ok(())
        });
        if !source.history_abort_disposal.succeeded() {
            return SourceHistoryAbort::Retained;
        }
        // All prior results were success, or their one exact refusal is now
        // owned in the returned value. No arbitrary failure is acknowledged.
        let refusal = source.history_refusal.take();
        source.history_setup = MetadataAttempt::new();
        source.history_prepare = MetadataAttempt::new();
        source.entry_mark = MetadataAttempt::new();
        source.cancellation = MetadataAttempt::new();
        source.census_cancelled = false;
        source.census_refused = false;
        source.history_abort_native = MetadataAttempt::new();
        source.history_native_aborted = false;
        source.history_abort_metadata = MetadataAttempt::new();
        source.history_metadata_aborted = false;
        source.history_abort_disposal = MetadataAttempt::new();
        state.phase = NodeReadPhase::SourceCaptured;
        SourceHistoryAbort::Restored { refusal }
    }
}
