//! Temporary recovery-route diagnostics. Every observation borrows its original
//! owner; this module never advances, closes, acknowledges or retires custody.
use kasumi_kv::TerminalObservation;
use std::fmt;

struct Observation<'a, E>(TerminalObservation<'a, E>);
impl<E: fmt::Debug> fmt::Display for Observation<'_, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            TerminalObservation::NotEntered => f.write_str("NotEntered"),
            TerminalObservation::Entered => f.write_str("Entered"),
            TerminalObservation::Returned(result) => write!(f, "Returned({result:#?})"),
            TerminalObservation::Panicked(payload) => write!(
                f,
                "Panicked(str={:?}, string={:?}, u64={:?})",
                payload.downcast_ref::<&str>(),
                payload.downcast_ref::<String>(),
                payload.downcast_ref::<u64>(),
            ),
        }
    }
}

#[cold]
#[inline(never)]
pub(super) fn fail(id: u64, create: bool, error: &kasumi_store::NodeStoreStartFailure) -> ! {
    eprintln!("node opening failure: node={id}, create={create}, original={error:#?}");
    if let kasumi_store::NodeStoreStartFailure::Opening(failure) = error {
        let custody = failure.custody();
        eprintln!(
            "startup: phase={:?}, opening={:?}, child={:?}, disposition={:?}, local={:#?}, close={:#?}",
            custody.phase(),
            failure.opening_id(),
            custody.child_id(),
            custody.child_disposition(),
            custody.local_error(),
            failure.close_error(),
        );
        // Release the opening report lock before borrowing either child report.
        {
            let report = custody.opening().report();
            eprintln!(
                "opening: acquisition={}, outer={}, ready={}, existing_verified={}, failed_recovery={}",
                Observation(report.acquisition()),
                Observation(report.opening_outer()),
                Observation(report.ready_publication()),
                report.existing_tables_verified(),
                Observation(report.failed_recovery()),
            );
            let native = report.engine();
            eprintln!(
                "native opening: phase={:?}, opening_phase={:?}, settlement={:?}, disposition={:?}, original={}, partial_close={}, failed_disposal={}",
                native.phase(),
                native.opening_phase(),
                native.settlement(),
                native.native_disposition(),
                Observation(native.opening()),
                Observation(native.partial_close()),
                Observation(native.failed_disposal()),
            );
            if let Some(fence) = native.fence().observation() {
                eprintln!("native opening fence: {}", Observation(fence));
            }
            if let Some(close) = native.database_close() {
                eprintln!(
                    "native database close: settlement={:?}, disposition={:?}, shutdown={}, backend={}, failed_disposal={}",
                    close.settlement(),
                    close.native_disposition(),
                    Observation(close.shutdown()),
                    Observation(close.backend()),
                    Observation(close.failed_disposal()),
                );
            }
        }
        if let Some(tables) = custody.tables() {
            let report = tables.report();
            eprintln!(
                "table child: id={:?}, begin={}, body={}, outer={}, capacity_denied={}",
                tables.id(),
                Observation(report.begin()),
                Observation(report.body()),
                Observation(report.outer()),
                report.is_capacity_denied(),
            );
            if let Some(native) = report.terminal() {
                eprintln!(
                    "table native: operation={:?}, settlement={:?}, terminal={}, rollback={}, disposal={}",
                    native.operation(),
                    native.settlement(),
                    Observation(native.terminal()),
                    Observation(native.rollback()),
                    Observation(native.disposal()),
                );
            }
        }
        if let Some(reader) = custody.verification() {
            let report = reader.report();
            eprintln!(
                "verification child: id={:?}, phase={:?}, has_failures={}, begin={}, tables={}, outer={}, read={}, body_panic={}, output={}, finish_outer={}",
                reader.id(),
                report.phase(),
                report.has_failures(),
                Observation(report.begin()),
                Observation(report.tables()),
                Observation(report.outer()),
                Observation(report.read_failure()),
                Observation(report.body_panic()),
                Observation(report.output_admission()),
                Observation(report.finish_outer()),
            );
            if let Some(native) = report.close() {
                eprintln!(
                    "verification native: settlement={:?}, retains_transaction={}, retains_database={}, release={}, disposal={}, native_retirement={}",
                    native.settlement(),
                    native.retains_transaction(),
                    native.retains_database(),
                    Observation(native.release()),
                    Observation(native.disposal()),
                    Observation(native.native_retirement()),
                );
            }
        }
    }
    panic!("node opening failed: node={id}, create={create}: {error:#}");
}
