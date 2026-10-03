//! Ordered prefix reads share one exact installed snapshot and point workspace.
use super::*;
use kasumi_store::PreparedTenantReadPoints;

pub(crate) struct Records {
    scan: Option<Scan>,
    error: Option<anyhow::Error>,
    #[cfg(test)]
    reads: usize,
}
struct Scan {
    source: ScanSource,
    head: StagedTerminalHead,
    last: Option<Ordinal>,
    previous: Option<String>,
    ordinal: u64,
    #[cfg(test)]
    reads: usize,
}
// Keep the admitted session inline. A Box solely to shrink this enum would
// introduce another allocation/owner into the bounded read operation.
#[allow(
    clippy::large_enum_variant,
    reason = "the admitted read owner stays inline"
)]
enum ScanSource {
    Durable {
        session: PreparedTenantReadPoints,
        namespace: String,
    },
    Staged(Arc<EncryptedTable>),
}
impl ScanSource {
    fn open(source: &Source) -> Result<Self> {
        match source {
            Source::Durable(rows) => {
                let namespace = rows.binding.namespace();
                let session = rows.store.read_view()?.prepare_point_reads(
                    namespace.len(),
                    b"id/".len() + 64,
                    MAX_ROW_BYTES,
                )?;
                Ok(Self::Durable { session, namespace })
            }
            Source::Staged(table) => Ok(Self::Staged(table.clone())),
        }
    }
    fn read<T>(
        &mut self,
        key: &[u8],
        decode: impl FnOnce(Option<&[u8]>) -> Result<T>,
    ) -> Result<T> {
        match self {
            Self::Durable { session, namespace } => {
                decode(session.get(namespace, key, MAX_ROW_BYTES)?)
            }
            Self::Staged(table) => {
                let bytes = table.get(key)?;
                ensure!(
                    bytes
                        .as_ref()
                        .is_none_or(|value| value.len() <= MAX_ROW_BYTES),
                    "terminal physical row exceeds bound"
                );
                decode(bytes.as_deref())
            }
        }
    }
    fn finish<T>(self, result: Result<T>) -> Result<T> {
        match self {
            Self::Durable { session, .. } => session.finish(result),
            Self::Staged(_) => result,
        }
    }
}
impl Scan {
    fn index(&mut self, ordinal: u64) -> Result<Ordinal> {
        #[cfg(test)]
        {
            self.reads += 1;
        }
        self.source.read(&ordinal_key(ordinal), |bytes| {
            let bytes = bytes.context("terminal ordinal missing")?;
            let index: Ordinal = serde_json::from_slice(bytes)?;
            crate::current_json::require_current_writer_bytes(
                bytes,
                &index,
                "staged terminal ordinal",
            )?;
            ensure!(
                digest(&index.key) && digest(&index.sha256),
                "invalid terminal ordinal index"
            );
            Ok(index)
        })
    }
    fn open(view: &View) -> Result<Self> {
        let source = view.source.as_deref().context("terminal ordinal missing")?;
        let mut scan = Self {
            source: ScanSource::open(source)?,
            head: view.head.clone(),
            last: None,
            previous: None,
            ordinal: 1,
            #[cfg(test)]
            reads: 0,
        };
        let result = (|| {
            let last = scan.index(scan.head.count)?;
            ensure!(
                last.sha256 == scan.head.sha256,
                "terminal selected root differs"
            );
            Ok(last)
        })();
        match result {
            Ok(last) => {
                scan.last = Some(last);
                Ok(scan)
            }
            Err(error) => scan.source.finish(Err(error)),
        }
    }
    fn row(&mut self) -> Result<Row> {
        let index = if self.ordinal == self.head.count {
            self.last.take().expect("selected terminal head")
        } else {
            self.index(self.ordinal)?
        };
        #[cfg(test)]
        {
            self.reads += 1;
        }
        let row = self.source.read(&id_key(&index.key), |bytes| {
            let bytes = bytes.context("terminal indexed row missing")?;
            let row: Row = serde_json::from_slice(bytes)?;
            // Preserve the selected logical prefix even when later rows exist.
            ensure!(
                row.ordinal <= self.head.count,
                "terminal indexed row missing"
            );
            crate::current_json::require_current_writer_bytes(
                bytes,
                &row,
                "staged terminal point",
            )?;
            ensure!(
                row.key == index.key && row.ordinal > 0,
                "terminal point identity differs"
            );
            ensure!(row.ordinal == self.ordinal, "terminal ordinal redirected");
            Ok(row)
        })?;
        let digest = row.sha256()?;
        ensure!(
            index.sha256 == digest,
            "terminal row differs from ordinal commitment"
        );
        match &self.previous {
            Some(previous) => ensure!(
                row.previous_sha256 == *previous,
                "terminal parent root differs"
            ),
            None => ensure!(
                row.previous_sha256
                    == StagedTerminalHead::empty(
                        &row.stage.scope.tenant,
                        &self.head.origin_incarnation,
                    )?
                    .sha256,
                "terminal initial root differs"
            ),
        }
        self.previous = Some(digest);
        Ok(row)
    }
}
impl Records {
    pub(super) fn new(view: &View) -> Self {
        let result = if view.head.count == 0 {
            Ok(None)
        } else {
            Scan::open(view).map(Some)
        };
        let (scan, error) = match result {
            Ok(scan) => (scan, None),
            Err(error) => (None, Some(error)),
        };
        Self {
            #[cfg(test)]
            reads: scan.as_ref().map_or(0, |scan| scan.reads),
            scan,
            error,
        }
    }
    #[cfg(test)]
    pub(super) fn point_reads(&self) -> usize {
        self.reads
    }
    #[cfg(test)]
    pub(super) fn registered_reader_id(&self) -> Option<kasumi_store::StorageOwnerId> {
        match &self.scan.as_ref()?.source {
            ScanSource::Durable { session, .. } => session.registered_reader_id(),
            ScanSource::Staged(_) => None,
        }
    }
}
impl Iterator for Records {
    type Item = Result<Row>;
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(error) = self.error.take() {
            return Some(Err(error));
        }
        let scan = self.scan.as_mut()?;
        let result = scan.row();
        #[cfg(test)]
        {
            self.reads = scan.reads;
        }
        if result.is_err() || scan.ordinal == scan.head.count {
            // Return the owned final row only after actual reader settlement.
            // The failed operation and failed close are retained together.
            Some(self.scan.take().expect("live scan").source.finish(result))
        } else {
            scan.ordinal += 1;
            Some(result)
        }
    }
}
