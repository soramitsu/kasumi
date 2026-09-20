//! Point reads retain their selected generation/namespace and original worker
//! ownership. No whole receipt history is cloned or decoded. A fixed physical
//! read floor precedes I/O; structural decode admission precedes the row DTO.
use super::*;
const POINT_READ_BYTES: u64 = 8 << 20;
pub(super) struct ReceiptRead {
    pub receipt: Option<StoredReceipt>,
    pub revision: u64,
    pub epoch: u64,
    pub strict: bool,
    pub strict_collections: BTreeSet<String>,
    _reservation: Reservation,
    _registration: Arc<WorkRegistration>,
}
impl Database {
    pub(super) async fn read_mutation_receipt(
        &self,
        context: &RequestContext,
        idempotency_key: &str,
        deadline: tokio::time::Instant,
    ) -> Result<ReceiptRead> {
        context.authorization.check_live()?;
        if tokio::time::Instant::now() >= deadline {
            return Err(Error::new(
                ErrorCode::Unavailable,
                "mutation receipt deadline exceeded",
            ));
        }
        self.access()?;
        validate_name(&context.principal)?;
        validate_name(idempotency_key)?;
        let cancellation = QueryCancellation::default();
        let _cancel = CancelOnDrop(cancellation.clone());
        let mut reservation = self
            .admission()
            .reserve(POINT_READ_BYTES, Some(cancellation.clone()))?;
        let registration = Arc::new(self.work.begin(cancellation.clone())?);
        // Typed context has no document Value or canonical map sorter. This
        // borrowed pass allocates no encoded metadata buffer before admission.
        reservation.reserve_additional(
            crate::snapshot_codec::inspect_typed_json_work(context).map_err(point_error)?,
        )?;
        let generation = self.engine.generation()?;
        crate::state::authorize_resource(&generation.state, context)?;
        if context.tenant != generation.state.tenant {
            return Err(Error::new(ErrorCode::Forbidden, "receipt tenant differs"));
        }
        let key = staged_digest(&(&context.principal, idempotency_key))?.0;
        let work = ReceiptWork {
            generation,
            context: context.clone(),
            cancellation,
            deadline,
            reservation,
            registration,
        };
        let worker = tokio::task::spawn_blocking(move || work.run(&key));
        tokio::time::timeout_at(deadline, worker)
            .await
            .map_err(|_| Error::new(ErrorCode::Unavailable, "mutation receipt deadline exceeded"))?
            .map_err(|_| Error::new(ErrorCode::Unavailable, "mutation receipt worker failed"))?
    }
}
/// Storage and decoded workspace drop before the shutdown registration on every
/// error/cancellation branch, independently of async or closure capture order.
struct ReceiptWork {
    generation: Arc<crate::Generation>,
    context: RequestContext,
    cancellation: QueryCancellation,
    deadline: tokio::time::Instant,
    reservation: Reservation,
    registration: Arc<WorkRegistration>,
}
impl ReceiptWork {
    fn run(mut self, key: &str) -> Result<ReceiptRead> {
        let mut check = || -> anyhow::Result<()> {
            self.cancellation.check()?;
            self.context.authorization.check_live()?;
            if tokio::time::Instant::now() >= self.deadline {
                anyhow::bail!(Error::new(
                    ErrorCode::Unavailable,
                    "mutation receipt deadline exceeded"
                ));
            }
            Ok(())
        };
        check().map_err(point_error)?;
        let row = self
            .generation
            .receipts
            .get_charged(key, |bytes| {
                let peak = crate::snapshot_codec::inspect_external_json_work(bytes, &mut check)?;
                // Row validation constructs at most one extra bounded canonical
                // receipt clone. Both remain charged until the worker returns.
                let peak = peak.checked_mul(2).ok_or_else(|| {
                    Error::new(
                        ErrorCode::ResourceExhausted,
                        "receipt decode workspace overflow",
                    )
                })?;
                self.reservation.reserve_additional(peak)?;
                check()
            })
            .map_err(point_error)?;
        let receipt = row
            .map(|row| {
                row.validate(&self.generation.state).map_err(point_error)?;
                Ok::<_, Error>(row.receipt)
            })
            .transpose()?;
        let strict_collections = receipt
            .as_ref()
            .map(|receipt| {
                receipt
                    .collections
                    .iter()
                    .filter(|name| {
                        self.generation
                            .state
                            .collections
                            .get(*name)
                            .is_some_and(|collection| collection.definition.strict_read_audit)
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        check().map_err(point_error)?;
        let revision = self.generation.state.revision;
        let epoch = self.generation.state.policy_epoch;
        let strict = self.generation.state.policy.strict_read_audit;
        drop(self.generation);
        self.reservation.retain_workspace();
        Ok(ReceiptRead {
            receipt,
            revision,
            epoch,
            strict,
            strict_collections,
            _reservation: self.reservation,
            _registration: self.registration,
        })
    }
}

fn point_error(error: anyhow::Error) -> Error {
    error
        .downcast_ref::<Error>()
        .cloned()
        .unwrap_or_else(|| Error::new(ErrorCode::Corruption, error.to_string()))
}
