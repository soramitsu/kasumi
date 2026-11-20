//! A bounded history of operations observed by this physical issuer. This
//! member-local namespace is deliberately outside every Raft generation;
//! restoring another member's state cannot establish a local clock interval.
use super::*;
use kasumi_types::{IssuerStopQuery, IssuerStopStage, IssuerStopStatus};

const NS: &str = "kasumi.authority.local-stop-observations";
const MAX_BYTES: usize = 2048;

// Exactly 256 slots. A later colliding stop can displace an earlier one; a
// missing or displaced observation supplies no qualification evidence.
fn slot(query: &IssuerStopQuery) -> Result<u8> {
    query.validate()?;
    let digest = kasumi_types::staged_digest(&("kasumi.issuer-stop-slot.v1", query))?.0;
    Ok(u8::from_str_radix(&digest[..2], 16)?)
}

impl Backend {
    fn read_stop_slot(&self, index: u8) -> Result<Option<IssuerStopStatus>> {
        self.store
            .get_bounded(NS, &[index], MAX_BYTES)?
            .map(|bytes| {
                let value: IssuerStopStatus = serde_json::from_slice(&bytes)?;
                value.validate_for(&value.query)?;
                ensure!(
                    slot(&value.query)? == index,
                    "issuer stop slot identity differs"
                );
                Ok(value)
            })
            .transpose()
    }

    pub(crate) fn note_stop(&self, value: &IssuerStopStatus) -> Result<()> {
        let _guard = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("authority state poisoned"))?;
        value.validate_for(&value.query)?;
        let index = slot(&value.query)?;
        if let Some(prior) = self.read_stop_slot(index)?
            && prior.query == value.query
        {
            ensure!(
                prior.authority_id == value.authority_id
                    && prior.partition == value.partition
                    && prior.node_id == value.node_id,
                "issuer stop observation belongs to another physical owner"
            );
            ensure!(
                prior.command_sha256 == value.command_sha256,
                "issuer stop command conflicts with the original local submission"
            );
            if prior.term > value.term {
                return Ok(());
            }
            if prior.term == value.term
                && prior.boot_id == value.boot_id
                && prior.interval_id == value.interval_id
            {
                if let (Some(first), Some(next)) =
                    (&prior.first_stop_sha256, &value.first_stop_sha256)
                {
                    ensure!(first == next, "issuer stop high-water outcome differs");
                }
                if prior.stage >= value.stage {
                    return Ok(());
                }
            }
        }
        let bytes = serde_json::to_vec(value)?;
        ensure!(
            bytes.len() <= MAX_BYTES,
            "issuer stop exceeds bounded physical observation slot"
        );
        self.store.write_batch(&[WriteOp::put(NS, [index], bytes)])
    }

    pub(crate) fn observed_stop(
        &self,
        query: &IssuerStopQuery,
    ) -> Result<Option<IssuerStopStatus>> {
        let mut observed = match self.read_stop_slot(slot(query)?)? {
            Some(prior) if prior.query == *query => prior,
            _ => return Ok(None),
        };
        if let Some(receipt) = self.receipt(&query.tenant, query.command_id)? {
            ensure!(
                receipt.command.digest()? == observed.command_sha256,
                "issuer stop command bytes differ"
            );
            let AuthorityOutcome::TargetStopped { target, .. } = &receipt.outcome else {
                return Ok(None);
            };
            ensure!(
                target.incarnation == query.target_incarnation,
                "issuer stop target differs"
            );
            let reference = TargetStopReference {
                tenant: query.tenant.clone(),
                command_id: query.command_id,
                receipt_digest: receipt.digest()?,
            };
            let first = self.stopped_target(&reference)?.digest()?;
            if observed.stage == IssuerStopStage::Submitting {
                observed.stage = IssuerStopStage::Committed;
                observed.first_stop_sha256 = Some(first);
            } else {
                ensure!(
                    observed.first_stop_sha256.as_ref() == Some(&first),
                    "issuer stop differs from its original quorum outcome"
                );
            }
        } else {
            ensure!(
                observed.stage == IssuerStopStage::Submitting,
                "issuer drain lacks its quorum stop"
            );
        }
        Ok(Some(observed))
    }
}
