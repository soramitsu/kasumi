//! Bounded standalone group commit. The existing proposal gate covers every
//! admission and the final apply; nothing is admitted against an in-flight
//! candidate. A lone caller proceeds immediately, without a batching timer.
use super::*;
use std::collections::VecDeque;

pub(super) struct Queued {
    pub(super) work: ProposalWork,
    pub(super) command: proposal_input::ProposalCommand,
    pub(super) max_bytes: usize,
    pub(super) send: tokio::sync::oneshot::Sender<proposal_jobs::Response>,
}

fn batch(item: &Queued) -> Option<&MutationBatch> {
    let Operation::Mutate(batch) = &item.command.command.operation else {
        return None;
    };
    (item.work.group.is_local()
        && !batch.operations.is_empty()
        && batch.operations.len() <= 16
        && proposal_input_len(&item.command.command).ok()? <= 64 << 10)
        .then_some(batch)
}

/// Take only a consecutive independent prefix. Other commands and conflicting
/// targets stay ordered behind it, so their admission sees its applied state.
pub(super) fn take(queue: &mut VecDeque<Queued>) -> Vec<Queued> {
    let Some(first) = queue.pop_front() else {
        return Vec::new();
    };
    let mut operations = batch(&first).map_or(0, |batch| batch.operations.len());
    let mut selected = vec![first];
    if operations == 0 {
        return selected;
    }
    while selected.len() < 16 {
        let Some(next) = queue.front() else { break };
        let Some(candidate) = batch(next) else { break };
        if operations + candidate.operations.len() > 32 {
            break;
        }
        let conflict = selected.iter().any(|prior| {
            let prior_batch = batch(prior).expect("selected mutation");
            (prior.command.command.context.principal == next.command.command.context.principal
                && prior_batch.idempotency_key == candidate.idempotency_key)
                || prior_batch.operations.iter().any(|previous| {
                    candidate
                        .operations
                        .iter()
                        .any(|next| previous.target() == next.target())
                })
        });
        if conflict {
            break;
        }
        operations += candidate.operations.len();
        selected.push(queue.pop_front().expect("peeked proposal"));
    }
    selected
}

fn denied(error: Error) -> anyhow::Result<Vec<u8>> {
    Ok(serde_json::to_vec(&Err::<WriteReceipt, _>(error))?)
}

fn answer(item: Queued, bytes: Vec<u8>) {
    let _ = item
        .send
        .send(proposal_jobs::Jobs::response(item.work, bytes));
}

/// Prepare only ordinary small mutations. Returning None selects the existing
/// sequential path for the entire prefix, without publishing any member.
fn prepare(items: &mut [Queued]) -> anyhow::Result<Option<(Vec<Vec<u8>>, u64)>> {
    let mut encoded = Vec::with_capacity(items.len());
    let mut quote = 0u64;
    for item in items {
        let command = &mut item.command.command;
        if command.context.authorization.check_live().is_err()
            || item
                .work
                .source_engine
                .check_operation_access(&command.operation)
                .is_err()
            || item.work.source_engine.generation()?.state.retired
        {
            return Ok(None);
        }
        command.timestamp_ms = item.work.clock.now_ms()?;
        if command
            .context
            .authorization
            .check_admitted_at(command.timestamp_ms)
            .is_err()
        {
            return Ok(None);
        }
        let bytes = encode_proposal_input(command, item.max_bytes)?;
        if proposal_input::check_command_nesting(&bytes).is_err() {
            return Ok(None);
        }
        let Ok((joined, member)) = item
            .work
            .source_engine
            .quote_command_publication(command, Some(bytes.len()))
        else {
            return Ok(None);
        };
        if !joined {
            return Ok(None);
        }
        quote = quote
            .checked_add(member)
            .ok_or_else(|| anyhow::anyhow!("group publication admission overflow"))?;
        encoded.push(bytes);
    }
    Ok(Some((encoded, quote)))
}

async fn sequential(items: Vec<Queued>) -> anyhow::Result<()> {
    for mut item in items {
        let bytes = item.work.run(item.command, item.max_bytes).await?;
        let _ = item
            .send
            .send(proposal_jobs::Jobs::response(item.work, bytes));
    }
    Ok(())
}

pub(super) async fn run(mut items: Vec<Queued>) -> anyhow::Result<()> {
    if items.is_empty() {
        return Ok(());
    }
    let group = items[0].work.group.clone();
    let prepared = if items.len() > 1 && group.admission_term(APPLIED_TERM_DEADLINE).await.is_some()
    {
        prepare(&mut items)?
    } else {
        None
    };
    let Some((encoded, quote)) = prepared else {
        return sequential(items).await;
    };
    // Each conservative quote includes that member's native input, bodies and
    // receipt. One escrow holds their sum; repeated admission must not replace
    // or shrink earlier members' capacity before their common apply.
    if let Err(error) = items[0].work.source_engine.admit_publication_bytes(quote) {
        if error.code == ErrorCode::ResourceExhausted {
            // No member has been prepared or written. Re-admit the same owned
            // requests one at a time, each replacing the unused aggregate peak.
            // A batching optimization must not impose a new acceptance limit.
            drop(encoded);
            return sequential(items).await;
        }
        for item in items {
            answer(item, denied(error.clone())?);
        }
        return Ok(());
    }
    let mut proposals = Vec::with_capacity(items.len());
    for (item, bytes) in items.iter().zip(encoded) {
        let provider: Arc<dyn kasumi_store::NodeDiskMemoryAdmission> =
            item.work.admission.memory().clone();
        let mut input = kasumi_raft::ApplicationInputInstall::new(bytes, provider);
        let Operation::Mutate(batch) = &item.command.command.operation else {
            unreachable!("selected mutation")
        };
        input
            .prepare_mutation_change_tree(batch)
            .map_err(|error| anyhow::anyhow!("group change-tree recipe refused: {error:?}"))?;
        item.work
            .admission
            .memory()
            .bind_application_input(&item.work._reservation, &mut input)
            .map_err(|error| anyhow::anyhow!("group input binding refused: {error:?}"))?;
        proposals.push(kasumi_raft::ApplicationProposal::admitted_input(
            input
                .finish()
                .unwrap_or_else(|_| unreachable!("original input installed once")),
        ));
    }
    let responses = match group.write_joined_group(proposals).await {
        Ok(responses) => responses,
        Err(error) => {
            // A typed pre-publication refusal or post-commit access loss is a
            // request outcome for every member. Any other original error stays
            // in this driver's registered BackgroundWork, closing proposal work.
            let bytes = proposal_response(Err(error))?;
            for item in items {
                answer(item, bytes.clone());
            }
            return Ok(());
        }
    };
    anyhow::ensure!(
        responses.len() == items.len(),
        "group response count differs"
    );
    for (item, result) in items.into_iter().zip(responses) {
        answer(item, proposal_response(result)?);
    }
    Ok(())
}
